import AxeBuilder from '@axe-core/playwright';
import { expect, type Page } from '@playwright/test';
import { auditContrast, formatContrastFailures } from './contrast';
import { auditNonText, formatNonTextFailures, type NonTextFailure } from './nontext';
import { NONTEXT_BASELINE } from './nontext-baseline';

export const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

/** A phone-width viewport, for the WCAG 1.4.10 reflow half of the gate. */
export const NARROW = { width: 380, height: 800 };

/**
 * Shared machinery for the WCAG gate.
 *
 * Three rules govern everything here:
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE BEFORE A SCAN. The gate this replaced
 *     forced `details.open = true` on a page that has no `<details>`, and
 *     measured a "gradient contrast" helper that RETURNED A PASSING 5.0 (well,
 *     a literal `100`) whenever it could not find or parse the element it was
 *     given. A default that passes on absence is not an oracle.
 *
 *  2. EVERY SCAN ASSERTS ITS CONTENT IS PRESENT FIRST, and there are scans well
 *     past first paint. This lab is five tab panels, four of which render
 *     `aria-hidden` and `display: none` until their tab is clicked — so a gate
 *     that scans only the untouched page has audited one fifth of it. The
 *     forgery verdicts, the sweep grid, the avalanche distribution chart and
 *     the benchmark table do not exist at first paint at all.
 *
 *  3. `violations` IS NOT THE WHOLE ORACLE. See `scan`.
 */

/**
 * Wait for every running animation and transition to drain.
 *
 * Transitions drain in waves, not in one batch, so a poll for "nothing running
 * right now" can exit through a gap between waves. Require quiescence to hold
 * for several consecutive frames instead.
 */
export async function settle(page: Page): Promise<void> {
  await page.waitForFunction(
    () => {
      const w = window as unknown as { __quietFrames?: number };
      const running = document.getAnimations().filter((a) => a.playState === 'running');
      w.__quietFrames = running.length === 0 ? (w.__quietFrames ?? 0) + 1 : 0;
      return w.__quietFrames >= 6;
    },
    undefined,
    { timeout: 20_000, polling: 'raf' }
  );
}

/**
 * Assert that reduced motion left the page visible, not merely un-animated.
 *
 * The failure mode this guards against is an element whose only route to its
 * visible state is an animation, in a stylesheet whose reduced-motion block
 * cancels that animation without restoring its end state — the element then
 * renders at `opacity: 0` for every reader with the preference set. This lab's
 * reduced-motion block cancels `.bit-cell.flash`, which animates `transform`
 * and `filter` only, so the end state is not at risk here; the assertion stays
 * because it is cheap and the block is the kind of thing that grows.
 */
async function expectNotBlank(page: Page, label: string): Promise<void> {
  const invisible = await page.evaluate(() => {
    const out: string[] = [];
    for (const el of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(el.childNodes)
        .filter((n) => n.nodeType === Node.TEXT_NODE)
        .map((n) => n.textContent ?? '')
        .join('')
        .trim();
      if (!own) continue;
      // Deliberately hidden subtrees are not "blank", they are closed.
      if (!(el as HTMLElement).checkVisibility?.({ checkVisibilityCSS: true })) continue;
      let effective = 1;
      let node: Element | null = el;
      while (node) {
        effective *= parseFloat(getComputedStyle(node).opacity);
        node = node.parentElement;
      }
      if (effective === 0) {
        out.push(`${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}`);
      }
    }
    return Array.from(new Set(out));
  });
  expect(invisible, `no visible text may render at opacity 0 in state: ${label}`).toEqual([]);
}

/**
 * Load the page in a known theme with reduced motion actually in effect, and
 * assert the content every scan relies on is really on the page.
 *
 * `test.use({ reducedMotion })` silently does nothing on Playwright 1.61.1, so
 * the emulation is applied imperatively BEFORE the navigation and then
 * *asserted* from inside the page. The gate this replaced called
 * `emulateMedia({ reducedMotion: 'reduce' })` and never checked it took effect,
 * which is indistinguishable from not calling it at all.
 *
 * The theme is seeded in `localStorage` rather than reached by clicking the
 * toggle, so the light run boots light instead of ramping into it.
 */
export async function boot(page: Page, theme: 'dark' | 'light'): Promise<void> {
  // A click on a control that never becomes actionable otherwise burns the
  // whole test timeout and reports nothing useful. 20s turns that silent hang
  // into a named failure naming the locator.
  page.setDefaultTimeout(20_000);
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.addInitScript((t) => localStorage.setItem('theme', t), theme);
  await page.goto('.');
  expect(
    await page.evaluate(() => matchMedia('(prefers-reduced-motion: reduce)').matches),
    'reduced-motion emulation must actually be in effect'
  ).toBe(true);
  await expect(page.locator('html')).toHaveAttribute('data-theme', theme);

  // The app renders itself into #app, so an empty shell would otherwise scan
  // clean. Assert the tab strip and the first panel's own controls exist.
  await expect(page.locator('[role="tablist"] [role="tab"]')).toHaveCount(5);
  await expect(page.locator('#avalanche-algorithm')).toBeVisible();
  await expect(page.locator('.bit-grid').first()).toBeVisible();

  await settle(page);
  await expectNotBlank(page, `${theme} first paint`);
}

/**
 * Assert the page does not require horizontal scrolling.
 *
 * WCAG 1.4.10 (Reflow, AA). axe has no rule for this at all, and this lab is a
 * plausible offender: it prints 64-character hex digests, a 32-column bit grid
 * per digest, a six-row comparison table and a 32-chip sweep row.
 */
export async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const overflow = await page.evaluate(() => {
    const doc = document.documentElement;
    if (doc.scrollWidth <= doc.clientWidth) return null;

    // Only elements that actually push the DOCUMENT sideways are culprits. A
    // wide table inside an `overflow-x: auto` wrapper has a huge bounding rect
    // but is clipped by its scroller and contributes nothing to the document's
    // scroll width — naming it sends you off fixing the wrong element.
    const clipped = (el: Element): boolean => {
      let n = el.parentElement;
      while (n && n !== doc) {
        const ox = getComputedStyle(n).overflowX;
        if (ox === 'auto' || ox === 'scroll' || ox === 'hidden' || ox === 'clip') return true;
        n = n.parentElement;
      }
      return false;
    };

    const over = Array.from(document.querySelectorAll('body *'))
      .map((el) => ({ el, r: el.getBoundingClientRect() }))
      .filter((x) => x.r.width > 0 && x.r.right > doc.clientWidth + 1)
      .sort((a, b) => b.r.right - a.r.right);
    // Prefer an unclipped culprit; fall back to the widest clipped one rather
    // than reporting nothing, so the message always names something to look at.
    const widest = over.filter((x) => !clipped(x.el))[0] ?? over[0];
    return {
      scrollWidth: doc.scrollWidth,
      clientWidth: doc.clientWidth,
      widest: widest
        ? `${clipped(widest.el) ? '[clipped] ' : ''}${widest.el.tagName.toLowerCase()}${widest.el.id ? '#' + widest.el.id : ''}` +
          `${widest.el.getAttribute('class') ? '.' + widest.el.getAttribute('class')!.trim().split(/\s+/).join('.') : ''}` +
          ` @${Math.round(widest.r.width)}px right=${Math.round(widest.r.right)}`
        : '(none identified)',
    };
  });
  expect(overflow, `page must not scroll horizontally in state: ${label}`).toBeNull();
}

/**
 * Every scrolling container must be operable from the keyboard (WCAG 2.1.1).
 * If it holds no focusable content it needs `tabindex="0"`, so it becomes a
 * focus target arrow keys can then scroll.
 */
export async function expectScrollersReachable(page: Page, label: string): Promise<void> {
  const unreachable = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => el.tabIndex < 0 && !el.querySelector(FOCUSABLE))
      .map(
        (el) =>
          `${el.tagName.toLowerCase()}.${(el.getAttribute('class') ?? '').trim()}` +
          ` (${el.scrollWidth}x${el.scrollHeight} in ${el.clientWidth}x${el.clientHeight})`
      );
  });
  expect(
    Array.from(new Set(unreachable)),
    `scrolling regions with no keyboard route in state: ${label}`
  ).toEqual([]);
}

/**
 * Scan the page as it currently stands.
 *
 * Five assertions, because axe's `violations` array alone is not a complete
 * oracle:
 *
 *  - `violations` — the usual WCAG A/AA rule failures.
 *  - `incomplete` — axe's "could not decide" bucket, which never reaches the
 *    violations array. The one rule id allowed to remain incomplete is
 *    `color-contrast`, and only because the next assertion computes those
 *    ratios arithmetically. Everything else in that bucket is a real result
 *    axe simply could not finish — including `aria-prohibited-attr`, which is
 *    where an `aria-label` on a role-less div hides, a defect that never
 *    reaches the violations array at all.
 *  - arithmetic contrast — composite-aware WCAG 1.4.3 over every text node.
 *  - keyboard reachability of scrolling regions — WCAG 2.1.1.
 *  - reflow — WCAG 1.4.10, which axe has no rule for at all.
 */
/**
 * WCAG 1.4.11 and generated content, ratcheted against a per-repo baseline.
 *
 * Neither class has ANY other oracle: axe has no rule for non-text contrast,
 * and the arithmetic text walk cannot reach a control's boundary or a
 * `::before` glyph, because a pseudo-element is not an element and owns no text
 * node. Both were being found by hand-sampling screenshot pixels, which does
 * not regress-test.
 *
 * The backlog is real, so this does not block on it — but a check that merely
 * logs is not a gate, and this sweep has spent its whole length deleting checks
 * that could not fail. So it ratchets instead: anything NOT in the baseline
 * fails, anything in the baseline that got WORSE fails, and anything in the
 * baseline that has been FIXED fails until its entry is deleted. That last rule
 * is what stops the allowlist becoming a permanent exemption.
 */
const nonTextSeen = new Set<string>();

export async function expectNoNewNonTextFailures(page: Page, label: string): Promise<void> {
  const found = await auditNonText(page);
  // Capture mode: emit every finding and assert nothing, so a baseline can be
  // generated by the SAME path that checks it. Opt-in via env, and the run is
  // deliberately left failing at the end by `expectBaselineNotStale` so a
  // capture pass can never be mistaken for a passing gate.
  if (process.env.NT_BASELINE_CAPTURE) {
    for (const f of found) {
      console.log(`NTCAP|${f.kind}|${f.selector}|${f.ratio}|${f.required}|${/POSITIONED/.test(f.detail)}`);
    }
    return;
  }
  const problems: string[] = [];
  for (const f of found) {
    const key = `${f.kind}|${f.selector}`;
    nonTextSeen.add(key);
    const base = NONTEXT_BASELINE[key];
    if (!base) {
      problems.push(`NEW ${f.ratio}:1 (needs ${f.required}:1) [${f.kind}] ${f.selector} — ${f.detail}`);
    } else if (f.ratio < base.ratio - 0.01) {
      problems.push(
        `WORSE ${f.selector}: ${f.ratio}:1, baseline recorded ${base.ratio}:1`
      );
    }
  }
  expect(problems, `new or worsened non-text contrast in state: ${label}`).toEqual([]);
}

/**
 * Fail if a baselined finding never appeared during the whole drive.
 *
 * It has either been fixed — in which case delete the entry, which is the point
 * — or the drive stopped reaching the state that shows it, which is a coverage
 * regression worth knowing about. Call once, after `driveAllStates`.
 */
export function expectBaselineNotStale(): void {
  const unseen = Object.keys(NONTEXT_BASELINE).filter((k) => !nonTextSeen.has(k));
  expect(
    unseen,
    'baselined non-text findings that no longer appear — delete them from nontext-baseline.ts (or restore the drive state that showed them)'
  ).toEqual([]);
}

export async function scan(page: Page, label: string): Promise<void> {
  await settle(page);
  await expectNotBlank(page, label);
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();

  const violations = results.violations.map((v) => ({
    state: label,
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
  }));
  expect(violations, `axe violations in state: ${label}`).toEqual([]);

  const unexplainedIncomplete = results.incomplete
    .filter((v) => v.id !== 'color-contrast')
    .map((v) => ({
      state: label,
      id: v.id,
      nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 8),
    }));
  expect(unexplainedIncomplete, `axe incomplete results in state: ${label}`).toEqual([]);

  const contrast = Array.from(new Set(formatContrastFailures(await auditContrast(page))));
  expect(contrast, `measured contrast failures in state: ${label}`).toEqual([]);

  await expectNoNewNonTextFailures(page, label);
  await expectScrollersReachable(page, label);
  await expectNoHorizontalOverflow(page, label);
}

/** Click a tab and wait for its panel to be the shown one. */
async function openTab(page: Page, id: string): Promise<void> {
  await page.locator(`#tab-${id}`).click();
  await expect(page.locator(`#panel-${id}`)).toHaveAttribute('aria-hidden', 'false');
  await expect(page.locator(`#panel-${id}`)).toBeVisible();
}

/**
 * Drive the lab through the states that render content, scanning each.
 *
 * All five tabs are opened, because four of them are `display: none` at first
 * paint and a gate that never clicks a tab has scanned one panel out of five.
 * Within them, both branches of each verdict are reached: the length-extension
 * forgery is driven to ACCEPTED (a correct length guess) and to REJECTED (a
 * wrong one), and the HMAC panel is driven to its normal rejection AND to its
 * empty-key error branch, which renders a different panel entirely.
 */
export async function driveAllStates(page: Page, theme: string): Promise<void> {
  await scan(page, `${theme} / first paint (avalanche)`);

  // --- Tab 1: avalanche ---------------------------------------------------
  // A short input keeps the "one flip per input bit" sweep to 32 hashes rather
  // than 552; the rendering under test is the same either way.
  await page.locator('#avalanche-input').fill('babel');
  await expect(page.locator('#avalanche-bit')).toHaveAttribute('max', '39');
  await scan(page, `${theme} / avalanche input changed`);

  await page.locator('#avalanche-algorithm').selectOption('sha3-256');
  await scan(page, `${theme} / avalanche sha3-256`);

  await page.locator('#avalanche-algorithm').selectOption('blake3');
  await scan(page, `${theme} / avalanche blake3`);

  // The slider re-renders the grids and repaints the highlighted input byte.
  await page.locator('#avalanche-bit').fill('17');
  await scan(page, `${theme} / avalanche bit 17 flipped`);

  // Clicking an output bit writes the explanation callout — a surface that
  // does not exist until a bit is clicked.
  await page.locator('.bit-cell[data-changed="true"]').first().click();
  await expect(page.locator('#panel-avalanche .callout.warn')).toContainText('output bit');
  await scan(page, `${theme} / avalanche bit explained`);

  // Copy buttons switch to a "Copied!" label with its own colours.
  await page.locator('#panel-avalanche .copy-btn').first().click();
  await scan(page, `${theme} / digest copied`);

  await page.locator('#toggle-compare-all').click();
  await expect(page.locator('.bit-grid')).toHaveCount(6);
  await scan(page, `${theme} / avalanche all three algorithms`);

  // The distribution chart is a whole exhibit that renders only after this run.
  await page.locator('#run-distribution').click();
  await expect(page.locator('.dist-chart')).toBeVisible();
  await scan(page, `${theme} / avalanche distribution measured`);

  // --- Tab 2: length extension -------------------------------------------
  await openTab(page, 'length');
  await scan(page, `${theme} / length extension first view`);

  // A wrong length guess: the REJECTED branch of the verdict.
  await page.locator('#attack-secret-length').fill('3');
  await expect(page.locator('#panel-length .failure')).toContainText('forgery rejected');
  await scan(page, `${theme} / forgery rejected`);

  // The real secret is 9 bytes ("kingdom42"): the ACCEPTED branch.
  await page.locator('#attack-secret-length').fill('9');
  await expect(page.locator('#panel-length .success')).toContainText('forgery accepted');
  await scan(page, `${theme} / forgery accepted`);

  await page.locator('#attack-extension').fill('&role=admin');
  await scan(page, `${theme} / extension edited`);

  // The 32-chip sweep grid, which does not exist until the sweep runs.
  await page.locator('#sweep-secret-lengths').click();
  await expect(page.locator('.sweep-chip')).toHaveCount(32);
  await expect(page.locator('.sweep-chip.verified')).toHaveCount(1);
  await scan(page, `${theme} / secret-length sweep`);

  await page.locator('.sweep-chip').nth(0).click();
  await scan(page, `${theme} / sweep chip selected`);

  // --- Tab 3: HMAC --------------------------------------------------------
  await openTab(page, 'hmac');
  await expect(page.locator('#panel-hmac .failure')).toContainText('forgery rejected');
  await scan(page, `${theme} / hmac rejects the same forgery`);

  await page.locator('#hmac-message').fill('amount=10&to=bob');
  await page.locator('#hmac-secret-length').fill('9');
  await scan(page, `${theme} / hmac message edited`);

  // --- Tab 4: algorithm comparison ---------------------------------------
  await openTab(page, 'comparison');
  await scan(page, `${theme} / comparison table`);

  // Opening this tab STARTS the benchmark by itself (setActiveTab runs it
  // lazily the first time), and the button is disabled while it runs. Wait for
  // that pass to finish before clicking, or the click races a disabled control.
  await expect(page.locator('#run-benchmark')).toBeEnabled();
  await expect(page.locator('#benchmark-rows')).toContainText('MB/s');
  await scan(page, `${theme} / benchmark complete`);

  await page.locator('#run-benchmark').click();
  await expect(page.locator('#run-benchmark')).toBeEnabled();
  await scan(page, `${theme} / benchmark re-run`);

  // --- Tab 5: portfolio ---------------------------------------------------
  await openTab(page, 'portfolio');
  await scan(page, `${theme} / portfolio thread`);

  // Both skip links are parked off-screen until focused; the focused rendering
  // is the only one that paints, so it is the only one worth measuring.
  await page.keyboard.press('Tab');
  await scan(page, `${theme} / skip link focused`);

  // --- The empty-secret error branch --------------------------------------
  // Clearing the server secret makes WebCrypto refuse to sign, and the HMAC
  // panel replaces itself with an explanatory failure state. It is a real
  // rendering a visitor reaches by clearing a text field.
  await openTab(page, 'length');
  await page.locator('#attack-secret').fill('');
  await openTab(page, 'hmac');
  await expect(page.locator('#panel-hmac .failure')).toContainText('No HMAC key');
  await scan(page, `${theme} / hmac empty-secret error`);
}
