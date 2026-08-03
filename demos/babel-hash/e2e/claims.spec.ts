import { Buffer } from 'node:buffer';
import { createHash, createHmac } from 'node:crypto';

import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * Claims gate. Every headline verdict, counter and failure path this demo
 * advertises is asserted here against the rendered page — not against a
 * hardcoded transcript of it.
 *
 * Where the page computes a value, the assertion recomputes it independently
 * (Node's SHA-256/HMAC, or the page's own other code path) and compares.
 * Where the page states a statistic, the assertion checks it against its own
 * parts: percentages against their numerator and denominator, histogram
 * buckets against the trial count, bit grids against the digests they claim
 * to visualize.
 */

const DEFAULT_SECRET = 'kingdom42';
const DEFAULT_MESSAGE = 'comment=hello&admin=false';
const DEFAULT_EXTENSION = '&admin=true';

/* ------------------------------------------------------------------ */
/* independent reference implementations                               */
/* ------------------------------------------------------------------ */

function sha256Hex(...parts: Buffer[]): string {
  return createHash('sha256').update(Buffer.concat(parts)).digest('hex');
}

function hmacHex(key: string, message: string): string {
  return createHmac('sha256', Buffer.from(key, 'utf8')).update(message, 'utf8').digest('hex');
}

function utf8(value: string): Buffer {
  return Buffer.from(value, 'utf8');
}

function hexToBuffer(hex: string): Buffer {
  return Buffer.from(hex, 'hex');
}

/** Flip bit `position` (MSB-first within each byte), matching flipBitBytes. */
function flipBit(value: string, position: number): Buffer {
  const bytes = utf8(value);
  bytes[Math.floor(position / 8)] ^= 1 << (7 - (position % 8));
  return bytes;
}

function popcount(hex: string): number {
  let bits = 0;
  for (const byte of hexToBuffer(hex)) {
    for (let index = 0; index < 8; index += 1) {
      bits += (byte >> index) & 1;
    }
  }
  return bits;
}

function hammingDistance(a: string, b: string): number {
  const left = hexToBuffer(a);
  const right = hexToBuffer(b);
  expect(left.length).toBe(right.length);
  let distance = 0;
  for (let index = 0; index < left.length; index += 1) {
    let diff = left[index] ^ right[index];
    while (diff !== 0) {
      distance += diff & 1;
      diff >>= 1;
    }
  }
  return distance;
}

/* ------------------------------------------------------------------ */
/* page helpers                                                        */
/* ------------------------------------------------------------------ */

const HEX64 = /^[0-9a-f]{64}$/;

async function boot(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('#panel-avalanche .card').first()).toBeVisible();
}

async function openTab(page: Page, tab: 'avalanche' | 'length' | 'hmac' | 'comparison'): Promise<void> {
  await page.locator(`[data-tab-target="${tab}"]`).click();
  await expect(page.locator(`#panel-${tab}`)).toHaveAttribute('aria-hidden', 'false');
}

/** Range inputs ignore fill(); drive them the way the page's own listener sees. */
async function setRange(page: Page, id: string, value: number): Promise<void> {
  await page.locator(`#${id}`).evaluate((element, next) => {
    (element as HTMLInputElement).value = String(next);
    element.dispatchEvent(new Event('input', { bubbles: true }));
  }, value);
}

function squash(text: string | null): string {
  return (text ?? '').replace(/\s+/gu, ' ').trim();
}

async function textOf(locator: Locator): Promise<string> {
  return squash(await locator.textContent());
}

/** Pull one anchored number out of a label that may contain several. */
function numberFrom(text: string, pattern: RegExp): number {
  const match = pattern.exec(text);
  expect(match, `expected ${String(pattern)} to match ${JSON.stringify(text)}`).not.toBeNull();
  return Number(match![1]);
}

async function avalancheCard(page: Page, index = 0): Promise<{
  algorithm: string;
  changedBits: number;
  totalBits: number;
  percentText: string;
  originalDigest: string;
  modifiedDigest: string;
  card: Locator;
}> {
  const card = page.locator('#panel-avalanche .card').nth(index);
  const chips = card.locator('.stat-chip');
  const changedText = await textOf(chips.nth(0));
  const percentText = await textOf(chips.nth(1));
  const digests = await card.locator('.copyable-value').allTextContents();

  return {
    algorithm: await textOf(card.locator('h3')),
    changedBits: numberFrom(changedText, /(\d+) \/ \d+ bits changed/u),
    totalBits: numberFrom(changedText, /\d+ \/ (\d+) bits changed/u),
    percentText: numberFrom(percentText, /([\d.]+)% diffusion/u).toFixed(1),
    originalDigest: digests[0].trim(),
    modifiedDigest: digests[1].trim(),
    card
  };
}

function sweepPanel(page: Page): Locator {
  return page.locator('#panel-length .panel').filter({ has: page.locator('.sweep-grid') });
}

function lengthVerdict(page: Page): Locator {
  return page.locator('#panel-length .callout.warn').first();
}

function hmacVerdict(page: Page): Locator {
  return page.locator('#panel-hmac .callout.warn').first();
}

/* ================================================================== */
/* 1. Avalanche — the headline counter, checked against its own digests */
/* ================================================================== */

test('avalanche counter, percentage and bit grids all agree with the digests on screen', async ({ page }) => {
  await boot(page);

  const view = await avalancheCard(page);

  // The two digests are the artifacts the headline number is a claim about.
  expect(view.originalDigest).toMatch(HEX64);
  expect(view.modifiedDigest).toMatch(HEX64);
  expect(view.totalBits).toBe(256);

  // Verdict vs. the thing it describes: "N / 256 bits changed" must be the
  // real Hamming distance between the two rendered digests.
  expect(view.changedBits).toBe(hammingDistance(view.originalDigest, view.modifiedDigest));

  // The rendered percentage must be its own numerator over its own denominator.
  expect(view.percentText).toBe(((view.changedBits / view.totalBits) * 100).toFixed(1));

  // Independent implementation: the digests are SHA-256 of the stated input
  // and of that input with exactly the selected bit flipped.
  const input = await page.locator('#avalanche-input').inputValue();
  expect(view.originalDigest).toBe(sha256Hex(utf8(input)));
  expect(view.modifiedDigest).toBe(sha256Hex(flipBit(input, 0)));

  // Render layer: each grid paints all 256 bits, highlights exactly the
  // changed ones, and colours each cell by that digest's actual bit value.
  const grids = view.card.locator('.bit-grid');
  await expect(grids).toHaveCount(2);
  for (const [index, digest] of [view.originalDigest, view.modifiedDigest].entries()) {
    const grid = grids.nth(index);
    await expect(grid.locator('.bit-cell')).toHaveCount(256);
    await expect(grid.locator('.bit-cell.changed')).toHaveCount(view.changedBits);
    await expect(grid.locator('.bit-cell.bit-1')).toHaveCount(popcount(digest));
    await expect(grid.locator('.bit-cell.bit-0')).toHaveCount(256 - popcount(digest));
  }
});

test('the flip-position labels describe the bit the page actually flipped', async ({ page }) => {
  await boot(page);

  const input = await page.locator('#avalanche-input').inputValue();
  const inputBits = utf8(input).length * 8;

  await expect(page.locator('#avalanche-bit')).toHaveAttribute('max', String(inputBits - 1));
  expect(await textOf(page.locator('label[for="avalanche-bit"]'))).toBe(
    `Flip bit 0 of ${inputBits - 1}`
  );

  await setRange(page, 'avalanche-bit', 11);
  await expect(page.locator('label[for="avalanche-bit"]')).toContainText('Flip bit 11');

  const view = await avalancheCard(page);
  // 11 = byte 1, and bit 7 - (11 % 8) = bit 4 counting from the LSB.
  expect(await textOf(view.card.locator('.stat-chip').nth(2))).toBe('Flip: 11 (byte 1, bit 4)');
  expect(view.modifiedDigest).toBe(sha256Hex(flipBit(input, 11)));
  expect(view.changedBits).toBe(hammingDistance(view.originalDigest, view.modifiedDigest));
});

test('all three hash functions land near 50% diffusion, each consistent with its own digests', async ({ page }) => {
  await boot(page);
  await page.locator('#toggle-compare-all').click();
  await expect(page.locator('#panel-avalanche .card')).toHaveCount(3);

  const labels: string[] = [];
  const digests: string[] = [];

  for (let index = 0; index < 3; index += 1) {
    const view = await avalancheCard(page, index);
    labels.push(view.algorithm);

    expect(view.originalDigest).toMatch(HEX64);
    expect(view.modifiedDigest).toMatch(HEX64);
    expect(view.changedBits).toBe(hammingDistance(view.originalDigest, view.modifiedDigest));
    expect(view.percentText).toBe(((view.changedBits / 256) * 100).toFixed(1));

    // The README's headline property: ~50% of output bits move per input bit.
    expect(view.changedBits).toBeGreaterThan(256 * 0.3);
    expect(view.changedBits).toBeLessThan(256 * 0.7);

    digests.push(view.originalDigest, view.modifiedDigest);
  }

  expect(labels).toEqual(['SHA-256', 'SHA3-256', 'BLAKE3']);
  // Three genuinely different constructions, not the same digest relabelled.
  expect(new Set(digests).size).toBe(6);

  // Only SHA-256 is claimed to be the WebCrypto one; pin it to the reference.
  const input = await page.locator('#avalanche-input').inputValue();
  expect(digests[0]).toBe(sha256Hex(utf8(input)));
});

/* ================================================================== */
/* 2. Length extension — success path, failure path, and the sweep     */
/* ================================================================== */

test('the accepted forgery really verifies under the secret the attacker never saw', async ({ page }) => {
  await boot(page);
  await openTab(page, 'length');

  // Success verdict, and it is styled as a success rather than merely present.
  await expect(lengthVerdict(page).locator('.success')).toHaveText(
    'forgery accepted — attack succeeds'
  );
  await expect(lengthVerdict(page).locator('.failure')).toHaveCount(0);

  const chips = page.locator('#panel-length .stat-chip');
  const serverMac = (await textOf(chips.nth(0))).replace('Server MAC: ', '');
  const gluePaddingBytes = numberFrom(await textOf(chips.nth(1)), /Glue padding bytes: (\d+)/u);

  // The server MAC the page prints is really SHA-256(secret || message),
  // computed here by an implementation the demo does not own.
  expect(serverMac).toMatch(HEX64);
  expect(serverMac).toBe(sha256Hex(utf8(DEFAULT_SECRET), utf8(DEFAULT_MESSAGE)));

  const pres = page.locator('#panel-length pre.digest-block');
  const gluePadding = await textOf(pres.nth(0));
  const forgedPayload = await textOf(pres.nth(1));
  const forgedMac = (await page.locator('#panel-length .copyable-value').allTextContents())[0].trim();

  // The counter matches the artifact it counts.
  expect(gluePadding.length / 2).toBe(gluePaddingBytes);

  // The forged payload is exactly message ‖ glue padding ‖ extension, and the
  // secret plus that prefix is block-aligned — which is the whole trick.
  expect(forgedPayload).toBe(
    utf8(DEFAULT_MESSAGE).toString('hex') + gluePadding + utf8(DEFAULT_EXTENSION).toString('hex')
  );
  const guess = numberFrom(
    await textOf(page.locator('label[for="attack-secret-length"]')),
    /Guess secret length: (\d+) bytes/u
  );
  expect((guess + utf8(DEFAULT_MESSAGE).length + gluePaddingBytes) % 64).toBe(0);

  // The strongest claim on the page: the attacker's MAC, produced without the
  // secret, equals SHA-256(secret ‖ forged payload). Recomputed with the secret.
  expect(forgedMac).toMatch(HEX64);
  expect(forgedMac).toBe(sha256Hex(utf8(DEFAULT_SECRET), hexToBuffer(forgedPayload)));

  // Attacker-view vs. hidden-secret cards must not contradict each other.
  const known = await textOf(page.locator('#panel-length .card ul').nth(0));
  const hidden = await textOf(page.locator('#panel-length .card ul').nth(1));
  expect(known).toContain(`mac = ${serverMac}`);
  expect(known).toContain(`guessed secret length = ${guess}`);
  expect(hidden).toContain(`real secret length = ${utf8(DEFAULT_SECRET).length} bytes`);
  expect(guess).toBe(utf8(DEFAULT_SECRET).length);
});

test('the demo computes SHA-256 two independent ways and they agree', async ({ page }) => {
  await boot(page);

  // The length-extension tab hashes secret ‖ message with the demo's own
  // hand-rolled compression function; the avalanche tab hashes through
  // WebCrypto. Feed the second the first's input and the digests must match.
  await openTab(page, 'length');
  const serverMac = (await textOf(page.locator('#panel-length .stat-chip').nth(0))).replace(
    'Server MAC: ',
    ''
  );

  await openTab(page, 'avalanche');
  await page.locator('#avalanche-input').fill(`${DEFAULT_SECRET}${DEFAULT_MESSAGE}`);
  await expect(page.locator('label[for="avalanche-bit"]')).toContainText(
    `of ${utf8(`${DEFAULT_SECRET}${DEFAULT_MESSAGE}`).length * 8 - 1}`
  );

  const view = await avalancheCard(page);
  expect(view.originalDigest).toBe(serverMac);
});

test('a wrong secret-length guess reaches the rejected verdict and says why', async ({ page }) => {
  await boot(page);
  await openTab(page, 'length');

  await setRange(page, 'attack-secret-length', 7);
  await expect(lengthVerdict(page).locator('.failure')).toHaveText(
    'forgery rejected — wrong secret-length guess'
  );
  await expect(lengthVerdict(page).locator('.success')).toHaveCount(0);

  // Rejected for a reason: the forged MAC genuinely is not the one the server
  // would compute over the payload the attacker submitted.
  const forgedPayload = await textOf(page.locator('#panel-length pre.digest-block').nth(1));
  const forgedMac = (await page.locator('#panel-length .copyable-value').allTextContents())[0].trim();
  expect(forgedMac).not.toBe(sha256Hex(utf8(DEFAULT_SECRET), hexToBuffer(forgedPayload)));

  // And the guess really did change the padding the attacker reconstructed.
  const gluePaddingBytes = numberFrom(
    await textOf(page.locator('#panel-length .stat-chip').nth(1)),
    /Glue padding bytes: (\d+)/u
  );
  expect((7 + utf8(DEFAULT_MESSAGE).length + gluePaddingBytes) % 64).toBe(0);

  // Sliding back to the true length recovers the accepted verdict.
  await setRange(page, 'attack-secret-length', utf8(DEFAULT_SECRET).length);
  await expect(lengthVerdict(page).locator('.success')).toHaveText(
    'forgery accepted — attack succeeds'
  );
});

test('the length sweep finds exactly one accepted guess and names it correctly', async ({ page }) => {
  await boot(page);
  await openTab(page, 'length');
  await page.locator('#sweep-secret-lengths').click();

  const chips = page.locator('.sweep-chip');
  await expect(chips).toHaveCount(32);
  await expect(page.locator('.sweep-chip.verified')).toHaveCount(1);
  await expect(page.locator('.sweep-chip.verified')).toHaveAttribute(
    'data-sweep-guess',
    String(utf8(DEFAULT_SECRET).length)
  );

  const prose = await textOf(sweepPanel(page).locator('p.muted.small'));
  expect(prose).toContain(
    `The server accepted the guess ${utf8(DEFAULT_SECRET).length} — matching the real secret length of ${utf8(DEFAULT_SECRET).length} bytes.`
  );

  // Chips are actionable: loading a wrong one flips the verdict, and loading
  // the accepted one restores it.
  await page.locator('[data-sweep-guess="4"]').click();
  await expect(lengthVerdict(page).locator('.failure')).toBeVisible();
  await page.locator(`[data-sweep-guess="${utf8(DEFAULT_SECRET).length}"]`).click();
  await expect(lengthVerdict(page).locator('.success')).toBeVisible();
});

test('the sweep measures the secret in UTF-8 bytes, not UTF-16 characters', async ({ page }) => {
  await boot(page);
  await openTab(page, 'length');

  // "kingdöm42" is 9 JavaScript characters but 10 UTF-8 bytes; SHA-256 pads
  // over bytes, so 10 is the guess that must land.
  const secret = 'kingdöm42';
  expect(secret.length).toBe(9);
  expect(utf8(secret).length).toBe(10);

  await page.locator('#attack-secret').fill(secret);
  await page.locator('#sweep-secret-lengths').click();

  await expect(page.locator('.sweep-chip.verified')).toHaveCount(1);
  await expect(page.locator('.sweep-chip.verified')).toHaveAttribute('data-sweep-guess', '10');
  expect(await textOf(sweepPanel(page).locator('p.muted.small'))).toContain(
    'The server accepted the guess 10 — matching the real secret length of 10 bytes.'
  );
  expect(await textOf(page.locator('#panel-length .card ul').nth(1))).toContain(
    'real secret length = 10 bytes'
  );
});

test('a secret outside the swept range fails the sweep and explains the miss', async ({ page }) => {
  await boot(page);
  await openTab(page, 'length');

  // 17 two-byte characters clears the field's 32-character cap but is 34 bytes.
  const secret = 'ö'.repeat(17);
  expect(utf8(secret).length).toBe(34);

  await page.locator('#attack-secret').fill(secret);
  await page.locator('#sweep-secret-lengths').click();

  await expect(page.locator('.sweep-chip')).toHaveCount(32);
  await expect(page.locator('.sweep-chip.verified')).toHaveCount(0);
  expect(await textOf(sweepPanel(page).locator('p.muted.small'))).toContain(
    'No guess in 1–32 landed: this secret is 34 UTF-8 bytes long, outside the swept range.'
  );
  await expect(lengthVerdict(page).locator('.failure')).toBeVisible();
});

test('an empty secret fails the sweep and says the secret is empty', async ({ page }) => {
  await boot(page);
  await openTab(page, 'length');

  await page.locator('#attack-secret').fill('');
  await page.locator('#sweep-secret-lengths').click();

  await expect(page.locator('.sweep-chip.verified')).toHaveCount(0);
  expect(await textOf(sweepPanel(page).locator('p.muted.small'))).toContain(
    'the secret is empty, so there is no length in the swept range to find'
  );
});

/* ================================================================== */
/* 3. HMAC — the defense, and the state it must not get stuck in       */
/* ================================================================== */

test('HMAC rejects the same extension trick and shows a real HMAC tag', async ({ page }) => {
  await boot(page);
  await openTab(page, 'hmac');

  await expect(hmacVerdict(page).locator('.failure')).toHaveText(
    'forgery rejected — HMAC is not length-extendable'
  );
  await expect(hmacVerdict(page).locator('.success')).toHaveCount(0);

  const tags = await page.locator('#panel-hmac .copyable-value').allTextContents();
  const [tag, forgery] = tags.map((value) => value.trim());

  // The advertised tag is genuinely HMAC-SHA256(secret, message).
  expect(tag).toBe(hmacHex(DEFAULT_SECRET, DEFAULT_MESSAGE));

  // The attacker's continuation is a different, non-verifying tag — the point
  // of the panel is that it is computed and then rejected, not asserted away.
  expect(forgery).toMatch(HEX64);
  expect(forgery).not.toBe(tag);
  expect(forgery).not.toBe(hmacHex(DEFAULT_SECRET, `${DEFAULT_MESSAGE}${DEFAULT_EXTENSION}`));
});

test('the HMAC tab tracks the secret typed on the length-extension tab', async ({ page }) => {
  await boot(page);
  await openTab(page, 'length');
  await page.locator('#attack-secret').fill('another-secret');

  await openTab(page, 'hmac');
  await expect(page.locator('#panel-hmac .copyable-value').first()).toHaveText(
    hmacHex('another-secret', DEFAULT_MESSAGE)
  );
  await expect(hmacVerdict(page).locator('.failure')).toBeVisible();
});

test('an empty secret leaves the HMAC tab explained, not stuck computing', async ({ page }) => {
  const pageErrors: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));

  await boot(page);
  await openTab(page, 'length');
  await page.locator('#attack-secret').fill('');
  await openTab(page, 'hmac');

  // Regression: WebCrypto refuses a zero-length HMAC key, which used to leave
  // this panel painted with its "Computing HMAC view…" placeholder forever
  // and raise an unhandled rejection.
  await expect(page.locator('#panel-hmac .failure')).toBeVisible();
  await expect(page.locator('#panel-hmac')).not.toContainText('Computing HMAC view');
  await expect(page.locator('#panel-hmac .failure')).toContainText('empty');
  expect(pageErrors).toEqual([]);

  // Typing a secret back in recovers the real panel.
  await openTab(page, 'length');
  await page.locator('#attack-secret').fill(DEFAULT_SECRET);
  await openTab(page, 'hmac');
  await expect(page.locator('#panel-hmac .copyable-value').first()).toHaveText(
    hmacHex(DEFAULT_SECRET, DEFAULT_MESSAGE)
  );
});

test('a shared link carrying an empty secret still explains the HMAC tab', async ({ page }) => {
  // The same regression from the other direction: state restored from the URL
  // hash reaches renderHmacPanel before any click, so the panel was dead on
  // arrival — and boot()'s allSettled swallowed the rejection, leaving not even
  // a console error to explain the placeholder that never resolved.
  await page.goto('./#t=hmac&s=');
  await expect(page.locator('#panel-hmac .failure')).toBeVisible();
  await expect(page.locator('#panel-hmac')).not.toContainText('Computing HMAC view');
  await expect(page.locator('#panel-hmac')).toContainText('2. Length extension');
});

/* ================================================================== */
/* 4. Benchmark — every measured statistic checked against its own row */
/* ================================================================== */

test('the 1 MB benchmark reports throughput consistent with the time it measured', async ({ page }) => {
  await boot(page);
  await openTab(page, 'comparison');

  const table = page.locator('#panel-comparison table').filter({ hasText: 'Throughput' });
  await expect(page.locator('#panel-comparison')).toContainText('Benchmark complete', {
    timeout: 60_000
  });

  const rows = table.locator('tbody tr');
  await expect(rows).toHaveCount(3);

  const measured: Array<{ label: string; timeMs: number; mbps: number }> = [];
  for (let index = 0; index < 3; index += 1) {
    const cells = await rows.nth(index).locator('td').allTextContents();
    const [label, time, throughput, digest] = cells.map(squash);

    const timeMs = numberFrom(time, /^([\d.]+) ms$/u);
    const mbps = numberFrom(throughput, /^([\d.]+) MB\/s$/u);
    expect(timeMs).toBeGreaterThan(0);

    // 1 MB in timeMs milliseconds is 1000/timeMs MB/s. The rendered time is
    // rounded to 2dp, so allow that rounding but nothing else.
    expect(Math.abs(mbps - 1000 / timeMs) / mbps).toBeLessThan(0.05);

    // The digest preview is a real 16-hex-character prefix, not a placeholder.
    expect(digest).toMatch(/^[0-9a-f]{16}…$/u);

    measured.push({ label, timeMs, mbps });
  }

  expect(measured.map((row) => row.label)).toEqual(['SHA-256', 'SHA3-256', 'BLAKE3']);

  // Throughput must rank inversely to time — the same data, so the fastest
  // pass is necessarily the highest MB/s.
  const byTime = [...measured].sort((a, b) => a.timeMs - b.timeMs);
  const bySpeed = [...measured].sort((a, b) => b.mbps - a.mbps);
  expect(byTime.map((row) => row.label)).toEqual(bySpeed.map((row) => row.label));

  // All three digests are over the same 1 MB buffer but from different
  // functions, so they must differ.
  const previews = await rows.locator('td:nth-child(4)').allTextContents();
  expect(new Set(previews.map(squash)).size).toBe(3);
});

/* ================================================================== */
/* 5. Distribution — the parts must sum to the whole                   */
/* ================================================================== */

test('the avalanche distribution is internally consistent and agrees with a single flip', async ({
  page
}) => {
  await boot(page);

  const input = 'kingdom';
  const trials = utf8(input).length * 8;
  await page.locator('#avalanche-input').fill(input);
  await expect(page.locator('label[for="avalanche-bit"]')).toContainText(`of ${trials - 1}`);

  // The single-flip reading the distribution has to be a draw from.
  const singleFlip = await avalancheCard(page);
  expect(singleFlip.changedBits).toBe(
    hammingDistance(singleFlip.originalDigest, singleFlip.modifiedDigest)
  );

  await page.locator('#run-distribution').click();
  const distribution = page
    .locator('#panel-avalanche .panel')
    .filter({ has: page.locator('.dist-chart') });
  await expect(distribution).toBeVisible({ timeout: 60_000 });

  expect(await textOf(distribution.locator('h3'))).toBe(
    `Avalanche distribution over all ${trials} input bits`
  );

  const bars = distribution.locator('.dist-bar');
  const titles = await bars.evaluateAll((elements) =>
    elements.map((element) => (element as HTMLElement).title)
  );

  // Parts sum to the whole: every flip lands in exactly one bucket.
  const counts = titles.map((title) => numberFrom(title, /^(\d+) flips? changed/u));
  expect(counts.reduce((sum, value) => sum + value, 0)).toBe(trials);

  // Buckets tile [0, 256] with no gap and no overlap.
  const ranges = titles.map((title) => {
    const match = /changed (\d+)(?:–(\d+))? of (\d+) output bits$/u.exec(title);
    expect(match, `unparsable bar title ${JSON.stringify(title)}`).not.toBeNull();
    return {
      lo: Number(match![1]),
      hi: Number(match![2] ?? match![1]),
      total: Number(match![3])
    };
  });
  expect(ranges[0].lo).toBe(0);
  expect(ranges[ranges.length - 1].hi).toBe(256);
  for (let index = 1; index < ranges.length; index += 1) {
    expect(ranges[index].lo).toBe(ranges[index - 1].hi + 1);
    expect(ranges[index].total).toBe(256);
  }

  // The tallest bar is the one drawn at full height.
  const peak = Math.max(...counts);
  const peakIndex = counts.indexOf(peak);
  await expect(bars.nth(peakIndex)).toHaveAttribute('style', /--bar-height: 100\.0%/u);

  const chips = await distribution.locator('.stat-chip').allTextContents();
  const summary = chips.map(squash);
  const mean = numberFrom(summary[0], /Mean: ([\d.]+) bits/u);
  const meanPercent = numberFrom(summary[0], /\(([\d.]+)%\)/u);
  const min = numberFrom(summary[2], /Range: (\d+)–\d+/u);
  const max = numberFrom(summary[2], /Range: \d+–(\d+)/u);
  const ideal = numberFrom(summary[3], /Ideal: (\d+)/u);

  // The rendered percentage is the rendered mean over the stated digest width.
  expect(Math.abs(meanPercent - (mean / 256) * 100)).toBeLessThan(0.1);
  expect(ideal).toBe(128);
  expect(min).toBeLessThanOrEqual(mean);
  expect(max).toBeGreaterThanOrEqual(mean);

  // The README's promise, measured rather than asserted.
  expect(mean).toBeGreaterThan(256 * 0.4);
  expect(mean).toBeLessThan(256 * 0.6);

  // Cross-path agreement: the single-flip reading from computeAvalanche must
  // be inside the range computeAvalancheDistribution measured, and its bucket
  // must hold at least one sample.
  expect(singleFlip.changedBits).toBeGreaterThanOrEqual(min);
  expect(singleFlip.changedBits).toBeLessThanOrEqual(max);
  const bucket = ranges.findIndex(
    (range) => singleFlip.changedBits >= range.lo && singleFlip.changedBits <= range.hi
  );
  expect(bucket).toBeGreaterThanOrEqual(0);
  expect(counts[bucket]).toBeGreaterThanOrEqual(1);

  // The status line repeats the same mean and trial count.
  const status = await textOf(
    page.locator('#panel-avalanche .panel').first().locator('p.muted.small').first()
  );
  expect(status).toBe(
    `SHA-256: mean ${mean.toFixed(1)} of 256 bits changed across ${trials} flips.`
  );
});

test('an empty input refuses the distribution run and says there is nothing to flip', async ({
  page
}) => {
  await boot(page);

  await page.locator('#avalanche-input').fill('');
  await expect(page.locator('label[for="avalanche-bit"]')).toContainText('Flip bit 0 of 0');
  await page.locator('#run-distribution').click();

  await expect(page.locator('#panel-avalanche .panel').first().locator('p.muted.small').first())
    .toHaveText('Type some input first — there are no bits to flip.');
  await expect(page.locator('.dist-chart')).toHaveCount(0);
});
