import './styles.css';

import {
  computeAvalanche,
  computeAvalancheDistribution,
  flipBitBytes,
  type AvalancheDistribution
} from './crypto/avalanche';
import { attemptLengthExtensionOnHMAC, hmacSign, hmacVerify } from './crypto/hmac';
import {
  buildForgedMessageBytes,
  lengthExtensionForge,
  sha256PrefixMac,
  sweepSecretLengths,
  verifyLengthExtension,
  type SecretLengthSweepEntry
} from './crypto/length-extension';
import {
  bytesToHex,
  digestHexToBits,
  hashBytes,
  type HashAlgorithm,
  utf8ToBytes
} from './crypto/hash';

type TabId = 'avalanche' | 'length' | 'hmac' | 'comparison' | 'portfolio';

type BenchmarkResult = {
  timeMs: number;
  mbps: number;
  digest: string;
};

const ALGORITHMS: HashAlgorithm[] = ['sha-256', 'sha3-256', 'blake3'];
const ALGORITHM_LABELS: Record<HashAlgorithm, string> = {
  'sha-256': 'SHA-256',
  'sha3-256': 'SHA3-256',
  blake3: 'BLAKE3'
};

const TABS: Array<{ id: TabId; label: string }> = [
  { id: 'avalanche', label: '1. Avalanche' },
  { id: 'length', label: '2. Length extension' },
  { id: 'hmac', label: '3. HMAC saves the day' },
  { id: 'comparison', label: '4. Algorithm comparison' },
  { id: 'portfolio', label: '5. Portfolio thread' }
];

const DEFAULT_SECRET = 'kingdom42';

const state = {
  activeTab: 'avalanche' as TabId,
  // Shared across the length-extension and HMAC tabs so a visitor can watch the
  // forgery track *their* secret, not a value hardcoded into the demo.
  secret: DEFAULT_SECRET,
  avalanche: {
    input: 'Hash functions are the silent foundation under modern cryptography.',
    algorithm: 'sha-256' as HashAlgorithm,
    bitPosition: 0,
    compareAll: false,
    flashDiff: false,
    selectedBitNote: 'Click any highlighted bit to inspect the diffusion path.',
    distribution: null as AvalancheDistribution | null,
    distributionRunning: false,
    distributionStatus: 'Run one flip per input bit to see the whole avalanche distribution.'
  },
  attack: {
    message: 'comment=hello&admin=false',
    extension: '&admin=true',
    secretGuess: DEFAULT_SECRET.length,
    sweep: null as SecretLengthSweepEntry[] | null
  },
  hmac: {
    message: 'comment=hello&admin=false',
    extension: '&admin=true',
    secretGuess: DEFAULT_SECRET.length
  },
  benchmark: {
    running: false,
    completed: false,
    status: 'Ready to benchmark 1 MB of random data in-browser.',
    results: {} as Partial<Record<HashAlgorithm, BenchmarkResult>>
  }
};

let avalancheRenderToken = 0;
let hmacRenderToken = 0;
let announceTimer = 0;

/**
 * Route screen-reader updates through one persistent live region instead of
 * sprinkling aria-live on nodes that re-render on every keystroke. Input-driven
 * updates are debounced so only the settled value is announced; discrete actions
 * (like clicking a bit) can announce immediately.
 */
function announce(message: string, immediate = false): void {
  const region = document.getElementById('sr-announcer');
  if (!region) {
    return;
  }

  window.clearTimeout(announceTimer);
  const apply = (): void => {
    // Clear first so repeating the same text is still re-announced.
    region.textContent = '';
    window.setTimeout(() => {
      region.textContent = message;
    }, 30);
  };

  if (immediate) {
    apply();
  } else {
    announceTimer = window.setTimeout(apply, 450);
  }
}

function escapeHtml(input: string): string {
  return input
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function formatHexWithHighlight(bytes: Uint8Array, highlightedByte: number): string {
  return Array.from(bytes, (byte, index) => {
    const hex = byte.toString(16).padStart(2, '0');
    return index === highlightedByte ? `<mark>${hex}</mark>` : hex;
  }).join(' ');
}

function byteAndBitLabel(bitPosition: number): string {
  return `byte ${Math.floor(bitPosition / 8)}, bit ${7 - (bitPosition % 8)}`;
}

/**
 * A monospace block holding a hex digest/MAC with a one-click copy button.
 * Only used for hex values, which are safe inside the data-copy attribute.
 */
function copyableHex(hex: string, label: string): string {
  return `<div class="digest-block copyable">
    <span class="copyable-value">${hex}</span>
    <button type="button" class="copy-btn" data-copy="${hex}" aria-label="Copy ${escapeHtml(label)}" title="Copy ${escapeHtml(label)}">
      <span aria-hidden="true">Copy</span>
    </button>
  </div>`;
}

const BIT_GRID_LEGEND = `
  <div class="legend" aria-hidden="true">
    <span class="legend-item"><span class="swatch swatch-0"></span> bit = 0</span>
    <span class="legend-item"><span class="swatch swatch-1"></span> bit = 1</span>
    <span class="legend-item"><span class="swatch swatch-changed"></span> flipped by the input change</span>
  </div>
`;

function setActiveTab(tabId: TabId): void {
  state.activeTab = tabId;
  document.querySelectorAll<HTMLButtonElement>('[data-tab-target]').forEach((button) => {
    const active = button.dataset.tabTarget === tabId;
    button.classList.toggle('active', active);
    button.setAttribute('aria-selected', String(active));
    button.setAttribute('tabindex', active ? '0' : '-1');
  });
  document.querySelectorAll<HTMLElement>('[data-tab-panel]').forEach((panel) => {
    const active = panel.dataset.tabPanel === tabId;
    panel.classList.toggle('active', active);
    panel.setAttribute('aria-hidden', String(!active));
  });

  // Run the 1 MB benchmark lazily, the first time the comparison tab is opened,
  // so it never janks initial page load.
  if (tabId === 'comparison' && !state.benchmark.running && !state.benchmark.completed) {
    void runBenchmark();
  }

  writeStateToHash();
}

function buildBitGrid(
  bits: boolean[],
  diff: boolean[],
  inputBit: number,
  algorithm: HashAlgorithm,
  flash: boolean
): string {
  return `
    <div class="bit-grid">
      ${bits
        .map((bit, index) => {
          const changed = diff[index];
          const classes = ['bit-cell', `bit-${bit ? 1 : 0}`];
          if (changed) {
            classes.push('changed');
          }
          if (flash && changed) {
            classes.push('flash');
          }

          const title = `Output bit ${index}: ${bit ? 1 : 0} — ${changed ? 'changed' : 'unchanged'} after flipping input bit ${inputBit}`;
          return `<button
            type="button"
            class="${classes.join(' ')}"
            title="${escapeHtml(title)}"
            data-output-bit="${index}"
            data-input-bit="${inputBit}"
            data-algorithm="${algorithm}"
            data-changed="${changed}"
          ></button>`;
        })
        .join('')}
    </div>
  `;
}

function buildDistributionView(distribution: AvalancheDistribution): string {
  const ideal = distribution.totalBits / 2;
  const peak = Math.max(1, ...distribution.histogram);
  const idealBucket = Math.floor(ideal / distribution.bucketSize);

  const bars = distribution.histogram
    .map((count, index) => {
      const lo = index * distribution.bucketSize;
      const hi = Math.min(lo + distribution.bucketSize - 1, distribution.totalBits);
      const heightPct = (count / peak) * 100;
      const rangeLabel = lo === hi ? `${lo}` : `${lo}–${hi}`;
      const classes = ['dist-bar'];
      if (index === idealBucket) {
        classes.push('ideal');
      }
      return `<div
        class="${classes.join(' ')}"
        style="--bar-height: ${heightPct.toFixed(1)}%"
        title="${count} flip${count === 1 ? '' : 's'} changed ${rangeLabel} of ${distribution.totalBits} output bits"
      ><span class="dist-bar-fill"></span></div>`;
    })
    .join('');

  return `
    <div class="panel" style="margin-top: 1rem;">
      <h3>Avalanche distribution over all ${distribution.trials} input bits</h3>
      <p class="muted small">
        Each bar counts how many single-bit input flips changed a given number of output bits.
        A single reading of, say, 47% is just one draw from this curve — which piles up tightly
        around <strong>${ideal}</strong> bits (half of ${distribution.totalBits}).
      </p>
      <div class="stat-row">
        <span class="stat-chip">Mean: <strong>${distribution.mean.toFixed(1)}</strong> bits (${((distribution.mean / distribution.totalBits) * 100).toFixed(1)}%)</span>
        <span class="stat-chip">Std dev: <strong>${distribution.stdDev.toFixed(1)}</strong></span>
        <span class="stat-chip">Range: <strong>${distribution.min}–${distribution.max}</strong></span>
        <span class="stat-chip">Ideal: <strong>${ideal}</strong></span>
      </div>
      <div class="dist-chart" aria-hidden="true">
        ${bars}
      </div>
      <p class="muted small">The highlighted bar straddles the ideal of ${ideal} changed bits.</p>
    </div>
  `;
}

function renderShell(): void {
  const app = document.querySelector<HTMLDivElement>('#app');
  if (!app) {
    throw new Error('Missing #app mount node.');
  }

  const currentTheme = document.documentElement.getAttribute('data-theme') ?? 'dark';
  const toggleEmoji = currentTheme === 'dark' ? '☀️' : '🌙';
  const toggleLabel = currentTheme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';

  app.innerHTML = `
    <div class="app-shell">
      <header class="hero">
        <button class="theme-toggle" id="theme-toggle" aria-label="${toggleLabel}" title="${toggleLabel}">${toggleEmoji}</button>
        <div class="hero-badges">
          <span class="badge">Hash functions</span>
          <span class="badge">SHA-256 · SHA3-256 · BLAKE3</span>
          <span class="badge">Avalanche · Length Extension · HMAC</span>
        </div>
        <h1>babel-hash</h1>
        <p>
          A browser lab for seeing how tiny input changes explode across digest bits, why bare prefix-MACs break,
          and why <code>HMAC-SHA256</code> is the safe construction.
        </p>
      </header>

      <nav class="tabs" role="tablist" aria-label="Demo tabs">
        ${TABS.map(
          (tab, index) => `<button
            type="button"
            class="tab-button${index === 0 ? ' active' : ''}"
            role="tab"
            id="tab-${tab.id}"
            data-tab-target="${tab.id}"
            aria-controls="panel-${tab.id}"
            aria-selected="${index === 0}"
            tabindex="${index === 0 ? '0' : '-1'}"
          >${tab.label}</button>`
        ).join('')}
      </nav>

      <div id="sr-announcer" class="sr-only" role="status" aria-live="polite" aria-atomic="true"></div>

      <main id="main-content" tabindex="-1">
        ${TABS.map(
          (tab, index) => `<section
            id="panel-${tab.id}"
            class="tab-panel${index === 0 ? ' active' : ''}"
            role="tabpanel"
            tabindex="0"
            data-tab-panel="${tab.id}"
            aria-labelledby="tab-${tab.id}"
            aria-hidden="${index !== 0}"
          ></section>`
        ).join('')}
      </main>
    </div>
  `;
}

async function renderAvalanchePanel(announceMode: 'stats' | 'none' = 'stats'): Promise<void> {
  const panel = document.querySelector<HTMLElement>('#panel-avalanche');
  if (!panel) {
    return;
  }

  const inputBytes = utf8ToBytes(state.avalanche.input);
  const maxBit = Math.max(inputBytes.length * 8 - 1, 0);
  state.avalanche.bitPosition = Math.min(state.avalanche.bitPosition, maxBit);

  const renderToken = ++avalancheRenderToken;
  panel.innerHTML = '<div class="panel">Computing avalanche view…</div>';

  const algorithms = state.avalanche.compareAll ? ALGORITHMS : [state.avalanche.algorithm];
  let results: Array<{ algorithm: HashAlgorithm; result: Awaited<ReturnType<typeof computeAvalanche>> }>;

  try {
    results = await Promise.all(
      algorithms.map(async (algorithm) => ({
        algorithm,
        result: await computeAvalanche(state.avalanche.input, state.avalanche.bitPosition, algorithm)
      }))
    );
  } catch (error) {
    panel.innerHTML = `
      <div class="panel">
        <h2>Avalanche effect visualizer</h2>
        <p class="failure">This runtime could not compute one of the requested digests: ${escapeHtml(String(error))}</p>
      </div>
    `;
    return;
  }

  if (renderToken !== avalancheRenderToken) {
    return;
  }

  const modifiedBytes = flipBitBytes(state.avalanche.input, state.avalanche.bitPosition);
  const view = results
    .map(({ algorithm, result }) => {
      const originalBits = digestHexToBits(result.originalDigest);
      const modifiedBits = digestHexToBits(result.modifiedDigest);

      return `
        <div class="card">
          <h3>${ALGORITHM_LABELS[algorithm]}</h3>
          <div class="stat-row">
            <span class="stat-chip"><strong>${result.changedBits}</strong> / 256 bits changed</span>
            <span class="stat-chip"><strong>${result.changedPercent.toFixed(1)}%</strong> diffusion</span>
            <span class="stat-chip">Flip: <strong>${state.avalanche.bitPosition}</strong> (${byteAndBitLabel(state.avalanche.bitPosition)})</span>
          </div>
          <div class="grid-2">
            <div>
              <strong>Original digest</strong>
              ${copyableHex(result.originalDigest, `${ALGORITHM_LABELS[algorithm]} original digest`)}
              ${buildBitGrid(originalBits, result.bitDiff, state.avalanche.bitPosition, algorithm, state.avalanche.flashDiff)}
            </div>
            <div>
              <strong>Modified digest</strong>
              ${copyableHex(result.modifiedDigest, `${ALGORITHM_LABELS[algorithm]} modified digest`)}
              ${buildBitGrid(modifiedBits, result.bitDiff, state.avalanche.bitPosition, algorithm, state.avalanche.flashDiff)}
            </div>
          </div>
        </div>
      `;
    })
    .join('');

  panel.innerHTML = `
    <div class="grid-2">
      <div class="panel">
        <h2>Avalanche effect visualizer</h2>
        <p class="muted">
          A good 256-bit hash changes about half its output bits after a one-bit change in the input.
        </p>
        <label for="avalanche-algorithm">
          Algorithm
        </label>
        <select id="avalanche-algorithm" aria-label="Hash algorithm">
            ${ALGORITHMS.map(
              (algorithm) =>
                `<option value="${algorithm}" ${state.avalanche.algorithm === algorithm ? 'selected' : ''}>${ALGORITHM_LABELS[algorithm]}</option>`
            ).join('')}
        </select>
        <label for="avalanche-input">
          Input text
        </label>
        <textarea id="avalanche-input" aria-label="Hash input text">${escapeHtml(state.avalanche.input)}</textarea>
        <label for="avalanche-bit">
          Flip bit <strong>${state.avalanche.bitPosition}</strong> of <strong>${Math.max(maxBit, 0)}</strong>
        </label>
        <input id="avalanche-bit" type="range" min="0" max="${Math.max(maxBit, 0)}" value="${state.avalanche.bitPosition}" aria-label="Select which input bit to flip" aria-valuemin="0" aria-valuemax="${Math.max(maxBit, 0)}" aria-valuenow="${state.avalanche.bitPosition}" />
        <div class="button-row">
          <button type="button" class="primary" id="toggle-compare-all" aria-pressed="${state.avalanche.compareAll}">
            ${state.avalanche.compareAll ? 'Show one algorithm' : 'Compare all three side by side'}
          </button>
          <button type="button" id="run-distribution" ${state.avalanche.distributionRunning ? 'disabled aria-disabled="true"' : ''} aria-label="Flip every input bit once and chart the distribution">
            ${state.avalanche.distributionRunning ? 'Measuring…' : 'Run one flip per input bit'}
          </button>
        </div>
        <p class="muted small" style="margin-top: 0.4rem;">${escapeHtml(state.avalanche.distributionStatus)}</p>
        <div class="callout small">
          <strong>Original input</strong><br />
          <code>${escapeHtml(state.avalanche.input)}</code><br /><br />
          <strong>Original UTF-8 bytes</strong><br />
          <code>${formatHexWithHighlight(inputBytes, Math.floor(state.avalanche.bitPosition / 8))}</code><br /><br />
          <strong>Modified UTF-8 bytes</strong><br />
          <code>${formatHexWithHighlight(modifiedBytes, Math.floor(state.avalanche.bitPosition / 8))}</code>
        </div>
        <div class="callout warn small" style="margin-top: 0.8rem;">
          ${escapeHtml(state.avalanche.selectedBitNote)}
        </div>
      </div>
      <div class="panel">
        <h2>What to watch for</h2>
        ${BIT_GRID_LEGEND}
        <ul>
          <li>Each output grid contains all <strong>256 digest bits</strong>, read left to right, top to bottom.</li>
          <li>Amber cells are the bits that changed after the selected input bit flip.</li>
          <li>Hover any bit for its position; click a changed bit for a short explanation.</li>
          <li>SHA-256, SHA3-256, and BLAKE3 should all land close to <strong>50%</strong> — that is the avalanche effect.</li>
        </ul>
      </div>
    </div>

    <div class="grid-2" style="margin-top: 1rem;">
      ${view}
    </div>

    ${state.avalanche.distribution ? buildDistributionView(state.avalanche.distribution) : ''}
  `;

  if (announceMode === 'stats') {
    const summary =
      results.length === 1
        ? `${ALGORITHM_LABELS[results[0].algorithm]}: ${results[0].result.changedBits} of 256 bits changed, ${results[0].result.changedPercent.toFixed(1)} percent diffusion after flipping input bit ${state.avalanche.bitPosition}.`
        : `After flipping input bit ${state.avalanche.bitPosition}: ${results
            .map(({ algorithm, result }) => `${ALGORITHM_LABELS[algorithm]} ${result.changedPercent.toFixed(1)} percent`)
            .join(', ')} diffusion.`;
    announce(summary);
  }

  window.setTimeout(() => {
    state.avalanche.flashDiff = false;
  }, 350);
}

function renderLengthExtensionPanel(): void {
  const panel = document.querySelector<HTMLElement>('#panel-length');
  if (!panel) {
    return;
  }

  const secret = state.secret;
  const bareMac = sha256PrefixMac(secret, state.attack.message);
  const attack = lengthExtensionForge(
    bareMac,
    state.attack.message,
    state.attack.secretGuess,
    state.attack.extension
  );
  attack.verified = verifyLengthExtension(secret, attack);
  const forgedMessageBytes = buildForgedMessageBytes(
    state.attack.message,
    state.attack.secretGuess,
    state.attack.extension
  );

  const sweep = state.attack.sweep;
  const sweepHit = sweep?.find((entry) => entry.verified) ?? null;
  const sweepView = sweep
    ? `
      <div class="panel" style="margin-top: 1rem;">
        <h3>Sweep every secret length</h3>
        <p class="muted small">
          The attacker never learns the length — they just try all of them. Each chip is a guess;
          the amber one is the length whose forgery the server accepts. Click any chip to load that guess above.
          ${
            sweepHit
              ? `The server accepted the guess <strong>${sweepHit.guess}</strong> — matching the real secret length of ${secret.length}.`
              : `No guess in 1–32 landed, because this secret is ${secret.length} bytes long (outside the swept range).`
          }
        </p>
        <div class="sweep-grid" role="group" aria-label="Secret-length sweep results — select a guess to load it">
          ${sweep
            .map(
              (entry) =>
                `<button
                  type="button"
                  class="sweep-chip${entry.verified ? ' verified' : ''}${entry.guess === state.attack.secretGuess ? ' current' : ''}"
                  data-sweep-guess="${entry.guess}"
                  aria-pressed="${entry.guess === state.attack.secretGuess}"
                  aria-label="Secret length ${entry.guess} bytes — forgery ${entry.verified ? 'accepted' : 'rejected'}"
                  title="Guess ${entry.guess} byte secret — ${entry.verified ? 'forgery accepted' : 'rejected'}"
                >${entry.guess}${entry.verified ? ' ✓' : ''}</button>`
            )
            .join('')}
        </div>
      </div>
    `
    : '';

  panel.innerHTML = `
    <div class="grid-2">
      <div class="panel">
        <h2>Length extension attack against bare <code>SHA-256(secret ∥ message)</code></h2>
        <p class="muted">
          A server authenticates messages with <code>MAC = SHA-256(secret ∥ message)</code>. The attacker never learns the
          secret, yet can still append data and produce a valid MAC. Move the slider to the real secret length to watch the forgery land.
        </p>
        <ol class="steps muted">
          <li>Capture a legitimate <code>(message, MAC)</code> pair.</li>
          <li>Guess the secret length to reconstruct SHA-256's internal padding.</li>
          <li>Load the captured MAC back into SHA-256 as its chaining state.</li>
          <li>Hash the chosen extension on top and emit the new MAC — no secret required.</li>
        </ol>

        <label for="attack-secret">
          Server secret <span class="muted small">(you set it; the attacker never sees it)</span>
        </label>
        <input id="attack-secret" type="text" value="${escapeHtml(secret)}" maxlength="32" aria-label="Server secret" autocomplete="off" spellcheck="false" />
        <label for="attack-message">
          Known message
        </label>
        <textarea id="attack-message" aria-label="Known message">${escapeHtml(state.attack.message)}</textarea>
        <label for="attack-extension">
          Attacker-chosen extension
        </label>
        <input id="attack-extension" type="text" value="${escapeHtml(state.attack.extension)}" aria-label="Attacker extension" />
        <label for="attack-secret-length">
          Guess secret length: <strong>${state.attack.secretGuess}</strong> bytes
        </label>
        <input id="attack-secret-length" type="range" min="1" max="32" value="${state.attack.secretGuess}" aria-label="Guess secret length" aria-valuemin="1" aria-valuemax="32" aria-valuenow="${state.attack.secretGuess}" />
        <div class="button-row">
          <button type="button" class="primary" id="sweep-secret-lengths" aria-label="Try every secret length from 1 to 32">
            Sweep lengths 1–32
          </button>
        </div>

        <div class="stat-row" aria-label="Server MAC and padding summary">
          <span class="stat-chip">Server MAC: <code>${bareMac}</code></span>
          <span class="stat-chip">Glue padding bytes: <strong>${attack.gluePadding.length / 2}</strong></span>
        </div>
      </div>

      <div class="panel">
        <h2>Attacker view vs hidden secret</h2>
        <div class="grid-2">
          <div class="card">
            <strong>Known to attacker</strong>
            <ul>
              <li><code>message = ${escapeHtml(state.attack.message)}</code></li>
              <li><code>mac = ${bareMac}</code></li>
              <li>guessed secret length = ${state.attack.secretGuess}</li>
            </ul>
          </div>
          <div class="card">
            <strong>Not known to attacker</strong>
            <ul>
              <li><code>secret = ${'•'.repeat(Math.max(secret.length, 1))}</code></li>
              <li>real secret length = ${secret.length}</li>
            </ul>
          </div>
        </div>
        <div class="callout warn" style="margin-top: 1rem;">
          <strong>Server verdict:</strong>
          <span class="${attack.verified ? 'success' : 'failure'}">
            ${attack.verified ? 'forgery accepted — attack succeeds' : 'forgery rejected — wrong secret-length guess'}
          </span>
        </div>
      </div>
    </div>

    <div class="grid-2" style="margin-top: 1rem;">
      <div class="card">
        <h3>Step 1–4: Build the forged message</h3>
        <p><strong>Glue padding (hex)</strong></p>
        <pre class="digest-block">${attack.gluePadding}</pre>
        <p><strong>Forged payload bytes (message ∥ padding ∥ extension)</strong></p>
        <pre class="digest-block">${bytesToHex(forgedMessageBytes)}</pre>
      </div>
      <div class="card">
        <h3>Step 5–6: Continue hashing from the exposed state</h3>
        <p><strong>Forged MAC</strong></p>
        ${copyableHex(attack.forgeryMAC, 'forged MAC')}
        <p class="small muted">Because SHA-256 is Merkle–Damgård, the final digest leaks the full 256-bit chaining state.</p>
      </div>
    </div>

    <div class="panel" style="margin-top: 1rem;">
      <h3>Why does this work?</h3>
      <div class="grid-3">
        <div class="card"><strong>Merkle–Damgård</strong><br /><span class="muted">SHA-256 processes 64-byte blocks in sequence.</span></div>
        <div class="card"><strong>Digest = state</strong><br /><span class="muted">The 32-byte output reveals the complete final chaining value.</span></div>
        <div class="card"><strong>Resume hashing</strong><br /><span class="muted">With the guessed length and the MAC, the attacker can append more blocks.</span></div>
      </div>
      <p class="muted small">SHA3-256 and BLAKE3 do not expose a resumable Merkle–Damgård state in the same way, so this attack does not carry over.</p>
    </div>
    ${sweepView}
  `;

  announce(
    `Length extension server verdict: ${attack.verified ? 'forgery accepted, the attack succeeds' : 'forgery rejected, wrong secret-length guess'}.`
  );
}

async function renderHmacPanel(): Promise<void> {
  const panel = document.querySelector<HTMLElement>('#panel-hmac');
  if (!panel) {
    return;
  }

  const renderToken = ++hmacRenderToken;
  panel.innerHTML = '<div class="panel">Computing HMAC view…</div>';

  const secret = state.secret;
  const mac = await hmacSign(secret, state.hmac.message);
  const attempt = await attemptLengthExtensionOnHMAC(
    mac,
    state.hmac.message,
    state.hmac.secretGuess,
    state.hmac.extension
  );
  const serverAccepted = await hmacVerify(secret, `${state.hmac.message}${state.hmac.extension}`, attempt.forgery);

  if (renderToken !== hmacRenderToken) {
    return;
  }

  panel.innerHTML = `
    <div class="grid-2">
      <div class="panel">
        <h2>HMAC-SHA256 closes the hole</h2>
        <label for="hmac-message">
          Message
        </label>
        <textarea id="hmac-message" aria-label="HMAC message">${escapeHtml(state.hmac.message)}</textarea>
        <label for="hmac-extension">
          Same attacker extension
        </label>
        <input id="hmac-extension" type="text" value="${escapeHtml(state.hmac.extension)}" aria-label="HMAC extension" />
        <label for="hmac-secret-length">
          Guessed secret length: <strong>${state.hmac.secretGuess}</strong> bytes
        </label>
        <input id="hmac-secret-length" type="range" min="1" max="32" value="${state.hmac.secretGuess}" aria-label="Guessed secret length" aria-valuemin="1" aria-valuemax="32" aria-valuenow="${state.hmac.secretGuess}" />
        <p style="margin-bottom: 0.4rem;"><strong>HMAC(secret, message)</strong></p>
        ${copyableHex(mac, 'HMAC tag')}
      </div>

      <div class="panel">
        <h2>Why the extension trick fails</h2>
        <div class="digest-block">HMAC(K, m) = H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ m))</div>
        <ul>
          <li>The inner hash is <strong>not</strong> the final output.</li>
          <li>The outer hash hides the internal state from the attacker.</li>
          <li>Resuming from the visible tag does not produce a valid MAC.</li>
        </ul>
        <div class="callout warn">
          <strong>Server verdict:</strong>
          <span class="${serverAccepted ? 'success' : 'failure'}">
            ${serverAccepted ? 'unexpectedly accepted' : 'forgery rejected — HMAC is not length-extendable'}
          </span>
        </div>
      </div>
    </div>

    <div class="grid-2" style="margin-top: 1rem;">
      <div class="card">
        <h3>Attacker’s fake continuation</h3>
        ${copyableHex(attempt.forgery, 'attacker forgery attempt')}
        <p class="small muted">The same length-extension math runs against the HMAC tag — and the server still rejects it.</p>
      </div>
      <div class="card">
        <h3>When to use HMAC</h3>
        <ul>
          <li>Use <strong>HMAC</strong> for message authentication.</li>
          <li>Do <strong>not</strong> use bare <code>hash(secret ∥ message)</code> as a MAC.</li>
          <li>Protocols like TLS, HKDF, and many application tokens rely on this fix.</li>
        </ul>
      </div>
    </div>

    <div class="callout warn small" style="margin-top: 1rem;">
      <strong>One more rule:</strong> compare MAC tags in <strong>constant time</strong>. A verifier that
      bails on the first mismatched byte leaks, through its timing, how much of a guessed tag was
      correct — enough to forge one byte at a time. This demo uses <code>SubtleCrypto.verify</code>,
      which performs the equality check in constant time for you.
    </div>
  `;

  announce(
    `HMAC server verdict: ${serverAccepted ? 'unexpectedly accepted' : 'forgery rejected, HMAC is not length-extendable'}.`
  );
}

function renderComparisonPanel(): void {
  const panel = document.querySelector<HTMLElement>('#panel-comparison');
  if (!panel) {
    return;
  }

  const benchmarkRows = ALGORITHMS.map((algorithm) => {
    const result = state.benchmark.results[algorithm];
    return `
      <tr>
        <td>${ALGORITHM_LABELS[algorithm]}</td>
        <td>${result ? `${result.timeMs.toFixed(2)} ms` : '—'}</td>
        <td>${result ? `${result.mbps.toFixed(2)} MB/s` : '—'}</td>
        <td><code>${result ? `${result.digest.slice(0, 16)}…` : 'pending'}</code></td>
      </tr>
    `;
  }).join('');

  panel.innerHTML = `
    <div class="grid-3">
      <div class="card"><h3>SHA-256</h3><p>Merkle–Damgård</p><p class="muted">256-bit output; 256-bit chaining state exposed in the digest; vulnerable to length extension.</p></div>
      <div class="card"><h3>SHA3-256</h3><p>Sponge / Keccak</p><p class="muted">1600-bit internal state; designed to avoid Merkle–Damgård weaknesses.</p></div>
      <div class="card"><h3>BLAKE3</h3><p>Tree hash</p><p class="muted">Fast, parallel-friendly design; immune to classic length extension tricks.</p></div>
    </div>

    <div class="panel" style="margin-top: 1rem;">
      <h2>Comparison table</h2>
      <table class="comparison-table">
        <thead>
          <tr>
            <th>Property</th>
            <th>SHA-256</th>
            <th>SHA3-256</th>
            <th>BLAKE3</th>
          </tr>
        </thead>
        <tbody>
          <tr><td>Output size</td><td>256 bits</td><td>256 bits</td><td>256 bits</td></tr>
          <tr><td>Construction</td><td>Merkle–Damgård</td><td>Sponge / Keccak</td><td>Tree</td></tr>
          <tr><td>Internal state</td><td>256-bit chaining value</td><td>1600-bit sponge state</td><td>Wide compression state / tree fan-out</td></tr>
          <tr><td>Length extension</td><td>Vulnerable</td><td>Immune</td><td>Immune</td></tr>
          <tr><td>Quantum note</td><td>Grover reduces brute-force to ~128-bit security</td><td>Same ~128-bit post-Grover</td><td>Same ~128-bit post-Grover</td></tr>
          <tr><td>Speed note</td><td>Solid baseline</td><td>Usually slower in software</td><td>Fastest of the three</td></tr>
        </tbody>
      </table>
    </div>

    <div class="panel" style="margin-top: 1rem;">
      <h2>What a hash is <em>not</em></h2>
      <p class="muted">These three functions are excellent at one job — a fixed-size fingerprint — and wrong for several others.</p>
      <div class="grid-3">
        <div class="card"><strong>Not encryption</strong><br /><span class="muted">A digest is one-way. There is no key and nothing to decrypt — you cannot recover the input from it.</span></div>
        <div class="card"><strong>Not a MAC on its own</strong><br /><span class="muted">Bare <code>hash(secret ∥ msg)</code> is forgeable (tab 2). Authentication needs HMAC or another keyed construction.</span></div>
        <div class="card"><strong>Not a password store</strong><br /><span class="muted">Fast hashes are a liability for passwords. Use a slow KDF — bcrypt, scrypt, or Argon2id — instead.</span></div>
      </div>
    </div>

    <div class="panel" style="margin-top: 1rem;">
      <h2>Live 1 MB benchmark</h2>
      <p class="muted">${state.benchmark.status}</p>
      <div class="callout warn small">
        <strong>Read this before trusting the numbers:</strong> SHA-256 runs in the browser's
        <strong>native</strong> WebCrypto engine, while BLAKE3 (and SHA3-256 where WebCrypto lacks it)
        run as portable <strong>JavaScript</strong> via <code>@noble/hashes</code>. So this measures
        implementation paths, not the algorithms themselves — a native BLAKE3 build is typically the
        fastest of the three.
      </div>
      <div class="button-row">
        <button type="button" id="run-benchmark" class="primary" ${state.benchmark.running ? 'disabled aria-disabled="true"' : ''} aria-label="Run 1 MB hash benchmark">
          ${state.benchmark.running ? 'Benchmark running…' : 'Run benchmark'}
        </button>
      </div>
      <table class="comparison-table" style="margin-top: 0.8rem;">
        <thead>
          <tr><th>Algorithm</th><th>Time</th><th>Throughput</th><th>Digest preview</th></tr>
        </thead>
        <tbody>${benchmarkRows}</tbody>
      </table>
    </div>
  `;
}

function renderPortfolioPanel(): void {
  const panel = document.querySelector<HTMLElement>('#panel-portfolio');
  if (!panel) {
    return;
  }

  panel.innerHTML = `
    <div class="panel">
      <h2>Where hashes live in the portfolio</h2>
      <p class="muted">Hash functions are the quiet foundation under the rest of <code>crypto-compare</code>. This demo makes them the star.</p>
      <div class="portfolio-list">
        <div class="portfolio-item"><strong>iron-serpent</strong> — HMAC-SHA256 authenticates each ciphertext, which is why this demo ends with HMAC.</div>
        <div class="portfolio-item"><strong>ratchet-wire</strong> — HKDF-SHA256 derives fresh keys in every Double Ratchet step.</div>
        <div class="portfolio-item"><strong>sphincs-ledger</strong> — hash-only post-quantum signatures ultimately lean on SHA-256 style security assumptions.</div>
        <div class="portfolio-item"><strong>dead-sea-cipher</strong> — authenticated encryption depends on integrity checks built from hash-like ideas and constructions.</div>
        <div class="portfolio-item"><strong>shamir-gate</strong> — secret verification and commitments lean on strong digests.</div>
        <div class="portfolio-item"><strong>meow-decoder</strong> — BLAKE3 appears as the modern high-speed option.</div>
      </div>
    </div>

    <div class="grid-3" style="margin-top: 1rem;">
      <div class="card"><strong>SHA-256</strong><br /><span class="muted">NSA / NIST, 2001</span></div>
      <div class="card"><strong>SHA-3 / Keccak</strong><br /><span class="muted">Bertoni, Daemen, Peeters, Van Assche — 2012</span></div>
      <div class="card"><strong>BLAKE3</strong><br /><span class="muted">O’Connor, Aumasson, Neves, Wilcox-O’Hearn — 2020</span></div>
    </div>
  `;
}

const BENCHMARK_WARMUP_RUNS = 1;
const BENCHMARK_TIMED_RUNS = 5;

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle];
}

async function runBenchmark(): Promise<void> {
  if (state.benchmark.running) {
    return;
  }

  state.benchmark.running = true;
  state.benchmark.status = `Benchmark running… ${BENCHMARK_WARMUP_RUNS} warmup + ${BENCHMARK_TIMED_RUNS} timed passes per algorithm.`;
  renderComparisonPanel();

  const data = getRandomBytes(1024 * 1024);
  const megabytes = data.length / (1024 * 1024);

  for (const algorithm of ALGORITHMS) {
    await new Promise<void>((resolve) => window.setTimeout(resolve, 0));

    try {
      // Discard warmup passes so JIT compilation and first-call overhead do not
      // land in the reported time, then report the median of the timed runs to
      // shrug off the occasional GC pause or scheduler hiccup.
      for (let run = 0; run < BENCHMARK_WARMUP_RUNS; run += 1) {
        await hashBytes(data, algorithm);
      }

      const samples: number[] = [];
      let digest = '';
      for (let run = 0; run < BENCHMARK_TIMED_RUNS; run += 1) {
        const start = performance.now();
        digest = await hashBytes(data, algorithm);
        samples.push(performance.now() - start);
      }

      const timeMs = median(samples);
      state.benchmark.results[algorithm] = {
        timeMs,
        mbps: megabytes / (timeMs / 1000),
        digest
      };
      state.benchmark.status = `${ALGORITHM_LABELS[algorithm]}: median ${timeMs.toFixed(2)} ms over ${BENCHMARK_TIMED_RUNS} runs.`;
    } catch (error) {
      state.benchmark.status = `${ALGORITHM_LABELS[algorithm]} is unavailable in this runtime: ${String(error)}`;
    }

    renderComparisonPanel();
  }

  state.benchmark.running = false;
  state.benchmark.completed = true;
  state.benchmark.status = `Benchmark complete — median of ${BENCHMARK_TIMED_RUNS} timed runs (after ${BENCHMARK_WARMUP_RUNS} warmup). Exact rankings depend on the browser and implementation path.`;
  renderComparisonPanel();
}

async function runAvalancheDistribution(): Promise<void> {
  if (state.avalanche.distributionRunning) {
    return;
  }

  const algorithm = state.avalanche.algorithm;
  const input = state.avalanche.input;
  const inputBytes = utf8ToBytes(input);
  if (inputBytes.length === 0) {
    state.avalanche.distributionStatus = 'Type some input first — there are no bits to flip.';
    void renderAvalanchePanel('none');
    return;
  }

  state.avalanche.distributionRunning = true;
  state.avalanche.distributionStatus = `Flipping each of ${inputBytes.length * 8} input bits for ${ALGORITHM_LABELS[algorithm]}…`;
  await renderAvalanchePanel('none');

  try {
    // Yield once so the "measuring" state paints before the loop blocks.
    await new Promise<void>((resolve) => window.setTimeout(resolve, 0));
    const distribution = await computeAvalancheDistribution(input, algorithm);
    // If the input or algorithm changed while we were measuring, drop this
    // now-stale result rather than painting it over the current input.
    if (state.avalanche.input !== input || state.avalanche.algorithm !== algorithm) {
      return;
    }
    state.avalanche.distribution = distribution;
    state.avalanche.distributionStatus = `${ALGORITHM_LABELS[algorithm]}: mean ${distribution.mean.toFixed(1)} of ${distribution.totalBits} bits changed across ${distribution.trials} flips.`;
    announce(
      `${ALGORITHM_LABELS[algorithm]} avalanche distribution: mean ${distribution.mean.toFixed(1)} bits changed, standard deviation ${distribution.stdDev.toFixed(1)}, across ${distribution.trials} single-bit flips.`,
      true
    );
  } catch (error) {
    state.avalanche.distributionStatus = `Could not measure the distribution: ${String(error)}`;
  } finally {
    state.avalanche.distributionRunning = false;
    await renderAvalanchePanel('none');
  }
}

async function copyToClipboard(text: string, button: HTMLButtonElement): Promise<void> {
  const label = button.querySelector('span');
  const restore = label?.textContent ?? 'Copy';

  try {
    if (globalThis.navigator?.clipboard?.writeText) {
      await globalThis.navigator.clipboard.writeText(text);
    } else {
      throw new Error('Clipboard API unavailable');
    }
    button.classList.add('copied');
    if (label) {
      label.textContent = 'Copied!';
    }
  } catch {
    if (label) {
      label.textContent = 'Press Ctrl+C';
    }
  }

  window.setTimeout(() => {
    button.classList.remove('copied');
    if (label) {
      label.textContent = restore;
    }
  }, 1400);
}

function getRandomBytes(length: number): Uint8Array {
  const buffer = new Uint8Array(length);
  const chunkSize = 65_536;
  for (let offset = 0; offset < length; offset += chunkSize) {
    globalThis.crypto.getRandomValues(buffer.subarray(offset, Math.min(offset + chunkSize, length)));
  }
  return buffer;
}

function wireEvents(): void {
  document.addEventListener('click', (event) => {
    const target = event.target as HTMLElement | null;
    if (!target) {
      return;
    }

    const copyBtn = target.closest<HTMLButtonElement>('.copy-btn');
    if (copyBtn?.dataset.copy) {
      void copyToClipboard(copyBtn.dataset.copy, copyBtn);
      return;
    }

    if (target instanceof HTMLButtonElement && target.id === 'theme-toggle') {
      const currentTheme = document.documentElement.getAttribute('data-theme') ?? 'dark';
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', newTheme);
      localStorage.setItem('theme', newTheme);
      
      const newEmoji = newTheme === 'dark' ? '☀️' : '🌙';
      const newLabel = newTheme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode';
      target.textContent = newEmoji;
      target.setAttribute('aria-label', newLabel);
      target.setAttribute('title', newLabel);
      return;
    }

    const tabButton = target.closest<HTMLButtonElement>('[data-tab-target]');
    if (tabButton?.dataset.tabTarget) {
      setActiveTab(tabButton.dataset.tabTarget as TabId);
      return;
    }

    if (target instanceof HTMLButtonElement && target.id === 'toggle-compare-all') {
      state.avalanche.compareAll = !state.avalanche.compareAll;
      void renderAvalanchePanel();
      return;
    }

    if (target instanceof HTMLButtonElement && target.id === 'run-benchmark') {
      void runBenchmark();
      return;
    }

    if (target instanceof HTMLButtonElement && target.id === 'run-distribution') {
      void runAvalancheDistribution();
      return;
    }

    if (target instanceof HTMLButtonElement && target.id === 'sweep-secret-lengths') {
      const bareMac = sha256PrefixMac(state.secret, state.attack.message);
      state.attack.sweep = sweepSecretLengths(state.secret, bareMac, state.attack.message, state.attack.extension);
      const hit = state.attack.sweep.find((entry) => entry.verified);
      renderLengthExtensionPanel();
      announce(
        hit
          ? `Secret-length sweep complete: guess ${hit.guess} bytes produced an accepted forgery.`
          : 'Secret-length sweep complete: no guess between 1 and 32 bytes was accepted.',
        true
      );
      return;
    }

    const sweepChip = target.closest<HTMLButtonElement>('[data-sweep-guess]');
    if (sweepChip?.dataset.sweepGuess) {
      state.attack.secretGuess = Number(sweepChip.dataset.sweepGuess);
      renderLengthExtensionPanel();
      writeStateToHash();
      return;
    }

    const bitButton = target.closest<HTMLButtonElement>('[data-output-bit]');
    if (bitButton) {
      const changed = bitButton.dataset.changed === 'true';
      const algorithm = bitButton.dataset.algorithm ?? 'hash';
      const outputBit = bitButton.dataset.outputBit ?? '?';
      const inputBit = bitButton.dataset.inputBit ?? '?';
      state.avalanche.selectedBitNote = changed
        ? `${algorithm.toUpperCase()} output bit ${outputBit} flipped because changing input bit ${inputBit} diffused through many rounds of mixing.`
        : `${algorithm.toUpperCase()} output bit ${outputBit} stayed the same for this particular input flip, while many neighboring bits changed.`;
      void renderAvalanchePanel('none');
      announce(state.avalanche.selectedBitNote, true);
    }
  });

  document.addEventListener('input', (event) => {
    const target = event.target as HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement | null;
    if (!target) {
      return;
    }

    switch (target.id) {
      case 'avalanche-input':
        state.avalanche.input = target.value;
        state.avalanche.bitPosition = 0;
        state.avalanche.flashDiff = true;
        state.avalanche.distribution = null;
        state.avalanche.distributionStatus = 'Input changed — rerun to refresh the distribution.';
        void renderAvalanchePanel();
        break;
      case 'avalanche-algorithm':
        state.avalanche.algorithm = target.value as HashAlgorithm;
        state.avalanche.flashDiff = true;
        state.avalanche.distribution = null;
        state.avalanche.distributionStatus = 'Algorithm changed — rerun to refresh the distribution.';
        void renderAvalanchePanel();
        break;
      case 'avalanche-bit':
        state.avalanche.bitPosition = Number(target.value);
        state.avalanche.flashDiff = true;
        void renderAvalanchePanel();
        break;
      case 'attack-secret':
        state.secret = target.value;
        state.attack.sweep = null;
        renderLengthExtensionPanel();
        // The HMAC tab shares this secret; keep its (currently hidden) panel in
        // sync so switching tabs never shows a MAC for a stale secret.
        void renderHmacPanel();
        break;
      case 'attack-message':
        state.attack.message = target.value;
        state.attack.sweep = null;
        renderLengthExtensionPanel();
        break;
      case 'attack-extension':
        state.attack.extension = target.value;
        state.attack.sweep = null;
        renderLengthExtensionPanel();
        break;
      case 'attack-secret-length':
        state.attack.secretGuess = Number(target.value);
        renderLengthExtensionPanel();
        break;
      case 'hmac-message':
        state.hmac.message = target.value;
        void renderHmacPanel();
        break;
      case 'hmac-extension':
        state.hmac.extension = target.value;
        void renderHmacPanel();
        break;
      case 'hmac-secret-length':
        state.hmac.secretGuess = Number(target.value);
        void renderHmacPanel();
        break;
      default:
        break;
    }

    writeStateToHash();
  });

  // Keyboard arrow-key navigation for the tab bar (WAI-ARIA tabs pattern)
  document.addEventListener('keydown', (event) => {
    const target = event.target as HTMLElement | null;
    if (!target?.closest('[role="tablist"]')) {
      return;
    }

    const tabs = Array.from(document.querySelectorAll<HTMLButtonElement>('[role="tab"]'));
    const currentIndex = tabs.indexOf(target as HTMLButtonElement);
    if (currentIndex === -1) {
      return;
    }

    let nextIndex: number | null = null;
    if (event.key === 'ArrowRight' || event.key === 'ArrowDown') {
      nextIndex = (currentIndex + 1) % tabs.length;
    } else if (event.key === 'ArrowLeft' || event.key === 'ArrowUp') {
      nextIndex = (currentIndex - 1 + tabs.length) % tabs.length;
    } else if (event.key === 'Home') {
      nextIndex = 0;
    } else if (event.key === 'End') {
      nextIndex = tabs.length - 1;
    }

    if (nextIndex !== null) {
      event.preventDefault();
      tabs[nextIndex].focus();
      const tabId = tabs[nextIndex].dataset.tabTarget as TabId | undefined;
      if (tabId) {
        setActiveTab(tabId);
      }
    }
  });
}

const TAB_IDS = new Set<TabId>(TABS.map((tab) => tab.id));
let hashWriteTimer = 0;

/**
 * Serialize the interesting bits of state into the URL hash so a specific
 * walkthrough — a chosen tab, message, secret, and slider position — is
 * shareable and reload-safe. Writes are debounced and use replaceState so
 * typing does not flood the browser history.
 */
function writeStateToHash(): void {
  if (typeof window === 'undefined') {
    return;
  }

  window.clearTimeout(hashWriteTimer);
  hashWriteTimer = window.setTimeout(() => {
    const params = new URLSearchParams();
    params.set('t', state.activeTab);
    params.set('ai', state.avalanche.input);
    params.set('aa', state.avalanche.algorithm);
    params.set('ab', String(state.avalanche.bitPosition));
    params.set('ac', state.avalanche.compareAll ? '1' : '0');
    params.set('s', state.secret);
    params.set('am', state.attack.message);
    params.set('ae', state.attack.extension);
    params.set('ag', String(state.attack.secretGuess));
    params.set('hm', state.hmac.message);
    params.set('he', state.hmac.extension);
    params.set('hg', String(state.hmac.secretGuess));

    const nextHash = `#${params.toString()}`;
    if (nextHash !== window.location.hash) {
      window.history.replaceState(null, '', nextHash);
    }
  }, 250);
}

function clampInt(value: string | null, min: number, max: number, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.min(max, Math.max(min, Math.round(parsed)));
}

function readStateFromHash(): void {
  if (typeof window === 'undefined' || !window.location.hash) {
    return;
  }

  const params = new URLSearchParams(window.location.hash.slice(1));

  const tab = params.get('t');
  if (tab && TAB_IDS.has(tab as TabId)) {
    state.activeTab = tab as TabId;
  }

  if (params.has('ai')) {
    state.avalanche.input = params.get('ai') ?? state.avalanche.input;
  }
  const algorithm = params.get('aa');
  if (algorithm && ALGORITHMS.includes(algorithm as HashAlgorithm)) {
    state.avalanche.algorithm = algorithm as HashAlgorithm;
  }
  if (params.has('ab')) {
    const maxBit = Math.max(utf8ToBytes(state.avalanche.input).length * 8 - 1, 0);
    state.avalanche.bitPosition = clampInt(params.get('ab'), 0, maxBit, 0);
  }
  if (params.get('ac') === '1') {
    state.avalanche.compareAll = true;
  }

  if (params.has('s')) {
    state.secret = (params.get('s') ?? state.secret).slice(0, 32);
  }
  if (params.has('am')) {
    state.attack.message = params.get('am') ?? state.attack.message;
  }
  if (params.has('ae')) {
    state.attack.extension = params.get('ae') ?? state.attack.extension;
  }
  if (params.has('ag')) {
    state.attack.secretGuess = clampInt(params.get('ag'), 1, 32, state.attack.secretGuess);
  }
  if (params.has('hm')) {
    state.hmac.message = params.get('hm') ?? state.hmac.message;
  }
  if (params.has('he')) {
    state.hmac.extension = params.get('he') ?? state.hmac.extension;
  }
  if (params.has('hg')) {
    state.hmac.secretGuess = clampInt(params.get('hg'), 1, 32, state.hmac.secretGuess);
  }
}

async function boot(): Promise<void> {
  readStateFromHash();
  renderShell();
  wireEvents();
  setActiveTab(state.activeTab);
  renderLengthExtensionPanel();
  renderComparisonPanel();
  renderPortfolioPanel();
  await Promise.allSettled([renderAvalanchePanel(), renderHmacPanel()]);
}

void boot();
