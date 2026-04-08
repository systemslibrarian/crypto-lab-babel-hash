import './styles.css';

import { computeAvalanche, flipBitBytes } from './crypto/avalanche';
import { attemptLengthExtensionOnHMAC, hmacSign, hmacVerify } from './crypto/hmac';
import {
  buildForgedMessageBytes,
  lengthExtensionForge,
  sha256PrefixMac,
  verifyLengthExtension
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

const HIDDEN_SECRET = 'kingdom42';

const state = {
  activeTab: 'avalanche' as TabId,
  avalanche: {
    input: 'Hash functions are the silent foundation under modern cryptography.',
    algorithm: 'sha-256' as HashAlgorithm,
    bitPosition: 0,
    compareAll: false,
    flashDiff: false,
    selectedBitNote: 'Click any highlighted bit to inspect the diffusion path.'
  },
  attack: {
    message: 'comment=hello&admin=false',
    extension: '&admin=true',
    secretGuess: HIDDEN_SECRET.length
  },
  hmac: {
    message: 'comment=hello&admin=false',
    extension: '&admin=true',
    secretGuess: HIDDEN_SECRET.length
  },
  benchmark: {
    running: false,
    status: 'Ready to benchmark 1 MB of random data in-browser.',
    results: {} as Partial<Record<HashAlgorithm, BenchmarkResult>>
  }
};

let avalancheRenderToken = 0;
let hmacRenderToken = 0;

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

      <nav class="tabs" aria-label="Demo tabs">
        <button class="tab-button active" data-tab-target="avalanche">1. Avalanche</button>
        <button class="tab-button" data-tab-target="length">2. Length extension</button>
        <button class="tab-button" data-tab-target="hmac">3. HMAC saves the day</button>
        <button class="tab-button" data-tab-target="comparison">4. Algorithm comparison</button>
        <button class="tab-button" data-tab-target="portfolio">5. Portfolio thread</button>
      </nav>

      <section id="panel-avalanche" class="tab-panel active" data-tab-panel="avalanche"></section>
      <section id="panel-length" class="tab-panel" data-tab-panel="length"></section>
      <section id="panel-hmac" class="tab-panel" data-tab-panel="hmac"></section>
      <section id="panel-comparison" class="tab-panel" data-tab-panel="comparison"></section>
      <section id="panel-portfolio" class="tab-panel" data-tab-panel="portfolio"></section>
    </div>
  `;
}

async function renderAvalanchePanel(): Promise<void> {
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
          <div class="stat-row" role="status" aria-live="polite">
            <span class="stat-chip"><strong>${result.changedBits}</strong> / 256 bits changed</span>
            <span class="stat-chip"><strong>${result.changedPercent.toFixed(1)}%</strong> diffusion</span>
            <span class="stat-chip">Flip: <strong>${state.avalanche.bitPosition}</strong> (${byteAndBitLabel(state.avalanche.bitPosition)})</span>
            <span class="sr-only">${result.changedBits} of 256 bits changed, ${result.changedPercent.toFixed(1)} percent diffusion</span>
          </div>
          <div class="grid-2">
            <div>
              <strong>Original digest</strong>
              <div class="digest-block">${result.originalDigest}</div>
              ${buildBitGrid(originalBits, result.bitDiff, state.avalanche.bitPosition, algorithm, state.avalanche.flashDiff)}
            </div>
            <div>
              <strong>Modified digest</strong>
              <div class="digest-block">${result.modifiedDigest}</div>
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
        </div>
        <div class="callout small">
          <strong>Original input</strong><br />
          <code>${escapeHtml(state.avalanche.input)}</code><br /><br />
          <strong>Original UTF-8 bytes</strong><br />
          <code>${formatHexWithHighlight(inputBytes, Math.floor(state.avalanche.bitPosition / 8))}</code><br /><br />
          <strong>Modified UTF-8 bytes</strong><br />
          <code>${formatHexWithHighlight(modifiedBytes, Math.floor(state.avalanche.bitPosition / 8))}</code>
        </div>
        <div class="callout warn small" style="margin-top: 0.8rem;" role="status" aria-live="polite">
          ${escapeHtml(state.avalanche.selectedBitNote)}
        </div>
      </div>
      <div class="panel">
        <h2>What to watch for</h2>
        <ul>
          <li>Each output grid contains all <strong>256 digest bits</strong>.</li>
          <li>Amber cells changed after the selected input bit flip.</li>
          <li>Hover any bit for its position; click a changed bit for a short explanation.</li>
          <li>SHA-256, SHA3-256, and BLAKE3 should all land close to <strong>50%</strong>.</li>
        </ul>
      </div>
    </div>

    <div class="grid-2" style="margin-top: 1rem;">
      ${view}
    </div>
  `;

  window.setTimeout(() => {
    state.avalanche.flashDiff = false;
  }, 350);
}

function renderLengthExtensionPanel(): void {
  const panel = document.querySelector<HTMLElement>('#panel-length');
  if (!panel) {
    return;
  }

  const bareMac = sha256PrefixMac(HIDDEN_SECRET, state.attack.message);
  const attack = lengthExtensionForge(
    bareMac,
    state.attack.message,
    state.attack.secretGuess,
    state.attack.extension
  );
  attack.verified = verifyLengthExtension(HIDDEN_SECRET, attack);
  const forgedMessageBytes = buildForgedMessageBytes(
    state.attack.message,
    state.attack.secretGuess,
    state.attack.extension
  );

  panel.innerHTML = `
    <div class="grid-2">
      <div class="panel">
        <h2>Length extension attack against bare <code>SHA-256(secret ∥ message)</code></h2>
        <p class="muted">
          The attacker sees the message and the MAC, guesses the secret length, then resumes SHA-256 from the exposed internal state.
        </p>

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
              <li><code>secret = ${'•'.repeat(HIDDEN_SECRET.length)}</code></li>
              <li>real secret length = ${HIDDEN_SECRET.length}</li>
            </ul>
          </div>
        </div>
        <div class="callout warn" style="margin-top: 1rem;" role="status" aria-live="polite">
          <strong>Server verdict:</strong>
          <span class="${attack.verified ? 'success' : 'failure'}" role="alert">
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
        <pre class="digest-block">${attack.forgeryMAC}</pre>
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
  `;
}

async function renderHmacPanel(): Promise<void> {
  const panel = document.querySelector<HTMLElement>('#panel-hmac');
  if (!panel) {
    return;
  }

  const renderToken = ++hmacRenderToken;
  panel.innerHTML = '<div class="panel">Computing HMAC view…</div>';

  const mac = await hmacSign(HIDDEN_SECRET, state.hmac.message);
  const attempt = await attemptLengthExtensionOnHMAC(
    mac,
    state.hmac.message,
    state.hmac.secretGuess,
    state.hmac.extension
  );
  const serverAccepted = await hmacVerify(HIDDEN_SECRET, `${state.hmac.message}${state.hmac.extension}`, attempt.forgery);

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
        <div class="stat-row" aria-label="HMAC result">
          <span class="stat-chip">HMAC(secret, message)</span>
          <span class="stat-chip"><code>${mac}</code></span>
        </div>
      </div>

      <div class="panel">
        <h2>Why the extension trick fails</h2>
        <div class="digest-block">HMAC(K, m) = H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ m))</div>
        <ul>
          <li>The inner hash is <strong>not</strong> the final output.</li>
          <li>The outer hash hides the internal state from the attacker.</li>
          <li>Resuming from the visible tag does not produce a valid MAC.</li>
        </ul>
        <div class="callout warn" role="status" aria-live="polite">
          <strong>Server verdict:</strong>
          <span class="${serverAccepted ? 'success' : 'failure'}" role="alert">
            ${serverAccepted ? 'unexpectedly accepted' : 'forgery rejected — HMAC is not length-extendable'}
          </span>
        </div>
      </div>
    </div>

    <div class="grid-2" style="margin-top: 1rem;">
      <div class="card">
        <h3>Attacker’s fake continuation</h3>
        <pre class="digest-block">${attempt.forgery}</pre>
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
  `;
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
      <h2>Live 1 MB benchmark</h2>
      <p class="muted">${state.benchmark.status}</p>
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

async function runBenchmark(): Promise<void> {
  if (state.benchmark.running) {
    return;
  }

  state.benchmark.running = true;
  state.benchmark.status = 'Benchmark running… the UI stays responsive while each digest finishes.';
  renderComparisonPanel();

  const data = getRandomBytes(1024 * 1024);

  for (const algorithm of ALGORITHMS) {
    await new Promise<void>((resolve) => window.setTimeout(resolve, 0));

    try {
      const start = performance.now();
      const digest = await hashBytes(data, algorithm);
      const timeMs = performance.now() - start;
      state.benchmark.results[algorithm] = {
        timeMs,
        mbps: 1 / (timeMs / 1000),
        digest
      };
      state.benchmark.status = `${ALGORITHM_LABELS[algorithm]} finished in ${timeMs.toFixed(2)} ms.`;
    } catch (error) {
      state.benchmark.status = `${ALGORITHM_LABELS[algorithm]} is unavailable in this runtime: ${String(error)}`;
    }

    renderComparisonPanel();
  }

  state.benchmark.running = false;
  state.benchmark.status = 'Benchmark complete. Exact rankings depend on the browser and implementation path.';
  renderComparisonPanel();
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

    const bitButton = target.closest<HTMLButtonElement>('[data-output-bit]');
    if (bitButton) {
      const changed = bitButton.dataset.changed === 'true';
      const algorithm = bitButton.dataset.algorithm ?? 'hash';
      const outputBit = bitButton.dataset.outputBit ?? '?';
      const inputBit = bitButton.dataset.inputBit ?? '?';
      state.avalanche.selectedBitNote = changed
        ? `${algorithm.toUpperCase()} output bit ${outputBit} flipped because changing input bit ${inputBit} diffused through many rounds of mixing.`
        : `${algorithm.toUpperCase()} output bit ${outputBit} stayed the same for this particular input flip, while many neighboring bits changed.`;
      void renderAvalanchePanel();
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
        void renderAvalanchePanel();
        break;
      case 'avalanche-algorithm':
        state.avalanche.algorithm = target.value as HashAlgorithm;
        state.avalanche.flashDiff = true;
        void renderAvalanchePanel();
        break;
      case 'avalanche-bit':
        state.avalanche.bitPosition = Number(target.value);
        state.avalanche.flashDiff = true;
        void renderAvalanchePanel();
        break;
      case 'attack-message':
        state.attack.message = target.value;
        renderLengthExtensionPanel();
        break;
      case 'attack-extension':
        state.attack.extension = target.value;
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

async function boot(): Promise<void> {
  renderShell();
  wireEvents();
  setActiveTab(state.activeTab);
  renderLengthExtensionPanel();
  renderComparisonPanel();
  renderPortfolioPanel();
  await Promise.allSettled([renderAvalanchePanel(), renderHmacPanel()]);
  void runBenchmark();
}

void boot();
