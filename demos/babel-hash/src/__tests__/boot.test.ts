// @vitest-environment jsdom
import { beforeAll, describe, expect, it } from 'vitest';

/**
 * A DOM smoke test: the entire UI is built by writing template strings into
 * innerHTML, so a typo in any panel only surfaces at runtime. Booting the real
 * app against jsdom and asserting each panel mounts guards every render path
 * against regressions the type checker cannot see.
 */
describe('app boot', () => {
  beforeAll(async () => {
    document.body.innerHTML = '<div id="app"></div>';
    await import('../main');
    // Let the two async panels (avalanche, HMAC) settle after the synchronous
    // shell render completes.
    await new Promise((resolve) => setTimeout(resolve, 50));
  });

  it('mounts the tab bar with every demo tab', () => {
    const tabs = document.querySelectorAll('[role="tab"]');
    expect(tabs).toHaveLength(5);
  });

  it('renders all five tab panels', () => {
    for (const id of ['avalanche', 'length', 'hmac', 'comparison', 'portfolio']) {
      expect(document.querySelector(`#panel-${id}`)).not.toBeNull();
    }
  });

  it('exposes the editable server secret in the length-extension panel', () => {
    const secretInput = document.querySelector<HTMLInputElement>('#attack-secret');
    expect(secretInput).not.toBeNull();
    expect(secretInput?.value).toBe('kingdom42');
  });

  it('offers the avalanche distribution and secret-length sweep controls', () => {
    expect(document.querySelector('#run-distribution')).not.toBeNull();
    expect(document.querySelector('#sweep-secret-lengths')).not.toBeNull();
  });

  it('renders the avalanche bit grids once WebCrypto resolves', () => {
    const cells = document.querySelectorAll('#panel-avalanche [data-output-bit]');
    expect(cells.length).toBeGreaterThan(0);
  });

  it('shows the "what a hash is not" mental-model card', () => {
    expect(document.querySelector('#panel-comparison')?.textContent).toContain('What a hash is');
  });
});
