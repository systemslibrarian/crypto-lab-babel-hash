/**
 * Known WCAG 1.4.11 / generated-content findings in this lab, captured through
 * the gate's own path so the baseline and the check cannot disagree.
 *
 * THIS FILE IS A TO-DO LIST, NOT A SET OF EXEMPTIONS. The gate ratchets on it:
 *   - a finding NOT listed here fails the run, so a regression cannot land;
 *   - a listed finding whose ratio gets WORSE fails, so the list cannot rot;
 *   - a listed finding that no longer appears ALSO fails, so a fixed entry must
 *     be deleted and the file can only shrink toward empty.
 * The last rule is what stops an allowlist becoming a permanent exemption.
 *
 * `unverified: true` marks an absolutely-positioned pseudo-element. It can paint
 * outside its host and the oracle measures it against the host's backdrop, so
 * that ratio is NOT trustworthy — hand-measure before acting on it.
 */
export const NONTEXT_BASELINE: Record<
  string,
  { ratio: number; required: number; unverified: boolean }
> = {
  "control-boundary|button#cl-theme-toggle.cl-btn.cl-icon": { ratio: 1.46, required: 3.0, unverified: false },
  "control-boundary|button#run-distribution": { ratio: 1.44, required: 3.0, unverified: false },
  "control-boundary|button#tab-avalanche.tab-button": { ratio: 1.38, required: 3.0, unverified: false },
  "control-boundary|button#tab-avalanche.tab-button.active": { ratio: 1.36, required: 3.0, unverified: false },
  "control-boundary|button#tab-comparison.tab-button": { ratio: 1.36, required: 3.0, unverified: false },
  "control-boundary|button#tab-comparison.tab-button.active": { ratio: 1.39, required: 3.0, unverified: false },
  "control-boundary|button#tab-hmac.tab-button": { ratio: 1.36, required: 3.0, unverified: false },
  "control-boundary|button#tab-hmac.tab-button.active": { ratio: 1.4, required: 3.0, unverified: false },
  "control-boundary|button#tab-length.tab-button": { ratio: 1.35, required: 3.0, unverified: false },
  "control-boundary|button#tab-length.tab-button.active": { ratio: 1.37, required: 3.0, unverified: false },
  "control-boundary|button#tab-portfolio.tab-button": { ratio: 1.37, required: 3.0, unverified: false },
  "control-boundary|button#tab-portfolio.tab-button.active": { ratio: 1.41, required: 3.0, unverified: false },
  "control-boundary|button.bit-cell.bit-0": { ratio: 1.93, required: 3.0, unverified: false },
  "control-boundary|button.bit-cell.bit-1": { ratio: 1.62, required: 3.0, unverified: false },
  "control-boundary|button.copy-btn": { ratio: 1.37, required: 3.0, unverified: false },
  "control-boundary|button.sweep-chip": { ratio: 1.45, required: 3.0, unverified: false }
};
