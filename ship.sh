#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="/workspaces/crypto-lab-babel-hash"
DEMO_DIR="$REPO_ROOT/demos/babel-hash"

echo "=== 1/6 Installing dependencies ==="
cd "$DEMO_DIR"
npm install

echo ""
echo "=== 2/6 Type-checking ==="
npx tsc --noEmit

echo ""
echo "=== 3/6 Running tests ==="
npx vitest run

echo ""
echo "=== 4/6 Building for production ==="
npx vite build

echo ""
echo "=== 5/6 Committing ==="
cd "$REPO_ROOT"
git add -A
git status
git commit -m "feat(babel-hash): SHA-256, SHA3-256, BLAKE3 demo with a11y and mobile support

- SHA-256, SHA3-256, BLAKE3 hash primitives with verified test vectors
- Avalanche effect visualizer with interactive 256-bit grid
- Length extension attack against bare SHA-256 prefix-MAC
- HMAC-SHA256 demonstration showing immunity to length extension
- Algorithm comparison table with live 1 MB benchmark
- Portfolio cross-references to iron-serpent, ratchet-wire, sphincs-ledger, dead-sea-cipher
- WCAG: ARIA tablist, keyboard arrows, focus rings, skip link, sr-only, live regions, prefers-reduced-motion
- Mobile: responsive grids, 44px touch targets, safe-area-inset, horizontal table scroll
- GitHub Pages: relative base path, demo link in README"

echo ""
echo "=== 6/6 Pushing ==="
git push origin main

echo ""
echo "=== Done ==="
