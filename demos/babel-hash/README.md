# babel-hash

> **[Live demo →](https://systemslibrarian.github.io/crypto-lab-babel-hash/)**

`babel-hash` is a browser-based cryptography demo for the `crypto-compare` portfolio. It focuses on the hash function itself: how SHA-256, SHA3-256, and BLAKE3 diffuse tiny input changes, why bare prefix-MACs fail under length extension, and why HMAC-SHA256 exists.

## What the demo shows

1. **Avalanche effect** — flip one input bit and watch roughly half the output bits change.
2. **Length extension attack** — forge a valid `SHA-256(secret ∥ message ∥ padding ∥ extension)` MAC without knowing the secret.
3. **HMAC rescue** — repeat the same idea against HMAC-SHA256 and watch it fail.
4. **Algorithm comparison** — compare construction, internal state, speed notes, and immunity to length extension.
5. **Portfolio thread** — see where hashes appear across `iron-serpent`, `ratchet-wire`, `sphincs-ledger`, `dead-sea-cipher`, `shamir-gate`, and `meow-decoder`.

## Run locally

```bash
cd demos/babel-hash
npm install
npm run dev
```

For tests and a production bundle:

```bash
npm test
npm run build
```

## Stack

- **Frontend:** Vite + TypeScript
- **SHA-256:** Web Crypto API (`crypto.subtle.digest('SHA-256', ...)`)
- **SHA3-256:** Web Crypto API (`crypto.subtle.digest('SHA3-256', ...)`, with `SHA-3-256` fallback)
- **BLAKE3:** [`@noble/hashes`](https://www.npmjs.com/package/@noble/hashes) from npm, version range `^1.8.0`
- **Length extension:** manual SHA-256 padding and state continuation in TypeScript
- **HMAC-SHA256:** Web Crypto API
- **UI:** vanilla TypeScript, no framework

## Why SHA-3 and BLAKE3 are immune to length extension

- **SHA-256** is a Merkle–Damgård hash. Its final digest corresponds to the full 256-bit chaining state, so an attacker can continue hashing when a protocol incorrectly uses `hash(secret ∥ message)` as a MAC.
- **SHA3-256** uses the **Keccak sponge** construction. The output does not simply reveal a resumable internal state in the Merkle–Damgård sense.
- **BLAKE3** uses a **tree-based design** and is also not vulnerable to the classic SHA-256 length-extension attack.
- **HMAC** fixes the problem by wrapping the inner keyed hash inside a second outer hash: `H((K ⊕ opad) ∥ H((K ⊕ ipad) ∥ m))`.

## Test vector sources

- **SHA-256:** NIST FIPS 180-4 — <https://csrc.nist.gov/publications/detail/fips/180/4/final>
- **SHA3-256:** NIST FIPS 202 — <https://csrc.nist.gov/publications/detail/fips/202/final>
- **BLAKE3:** BLAKE3 specification and official vectors — <https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf>
- **HMAC:** RFC 2104 — <https://www.rfc-editor.org/rfc/rfc2104>

## Offline runtime note

The app is fully local once dependencies are installed. It uses no external CDN assets at runtime.
