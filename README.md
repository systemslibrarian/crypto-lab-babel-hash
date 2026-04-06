# crypto-lab-babel-hash

> **[Live demo →](https://systemslibrarian.github.io/crypto-lab-babel-hash/)**

`crypto-lab-babel-hash` is the hash-functions entry in the `crypto-compare` portfolio. The browser demo lives in `demos/babel-hash/`.

## Hash Functions catalog entry

| Field | Value |
|---|---|
| Algorithms | SHA-256 (FIPS 180-4), SHA3-256 (FIPS 202), BLAKE3 |
| Output size | 256 bits (32 bytes) for all three |
| Constructions | Merkle–Damgård (SHA-256), Sponge / Keccak (SHA3), Tree (BLAKE3) |
| Attack shown | Length extension attack against SHA-256 |
| Defense shown | HMAC-SHA256 |
| Key property | Avalanche effect — ~50% output bits change per input bit flip |

## Why this demo matters

Hash functions are the silent foundation under the rest of the portfolio:

- [`crypto-lab-sphincs-ledger`](https://github.com/systemslibrarian/crypto-lab-sphincs-ledger) — SPHINCS / SLH-DSA reduces to hash security assumptions.
- [`crypto-lab-ratchet-wire`](https://github.com/systemslibrarian/crypto-lab-ratchet-wire) — HKDF-SHA256 drives every Double Ratchet step.
- [`crypto-lab-iron-serpent`](https://github.com/systemslibrarian/crypto-lab-iron-serpent) — HMAC-SHA256 authenticates each ciphertext, which is why this demo shows HMAC instead of bare SHA-256.
- [`crypto-lab-dead-sea-cipher`](https://github.com/systemslibrarian/crypto-lab-dead-sea-cipher) — authenticated encryption depends on strong integrity primitives in the same historical arc.

## Local run

```bash
cd demos/babel-hash
npm install
npm run dev
```

See [`demos/babel-hash/README.md`](./demos/babel-hash/README.md) for the full walkthrough, references, and implementation notes.