# crypto-lab-babel-hash

## What It Is

`crypto-lab-babel-hash` is the hash-functions entry in the `crypto-compare` portfolio. The browser demo lives in `demos/babel-hash/`.

## When to Use It

- Understanding three modern 256-bit hash functions side by side: SHA-256 (Merkle–Damgård), SHA3-256 (sponge/Keccak), and BLAKE3 (tree).
- Seeing the avalanche effect — how flipping one input bit changes roughly 50% of the output bits.
- Teaching the SHA-256 length-extension weakness and why HMAC-SHA256 fixes it.
- Do NOT use this as a production hashing library — it is a teaching demo, not a hardened implementation.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-babel-hash](https://systemslibrarian.github.io/crypto-lab-babel-hash/)**

The demo computes SHA-256, SHA3-256, and BLAKE3 over your input and visualizes the avalanche effect, then walks through a length-extension attack against SHA-256 and shows HMAC-SHA256 as the defense.

## What Can Go Wrong

- **Length-extension:** raw SHA-256 (Merkle–Damgård) lets an attacker extend a digest without knowing the secret, so `hash(secret || message)` is not a safe MAC.
- **Wrong tool for passwords:** plain hashes are deliberately fast; password storage needs a slow KDF such as bcrypt, scrypt, or Argon2id.
- **Timing leaks:** comparing digests or MACs with a non-constant-time check can leak information byte by byte.
- **Over-truncation:** shortening a digest below the needed security level weakens collision and preimage resistance.
- **Hash is not authentication:** a bare hash only protects integrity when its full input is trusted; authenticating data needs a keyed construction like HMAC.

## Real-World Usage

- SHA-256 underpins TLS certificate signatures, Bitcoin proof-of-work and addresses, and Git object identifiers.
- HMAC-SHA256 authenticates API requests, signed cookies/JWTs, and TLS records.
- SHA3-256 / Keccak is standardized by NIST and used in the Ethereum ecosystem.
- BLAKE3 is used where high-throughput hashing matters, such as content-addressed storage and file-integrity tooling.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-babel-hash
cd crypto-lab-babel-hash/demos/babel-hash
npm install
npm run dev
```

## Related Demos

- [crypto-lab-hash-zoo](https://systemslibrarian.github.io/crypto-lab-hash-zoo/) — hash constructions: Merkle–Damgård vs sponge vs tree.
- [crypto-lab-merkle-vault](https://systemslibrarian.github.io/crypto-lab-merkle-vault/) — SHA-256 Merkle trees and inclusion proofs.
- [crypto-lab-collision-vault](https://systemslibrarian.github.io/crypto-lab-collision-vault/) — MD5/SHA-1 collisions and why they broke.
- [crypto-lab-bcrypt-forge](https://systemslibrarian.github.io/crypto-lab-bcrypt-forge/) — password hashing with bcrypt.
- [crypto-lab-kdf-arena](https://systemslibrarian.github.io/crypto-lab-kdf-arena/) — HKDF, PBKDF2, scrypt, and Argon2id compared.

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

## Repository Layout

The browser demo source lives in `demos/babel-hash/`. To run it directly:

```bash
cd demos/babel-hash
npm install
npm run dev
```

See [`demos/babel-hash/README.md`](./demos/babel-hash/README.md) for the full walkthrough, references, and implementation notes.

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
