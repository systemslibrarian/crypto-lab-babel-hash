# babel-hash

> **[Live demo →](https://systemslibrarian.github.io/crypto-lab-babel-hash/)**

## What It Is

`babel-hash` is an interactive browser demo for three modern cryptographic hash functions: **SHA-256**, **SHA3-256**, and **BLAKE3**. The demo focuses on the avalanche effect (how tiny input changes propagate through output bits), length extension vulnerabilities in SHA-256-based MACs, and why HMAC wrapping is essential. SHA-256 and SHA3-256 are symmetric cryptographic primitives used for integrity and fingerprinting; BLAKE3 is a modern alternative designed for speed and parallelism. All three are one-way functions — given a digest, you cannot recover the input.

## When to Use It

- **SHA-256** — Use for legacy systems, regulatory compliance (FIPS 140-2), and TLS 1.2 cryptographic proofs. Do not use directly as a MAC for prefix-based secrets (use HMAC-SHA256 instead).
- **SHA3-256** — Use when resistant to length extension attacks is critical (e.g., custom protocols) and you want a NIST-approved cryptographic hash from the Keccak family. Not vulnerable to the Merkle–Damgård attack.
- **BLAKE3** — Use for high-throughput hashing, modern protocols (Signal, WireGuard), and systems where performance matters more than legacy certification. Immune to length extension and not patented.
- **For all three** — Use for fingerprinting, commitment schemes, and challenge-response; never as a raw MAC for secret-prefixed messages.
- **Do not use** any bare hash as a MAC (e.g., `hash(secret ∥ message)`). Always use HMAC or a dedicated authenticated encryption scheme.

## Live Demo

The live demo at https://systemslibrarian.github.io/crypto-lab-babel-hash/ lets you:
- Flip individual input bits and watch the avalanche effect: roughly 50% of output bits change in a good hash.
- Forge a forged SHA-256-based MAC using length extension without knowing the secret, then verify the attack succeeds.
- Attempt the same attack against HMAC-SHA256 and watch it fail because HMAC's outer hash layer breaks the attack vector.
- Compare SHA-256, SHA3-256, and BLAKE3 side-by-side on construction, speed, and immunity properties.
- Explore the "portfolio thread" to see these hashes used in other demos across the crypto-lab.

## What Can Go Wrong

- **Length extension on Merkle–Damgård hashes** (SHA-256) — If you use `hash(secret ∥ message)` as a MAC, an attacker who sees the digest can append padding and new data, then forge a valid new digest without knowing the secret. This is why HMAC exists.
- **Hash collision in truncated outputs** — Using only the first 128 bits of a 256-bit hash for a signature cuts the security margin. An attacker only needs 2^64 collisions instead of 2^128.
- **Cryptographic timing attacks** — Comparing digests with simple string equality can leak timing information. Use constant-time comparison functions.
- **Passing the digest as entropy** — A cryptographic hash is deterministic and one-way, but not a random number generator. Never use a hash output as a session key seed without additional entropy.
- **Rebuilding state after a hash** — SHA-256's design allows state resumption if the full hash state leaks (length extension). SHA3 and BLAKE3 do not; their sponge and tree designs make resumption impossible.

## Real-World Usage

- **TLS 1.3** — Uses SHA-256 (and SHA-384) in the PRF (pseudorandom function) for key derivation and Finished message authentication.
- **Bitcoin** — Uses SHA-256 (RIPEMD-160 ∘ SHA-256) for address generation and proof-of-work mining.
- **Signal Protocol** (end-to-end encrypted messaging) — Uses SHA-256 for KDF (key derivation) and double ratchet state management.
- **WireGuard** (VPN) — Uses BLAKE3-based keyed hashing for packet authentication; BLAKE3 was chosen for its speed and simplicity over SHA-256.
- **FIDO2 / WebAuthn** — Uses SHA-256 for challenge hashing and attestation verification in hardware security keys.

---

*So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31*
