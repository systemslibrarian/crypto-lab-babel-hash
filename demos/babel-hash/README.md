# babel-hash

> **[Live demo →](https://systemslibrarian.github.io/crypto-lab-babel-hash/)**

## What It Is

`babel-hash` is a browser lab for **SHA-256**, **SHA3-256**, **BLAKE3**, and **HMAC-SHA256**. It demonstrates the avalanche effect, shows a practical length extension forgery against bare `SHA-256(secret || message)`, and contrasts that failure mode with HMAC. These primitives solve integrity and message-authentication problems by producing deterministic tags or digests that are hard to invert or forge. The security model here is symmetric cryptography: unkeyed hash functions for integrity/fingerprinting and keyed HMAC for authentication.

## When to Use It

- Use SHA-256 when you need broad interoperability and established standards support in existing systems.
- Use SHA3-256 when you want a NIST-standardized alternative with a sponge construction and no classic Merkle-Damgard length-extension behavior.
- Use BLAKE3 when throughput matters and you want a modern tree-hash design that performs well in software.
- Use HMAC-SHA256 for API signing or request authentication because keyed MAC construction is the right tool for authenticity and integrity together.
- Do not use bare `hash(secret || message)` for authentication, because this demo shows it can be forged with a length extension attack.

## Live Demo

[Live demo on GitHub Pages](https://systemslibrarian.github.io/crypto-lab-babel-hash/) runs fully in the browser. You can select the algorithm, edit message inputs, flip an exact input bit with the bit-position slider, and — with the *Run one flip per input bit* control — chart the full avalanche distribution to see that the ~50% figure is an average, not a coincidence. In the length-extension walkthrough you set the server's secret yourself, watch the forgery track it, and use *Sweep lengths 1–32* to show that keeping the secret's length private is no defense. The HMAC tab contrasts that failure and notes why MAC comparison must be constant-time. The interface includes tabs for Avalanche, Length extension, HMAC, and a comparison panel with a 1 MB in-browser benchmark (median of several timed runs after a warmup pass). The active tab and your inputs are encoded in the URL, so any particular walkthrough is shareable and reload-safe.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-babel-hash.git
cd crypto-lab-babel-hash/demos/babel-hash
npm install
npm run dev
```

No environment variables are required for local development.

## Part of the Crypto-Lab Suite

This demo is one entry in the broader Crypto-Lab collection at https://systemslibrarian.github.io/crypto-lab/.

---

*So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31*
