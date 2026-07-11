import { describe, expect, it } from 'vitest';
import { hashBytes, utf8ToBytes } from '../crypto/hash';
import { computeSHA256Padding, sha256PrefixMac } from '../crypto/length-extension';

/**
 * The length-extension attack relies on a hand-rolled SHA-256 (compression
 * function + Merkle–Damgård padding) rather than WebCrypto, because the attack
 * needs to resume hashing from a known chaining state. These tests pin that
 * implementation to FIPS 180-4 so the forgery math can never silently drift.
 *
 * `sha256PrefixMac('', message)` is exactly `SHA-256(message)`, which lets us
 * exercise the internal digest through the public API.
 */
const sha256 = (message: string): string => sha256PrefixMac('', message);

describe('SHA-256 known-answer vectors (FIPS 180-4)', () => {
  const VECTORS: Array<{ input: string; digest: string }> = [
    { input: '', digest: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
    { input: 'abc', digest: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' },
    {
      // 56-byte / 448-bit example — forces a second padding block.
      input: 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq',
      digest: '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1'
    },
    {
      input: 'The quick brown fox jumps over the lazy dog',
      digest: 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592'
    }
  ];

  it.each(VECTORS)('hashes "$input" to the FIPS reference digest', ({ input, digest }) => {
    expect(sha256(input)).toBe(digest);
  });

  it('matches WebCrypto SHA-256 across block-boundary lengths', async () => {
    // 55/56 straddle the single-vs-double final block; 63/64/65 and 120 cover
    // multi-block inputs where the internal compression loop runs repeatedly.
    for (const length of [1, 55, 56, 63, 64, 65, 119, 120, 200]) {
      const message = 'a'.repeat(length);
      const reference = await hashBytes(utf8ToBytes(message), 'sha-256');
      expect(sha256(message)).toBe(reference);
    }
  });
});

describe('SHA-256 Merkle–Damgård padding', () => {
  it('always produces a total length that is a multiple of 64 bytes', () => {
    for (let messageLength = 0; messageLength <= 130; messageLength += 1) {
      const padding = computeSHA256Padding(messageLength);
      expect((messageLength + padding.length) % 64).toBe(0);
      expect(padding[0]).toBe(0x80);
      // The trailing 8 bytes encode the message length in bits, big-endian.
      const encodedBits = padding.slice(-8).reduce((acc, byte) => acc * 256 + byte, 0);
      expect(encodedBits).toBe(messageLength * 8);
    }
  });

  it('rejects negative or non-integer lengths', () => {
    expect(() => computeSHA256Padding(-1)).toThrow();
    expect(() => computeSHA256Padding(1.5)).toThrow();
  });
});
