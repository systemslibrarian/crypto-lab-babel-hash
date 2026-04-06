import { describe, expect, it } from 'vitest';
import { computeAvalanche } from '../crypto/avalanche';
import type { HashAlgorithm } from '../crypto/hash';

function seededRandom(seed: number): () => number {
  let value = seed >>> 0;
  return () => {
    value = (value * 1664525 + 1013904223) >>> 0;
    return value / 0x1_0000_0000;
  };
}

describe('avalanche effect', () => {
  it('changes roughly half the output bits over 100 deterministic flips', async () => {
    const input = 'Hash functions diffuse tiny changes into radically different digests.';
    const algorithms: HashAlgorithm[] = ['sha-256', 'sha3-256', 'blake3'];
    const random = seededRandom(0xc0ffee);

    for (const algorithm of algorithms) {
      let totalPercent = 0;

      for (let index = 0; index < 100; index += 1) {
        const bitPosition = Math.floor(random() * input.length * 8);
        const result = await computeAvalanche(input, bitPosition, algorithm);
        totalPercent += result.changedPercent;

        expect(result.changedBits).toBeGreaterThan(80);
        expect(result.changedBits).toBeLessThan(176);
      }

      const averagePercent = totalPercent / 100;
      expect(averagePercent).toBeGreaterThan(40);
      expect(averagePercent).toBeLessThan(60);
    }
  });
});
