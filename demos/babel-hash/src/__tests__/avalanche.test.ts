import { describe, expect, it } from 'vitest';
import { computeAvalanche, computeAvalancheDistribution } from '../crypto/avalanche';
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

describe('avalanche distribution', () => {
  it('produces one sample per input bit, centered near half the digest width', async () => {
    const input = 'avalanche';
    const distribution = await computeAvalancheDistribution(input, 'sha-256');

    expect(distribution.trials).toBe(input.length * 8);
    expect(distribution.samples).toHaveLength(distribution.trials);
    expect(distribution.totalBits).toBe(256);
    // Mean sits close to 128 (half of 256); allow generous slack for a small sample.
    expect(distribution.mean).toBeGreaterThan(108);
    expect(distribution.mean).toBeLessThan(148);
    expect(distribution.min).toBeGreaterThanOrEqual(0);
    expect(distribution.max).toBeLessThanOrEqual(256);
    // Every trial is accounted for in exactly one histogram bucket.
    const histogramTotal = distribution.histogram.reduce((sum, count) => sum + count, 0);
    expect(histogramTotal).toBe(distribution.trials);
  });

  it('returns an empty, zeroed distribution for empty input', async () => {
    const distribution = await computeAvalancheDistribution('', 'sha-256');
    expect(distribution.trials).toBe(0);
    expect(distribution.samples).toHaveLength(0);
    expect(distribution.mean).toBe(0);
  });
});
