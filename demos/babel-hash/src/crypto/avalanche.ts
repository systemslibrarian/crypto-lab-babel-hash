import { bytesToUtf8, digestHexToBits, hashBytes, utf8ToBytes, type HashAlgorithm } from './hash';

export interface AvalancheResult {
  original: string;
  modified: string;
  originalDigest: string;
  modifiedDigest: string;
  changedBits: number;
  totalBits: number;
  changedPercent: number;
  bitDiff: boolean[];
}

export function flipBitBytes(input: string, bitPosition: number): Uint8Array {
  const originalBytes = utf8ToBytes(input);
  if (originalBytes.length === 0) {
    return originalBytes;
  }

  const safeBit = Math.max(0, Math.min(bitPosition, originalBytes.length * 8 - 1));
  const modifiedBytes = originalBytes.slice();
  const byteIndex = Math.floor(safeBit / 8);
  const bitIndex = 7 - (safeBit % 8);
  modifiedBytes[byteIndex] ^= 1 << bitIndex;

  return modifiedBytes;
}

export function flipBit(input: string, bitPosition: number): string {
  return bytesToUtf8(flipBitBytes(input, bitPosition));
}

export interface AvalancheDistribution {
  algorithm: HashAlgorithm;
  /** Number of output bits that changed, one entry per input-bit flip. */
  samples: number[];
  trials: number;
  totalBits: number;
  mean: number;
  min: number;
  max: number;
  stdDev: number;
  /** Histogram bucket counts across the [0, totalBits] range. */
  histogram: number[];
  bucketSize: number;
}

/**
 * The avalanche effect is a claim about the *average* over many single-bit
 * input changes, not about any one flip. This runs one flip for every input
 * bit and returns the distribution of changed-output-bit counts, so a single
 * "47%" reading can be seen for what it is — one draw from a curve that
 * clusters tightly around half the digest width.
 */
export async function computeAvalancheDistribution(
  input: string,
  algorithm: HashAlgorithm,
  bucketCount = 24
): Promise<AvalancheDistribution> {
  const inputBytes = utf8ToBytes(input);
  const trials = inputBytes.length * 8;
  const baselineDigest = await hashBytes(inputBytes, algorithm);
  const totalBits = digestHexToBits(baselineDigest).length;
  const baselineBits = digestHexToBits(baselineDigest);

  const samples: number[] = [];
  for (let bit = 0; bit < trials; bit += 1) {
    const modifiedDigest = await hashBytes(flipBitBytes(input, bit), algorithm);
    const modifiedBits = digestHexToBits(modifiedDigest);
    let changed = 0;
    for (let index = 0; index < modifiedBits.length; index += 1) {
      if (modifiedBits[index] !== baselineBits[index]) {
        changed += 1;
      }
    }
    samples.push(changed);
  }

  const mean = samples.length === 0 ? 0 : samples.reduce((sum, value) => sum + value, 0) / samples.length;
  const variance =
    samples.length === 0 ? 0 : samples.reduce((sum, value) => sum + (value - mean) ** 2, 0) / samples.length;

  const bucketSize = Math.max(1, Math.ceil((totalBits + 1) / bucketCount));
  const histogram = new Array<number>(Math.ceil((totalBits + 1) / bucketSize)).fill(0);
  for (const value of samples) {
    histogram[Math.floor(value / bucketSize)] += 1;
  }

  return {
    algorithm,
    samples,
    trials,
    totalBits,
    mean,
    min: samples.length === 0 ? 0 : Math.min(...samples),
    max: samples.length === 0 ? 0 : Math.max(...samples),
    stdDev: Math.sqrt(variance),
    histogram,
    bucketSize
  };
}

export async function computeAvalanche(
  input: string,
  bitPosition: number,
  algorithm: HashAlgorithm
): Promise<AvalancheResult> {
  const originalBytes = utf8ToBytes(input);
  const modifiedBytes = flipBitBytes(input, bitPosition);
  const originalDigest = await hashBytes(originalBytes, algorithm);
  const modifiedDigest = await hashBytes(modifiedBytes, algorithm);
  const originalBits = digestHexToBits(originalDigest);
  const modifiedBits = digestHexToBits(modifiedDigest);
  const bitDiff = originalBits.map((bit, index) => bit !== modifiedBits[index]);
  const changedBits = bitDiff.filter(Boolean).length;
  const totalBits = bitDiff.length;

  return {
    original: input,
    modified: bytesToUtf8(modifiedBytes),
    originalDigest,
    modifiedDigest,
    changedBits,
    totalBits,
    changedPercent: totalBits === 0 ? 0 : (changedBits / totalBits) * 100,
    bitDiff
  };
}
