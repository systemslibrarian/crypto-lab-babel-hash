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
