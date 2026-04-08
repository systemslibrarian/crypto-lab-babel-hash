/**
 * Hash primitives for the babel-hash demo.
 *
 * Sources:
 * - SHA-256: NIST FIPS 180-4 — https://csrc.nist.gov/publications/detail/fips/180/4/final
 * - SHA3-256: NIST FIPS 202 — https://csrc.nist.gov/publications/detail/fips/202/final
 * - BLAKE3: https://github.com/BLAKE3-team/BLAKE3-specs
 */
import { blake3 } from '@noble/hashes/blake3.js';
import { sha3_256 } from '@noble/hashes/sha3.js';

export type HashAlgorithm = 'sha-256' | 'sha3-256' | 'blake3';

export interface HashResult {
  algorithm: HashAlgorithm;
  input: string;
  inputBytes: number;
  digest: string;
  digestBytes: number;
  computeTimeMs: number;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

function now(): number {
  return typeof performance !== 'undefined' ? performance.now() : Date.now();
}

function getSubtle(): SubtleCrypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto API is unavailable in this runtime.');
  }

  return globalThis.crypto.subtle;
}

async function subtleDigest(input: Uint8Array, algorithmNames: string[]): Promise<Uint8Array> {
  const subtle = getSubtle();
  let lastError: unknown;

  for (const name of algorithmNames) {
    try {
      const digest = await subtle.digest(name, toBufferSource(input));
      return new Uint8Array(digest);
    } catch (error) {
      lastError = error;
    }
  }

  throw new Error(
    `Digest algorithm ${algorithmNames.join(' / ')} is not supported: ${String(lastError)}`
  );
}

export function utf8ToBytes(input: string): Uint8Array {
  return encoder.encode(input);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;

  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }

  return result;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.trim().toLowerCase();
  if (normalized.length % 2 !== 0) {
    throw new Error('Hex strings must contain an even number of characters.');
  }
  if (!/^[0-9a-f]*$/u.test(normalized)) {
    throw new Error('Hex strings may only contain characters 0-9 and a-f.');
  }

  const result = new Uint8Array(normalized.length / 2);
  for (let index = 0; index < normalized.length; index += 2) {
    result[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16);
  }

  return result;
}

export function bytesToBits(bytes: Uint8Array): boolean[] {
  return Array.from(bytes, (byte) =>
    Array.from({ length: 8 }, (_, bitIndex) => ((byte >> (7 - bitIndex)) & 1) === 1)
  ).flat();
}

export function digestHexToBits(hexDigest: string): boolean[] {
  return bytesToBits(hexToBytes(hexDigest));
}

export async function hashBytes(input: Uint8Array, algorithm: HashAlgorithm): Promise<string> {
  let digestBytes: Uint8Array;

  switch (algorithm) {
    case 'sha-256':
      digestBytes = await subtleDigest(input, ['SHA-256']);
      break;
    case 'sha3-256':
      try {
        digestBytes = await subtleDigest(input, ['SHA3-256', 'SHA-3-256']);
      } catch {
        digestBytes = sha3_256(input);
      }
      break;
    case 'blake3':
      digestBytes = blake3(input);
      break;
    default: {
      const exhaustiveCheck: never = algorithm;
      throw new Error(`Unsupported hash algorithm: ${String(exhaustiveCheck)}`);
    }
  }

  return bytesToHex(digestBytes).toLowerCase();
}

export async function hashString(input: string, algorithm: HashAlgorithm): Promise<HashResult> {
  const inputBytes = utf8ToBytes(input);
  const startedAt = now();
  const digest = await hashBytes(inputBytes, algorithm);
  const endedAt = now();

  return {
    algorithm,
    input,
    inputBytes: inputBytes.length,
    digest,
    digestBytes: digest.length / 2,
    computeTimeMs: Number((endedAt - startedAt).toFixed(3))
  };
}
