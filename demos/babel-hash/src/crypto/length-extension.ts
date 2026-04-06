/**
 * SHA-256 length extension helpers for the babel-hash demo.
 *
 * Sources:
 * - SHA-256: NIST FIPS 180-4 — https://csrc.nist.gov/publications/detail/fips/180/4/final
 * - Length extension background: https://en.wikipedia.org/wiki/Length_extension_attack
 */
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from './hash';

export interface LengthExtensionAttack {
  originalMessage: string;
  secretLength: number;
  originalMAC: string;
  extension: string;
  forgeryMAC: string;
  gluePadding: string;
  verified: boolean;
}

const INITIAL_STATE = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

const ROUND_CONSTANTS = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function rotateRight(value: number, shift: number): number {
  return ((value >>> shift) | (value << (32 - shift))) >>> 0;
}

function wordsToHex(words: Uint32Array): string {
  return Array.from(words, (word) => word.toString(16).padStart(8, '0')).join('');
}

function readWord(bytes: Uint8Array, offset: number): number {
  return (
    ((bytes[offset] ?? 0) << 24) |
    ((bytes[offset + 1] ?? 0) << 16) |
    ((bytes[offset + 2] ?? 0) << 8) |
    (bytes[offset + 3] ?? 0)
  ) >>> 0;
}

function sha256Compress(state: Uint32Array, chunk: Uint8Array): void {
  const schedule = new Uint32Array(64);

  for (let index = 0; index < 16; index += 1) {
    schedule[index] = readWord(chunk, index * 4);
  }

  for (let index = 16; index < 64; index += 1) {
    const s0 = rotateRight(schedule[index - 15], 7) ^ rotateRight(schedule[index - 15], 18) ^ (schedule[index - 15] >>> 3);
    const s1 = rotateRight(schedule[index - 2], 17) ^ rotateRight(schedule[index - 2], 19) ^ (schedule[index - 2] >>> 10);
    schedule[index] = (schedule[index - 16] + s0 + schedule[index - 7] + s1) >>> 0;
  }

  let [a, b, c, d, e, f, g, h] = Array.from(state);

  for (let index = 0; index < 64; index += 1) {
    const sigma1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
    const choice = (e & f) ^ (~e & g);
    const temp1 = (h + sigma1 + choice + ROUND_CONSTANTS[index] + schedule[index]) >>> 0;
    const sigma0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
    const majority = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (sigma0 + majority) >>> 0;

    h = g;
    g = f;
    f = e;
    e = (d + temp1) >>> 0;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) >>> 0;
  }

  state[0] = (state[0] + a) >>> 0;
  state[1] = (state[1] + b) >>> 0;
  state[2] = (state[2] + c) >>> 0;
  state[3] = (state[3] + d) >>> 0;
  state[4] = (state[4] + e) >>> 0;
  state[5] = (state[5] + f) >>> 0;
  state[6] = (state[6] + g) >>> 0;
  state[7] = (state[7] + h) >>> 0;
}

function sha256DigestHex(bytes: Uint8Array): string {
  const state = Uint32Array.from(INITIAL_STATE);
  const message = concatBytes(bytes, computeSHA256Padding(bytes.length));

  for (let offset = 0; offset < message.length; offset += 64) {
    sha256Compress(state, message.subarray(offset, offset + 64));
  }

  return wordsToHex(state);
}

function parseStateFromDigest(hexDigest: string): Uint32Array {
  const bytes = hexToBytes(hexDigest);
  if (bytes.length !== 32) {
    throw new Error('A SHA-256 digest must be exactly 32 bytes (64 hex characters).');
  }

  const state = new Uint32Array(8);
  for (let index = 0; index < 8; index += 1) {
    state[index] = readWord(bytes, index * 4);
  }

  return state;
}

function continueSha256FromState(
  stateWords: Uint32Array,
  extensionBytes: Uint8Array,
  bytesAlreadyProcessed: number
): string {
  if (bytesAlreadyProcessed % 64 !== 0) {
    throw new Error('bytesAlreadyProcessed must already include SHA-256 padding and be block aligned.');
  }

  const state = Uint32Array.from(stateWords);
  const totalLengthBeforeFinalPadding = bytesAlreadyProcessed + extensionBytes.length;
  const finalBlocks = concatBytes(
    extensionBytes,
    computeSHA256Padding(totalLengthBeforeFinalPadding)
  );

  for (let offset = 0; offset < finalBlocks.length; offset += 64) {
    sha256Compress(state, finalBlocks.subarray(offset, offset + 64));
  }

  return wordsToHex(state);
}

export function computeSHA256Padding(messageLength: number): Uint8Array {
  if (!Number.isInteger(messageLength) || messageLength < 0) {
    throw new Error('messageLength must be a non-negative integer.');
  }

  const zeroByteCount = (64 - ((messageLength + 1 + 8) % 64)) % 64;
  const padding = new Uint8Array(1 + zeroByteCount + 8);
  padding[0] = 0x80;

  const bitLength = BigInt(messageLength) * 8n;
  for (let index = 0; index < 8; index += 1) {
    padding[padding.length - 1 - index] = Number((bitLength >> BigInt(index * 8)) & 0xffn);
  }

  return padding;
}

export function buildForgedMessageBytes(
  originalMessage: string,
  secretLength: number,
  extension: string
): Uint8Array {
  const originalBytes = utf8ToBytes(originalMessage);
  const extensionBytes = utf8ToBytes(extension);
  const gluePadding = computeSHA256Padding(secretLength + originalBytes.length);

  return concatBytes(originalBytes, gluePadding, extensionBytes);
}

export function sha256PrefixMac(secret: string, message: string): string {
  return sha256DigestHex(utf8ToBytes(`${secret}${message}`));
}

export function lengthExtensionForge(
  originalMAC: string,
  originalMessage: string,
  secretLength: number,
  extension: string
): LengthExtensionAttack {
  const normalizedMac = originalMAC.trim().toLowerCase();
  const originalBytes = utf8ToBytes(originalMessage);
  const extensionBytes = utf8ToBytes(extension);
  const gluePadding = computeSHA256Padding(secretLength + originalBytes.length);
  const processedBytes = secretLength + originalBytes.length + gluePadding.length;
  const state = parseStateFromDigest(normalizedMac);
  const forgeryMAC = continueSha256FromState(state, extensionBytes, processedBytes);

  return {
    originalMessage,
    secretLength,
    originalMAC: normalizedMac,
    extension,
    forgeryMAC,
    gluePadding: bytesToHex(gluePadding),
    verified: false
  };
}

export function verifyLengthExtension(secret: string, attack: LengthExtensionAttack): boolean {
  const forgedMessageBytes = buildForgedMessageBytes(
    attack.originalMessage,
    attack.secretLength,
    attack.extension
  );
  const actualMac = sha256DigestHex(concatBytes(utf8ToBytes(secret), forgedMessageBytes));

  return actualMac === attack.forgeryMAC.toLowerCase();
}
