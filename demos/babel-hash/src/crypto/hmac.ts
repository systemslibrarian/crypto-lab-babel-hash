/**
 * HMAC-SHA256 helpers for the babel-hash demo.
 *
 * Source: RFC 2104 — https://www.rfc-editor.org/rfc/rfc2104
 */
import { hexToBytes, bytesToHex, utf8ToBytes } from './hash';
import { lengthExtensionForge } from './length-extension';

async function importHmacKey(key: string, usages: KeyUsage[]): Promise<CryptoKey> {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto API is unavailable in this runtime.');
  }

  return globalThis.crypto.subtle.importKey(
    'raw',
    utf8ToBytes(key) as unknown as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    usages
  );
}

export async function hmacSign(key: string, message: string): Promise<string> {
  const cryptoKey = await importHmacKey(key, ['sign']);
  const signature = await globalThis.crypto.subtle.sign(
    'HMAC',
    cryptoKey,
    utf8ToBytes(message) as unknown as BufferSource
  );
  return bytesToHex(new Uint8Array(signature));
}

export async function hmacVerify(key: string, message: string, mac: string): Promise<boolean> {
  const cryptoKey = await importHmacKey(key, ['verify']);
  return globalThis.crypto.subtle.verify(
    'HMAC',
    cryptoKey,
    hexToBytes(mac) as unknown as BufferSource,
    utf8ToBytes(message) as unknown as BufferSource
  );
}

/**
 * Runs the length-extension recipe against an HMAC tag and then *asks the real
 * verifier* whether the result is accepted.
 *
 * The verdict is computed, never asserted: `verified` is the boolean returned by
 * `hmacVerify` for the extended message, so it is earned the same way the
 * server's answer would be. (It comes back false — that is the lesson — but the
 * demo must never print a claim nobody computed.)
 */
export async function attemptLengthExtensionOnHMAC(
  key: string,
  mac: string,
  message: string,
  secretLength: number,
  extension: string
): Promise<{ forgery: string; verified: boolean }> {
  const attack = lengthExtensionForge(mac, message, secretLength, extension);
  const verified = await hmacVerify(key, `${message}${extension}`, attack.forgeryMAC);

  return {
    forgery: attack.forgeryMAC,
    verified
  };
}
