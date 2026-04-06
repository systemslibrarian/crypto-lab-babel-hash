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

export async function attemptLengthExtensionOnHMAC(
  mac: string,
  message: string,
  secretLength: number,
  extension: string
): Promise<{ forgery: string; verified: boolean }> {
  const attack = lengthExtensionForge(mac, message, secretLength, extension);
  void secretLength;
  void extension;

  return {
    forgery: attack.forgeryMAC,
    verified: false
  };
}
