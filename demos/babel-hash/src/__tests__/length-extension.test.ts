import { describe, expect, it } from 'vitest';
import { concatBytes, hashBytes, utf8ToBytes } from '../crypto/hash';
import {
  buildForgedMessageBytes,
  computeSHA256Padding,
  lengthExtensionForge,
  sha256PrefixMac,
  verifyLengthExtension
} from '../crypto/length-extension';

describe('length extension attack', () => {
  it('computes valid SHA-256 padding for a 3-byte message', () => {
    const padding = computeSHA256Padding(3);
    expect(padding.length).toBe(61);
    expect(padding[0]).toBe(0x80);
    expect(Array.from(padding.slice(-8))).toEqual([0, 0, 0, 0, 0, 0, 0, 24]);
  });

  it('forges a valid SHA-256 MAC when the secret-length guess is correct', () => {
    const secret = 'hiddenkey';
    const message = 'comment=10&uid=1';
    const extension = '&admin=true';
    const originalMAC = sha256PrefixMac(secret, message);
    const attack = lengthExtensionForge(originalMAC, message, secret.length, extension);

    expect(verifyLengthExtension(secret, attack)).toBe(true);
    expect(attack.forgeryMAC).toHaveLength(64);
  });

  it('does not transfer to SHA3-256', async () => {
    const secret = 'hiddenkey';
    const message = 'comment=10&uid=1';
    const extension = '&admin=true';
    const originalMac = await hashBytes(utf8ToBytes(`${secret}${message}`), 'sha3-256');
    const attack = lengthExtensionForge(originalMac, message, secret.length, extension);
    const actualSha3 = await hashBytes(
      concatBytes(utf8ToBytes(secret), buildForgedMessageBytes(message, secret.length, extension)),
      'sha3-256'
    );

    expect(actualSha3).not.toBe(attack.forgeryMAC);
  });
});
