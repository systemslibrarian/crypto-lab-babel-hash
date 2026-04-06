import { describe, expect, it } from 'vitest';
import { attemptLengthExtensionOnHMAC, hmacSign, hmacVerify } from '../crypto/hmac';

describe('hmac-sha256', () => {
  it('signs and verifies messages correctly', async () => {
    const key = 'kingdom-key';
    const message = 'amount=10&to=alice';
    const mac = await hmacSign(key, message);

    await expect(hmacVerify(key, message, mac)).resolves.toBe(true);
    await expect(hmacVerify(key, `${message}&tampered=1`, mac)).resolves.toBe(false);
  });

  it('rejects a length-extension style forgery', async () => {
    const key = 'kingdom-key';
    const message = 'amount=10&to=alice';
    const extension = '&admin=true';
    const mac = await hmacSign(key, message);
    const attempt = await attemptLengthExtensionOnHMAC(mac, message, key.length, extension);

    expect(attempt.verified).toBe(false);
    await expect(hmacVerify(key, `${message}${extension}`, attempt.forgery)).resolves.toBe(false);
  });
});
