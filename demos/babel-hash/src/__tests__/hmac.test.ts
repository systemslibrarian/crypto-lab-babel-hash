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
    const attempt = await attemptLengthExtensionOnHMAC(key, mac, message, key.length, extension);

    expect(attempt.verified).toBe(false);
    await expect(hmacVerify(key, `${message}${extension}`, attempt.forgery)).resolves.toBe(false);
  });

  it('earns its verdict from hmacVerify rather than asserting it', async () => {
    const key = 'kingdom-key';
    const message = 'amount=10&to=alice';
    const extension = '&admin=true';
    const mac = await hmacSign(key, message);

    // The genuine tag for the extended message is accepted, so the verifier the
    // attempt consults is live and capable of answering true; the forgery is a
    // different value, and the reported verdict is exactly what that same
    // verifier says about it — not a constant baked into the function.
    const genuine = await hmacSign(key, `${message}${extension}`);
    await expect(hmacVerify(key, `${message}${extension}`, genuine)).resolves.toBe(true);

    for (const guess of [key.length, key.length - 3, key.length + 5, 1]) {
      const attempt = await attemptLengthExtensionOnHMAC(key, mac, message, guess, extension);
      const independent = await hmacVerify(key, `${message}${extension}`, attempt.forgery);

      expect(attempt.forgery).not.toBe(genuine);
      expect(attempt.verified).toBe(independent);
      expect(attempt.verified).toBe(false);
    }
  });
});
