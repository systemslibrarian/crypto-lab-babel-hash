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

  it('refuses to sign with an empty key rather than inventing one', async () => {
    // This is the precondition renderHmacPanel's catch branch exists for. Web
    // Crypto rejects a zero-length HMAC key, and the demo's secret field can be
    // cleared (or arrive empty from a shared "#s=" link), so the panel has to
    // handle a rejection here rather than await a promise that never settles.
    // If a future runtime started accepting empty keys this test fails loudly,
    // which is the signal that the branch has gone dead.
    await expect(hmacSign('', 'amount=10&to=alice')).rejects.toThrow();
    await expect(hmacVerify('', 'amount=10&to=alice', '00'.repeat(32))).rejects.toThrow();

    // One byte of key is enough — the refusal is specifically about length zero.
    await expect(hmacSign('k', 'amount=10&to=alice')).resolves.toMatch(/^[0-9a-f]{64}$/u);
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
