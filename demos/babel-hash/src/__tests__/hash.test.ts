import { describe, expect, it } from 'vitest';
import { hashString } from '../crypto/hash';

describe('hash primitives', () => {
  it('matches the SHA-256 test vectors', async () => {
    await expect(hashString('', 'sha-256')).resolves.toMatchObject({
      digest: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    });

    await expect(hashString('abc', 'sha-256')).resolves.toMatchObject({
      digest: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    });
  });

  it('matches the SHA3-256 test vectors', async () => {
    await expect(hashString('', 'sha3-256')).resolves.toMatchObject({
      digest: 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a'
    });

    await expect(hashString('abc', 'sha3-256')).resolves.toMatchObject({
      digest: '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532'
    });
  });

  it('matches the BLAKE3 empty-string vector from the spec', async () => {
    await expect(hashString('', 'blake3')).resolves.toMatchObject({
      digest: 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262'
    });
  });
});
