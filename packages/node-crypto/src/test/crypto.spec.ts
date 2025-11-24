import { describe, expect, test } from 'vitest';
import { digest, ES256, ES384, ES512, generateSalt } from '../index';

// Extract the major version as a number
const nodeVersionMajor = Number.parseInt(
  process.version.split('.')[0].substring(1),
  10,
);

describe('This file is for utility functions', () => {
  test('generateSalt', async () => {
    const salt = generateSalt(8);
    expect(salt).toBeDefined();
    expect(salt.length).toBe(8);
  });

  test('generateSalt 0 length', async () => {
    const salt = generateSalt(0);
    expect(salt).toBeDefined();
    expect(salt.length).toBe(0);
  });

  test('digest', async () => {
    const payload = 'test1';
    const s1 = await digest(payload);
    expect(s1).toBeDefined();
    expect(s1.length).toBe(32);
  });

  test('digest', async () => {
    const payload = 'test1';
    const s1 = await digest(payload, 'SHA512');
    expect(s1).toBeDefined();
    expect(s1.length).toBe(64);
  });

  for (const algObj of [ ES256, ES384, ES512 ]) {
    (nodeVersionMajor < 20 ? test.skip : test)(algObj.alg, async () => {
      const { privateKey, publicKey } = await algObj.generateKeyPair();
      expect(privateKey).toBeDefined();
      expect(publicKey).toBeDefined();
      expect(typeof privateKey).toBe('object');
      expect(typeof publicKey).toBe('object');

      const data =
        'In cryptography, a salt is random data that is used as an additional input to a one-way function that hashes data, a password or passphrase.';
      const signer = await algObj.getSigner(privateKey);
      const signature = await signer(data);
      expect(signature).toBeDefined();
      expect(typeof signature).toBe('string');

      const verifier = await algObj.getVerifier(publicKey);
      const result = await verifier(data, signature);
      expect(result).toBe(true);
    });
  }
});
