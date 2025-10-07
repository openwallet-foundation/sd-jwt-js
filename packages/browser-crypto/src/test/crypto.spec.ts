import { describe, expect, test } from 'vitest';
import { digest, ES256, generateSalt, getHasher } from '../index';

// Extract the major version as a number
const nodeVersionMajor = Number.parseInt(
  process.version.split('.')[0].substring(1),
  10,
);

describe('This file is for utility functions', () => {
  (nodeVersionMajor < 20 ? test.skip : test)('generateSalt', async () => {
    const salt = generateSalt(8);
    expect(salt).toBeDefined();
    expect(salt.length).toBe(8);
  });

  (nodeVersionMajor < 20 ? test.skip : test)(
    'generateSalt 0 length',
    async () => {
      const salt = generateSalt(0);
      expect(salt).toBeDefined();
      expect(salt.length).toBe(0);
    },
  );

  (nodeVersionMajor < 20 ? test.skip : test)('digest', async () => {
    const payload = 'test1';
    const s1 = await digest(payload);
    expect(s1).toBeDefined();
    expect(s1.length).toBe(32);
  });

  (nodeVersionMajor < 20 ? test.skip : test)('digest', async () => {
    const payload = 'test1';
    const s1 = await digest(payload, 'SHA-512');
    expect(s1).toBeDefined();
    expect(s1.length).toBe(64);
  });

  (nodeVersionMajor < 20 ? test.skip : test)('get hasher', async () => {
    const hash = await getHasher('SHA-512')('test1');
    expect(hash).toBeDefined();
  });

  (nodeVersionMajor < 20 ? test.skip : test)('ES256 alg', () => {
    expect(ES256.alg).toBe('ES256');
  });

  (nodeVersionMajor < 20 ? test.skip : test)('ES256', async () => {
    const { privateKey, publicKey } = await ES256.generateKeyPair();
    expect(privateKey).toBeDefined();
    expect(publicKey).toBeDefined();
    expect(typeof privateKey).toBe('object');
    expect(typeof publicKey).toBe('object');

    const data =
      'In cryptography, a salt is random data that is used as an additional input to a one-way function that hashes data, a password or passphrase.';
    const signature = await (await ES256.getSigner(privateKey))(data);
    expect(signature).toBeDefined();
    expect(typeof signature).toBe('string');

    const result = await (await ES256.getVerifier(publicKey))(data, signature);
    expect(result).toBe(true);
  });
});
