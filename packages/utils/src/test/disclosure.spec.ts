import { generateSalt, digest as hasher } from '@sd-jwt/crypto-nodejs';
import { describe, expect, test } from 'vitest';
import { Disclosure } from '../disclosure';
import { base64urlEncode, type SDJWTException } from '../index';

const hash = { alg: 'SHA256', hasher };

/* 
  ref draft-ietf-oauth-selective-disclosure-jwt-07
  Claim given_name:
  SHA-256 Hash: jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4
  Disclosure: WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd
  Contents: ["2GLC42sKQveCfGfryNRN9w", "given_name", "John"]
  For example, the SHA-256 digest of the Disclosure
  WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0 would be uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY.
  The SHA-256 digest of the Disclosure
  WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0 would be w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs.
*/
const TestDataDraft7 = {
  claimTests: [
    {
      contents: '["2GLC42sKQveCfGfryNRN9w", "given_name", "John"]',
      digest: 'jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4',
      disclosure:
        'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd',
    },
  ],
  sha256Tests: [
    {
      digest: 'uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY',
      disclosure: 'WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0',
    },
    {
      digest: 'w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs',
      disclosure: 'WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0',
    },
  ],
};

describe('Disclosure', () => {
  test('create object disclosure', async () => {
    const salt = generateSalt(16);
    const disclosure = new Disclosure([salt, 'name', 'James']);
    expect(disclosure).toBeDefined();
    expect(disclosure.key).toBe('name');
    expect(disclosure.value).toBe('James');
    expect(disclosure.salt).toBe(salt);
  });

  test('create array disclosure', async () => {
    const salt = generateSalt(16);
    const disclosure = new Disclosure([salt, 'US']);
    expect(disclosure).toBeDefined();
    expect(disclosure.key).toBe(undefined);
    expect(disclosure.value).toBe('US');
    expect(disclosure.salt).toBe(salt);
  });

  test('create disclosure error', async () => {
    const salt = generateSalt(16);
    const data: [string, string, string] = [salt, 'name', 'James'];
    data.push('any');
    expect(() => new Disclosure(data)).toThrow();
    try {
      new Disclosure(data);
    } catch (e: unknown) {
      const error = e as SDJWTException;
      expect(typeof error.getFullMessage()).toBe('string');
    }
  });

  test('encode disclosure', async () => {
    const salt = generateSalt(16);
    const disclosure = new Disclosure([salt, 'name', 'James']);
    const encodedDisclosure = disclosure.encode();
    expect(encodedDisclosure).toBeDefined();
    expect(typeof encodedDisclosure).toBe('string');
  });

  test('decode disclosure', async () => {
    const salt = generateSalt(16);
    const disclosure = new Disclosure([salt, 'name', 'James']);
    const encodedDisclosure = disclosure.encode();
    const newDisclosure = await Disclosure.fromEncode(encodedDisclosure, {
      alg: 'SHA256',
      hasher,
    });

    expect(newDisclosure).toBeDefined();
    expect(newDisclosure.key).toBe('name');
    expect(newDisclosure.value).toBe('James');
    expect(newDisclosure.salt).toBe(salt);
  });

  test('decode disclosure sync', () => {
    const salt = generateSalt(16);
    const disclosure = new Disclosure([salt, 'name', 'James']);
    const encodedDisclosure = disclosure.encode();
    const newDisclosure = Disclosure.fromEncodeSync(encodedDisclosure, {
      alg: 'SHA256',
      hasher,
    });

    expect(newDisclosure).toBeDefined();
    expect(newDisclosure.key).toBe('name');
    expect(newDisclosure.value).toBe('James');
    expect(newDisclosure.salt).toBe(salt);
  });

  test('digest disclosure #1', async () => {
    const salt = generateSalt(16);
    const disclosure = new Disclosure([salt, 'name', 'James']);
    const digest = await disclosure.digest({ alg: 'SHA256', hasher });
    expect(digest).toBeDefined();
    expect(typeof digest).toBe('string');
  });

  test('digest disclosure #2', async () => {
    const disclosure = new Disclosure([
      '2GLC42sKQveCfGfryNRN9w',
      'given_name',
      'John',
    ]);
    const encode = disclosure.encode();
    expect(encode).toBe(
      'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ',
    );
    const digest = await disclosure.digest(hash);
    expect(digest).toBe('8VHiz7qTXavxvpiTYDCSr_shkUO6qRcVXjkhEnt1os4');
  });

  test('digest disclosure #2 sync', () => {
    const disclosure = new Disclosure([
      '2GLC42sKQveCfGfryNRN9w',
      'given_name',
      'John',
    ]);
    const encode = disclosure.encode();
    expect(encode).toBe(
      'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ',
    );
    const digest = disclosure.digestSync(hash);
    expect(digest).toBe('8VHiz7qTXavxvpiTYDCSr_shkUO6qRcVXjkhEnt1os4');
  });

  test('digest disclosure #3', async () => {
    const encoded = base64urlEncode(TestDataDraft7.claimTests[0].contents);
    expect(encoded).toStrictEqual(TestDataDraft7.claimTests[0].disclosure);

    const disclosure = await Disclosure.fromEncode(
      TestDataDraft7.claimTests[0].disclosure,
      hash,
    );

    const digest = await disclosure.digest(hash);
    expect(digest).toBe(TestDataDraft7.claimTests[0].digest);
  });

  test('digest disclosure #4', async () => {
    for (const sha256Test of TestDataDraft7.sha256Tests) {
      const disclosure = await Disclosure.fromEncode(
        sha256Test.disclosure,
        hash,
      );

      const digest = await disclosure.digest(hash);
      expect(digest).toBe(sha256Test.digest);
    }
  });
});
