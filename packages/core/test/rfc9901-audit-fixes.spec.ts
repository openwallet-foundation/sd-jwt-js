import Crypto from 'node:crypto';
import { hasher as digest, generateSalt } from '@owf/crypto';
import { describe, expect, test } from 'vitest';
import { unpackObj } from '../src/decode';
import { GeneralJSON, Jwt, KBJwt, SDJwtInstance } from '../src/index';
import { selectDisclosures, transformPresentationFrame } from '../src/present';
import type { Signer, Verifier } from '../src/types';
import { Disclosure } from '../src/utils';

const createSignerVerifier = () => {
  const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
  const signer: Signer = async (data: string) => {
    const sig = Crypto.sign(null, Buffer.from(data), privateKey);
    return Buffer.from(sig).toString('base64url');
  };
  const verifier: Verifier = async (data: string, sig: string) => {
    return Crypto.verify(
      null,
      Buffer.from(data),
      publicKey,
      Buffer.from(sig, 'base64url'),
    );
  };
  return { signer, verifier };
};

describe('RFC 9901 audit fixes', () => {
  test('rejects malformed disclosure containers', () => {
    const objectDisclosure = Disclosure.fromArray(['salt', 'name', 'Alice'], {
      digest: 'object-digest',
      encoded: 'object-disclosure',
    });
    const arrayDisclosure = Disclosure.fromArray(['salt', 'Alice'], {
      digest: 'array-digest',
      encoded: 'array-disclosure',
    });

    expect(() => unpackObj({ _sd: 'object-digest' }, {})).toThrow(
      'Invalid _sd claim: expected array of strings',
    );
    expect(() =>
      unpackObj({ items: [{ '...': 'array-digest', extra: true }] }, {}),
    ).toThrow('Invalid array disclosure placeholder');
    expect(() =>
      unpackObj({ _sd: ['array-digest'] }, { 'array-digest': arrayDisclosure }),
    ).toThrow('Array disclosure cannot be used as an object property');
    expect(() =>
      unpackObj(
        { items: [{ '...': 'object-digest' }] },
        { 'object-digest': objectDisclosure },
      ),
    ).toThrow('Object-property disclosure cannot be used as an array element');
  });

  test('rejects disclosed claim name collisions at the same object level', () => {
    const first = Disclosure.fromArray(['salt-1', 'name', 'Alice'], {
      digest: 'digest-1',
      encoded: 'disclosure-1',
    });
    const second = Disclosure.fromArray(['salt-2', 'name', 'Mallory'], {
      digest: 'digest-2',
      encoded: 'disclosure-2',
    });

    expect(() =>
      unpackObj(
        { _sd: ['digest-1', 'digest-2'] },
        { 'digest-1': first, 'digest-2': second },
      ),
    ).toThrow('Disclosed claim name "name" conflicts with another disclosure');
  });

  test('validates JWT claims after disclosure processing', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
    });

    const disclosure = new Disclosure(['salt', 'exp', 1]);
    const disclosureDigest = await disclosure.digest({
      hasher: digest,
      alg: 'sha-256',
    });
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA' })).toString(
      'base64url',
    );
    const payload = Buffer.from(
      JSON.stringify({ _sd: [disclosureDigest], _sd_alg: 'sha-256' }),
    ).toString('base64url');
    const unsignedJwt = `${header}.${payload}`;
    const signature = await signer(unsignedJwt);

    await expect(
      sdjwt.validate(`${unsignedJwt}.${signature}~${disclosure.encode()}~`, {
        currentDate: 1,
      }),
    ).rejects.toThrow('Verify Error: JWT is expired');
  });

  test('rejects unsafe JWT algorithm and invalid validity claims', async () => {
    const jwt = new Jwt({
      header: { alg: 'none' },
      payload: { exp: 100 },
      signature: 'signature',
    });

    await expect(jwt.verify(() => true)).rejects.toThrow(
      'Verify Error: alg "none" is not allowed',
    );

    const { signer, verifier } = createSignerVerifier();
    const signed = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { exp: '100' },
    });
    await signed.sign(signer);

    await expect(signed.verify(verifier)).rejects.toThrow(
      'Verify Error: JWT exp must be a number',
    );
  });

  test('validates expected issuer audience', async () => {
    const { signer, verifier } = createSignerVerifier();
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { aud: 'verifier-a' },
    });
    await jwt.sign(signer);

    await expect(
      jwt.verify(verifier, { expectedAudience: 'verifier-b' }),
    ).rejects.toThrow('Verify Error: Invalid audience');
  });

  test('validates key binding audience, age, and claim types', async () => {
    const { signer } = createSignerVerifier();
    const kbJwt = new KBJwt({
      header: { typ: 'kb+jwt', alg: 'EdDSA' },
      payload: { iat: 900, aud: 'verifier-a', nonce: 'nonce', sd_hash: 'hash' },
    });
    await kbJwt.sign(signer);

    await expect(
      kbJwt.verifyKB({
        verifier: () => true,
        payload: {},
        nonce: 'nonce',
        options: { expectedKeyBindingAudience: 'verifier-b' },
      }),
    ).rejects.toThrow('Verify Error: Invalid Key Binding audience');

    await expect(
      kbJwt.verifyKB({
        verifier: () => true,
        payload: {},
        nonce: 'nonce',
        options: { currentDate: 1000, keyBindingMaxAgeSeconds: 50 },
      }),
    ).rejects.toThrow('Verify Error: Key Binding JWT is too old');

    (kbJwt.payload as Record<string, unknown>).iat = '900';
    await expect(
      kbJwt.verifyKB({ verifier: () => true, payload: {}, nonce: 'nonce' }),
    ).rejects.toThrow('Invalid Key Binding Jwt');
  });

  test('rejects insecure disclosure hash algorithms by default', () => {
    const { signer, verifier } = createSignerVerifier();

    expect(
      () =>
        new SDJwtInstance({
          signer,
          signAlg: 'EdDSA',
          verifier,
          hasher: digest,
          saltGenerator: generateSalt,
          hashAlg: 'sha-256-32',
        }),
    ).toThrow('Disallowed hash algorithm: sha-256-32');
  });

  test('rejects duplicate salts during issuance', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      saltGenerator: () => 'same-salt',
    });

    await expect(
      sdjwt.issue({ first: 'a', second: 'b' }, { _sd: ['first', 'second'] }),
    ).rejects.toThrow('Duplicate disclosure salt detected');
  });

  test('rejects disclosures and kb_jwt outside the first General JSON header', () => {
    expect(() =>
      GeneralJSON.fromSerialized({
        payload: 'payload',
        signatures: [
          { protected: 'header-1', signature: 'sig-1', header: {} },
          {
            protected: 'header-2',
            signature: 'sig-2',
            header: { disclosures: [] },
          },
        ],
      }),
    ).toThrow(
      'disclosures and kb_jwt MUST only appear in the first unprotected header',
    );
  });

  test('escapes presentation paths with literal dots in claim names', () => {
    expect(transformPresentationFrame({ 'a.b': true })).toEqual(['a~1b']);
    expect(transformPresentationFrame({ a: { b: true } })).toEqual([
      'a',
      'a.b',
    ]);

    const selected = selectDisclosures(
      { _sd: ['top'], a: { _sd: ['nested'] } },
      [
        {
          digest: 'top',
          encoded: 'top-disclosure',
          salt: 'salt-1',
          key: 'a.b',
          value: 'top-level',
        },
        {
          digest: 'nested',
          encoded: 'nested-disclosure',
          salt: 'salt-2',
          key: 'b',
          value: 'nested',
        },
      ],
      { a: { b: true } },
    );

    expect(selected).toHaveLength(1);
    expect(selected[0].digest).toBe('nested');
  });
});
