import type { SDJWTException } from '@sd-jwt/utils';
import { KBJwt } from '../kbjwt';
import {
  type JwtPayload,
  KB_JWT_TYP,
  type KbVerifier,
  type Signer,
  Verifier,
} from '@sd-jwt/types';
import Crypto, { type KeyLike } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { type JWK, exportJWK, importJWK } from 'jose';

describe('KB JWT', () => {
  test('create', async () => {
    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: 'EdDSA',
      },
      payload: {
        iat: 1,
        aud: 'aud',
        nonce: 'nonce',
        sd_hash: 'hash',
      },
    });

    expect(kbJwt.header).toEqual({
      typ: KB_JWT_TYP,
      alg: 'EdDSA',
    });
    expect(kbJwt.payload).toEqual({
      iat: 1,
      aud: 'aud',
      nonce: 'nonce',
      sd_hash: 'hash',
    });
  });

  test('decode', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };
    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: 'EdDSA',
      },
      payload: {
        iat: 1,
        aud: 'aud',
        nonce: 'nonce',
        sd_hash: 'hash',
      },
    });
    const encodedKbJwt = await kbJwt.sign(testSigner);
    const decoded = KBJwt.fromKBEncode(encodedKbJwt);
    expect(decoded.header).toEqual({
      typ: KB_JWT_TYP,
      alg: 'EdDSA',
    });
    expect(decoded.payload).toEqual({
      iat: 1,
      aud: 'aud',
      nonce: 'nonce',
      sd_hash: 'hash',
    });
  });

  test('verify', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const payload = {
      cnf: {
        jwk: await exportJWK(publicKey),
      },
    };

    const testVerifier: KbVerifier = async (
      data: string,
      sig: string,
      payload: JwtPayload,
    ) => {
      expect(payload).toStrictEqual(payload);
      expect(payload.cnf?.jwk).toBeDefined();

      const publicKey = payload.cnf?.jwk;

      return Crypto.verify(
        null,
        Buffer.from(data),
        (await importJWK(publicKey as JWK, 'EdDSA')) as KeyLike,
        Buffer.from(sig, 'base64url'),
      );
    };
    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: 'EdDSA',
      },
      payload: {
        iat: 1,
        aud: 'aud',
        nonce: 'nonce',
        sd_hash: 'hash',
      },
    });
    const encodedKbJwt = await kbJwt.sign(testSigner);
    const decoded = KBJwt.fromKBEncode(encodedKbJwt);
    const verified = await decoded.verifyKB({
      verifier: testVerifier,
      payload,
      nonce: 'nonce',
    });
    expect(verified).toStrictEqual({
      header: {
        typ: KB_JWT_TYP,
        alg: 'EdDSA',
      },
      payload: {
        iat: 1,
        aud: 'aud',
        nonce: 'nonce',
        sd_hash: 'hash',
      },
    });
  });

  test('verify failed', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const payload = {
      cnf: {
        jwk: await exportJWK(publicKey),
      },
    };
    const testVerifier: KbVerifier = async (
      data: string,
      sig: string,
      payload: JwtPayload,
    ) => {
      expect(payload).toStrictEqual(payload);
      expect(payload.cnf?.jwk).toBeDefined();

      const publicKey = payload.cnf?.jwk;

      return Crypto.verify(
        null,
        Buffer.from(data),
        (await importJWK(publicKey as JWK, 'EdDSA')) as KeyLike,
        Buffer.from(sig, 'base64url'),
      );
    };

    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: 'EdDSA',
      },
      payload: {
        iat: 1,
        aud: 'aud',
        nonce: 'nonce',
        sd_hash: '',
      },
    });
    const encodedKbJwt = await kbJwt.sign(testSigner);
    const decoded = KBJwt.fromKBEncode(encodedKbJwt);
    try {
      await decoded.verifyKB({
        verifier: testVerifier,
        payload,
        nonce: 'nonce',
      });
    } catch (e: unknown) {
      const error = e as SDJWTException;
      expect(error.message).toBe('Invalid Key Binding Jwt');
    }
  });

  test('verify failed with verifier return false', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const payload = {
      cnf: {
        jwk: await exportJWK(publicKey),
      },
    };
    const testVerifier: KbVerifier = async (
      data: string,
      sig: string,
      payload: JwtPayload,
    ) => {
      expect(payload).toStrictEqual(payload);
      expect(payload.cnf?.jwk).toBeDefined();

      return false;
    };

    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: 'EdDSA',
      },
      payload: {
        iat: 1,
        aud: 'aud',
        nonce: 'nonce',
        sd_hash: 'hash',
      },
    });
    const encodedKbJwt = await kbJwt.sign(testSigner);
    const decoded = KBJwt.fromKBEncode(encodedKbJwt);
    try {
      await decoded.verifyKB({
        verifier: testVerifier,
        payload,
        nonce: 'nonce',
      });
    } catch (e: unknown) {
      const error = e as SDJWTException;
      expect(error.message).toBe('Verify Error: Invalid JWT Signature');
    }
  });

  test('verify failed with invalid jwt', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const payload = {
      cnf: {
        jwk: await exportJWK(publicKey),
      },
    };
    const testVerifier: KbVerifier = async (
      data: string,
      sig: string,
      payload: JwtPayload,
    ) => {
      expect(payload).toStrictEqual(payload);
      expect(payload.cnf?.jwk).toBeDefined();

      return false;
    };

    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: 'EdDSA',
      },
      payload: {
        iat: 1,
        aud: 'aud',
        nonce: 'nonce',
        sd_hash: 'hash',
      },
    });
    const encodedKbJwt = await kbJwt.sign(testSigner);
    const decoded = KBJwt.fromKBEncode(encodedKbJwt);
    decoded.signature = undefined;
    try {
      await decoded.verifyKB({
        verifier: testVerifier,
        payload,
        nonce: 'nonce',
      });
    } catch (e: unknown) {
      const error = e as SDJWTException;
      expect(error.message).toBe('Verify Error: Invalid JWT');
    }
  });

  test('compatibility test for version 06', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };
    const payload = {
      cnf: {
        jwk: await exportJWK(publicKey),
      },
    };
    const testVerifier: KbVerifier = async (
      data: string,
      sig: string,
      payload: JwtPayload,
    ) => {
      expect(payload).toStrictEqual(payload);
      expect(payload.cnf?.jwk).toBeDefined();

      const publicKey = payload.cnf?.jwk;

      return Crypto.verify(
        null,
        Buffer.from(data),
        (await importJWK(publicKey as JWK, 'EdDSA')) as KeyLike,
        Buffer.from(sig, 'base64url'),
      );
    };
    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: 'EdDSA',
      },
      payload: {
        iat: 1,
        aud: 'aud',
        nonce: 'nonce',
        sd_hash: 'hash',
      },
    });

    (kbJwt.payload as Record<string, unknown>)._sd_hash = 'hash';
    (kbJwt.payload as Record<string, unknown>).sd_hash = undefined;

    const encodedKbJwt = await kbJwt.sign(testSigner);
    const decoded = KBJwt.fromKBEncode(encodedKbJwt);
    const verified = await decoded.verifyKB({
      verifier: testVerifier,
      payload,
      nonce: 'nonce',
    });
    expect(verified).toStrictEqual({
      header: {
        typ: KB_JWT_TYP,
        alg: 'EdDSA',
      },
      payload: {
        iat: 1,
        aud: 'aud',
        nonce: 'nonce',
        _sd_hash: 'hash',
      },
    });
  });
});
