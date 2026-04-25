import Crypto from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { Jwt } from '../jwt';
import type { Signer, Verifier } from '../types';
import { base64urlEncode, SDJWTException } from '../utils';

describe('JWT', () => {
  test('create', async () => {
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    expect(jwt.header).toEqual({ alg: 'EdDSA' });
    expect(jwt.payload).toEqual({ foo: 'bar' });
  });

  test('returns decoded JWT when correct JWT string is provided', () => {
    const jwt = `${base64urlEncode(
      JSON.stringify({ alg: 'HS256', typ: 'JWT' }),
    )}.${base64urlEncode(
      JSON.stringify({ sub: '1234567890', name: 'John Doe' }),
    )}.signature`;
    const result = Jwt.decodeJWT(jwt);
    expect(result).toEqual({
      header: { alg: 'HS256', typ: 'JWT' },
      payload: { sub: '1234567890', name: 'John Doe' },
      signature: 'signature',
    });
  });

  test('throws an error when JWT string is not correctly formed', () => {
    const jwt = 'abc.def';
    expect(() => Jwt.decodeJWT(jwt)).toThrow('Invalid JWT as input');
  });

  test('throws an error when JWT parts are missing', () => {
    const jwt = `${base64urlEncode(
      JSON.stringify({ alg: 'HS256', typ: 'JWT' }),
    )}`;
    expect(() => Jwt.decodeJWT(jwt)).toThrow('Invalid JWT as input');
  });

  test('set', async () => {
    const jwt = new Jwt();
    jwt.setHeader({ alg: 'EdDSA' });
    jwt.setPayload({ foo: 'bar' });

    expect(jwt.header).toEqual({ alg: 'EdDSA' });
    expect(jwt.payload).toEqual({ foo: 'bar' });
  });

  test('sign', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    const encodedJwt = await jwt.sign(testSigner);
    expect(typeof encodedJwt).toBe('string');
  });

  test('verify', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(
        null,
        Buffer.from(data),
        publicKey,
        Buffer.from(sig, 'base64url'),
      );
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    const encodedJwt = await jwt.sign(testSigner);
    const newJwt = Jwt.fromEncode(encodedJwt);
    const verified = await newJwt.verify(testVerifier);
    expect(verified).toStrictEqual({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });
    try {
      await newJwt.verify(() => false);
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException);
    }
  });

  test('encode', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    const encodedJwt = await jwt.sign(testSigner);
    const newJwt = Jwt.fromEncode(encodedJwt);
    const newEncodedJwt = newJwt.encodeJwt();
    expect(newEncodedJwt).toBe(encodedJwt);
  });

  test('decode failed', () => {
    expect(() => Jwt.fromEncode('asfasfas')).toThrow();
  });

  test('encode failed', async () => {
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
    });

    try {
      jwt.encodeJwt();
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException);
    }
  });

  test('getUnsignedToken failed', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
    });

    try {
      await jwt.sign(testSigner);
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException);
    }
  });

  test('wrong encoded field', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
      encoded: 'asfasfafaf.dfasfafafasf', // it has to be 3 parts
    });

    try {
      await jwt.sign(testSigner);
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException);
    }
  });

  test('verify failed no signature', async () => {
    const { publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(
        null,
        Buffer.from(data),
        publicKey,
        Buffer.from(sig, 'base64url'),
      );
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    try {
      await jwt.verify(testVerifier);
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException);
    }
  });

  test('verify with issuance date in the future', async () => {
    const { publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(
        null,
        Buffer.from(data),
        publicKey,
        Buffer.from(sig, 'base64url'),
      );
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { iat: Math.floor(Date.now() / 1000) + 100 },
    });

    try {
      await jwt.verify(testVerifier);
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException);
      expect((e as SDJWTException).message).toBe(
        'Verify Error: JWT is not yet valid',
      );
    }
  });

  test('verify with not before in the future', async () => {
    const { publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(
        null,
        Buffer.from(data),
        publicKey,
        Buffer.from(sig, 'base64url'),
      );
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { nbf: Math.floor(Date.now() / 1000) + 100 },
    });

    try {
      await jwt.verify(testVerifier);
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException);
      expect((e as SDJWTException).message).toBe(
        'Verify Error: JWT is not yet valid',
      );
    }
  });

  test('verify with expired', async () => {
    const { publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(
        null,
        Buffer.from(data),
        publicKey,
        Buffer.from(sig, 'base64url'),
      );
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { exp: Math.floor(Date.now() / 1000) },
    });

    try {
      await jwt.verify(testVerifier, {
        currentDate: Math.floor(Date.now() / 1000) + 100,
      });
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException);
      expect((e as SDJWTException).message).toBe(
        'Verify Error: JWT is expired',
      );
    }
  });

  test('verify with skew', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(
        null,
        Buffer.from(data),
        publicKey,
        Buffer.from(sig, 'base64url'),
      );
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { exp: Math.floor(Date.now() / 1000) - 1 },
    });

    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    await jwt.sign(testSigner);
    await jwt.verify(testVerifier, { skewSeconds: 2 });
  });
});
