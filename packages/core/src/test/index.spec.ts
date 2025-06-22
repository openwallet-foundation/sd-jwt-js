import { SDJwtInstance, type SdJwtPayload } from '../index';
import type { Signer, Verifier, KbVerifier, JwtPayload } from '@sd-jwt/types';
import Crypto, { type KeyLike } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { digest, generateSalt, ES256 } from '@sd-jwt/crypto-nodejs';
import { importJWK, exportJWK, type JWK } from 'jose';

// Extract the major version as a number
const nodeVersionMajor = Number.parseInt(
  process.version.split('.')[0].substring(1),
  10,
);

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

describe('index', () => {
  test('create', async () => {
    const sdjwt = new SDJwtInstance<SdJwtPayload>();
    expect(sdjwt).toBeDefined();
  });

  test('kbJwt', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: signer,
      kbSignAlg: 'EdDSA',
    });
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: Math.floor(Date.now() / 1000),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );

    expect(credential).toBeDefined();

    const presentation = await sdjwt.present<typeof claims>(
      credential,
      { foo: true },
      {
        kb: {
          payload: {
            aud: '1',
            iat: 1,
            nonce: '342',
          },
        },
      },
    );

    expect(presentation).toBeDefined();
  });

  test('issue', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
    });
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: Math.floor(Date.now() / 1000),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );

    expect(credential).toBeDefined();
  });

  test('verify failed', async () => {
    const { signer } = createSignerVerifier();
    const { publicKey } = Crypto.generateKeyPairSync('ed25519');
    const failedverifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(
        null,
        Buffer.from(data),
        publicKey,
        Buffer.from(sig, 'base64url'),
      );
    };

    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      signAlg: 'EdDSA',
      verifier: failedverifier,
      hasher: digest,
      saltGenerator: generateSalt,
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: Math.floor(Date.now() / 1000),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );

    try {
      await sdjwt.verify(credential);
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('verify failed with kbJwt', async () => {
    const { signer, verifier } = createSignerVerifier();
    const { publicKey } = Crypto.generateKeyPairSync('ed25519');
    const failedverifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(
        null,
        Buffer.from(data),
        publicKey,
        Buffer.from(sig, 'base64url'),
      );
    };
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: signer,
      kbVerifier: failedverifier,
      kbSignAlg: 'EdDSA',
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: Math.floor(Date.now() / 1000),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = await sdjwt.present<typeof claims>(
      credential,
      { foo: true },
      {
        kb: {
          payload: {
            aud: '',
            iat: 1,
            nonce: '342',
          },
        },
      },
    );

    try {
      await sdjwt.verify(presentation);
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('verify with kbJwt', async () => {
    const { signer, verifier } = createSignerVerifier();

    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');

    //TODO: maybe we can pass a minial class of the jwt to pass the token
    const kbVerifier: KbVerifier = async (
      data: string,
      sig: string,
      payload: JwtPayload,
    ) => {
      let publicKey: JsonWebKey;
      if (payload.cnf) {
        // use the key from the cnf
        publicKey = payload.cnf.jwk;
      } else {
        throw Error('key binding not supported');
      }
      // get the key of the holder to verify the signature
      return Crypto.verify(
        null,
        Buffer.from(data),
        (await importJWK(publicKey as JWK, 'EdDSA')) as KeyLike,
        Buffer.from(sig, 'base64url'),
      );
    };

    const kbSigner = (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: kbSigner,
      kbVerifier: kbVerifier,
      kbSignAlg: 'EdDSA',
    });
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iat: Math.floor(Date.now() / 1000),
        cnf: {
          jwk: await exportJWK(publicKey),
        },
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = await sdjwt.present<typeof claims>(
      credential,
      { foo: true },
      {
        kb: {
          payload: {
            aud: '1',
            iat: 1,
            nonce: '342',
          },
        },
      },
    );

    const results = await sdjwt.verify(presentation, ['foo'], true);
    expect(results).toBeDefined();
  });

  test('Hasher not found', async () => {
    const sdjwt = new SDJwtInstance<SdJwtPayload>({});
    try {
      const credential = await sdjwt.issue(
        {
          foo: 'bar',
          iss: 'Issuer',
          iat: Math.floor(Date.now() / 1000),
          vct: '',
        },
        {
          _sd: ['foo'],
        },
      );

      expect(credential).toBeDefined();
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('SaltGenerator not found', async () => {
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      hasher: digest,
    });
    try {
      const credential = await sdjwt.issue(
        {
          foo: 'bar',
          iss: 'Issuer',
          iat: Math.floor(Date.now() / 1000),
          vct: '',
        },
        {
          _sd: ['foo'],
        },
      );

      expect(credential).toBeDefined();
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('Signer not found', async () => {
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      hasher: digest,
      saltGenerator: generateSalt,
    });
    try {
      const credential = await sdjwt.issue(
        {
          foo: 'bar',
          iss: 'Issuer',
          iat: Math.floor(Date.now() / 1000),
          vct: '',
        },
        {
          _sd: ['foo'],
        },
      );

      expect(credential).toBeDefined();
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('Verifier not found', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: signer,
      kbVerifier: verifier,
      signAlg: 'EdDSA',
      kbSignAlg: 'EdDSA',
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: Math.floor(Date.now() / 1000),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = await sdjwt.present<typeof claims>(
      credential,
      { foo: true },
      {
        kb: {
          payload: {
            aud: '1',
            iat: 1,
            nonce: '342',
          },
        },
      },
    );
    try {
      const results = await sdjwt.verify(presentation, ['foo'], true);
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('kbSigner not found', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbVerifier: verifier,
      signAlg: 'EdDSA',
      kbSignAlg: 'EdDSA',
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: Math.floor(Date.now() / 1000),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );
    try {
      const presentation = await sdjwt.present<typeof claims>(
        credential,
        { foo: true },
        {
          kb: {
            payload: {
              aud: '1',
              iat: 1,
              nonce: '342',
            },
          },
        },
      );
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('kbVerifier not found', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: signer,
      signAlg: 'EdDSA',
      kbSignAlg: 'EdDSA',
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: Math.floor(Date.now() / 1000),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = await sdjwt.present<typeof claims>(
      credential,
      { foo: true },
      {
        kb: {
          payload: {
            aud: '1',
            iat: 1,
            nonce: '342',
          },
        },
      },
    );
    try {
      const results = await sdjwt.verify(presentation, ['foo'], true);
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('kbSignAlg not found', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: signer,
      signAlg: 'EdDSA',
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: Math.floor(Date.now() / 1000),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = sdjwt.present<typeof claims>(
      credential,
      { foo: true },
      {
        kb: {
          payload: {
            aud: '1',
            iat: 1,
            nonce: '342',
          },
        },
      },
    );
    expect(presentation).rejects.toThrow(
      'Key Binding sign algorithm not specified',
    );
  });

  test('hasher is not found', async () => {
    const { signer } = createSignerVerifier();
    const sdjwt_create = new SDJwtInstance<SdJwtPayload>({
      signer,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    });
    const credential = await sdjwt_create.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: Math.floor(Date.now() / 1000),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );
    const sdjwt = new SDJwtInstance<SdJwtPayload>({});
    expect(sdjwt.keys('')).rejects.toThrow('Hasher not found');
    expect(sdjwt.presentableKeys('')).rejects.toThrow('Hasher not found');
    expect(sdjwt.getClaims('')).rejects.toThrow('Hasher not found');
    expect(() => sdjwt.decode('')).toThrowError('Hasher not found');
    expect(
      sdjwt.present<typeof claims>(credential, { foo: true }),
    ).rejects.toThrow('Hasher not found');
  });

  test('presentableKeys', async () => {
    const { signer } = createSignerVerifier();
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    });
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: Math.floor(Date.now() / 1000),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );
    const keys = await sdjwt.presentableKeys(credential);
    expect(keys).toBeDefined();
    expect(keys).toEqual(['foo']);
  });

  test('present all disclosures with kb jwt', async () => {
    const { signer } = createSignerVerifier();
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      kbSigner: signer,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
      kbSignAlg: 'EdDSA',
    });
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: Math.floor(Date.now() / 1000),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = await sdjwt.present<typeof claims>(
      credential,
      undefined,
      {
        kb: {
          payload: {
            aud: '1',
            iat: 1,
            nonce: '342',
          },
        },
      },
    );

    const decoded = await sdjwt.decode(presentation);
    expect(decoded.jwt).toBeDefined();
    expect(decoded.disclosures).toBeDefined();
    expect(decoded.kbJwt).toBeDefined();
  });

  (nodeVersionMajor < 20 ? test.skip : test)(
    'validate sd-jwt that created in other implemenation',
    async () => {
      const publicKeyExampleJwt: JsonWebKey = {
        kty: 'EC',
        crv: 'P-256',
        x: 'b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ',
        y: 'Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8',
      };
      const kbPubkey: JsonWebKey = {
        kty: 'EC',
        crv: 'P-256',
        x: 'TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc',
        y: 'ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ',
      };
      const encodedJwt =
        'eyJhbGciOiAiRVMyNTYiLCAidHlwIjogInZjK3NkLWp3dCIsICJraWQiOiAiZG9jLXNpZ25lci0wNS0yNS0yMDIyIn0.eyJfc2QiOiBbIjA5dktySk1PbHlUV00wc2pwdV9wZE9CVkJRMk0xeTNLaHBINTE1blhrcFkiLCAiMnJzakdiYUMwa3k4bVQwcEpyUGlvV1RxMF9kYXcxc1g3NnBvVWxnQ3diSSIsICJFa084ZGhXMGRIRUpidlVIbEVfVkNldUM5dVJFTE9pZUxaaGg3WGJVVHRBIiwgIklsRHpJS2VpWmREd3BxcEs2WmZieXBoRnZ6NUZnbldhLXNONndxUVhDaXciLCAiSnpZakg0c3ZsaUgwUjNQeUVNZmVadTZKdDY5dTVxZWhabzdGN0VQWWxTRSIsICJQb3JGYnBLdVZ1Nnh5bUphZ3ZrRnNGWEFiUm9jMkpHbEFVQTJCQTRvN2NJIiwgIlRHZjRvTGJnd2Q1SlFhSHlLVlFaVTlVZEdFMHc1cnREc3JaemZVYW9tTG8iLCAiamRyVEU4WWNiWTRFaWZ1Z2loaUFlX0JQZWt4SlFaSUNlaVVRd1k5UXF4SSIsICJqc3U5eVZ1bHdRUWxoRmxNXzNKbHpNYVNGemdsaFFHMERwZmF5UXdMVUs0Il0sICJpc3MiOiAiaHR0cHM6Ly9leGFtcGxlLmNvbS9pc3N1ZXIiLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2Y3QiOiAiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwgIl9zZF9hbGciOiAic2hhLTI1NiIsICJjbmYiOiB7Imp3ayI6IHsia3R5IjogIkVDIiwgImNydiI6ICJQLTI1NiIsICJ4IjogIlRDQUVSMTladnUzT0hGNGo0VzR2ZlNWb0hJUDFJTGlsRGxzN3ZDZUdlbWMiLCAieSI6ICJaeGppV1diWk1RR0hWV0tWUTRoYlNJaXJzVmZ1ZWNDRTZ0NGpUOUYySFpRIn19fQ.QXgzrePAdq_WZVGCwDxP-l8h0iyckrHBNidxVqGtKJ0LMzObqgaXUD1cgGEf7d9TexPkBcgQYqjuzlfbeCxxuA~WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0~WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ~WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd~eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImtiK2p3dCJ9.eyJub25jZSI6ICIxMjM0NTY3ODkwIiwgImF1ZCI6ICJodHRwczovL2V4YW1wbGUuY29tL3ZlcmlmaWVyIiwgImlhdCI6IDE3MDk5OTYxODUsICJzZF9oYXNoIjogIjc4cFFEazJOblNEM1dKQm5SN015aWpmeUVqcGJ5a01yRnlpb2ZYSjlsN0kifQ.7k4goAlxM4a3tHnvCBCe70j_I-BCwtzhBRXQNk9cWJnQWxxt2kIqCyzcwzzUc0gTwtbGWVQoeWCiL5K6y3a4VQ';

      const sdjwt = new SDJwtInstance({
        hasher: digest,
        verifier: await ES256.getVerifier(publicKeyExampleJwt),
        kbVerifier: await ES256.getVerifier(kbPubkey),
      });

      const decode = await sdjwt.verify(encodedJwt, undefined, true);
      expect(decode).toBeDefined();
    },
  );
});
