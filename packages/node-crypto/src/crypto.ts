import { createHash, randomBytes, subtle } from 'node:crypto';

export const generateSalt = (length: number): string => {
  if (length <= 0) {
    return '';
  }
  const saltBytes = randomBytes(length);
  const salt = saltBytes.toString('hex');
  return salt.substring(0, length);
};

export const digest = (
  data: string | ArrayBuffer,
  algorithm = 'sha-256',
): Uint8Array => {
  const nodeAlg = toNodeCryptoAlg(algorithm);
  const hash = createHash(nodeAlg);
  if (typeof data === 'string') {
    hash.update(data);
  } else {
    hash.update(Buffer.from(data));
  }
  const hashBuffer = hash.digest();
  return new Uint8Array(hashBuffer);
};

const toNodeCryptoAlg = (hashAlg: string): string =>
  hashAlg.replace('-', '').toLowerCase();

export const ES256 = {
  alg: 'ES256',

  async generateKeyPair() {
    const keyPair = await subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256', // ES256
      },
      true, // whether the key is extractable (i.e., can be used in exportKey)
      ['sign', 'verify'], // can be used to sign and verify signatures
    );

    // Export the public and private keys in JWK format
    const publicKeyJWK = await subtle.exportKey('jwk', keyPair.publicKey);
    const privateKeyJWK = await subtle.exportKey('jwk', keyPair.privateKey);

    return { publicKey: publicKeyJWK, privateKey: privateKeyJWK };
  },

  async getSigner(privateKeyJWK: object) {
    const privateKey = await subtle.importKey(
      'jwk',
      privateKeyJWK,
      {
        name: 'ECDSA',
        namedCurve: 'P-256', // Must match the curve used to generate the key
      },
      true, // whether the key is extractable (i.e., can be used in exportKey)
      ['sign'],
    );

    return async (data: string) => {
      const encoder = new TextEncoder();
      const signature = await subtle.sign(
        {
          name: 'ECDSA',
          hash: { name: 'sha-256' }, // Required for ES256
        },
        privateKey,
        encoder.encode(data),
      );

      return btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, ''); // Convert to base64url format
    };
  },

  async getVerifier(publicKeyJWK: object) {
    const publicKey = await subtle.importKey(
      'jwk',
      publicKeyJWK,
      {
        name: 'ECDSA',
        namedCurve: 'P-256', // Must match the curve used to generate the key
      },
      true, // whether the key is extractable (i.e., can be used in exportKey)
      ['verify'],
    );

    return async (data: string, signatureBase64url: string) => {
      const encoder = new TextEncoder();
      const signature = Uint8Array.from(
        atob(signatureBase64url.replace(/-/g, '+').replace(/_/g, '/')),
        (c) => c.charCodeAt(0),
      );
      const isValid = await subtle.verify(
        {
          name: 'ECDSA',
          hash: { name: 'sha-256' }, // Required for ES256
        },
        publicKey,
        signature,
        encoder.encode(data),
      );

      return isValid;
    };
  },
};
