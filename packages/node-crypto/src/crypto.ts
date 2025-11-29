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

// All derived from the subtle functions being called below
type GenerateKeyAlgorithm = RsaHashedKeyGenParams | EcKeyGenParams;
type ImportKeyAlgorithm =
  | AlgorithmIdentifier
  | RsaHashedImportParams
  | EcKeyImportParams
  | HmacImportParams
  | AesKeyAlgorithm;
type SignAlgorithm = AlgorithmIdentifier | RsaPssParams | EcdsaParams;
type VerifyAlgorithm = AlgorithmIdentifier | RsaPssParams | EcdsaParams;

export async function generateKeyPair(keyAlgorithm: GenerateKeyAlgorithm) {
  const keyPair = await subtle.generateKey(
    keyAlgorithm,
    true, // whether the key is extractable (i.e., can be used in exportKey)
    ['sign', 'verify'], // can be used to sign and verify signatures
  );

  // Export the public and private keys in JWK format
  const publicKeyJWK = await subtle.exportKey('jwk', keyPair.publicKey);
  const privateKeyJWK = await subtle.exportKey('jwk', keyPair.privateKey);

  return { publicKey: publicKeyJWK, privateKey: privateKeyJWK };
}

export async function getSigner(
  privateKeyJWK: object,
  keyAlgorithm: ImportKeyAlgorithm,
  signAlgorithm: SignAlgorithm,
) {
  const privateKey = await subtle.importKey(
    'jwk',
    privateKeyJWK,
    keyAlgorithm,
    true, // whether the key is extractable (i.e., can be used in exportKey)
    ['sign'],
  );

  return async (data: string) => {
    const encoder = new TextEncoder();
    const signature = await subtle.sign(
      signAlgorithm,
      privateKey,
      encoder.encode(data),
    );

    return btoa(String.fromCharCode(...new Uint8Array(signature)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, ''); // Convert to base64url format
  };
}

export async function getVerifier(
  publicKeyJWK: object,
  keyAlgorithm: ImportKeyAlgorithm,
  verifyAlgorithm: VerifyAlgorithm,
) {
  const publicKey = await subtle.importKey(
    'jwk',
    publicKeyJWK,
    keyAlgorithm,
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
      verifyAlgorithm,
      publicKey,
      signature,
      encoder.encode(data),
    );

    return isValid;
  };
}

export const ES256 = {
  alg: 'ES256',

  _keyAlgorithm: {
    name: 'ECDSA',
    namedCurve: 'P-256',
  },

  _hashAlgorithm: {
    name: 'ECDSA',
    hash: { name: 'sha-256' },
  },

  async generateKeyPair() {
    return await generateKeyPair(ES256._keyAlgorithm);
  },

  async getSigner(privateKeyJWK: object) {
    return await getSigner(
      privateKeyJWK,
      ES256._keyAlgorithm,
      ES256._hashAlgorithm,
    );
  },

  async getVerifier(publicKeyJWK: object) {
    return await getVerifier(
      publicKeyJWK,
      ES256._keyAlgorithm,
      ES256._hashAlgorithm,
    );
  },
};

export const ES384 = {
  alg: 'ES384',

  _keyAlgorithm: {
    name: 'ECDSA',
    namedCurve: 'P-384',
  },

  _hashAlgorithm: {
    name: 'ECDSA',
    hash: { name: 'sha-384' },
  },

  async generateKeyPair() {
    return await generateKeyPair(ES384._keyAlgorithm);
  },

  async getSigner(privateKeyJWK: object) {
    return await getSigner(
      privateKeyJWK,
      ES384._keyAlgorithm,
      ES384._hashAlgorithm,
    );
  },

  async getVerifier(publicKeyJWK: object) {
    return await getVerifier(
      publicKeyJWK,
      ES384._keyAlgorithm,
      ES384._hashAlgorithm,
    );
  },
};

export const ES512 = {
  alg: 'ES512',

  _keyAlgorithm: {
    name: 'ECDSA',
    namedCurve: 'P-521',
  },

  _hashAlgorithm: {
    name: 'ECDSA',
    hash: { name: 'sha-512' },
  },

  async generateKeyPair() {
    return await generateKeyPair(ES512._keyAlgorithm);
  },

  async getSigner(privateKeyJWK: object) {
    return await getSigner(
      privateKeyJWK,
      ES512._keyAlgorithm,
      ES512._hashAlgorithm,
    );
  },

  async getVerifier(publicKeyJWK: object) {
    return await getVerifier(
      publicKeyJWK,
      ES512._keyAlgorithm,
      ES512._hashAlgorithm,
    );
  },
};
