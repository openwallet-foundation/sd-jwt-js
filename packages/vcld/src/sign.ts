import { decodeSdJwtSync, getClaimsSync } from '@sd-jwt/decode';
import { hasher } from '@sd-jwt/hash';
import { JsonLdDocument } from 'jsonld';
import { SDJwtInstance } from '@sd-jwt/core';
import { createSign } from 'node:crypto';
import type { DisclosureFrame } from '@sd-jwt/types';
import { type KeyObject } from 'node:crypto';
import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { ALGORITHMS, type Alg } from './type';

export class Signer {
  private doc: JsonLdDocument;
  private signAlg: Alg;
  // TODO: fix type
  private disclosureFrame: DisclosureFrame<any> | undefined;
  private header: Record<string, unknown> | undefined;

  private vct: string;
  private iss: string | undefined;
  private exp: number | undefined;
  private nbf: number | undefined;

  constructor(doc: JsonLdDocument, vct: string) {
    this.doc = doc;
    this.signAlg = 'ES256';
    this.vct = vct;
  }

  setSignAlg(signAlg: Alg) {
    this.signAlg = signAlg;
    return this;
  }

  setDisclosureFrame(disclosureFrame: DisclosureFrame<any>) {
    this.disclosureFrame = disclosureFrame;
    return this;
  }

  setHeader(header: Record<string, unknown>) {
    this.header = header;
    return this;
  }

  setIss(iss: string) {
    this.iss = iss;
    return this;
  }

  setExp(exp: number) {
    this.exp = exp;
    return this;
  }

  setNbf(nbf: number) {
    this.nbf = nbf;
    return this;
  }

  async sign(key: KeyObject) {
    if (!this.iss) throw new Error('iss must be set when signing');
    if (!this.exp) throw new Error('exp must be set when signing');
    if (!this.nbf) throw new Error('nbf must be set when signing');
    if (!this.signAlg) throw new Error('alg must be set when signing');

    const sdjwtInstance = new SDJwtInstance({
      hashAlg: 'sha-256',
      signAlg: this.signAlg,
      hasher: digest,
      saltGenerator: generateSalt,
      signer: (data: string) => {
        return JWTSigner.sign(this.signAlg, data, key);
      },
    });

    const payload = {
      vct: this.vct,
      iss: this.iss,
      exp: this.exp,
      nbf: this.nbf,
      ld: this.doc,
    };
    const disclosureFrame = { ld: this.disclosureFrame };

    // TODO: fix type
    const compact = await sdjwtInstance.issue(payload, disclosureFrame as any, {
      header: this.header,
    });

    return compact;
  }
}

export const decode = (compact: string) => {
  const decodedSdJwt = decodeSdJwtSync(compact, hasher);
  const claims = getClaimsSync(
    decodedSdJwt.jwt.payload,
    decodedSdJwt.disclosures,
    hasher,
  ) as Record<string, unknown>;

  if ('ld' in claims) {
    return { claims, ld: claims['ld'] };
  }

  return { claims };
};

const JWTSigner = {
  sign(alg: Alg, signingInput: string, privateKey: KeyObject) {
    const signature = JWTSigner.createSignature(alg, signingInput, privateKey);
    return signature;
  },

  createSignature(alg: Alg, signingInput: string, privateKey: KeyObject) {
    switch (alg) {
      case 'RS256':
      case 'RS384':
      case 'RS512':
      case 'PS256':
      case 'PS384':
      case 'PS512': {
        const option = ALGORITHMS[alg];
        return JWTSigner.createRSASignature(signingInput, privateKey, option);
      }
      case 'ES256':
      case 'ES384':
      case 'ES512': {
        const option = ALGORITHMS[alg];
        return JWTSigner.createECDSASignature(signingInput, privateKey, option);
      }
      case 'EdDSA': {
        const option = ALGORITHMS[alg];
        return JWTSigner.createEdDSASignature(signingInput, privateKey, option);
      }
      default:
    }
    throw new Error(`Unsupported algorithm: ${alg}`);
  },

  createRSASignature(
    signingInput: string,
    privateKey: KeyObject,
    options: { hash: string; padding: number },
  ) {
    const signer = createSign(options.hash);
    signer.update(signingInput);
    const signature = signer.sign({
      key: privateKey,
      padding: options.padding,
    });
    return signature.toString('base64url');
  },

  createECDSASignature(
    signingInput: string,
    privateKey: KeyObject,
    options: { hash: string; namedCurve: string },
  ) {
    const signer = createSign(options.hash);
    signer.update(signingInput);

    const signature = signer.sign({
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    });

    return signature.toString('base64url');
  },

  createEdDSASignature(
    signingInput: string,
    privateKey: KeyObject,
    options: { curves: string[] },
  ) {
    const signer = createSign(options.curves[0]);
    signer.update(signingInput);
    const signature = signer.sign({
      key: privateKey,
    });
    return signature.toString('base64url');
  },
};
