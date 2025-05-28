import { DisclosureFrame } from '@sd-jwt/types';
import { KeyObject, X509Certificate, createHash, createSign } from 'crypto';
import { base64urlEncode } from '@sd-jwt/utils';
import { ALGORITHMS } from './constant';
import { GeneralJSON, SDJwtGeneralJSONInstance } from '@sd-jwt/core';
import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import {
  Alg,
  CommitmentOption,
  GeneralJWS,
  ProtectedHeader,
  SigD,
  UnprotectedHeader,
} from './type';

export class Sign<T extends Record<string, unknown>> {
  private serialized?: GeneralJWS;

  private protectedHeader: Partial<ProtectedHeader>;

  // TODO: implement
  // unprotected header
  private header: UnprotectedHeader;

  private disclosureFrame: DisclosureFrame<T> | undefined;

  /**
   * If payload is empty, the data of payload will be empty string.
   * This is the Detached JWS Payload described in TS 119 182-1 v1.2.1 section 5.2.8
   * The sigD header must be present when the payload is empty.
   */
  constructor(private readonly payload?: T) {
    this.protectedHeader = {};
    this.header = {};
  }

  private async appendSignature(key: KeyObject, kid: string) {
    if (this.serialized === undefined) {
      throw new Error('Signature must be appended to serialized');
    }

    if (
      !this.protectedHeader.alg ||
      (this.protectedHeader.alg as any) === 'none'
    ) {
      throw new Error('alg must be set and not "none"');
    }

    if (this.payload === undefined) {
      const encodedProtectedHeader = base64urlEncode(
        JSON.stringify({ ...this.protectedHeader, kid }),
      );
      const encodedPayload = '';
      const protectedData = `${encodedProtectedHeader}.${encodedPayload}`;

      const signature = JWTSigner.sign(
        this.protectedHeader.alg,
        protectedData,
        key,
      );
      this.serialized.signatures.push({
        protected: protectedData,
        signature,
        header: this.header,
      });
      return this;
    }

    const generalJSON = GeneralJSON.fromSerialized(this.serialized);
    const signer = (data: string) => {
      if (!this.protectedHeader.alg)
        throw new Error('alg must be set when signing');
      return JWTSigner.sign(this.protectedHeader.alg, data, key);
    };
    await generalJSON.addSignature({ ...this.protectedHeader, kid }, signer);
    const serialized = generalJSON.toJson();
    this.serialized = serialized;
    return this;
  }

  private async createSignature(key: KeyObject, kid: string) {
    if (
      !this.protectedHeader.alg ||
      (this.protectedHeader.alg as any) === 'none'
    ) {
      throw new Error('alg must be set and not "none"');
    }

    if (this.payload === undefined) {
      /**
       * If the payload is empty, It uses Detached JWS Payload described in TS 119 182-1 v1.2.1 section 5.2.8
       * So Create manual signature here.
       */

      const encodedProtectedHeader = base64urlEncode(
        JSON.stringify({ ...this.protectedHeader, kid }),
      );
      const encodedPayload = '';
      const protectedData = `${encodedProtectedHeader}.${encodedPayload}`;

      const signature = JWTSigner.sign(
        this.protectedHeader.alg,
        protectedData,
        key,
      );

      this.serialized = {
        payload: '',
        signatures: [
          {
            protected: encodedProtectedHeader,
            signature,
            header: this.header,
          },
        ],
      };
      return this;
    }

    /**
     * Create a General JWS Payload with SD-JWT library.
     */

    const sdjwtInstance = new SDJwtGeneralJSONInstance({
      hashAlg: 'sha-256',
      signAlg: this.protectedHeader.alg,
      hasher: digest,
      saltGenerator: generateSalt,
    });

    const disclosureFrame = this.disclosureFrame;

    const generalJSON = await sdjwtInstance.issue(
      this.payload,
      disclosureFrame,
      {
        sigs: [
          {
            alg: this.protectedHeader.alg,
            kid: kid,
            header: this.protectedHeader,
            signer: (data: string) => {
              if (!this.protectedHeader.alg)
                throw new Error('alg must be set when signing');
              return JWTSigner.sign(this.protectedHeader.alg, data, key);
            },
          },
        ],
      },
    );

    const serialized = generalJSON.toJson();
    this.serialized = {
      payload: serialized.payload,
      signatures: serialized.signatures.map((sig) => ({
        ...sig,
        header: {
          ...sig.header,
          ...this.header,
        },
      })),
    };

    return this;
  }

  async sign(key: KeyObject, kid: string) {
    if (
      !this.protectedHeader.alg ||
      (this.protectedHeader.alg as any) === 'none'
    ) {
      throw new Error('alg must be set and not "none"');
    }

    this.validateCertificateHeaders();

    if (this.serialized !== undefined) {
      return this.appendSignature(key, kid);
    }

    return this.createSignature(key, kid);
  }

  setProtectedHeader(header: ProtectedHeader) {
    if (!header.alg || (header.alg as any) === 'none') {
      throw new Error('alg must be set and not "none"');
    }
    this.protectedHeader = header;
    return this;
  }

  setDisclosureFrame(frame: DisclosureFrame<T>) {
    this.disclosureFrame = frame;
    return this;
  }

  setB64(b64: boolean) {
    if (b64) {
      this.protectedHeader.b64 = undefined;
    } else {
      this.protectedHeader.b64 = false;
    }
    return this;
  }

  setIssuedAt(sec?: number) {
    this.protectedHeader.iat = sec ?? Math.floor(Date.now() / 1000);
    return this;
  }

  setSignedAt(sec?: number) {
    this.protectedHeader.signedAt = sec ?? Math.floor(Date.now() / 1000);
    return this;
  }

  setSigD(sigd: SigD) {
    this.protectedHeader.sigD = sigd;
    /**
     * TS 119 182-1 v1.2.1 section 5.1.10
     * 
     * If the sigD header parameter is present with its member set to
      "http://uri.etsi.org/19182/HttpHeaders" then the b64 header parameter shall be present and set to
      "false".
     */
    if (sigd.mId === 'http://uri.etsi.org/19182/HttpHeaders') {
      this.setB64(false);
    }
    return this;
  }

  setJti(jti: string) {
    this.protectedHeader.jti = jti;
    return this;
  }

  setX5u(uri: string) {
    this.protectedHeader.x5u = uri;
    return this;
  }

  setX5c(certs: X509Certificate[]) {
    this.protectedHeader.x5c = certs.map((cert) => cert.raw.toString('base64'));
    return this;
  }

  setX5tS256(cert: X509Certificate) {
    this.protectedHeader['x5t#256'] = createHash('sha-256')
      .update(new Uint8Array(cert.raw))
      .digest('base64url');
    return this;
  }

  setX5tSo(cert: X509Certificate) {
    this.protectedHeader['x5t#o'] = {
      digAlg: 'sha-512',
      digVal: createHash('sha-512')
        .update(new Uint8Array(cert.raw))
        .digest('base64url'),
    };
    return this;
  }

  setX5ts(certs: X509Certificate[]) {
    if (certs.length < 2) {
      throw new Error(
        'at least 2 certificates are required, use setX5tSo instead',
      );
    }
    this.protectedHeader['x5t#s'] = certs.map((cert) => ({
      digAlg: 'sha-512',
      digVal: createHash('sha-512')
        .update(new Uint8Array(cert.raw))
        .digest('base64url'),
    }));
    return this;
  }

  setCty(cty: string) {
    this.protectedHeader.cty = cty;
    return this;
  }

  setCommitment(option: CommitmentOption) {
    this.protectedHeader.srCms = option;
    return this;
  }

  setUnprotectedHeader(header: UnprotectedHeader) {
    this.header = header;
    return this;
  }

  private validateCertificateHeaders() {
    const hasCertHeader = !!(
      this.protectedHeader['x5t#S256'] ||
      this.protectedHeader.x5c ||
      this.protectedHeader['x5t#o'] ||
      this.protectedHeader.sigX5ts
    );
    if (!hasCertHeader) {
      throw new Error(
        'JAdES signature requires at least one certificate header',
      );
    }
  }

  toJSON() {
    if (!this.serialized) {
      throw new Error('Not signed yet');
    }
    return this.serialized;
  }
}

class JWTSigner {
  static sign(alg: Alg, signingInput: string, privateKey: KeyObject) {
    const signature = this.createSignature(alg, signingInput, privateKey);
    return signature;
  }

  static createSignature(
    alg: Alg,
    signingInput: string,
    privateKey: KeyObject,
  ) {
    switch (alg) {
      case 'RS256':
      case 'RS384':
      case 'RS512':
      case 'PS256':
      case 'PS384':
      case 'PS512': {
        const option = ALGORITHMS[alg];
        return this.createRSASignature(signingInput, privateKey, option);
      }
      case 'ES256':
      case 'ES384':
      case 'ES512': {
        const option = ALGORITHMS[alg];
        return this.createECDSASignature(signingInput, privateKey, option);
      }
      case 'EdDSA': {
        const option = ALGORITHMS[alg];
        return this.createEdDSASignature(signingInput, privateKey, option);
      }
      default:
    }
    throw new Error(`Unsupported algorithm: ${alg}`);
  }

  static createRSASignature(
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
  }

  static createECDSASignature(
    signingInput: string,
    privateKey: KeyObject,
    options: { hash: string; namedCurve: string },
  ) {
    const signer = createSign(options.hash);
    signer.update(signingInput);

    let signature = signer.sign({
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    });

    return signature.toString('base64url');
  }

  static createEdDSASignature(
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
  }
}
