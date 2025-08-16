import type { DisclosureFrame } from '@sd-jwt/types';
import {
  type KeyObject,
  type X509Certificate,
  createHash,
  createSign,
} from 'node:crypto';
import { base64urlEncode } from '@sd-jwt/utils';
import { ALGORITHMS } from './constant';
import { GeneralJSON, SDJwtGeneralJSONInstance } from '@sd-jwt/core';
import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import type {
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

  async addSignature(signature: string, kid: string) {
    const encodedProtectedHeader = this.encodedProtectedHeader(kid);

    if (this.serialized === undefined) {
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
    } else {
      this.serialized.signatures.push({
        protected: encodedProtectedHeader,
        signature,
        header: this.header,
      });
    }

    return this;
  }

  private encodedProtectedHeader(kid: string): string {
    return base64urlEncode(JSON.stringify({ ...this.protectedHeader, kid }));
  }

  public getSignPayload(kid: string): string {
    const encodedProtectedHeader = this.encodedProtectedHeader(kid);

    const encodedPayload =
      this.payload === undefined
        ? ''
        : base64urlEncode(JSON.stringify(this.payload));

    const protectedData = `${encodedProtectedHeader}.${encodedPayload}`;
    return protectedData;
  }

  async getHash(alg: Alg, kid: string): Promise<Uint8Array> {
    const hashAlg = ALGORITHMS[alg].hash as string;

    const signPayload = this.getSignPayload(kid);
    return digest(signPayload, hashAlg);
  }

  setProtectedHeader(header: ProtectedHeader) {
    if (!header.alg || (header.alg as Alg | 'none') === 'none') {
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
