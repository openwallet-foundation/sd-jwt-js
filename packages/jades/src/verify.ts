import { createVerify, X509Certificate } from 'crypto';
import { GeneralJWS } from './type';
import { SDJwtGeneralJSONInstance } from '@sd-jwt/core';
import { digest } from '@sd-jwt/crypto-nodejs';
import { getGeneralJSONFromJWSToken } from './utils';

export class JWTVerifier {
  static async verify(
    credential: GeneralJWS | string,
    requiredClaimKeys?: string[],
  ) {
    const instance = new SDJwtGeneralJSONInstance({
      hasher: digest,
      verifier: JWTVerifier.verifier,
    });

    const generalJsonCredential = getGeneralJSONFromJWSToken(credential);

    const verifiedData = await instance.verify(
      generalJsonCredential,
      requiredClaimKeys,
    );
    return verifiedData;
  }

  static verifier(data: string, signatureB64: string): boolean {
    try {
      const [headerB64, payloadB64] = data.split('.');

      const headerStr = Buffer.from(headerB64, 'base64url').toString('utf-8');
      const header = JSON.parse(headerStr);

      if (!header.x5c || !Array.isArray(header.x5c)) {
        throw new Error('x5c certificate chain is missing in header');
      }

      const isValid = JWTVerifier.verifySig(
        data,
        signatureB64,
        header.x5c,
        header.alg,
      );

      return isValid;
    } catch (error) {
      console.error('JWT token verification error:', error);
      return false;
    }
  }

  private static getVerifyAlgorithm(jwtAlg: string): string {
    const algorithmMap: Record<string, string> = {
      RS256: 'SHA256',
      RS384: 'SHA384',
      RS512: 'SHA512',
      ES256: 'SHA256',
      ES384: 'SHA384',
      ES512: 'SHA512',
      PS256: 'SHA256',
      PS384: 'SHA384',
      PS512: 'SHA512',
    };

    const algorithm = algorithmMap[jwtAlg];
    if (!algorithm) {
      throw new Error(`Unsupported JWT algorithm: ${jwtAlg}`);
    }

    return algorithm;
  }

  static verifySig(
    data: string,
    sig: string,
    x5c: string[],
    algorithm: string,
  ): boolean {
    try {
      if (!x5c || x5c.length === 0) {
        console.error('x5c certificate chain is missing');
        return false;
      }

      const certDer = Buffer.from(x5c[0], 'base64');
      const cert = new X509Certificate(new Uint8Array(certDer));
      const publicKey = cert.publicKey;

      const signatureBytes = Buffer.from(sig, 'base64url');
      const signatureUint8Array = new Uint8Array(signatureBytes);

      const cryptoAlgorithm = this.getVerifyAlgorithm(algorithm);

      const verifier = createVerify(cryptoAlgorithm);
      verifier.update(data);

      return verifier.verify(publicKey, signatureUint8Array);
    } catch (error) {
      console.error('JWT verification error:', error);
      return false;
    }
  }
}
