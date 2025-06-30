import { SDJWTException } from '@sd-jwt/utils';
import { Jwt } from './jwt';
import {
  type JwtPayload,
  KB_JWT_TYP,
  type kbHeader,
  type kbPayload,
  type KbVerifier,
} from '@sd-jwt/types';

export class KBJwt<
  Header extends kbHeader = kbHeader,
  Payload extends kbPayload = kbPayload,
> extends Jwt<Header, Payload> {
  // Checking the validity of the key binding jwt
  // the type unknown is not good, but we don't know at this point how to get the public key of the signer, this is defined in the kbVerifier
  public async verifyKB(values: { verifier: KbVerifier; payload: JwtPayload, nonce: string }) {
    if (!this.header || !this.payload || !this.signature) {
      throw new SDJWTException('Verify Error: Invalid JWT');
    }

    if (
      !this.header.alg ||
      this.header.alg === 'none' ||
      !this.header.typ ||
      this.header.typ !== KB_JWT_TYP ||
      !this.payload.iat ||
      !this.payload.aud ||
      !this.payload.nonce ||
      // this is for backward compatibility with version 06
      !(
        this.payload.sd_hash ||
        (this.payload as Record<string, unknown> | undefined)?._sd_hash
      )
    ) {
      throw new SDJWTException('Invalid Key Binding Jwt');
    }

    const data = this.getUnsignedToken();
    const verified = await values.verifier(
      data,
      this.signature,
      values.payload,
    );
    if (!verified) {
      throw new SDJWTException('Verify Error: Invalid JWT Signature');
    }
    if(this.payload.nonce !== values.nonce) {
      throw new SDJWTException('Verify Error: Invalid Nonce');
    }

    return { payload: this.payload, header: this.header };
  }

  // This function is for creating KBJwt object for verify properly
  public static fromKBEncode<
    Header extends kbHeader = kbHeader,
    Payload extends kbPayload = kbPayload,
  >(encodedJwt: string): KBJwt<Header, Payload> {
    const { header, payload, signature } = Jwt.decodeJWT<Header, Payload>(
      encodedJwt,
    );

    const jwt = new KBJwt<Header, Payload>({
      header,
      payload,
      signature,
      encoded: encodedJwt,
    });

    return jwt;
  }
}
