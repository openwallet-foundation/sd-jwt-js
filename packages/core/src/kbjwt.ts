import { Jwt, type VerifierOptions } from './jwt';
import {
  KB_JWT_TYP,
  type KbVerifier,
  type kbHeader,
  type kbPayload,
} from './types';
import { SDJWTException } from './utils';

export class KBJwt<
  Header extends kbHeader = kbHeader,
  Payload extends kbPayload = kbPayload,
> extends Jwt<Header, Payload> {
  // Checking the validity of the key binding jwt
  // the type unknown is not good, but we don't know at this point how to get the public key of the signer, this is defined in the kbVerifier
  public async verifyKB(values: {
    verifier: KbVerifier;
    payload: Record<string, unknown>;
    nonce: string;
    /**
     * Options forwarded to the common JWT verification, e.g. currentDate and
     * skewSeconds used to validate the iat, nbf and exp claims.
     */
    options?: VerifierOptions;
  }) {
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
        ('_sd_hash' in this.payload && this.payload._sd_hash)
      )
    ) {
      throw new SDJWTException('Invalid Key Binding Jwt');
    }

    if (this.payload.nonce !== values.nonce) {
      throw new SDJWTException('Verify Error: Invalid Nonce');
    }

    // Delegate signature verification and common JWT claim validation
    // (iat, nbf, exp) to the shared Jwt.verify implementation. The kbVerifier
    // needs the kb+jwt payload (e.g. the holder's cnf key) which the base
    // verifier receives via the options argument.
    await this.verify(
      (data, sig) => values.verifier(data, sig, values.payload),
      values.options,
    );

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
