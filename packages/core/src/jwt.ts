import { base64urlEncode, SDJWTException } from '@sd-jwt/utils';
import type { Base64urlString, Signer, Verifier } from '@sd-jwt/types';
import { decodeJwt } from '@sd-jwt/decode';

export type JwtData<
  Header extends Record<string, unknown>,
  Payload extends Record<string, unknown>,
> = {
  header?: Header;
  payload?: Payload;
  signature?: Base64urlString;
  encoded?: string;
};

/**
 * Options for the JWT verifier
 */
export type VerifierOptions = {
  /**
   * current time in seconds since epoch
   */
  currentDate?: number;

  /**
   * allowed skew for the current time in seconds. Positive value that will lower the iat and nbf checks, and increase the exp check.
   */
  skewSeconds?: number;

  /**
   * required claim keys for the payload.
   * If the payload does not contain these keys, the verification will fail.
   */
  requiredClaimKeys?: string[],

  /**
   * nonce used to verify the key binding jwt to prevent replay attacks.
   */
  keyBindingNonce?: string,
};

// This class is used to create and verify JWT
// Contains header, payload, and signature
export class Jwt<
  Header extends Record<string, unknown> = Record<string, unknown>,
  Payload extends Record<string, unknown> = Record<string, unknown>,
> {
  public header?: Header;
  public payload?: Payload;
  public signature?: Base64urlString;
  private encoded?: string;

  constructor(data?: JwtData<Header, Payload>) {
    this.header = data?.header;
    this.payload = data?.payload;
    this.signature = data?.signature;
    this.encoded = data?.encoded;
  }

  public static decodeJWT<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
  >(
    jwt: string,
  ): { header: Header; payload: Payload; signature: Base64urlString } {
    return decodeJwt(jwt);
  }

  public static fromEncode<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
  >(encodedJwt: string): Jwt<Header, Payload> {
    const { header, payload, signature } = Jwt.decodeJWT<Header, Payload>(
      encodedJwt,
    );

    const jwt = new Jwt<Header, Payload>({
      header,
      payload,
      signature,
      encoded: encodedJwt,
    });

    return jwt;
  }

  public setHeader(header: Header): Jwt<Header, Payload> {
    this.header = header;
    this.encoded = undefined;
    return this;
  }

  public setPayload(payload: Payload): Jwt<Header, Payload> {
    this.payload = payload;
    this.encoded = undefined;
    return this;
  }

  protected getUnsignedToken() {
    if (!this.header || !this.payload) {
      throw new SDJWTException('Serialize Error: Invalid JWT');
    }

    if (this.encoded) {
      const parts = this.encoded.split('.');
      if (parts.length !== 3) {
        throw new SDJWTException(`Invalid JWT format: ${this.encoded}`);
      }
      const unsignedToken = parts.slice(0, 2).join('.');
      return unsignedToken;
    }

    const header = base64urlEncode(JSON.stringify(this.header));
    const payload = base64urlEncode(JSON.stringify(this.payload));
    return `${header}.${payload}`;
  }

  public async sign(signer: Signer) {
    const data = this.getUnsignedToken();
    this.signature = await signer(data);

    return this.encodeJwt();
  }

  public encodeJwt(): string {
    if (this.encoded) {
      return this.encoded;
    }

    if (!this.header || !this.payload || !this.signature) {
      throw new SDJWTException('Serialize Error: Invalid JWT');
    }

    const header = base64urlEncode(JSON.stringify(this.header));
    const payload = base64urlEncode(JSON.stringify(this.payload));
    const signature = this.signature;
    const compact = `${header}.${payload}.${signature}`;
    this.encoded = compact;

    return compact;
  }

  /**
   * Verify the JWT using the provided verifier function.
   * It checks the signature and validates the iat, nbf, and exp claims if they are present.
   * @param verifier
   * @param options - Options for verification, such as current date and skew seconds
   * @returns
   */
  public async verify(verifier: Verifier, options?: VerifierOptions) {
    const skew = options?.skewSeconds ? options.skewSeconds : 0;
    const currentDate = options?.currentDate ?? Math.floor(Date.now() / 1000);
    if (
      this.payload?.iat &&
      (this.payload.iat as number) - skew > currentDate
    ) {
      throw new SDJWTException('Verify Error: JWT is not yet valid');
    }

    if (
      this.payload?.nbf &&
      (this.payload.nbf as number) - skew > currentDate
    ) {
      throw new SDJWTException('Verify Error: JWT is not yet valid');
    }
    if (
      this.payload?.exp &&
      (this.payload.exp as number) + skew < currentDate
    ) {
      throw new SDJWTException('Verify Error: JWT is expired');
    }

    if (!this.signature) {
      throw new SDJWTException('Verify Error: no signature in JWT');
    }
    const data = this.getUnsignedToken();

    const verified = await verifier(data, this.signature);
    if (!verified) {
      throw new SDJWTException('Verify Error: Invalid JWT Signature');
    }
    return { payload: this.payload, header: this.header };
  }
}
