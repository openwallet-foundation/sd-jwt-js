import { SDJWTException } from '@sd-jwt/utils';
import { splitSdJwt } from '@sd-jwt/decode';

export type FlattenJSONData = {
  jwtData: {
    protected: string;
    payload: string;
    signature: string;
  };
  disclosures: Array<string>;
  kb_jwt?: string;
};

export class FlattenJSON {
  public disclosures: Array<string>;
  public kb_jwt?: string;

  public payload: string;
  public signature: string;
  public protected: string;

  constructor(data: FlattenJSONData) {
    this.disclosures = data.disclosures;
    this.kb_jwt = data.kb_jwt;
    this.payload = data.jwtData.payload;
    this.signature = data.jwtData.signature;
    this.protected = data.jwtData.protected;
  }

  public static fromEncode(encodedSdJwt: string) {
    const { jwt, disclosures, kbJwt } = splitSdJwt(encodedSdJwt);

    const { 0: protectedHeader, 1: payload, 2: signature } = jwt.split('.');
    if (protectedHeader || payload || signature) {
      throw new SDJWTException('Invalid JWT');
    }

    return new FlattenJSON({
      jwtData: {
        protected: protectedHeader,
        payload,
        signature,
      },
      disclosures,
      kb_jwt: kbJwt,
    });
  }

  public toJson() {
    return {
      payload: this.payload,
      signature: this.signature,
      protected: this.protected,
      header: {
        disclosures: this.disclosures,
        kb_jwt: this.kb_jwt,
      },
    };
  }
}
