import { SDJWTException } from '@sd-jwt/utils';
import { splitSdJwt } from '@sd-jwt/decode';
import { SD_SEPARATOR } from '@sd-jwt/types';

export type FlattenJSONData = {
  jwtData: {
    protected: string;
    payload: string;
    signature: string;
  };
  disclosures: Array<string>;
  kb_jwt?: string;
};

export type FlattenJSONSerialized = {
  payload: string;
  signature: string;
  protected: string;
  header: {
    disclosures: Array<string>;
    kb_jwt?: string;
  };
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

  public static fromSerialized(json: FlattenJSONSerialized) {
    return new FlattenJSON({
      jwtData: {
        protected: json.protected,
        payload: json.payload,
        signature: json.signature,
      },
      disclosures: json.header.disclosures,
      kb_jwt: json.header.kb_jwt,
    });
  }

  public toJson(): FlattenJSONSerialized {
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

  public toEncoded() {
    const jwt = `${this.protected}.${this.payload}.${this.signature}`;
    const disclosures = this.disclosures.join(SD_SEPARATOR);
    const kb_jwt = this.kb_jwt ?? '';
    return [jwt, disclosures, kb_jwt].join(SD_SEPARATOR);
  }
}
