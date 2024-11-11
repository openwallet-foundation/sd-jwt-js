import { base64urlEncode, SDJWTException } from '@sd-jwt/utils';
import { splitSdJwt } from '@sd-jwt/decode';
import { SD_SEPARATOR, Signer } from '@sd-jwt/types';

export type GeneralJSONData = {
  payload: string;
  disclosures: Array<string>;
  kb_jwt?: string;
  signatures: Array<{
    protected: string;
    signature: string;
    kid?: string;
  }>;
};

export type GeneralJSONSerialized = {
  payload: string;
  signatures: Array<{
    headers: {
      disclosures?: Array<string>;
      kid?: string;
      kb_jwt?: string;
    };
    protected: string;
    signature: string;
  }>;
};

export class GeneralJSON {
  public payload: string;
  public disclosures: Array<string>;
  public kb_jwt?: string;
  public signatures: Array<{
    protected: string;
    signature: string;
    kid?: string;
  }>;

  constructor(data: GeneralJSONData) {
    this.payload = data.payload;
    this.disclosures = data.disclosures;
    this.kb_jwt = data.kb_jwt;
    this.signatures = data.signatures;
  }

  public static fromEncode(encodedSdJwt: string) {
    const { jwt, disclosures, kbJwt } = splitSdJwt(encodedSdJwt);

    const { 0: protectedHeader, 1: payload, 2: signature } = jwt.split('.');
    if (protectedHeader || payload || signature) {
      throw new SDJWTException('Invalid JWT');
    }

    return new GeneralJSON({
      payload,
      disclosures,
      kb_jwt: kbJwt,
      signatures: [
        {
          protected: protectedHeader,
          signature,
        },
      ],
    });
  }

  public static fromSerialized(json: GeneralJSONSerialized) {
    if (!json.signatures[0]) {
      throw new SDJWTException('Invalid JSON');
    }
    const disclosures = json.signatures[0].headers?.disclosures ?? [];
    const kb_jwt = json.signatures[0].headers?.kb_jwt;
    return new GeneralJSON({
      payload: json.payload,
      disclosures,
      kb_jwt,
      signatures: json.signatures.map((s) => {
        return {
          protected: s.protected,
          signature: s.signature,
          kid: s.headers?.kid,
        };
      }),
    });
  }

  public toJson() {
    return {
      payload: this.payload,
      signatures: this.signatures.map((s, i) => {
        if (i !== 0) {
          // If present, disclosures and kb_jwt, MUST be included in the first unprotected header and
          // MUST NOT be present in any following unprotected headers.
          return {
            headers: {
              kid: s.kid,
            },
            protected: s.protected,
            signature: s.signature,
          };
        }
        return {
          headers: {
            disclosures: this.disclosures,
            kid: s.kid,
            kb_jwt: this.kb_jwt,
          },
          protected: s.protected,
          signature: s.signature,
        };
      }),
    };
  }

  public toEncoded(index: number) {
    if (index < 0 || index >= this.signatures.length) {
      throw new SDJWTException('Index out of bounds');
    }

    const { protected: protectedHeader, signature } = this.signatures[index];
    const disclosures = this.disclosures.join(SD_SEPARATOR);
    const kb_jwt = this.kb_jwt ?? '';
    const jwt = `${protectedHeader}.${this.payload}.${signature}`;
    return [jwt, disclosures, kb_jwt].join(SD_SEPARATOR);
  }

  public async addSignature(
    protectedHeader: Record<string, unknown>,
    signer: Signer,
    kid?: string,
  ) {
    const header = base64urlEncode(JSON.stringify(protectedHeader));
    const signature = await signer(`${header}.${this.payload}`);
    this.signatures.push({
      protected: header,
      signature,
      kid,
    });
  }
}
