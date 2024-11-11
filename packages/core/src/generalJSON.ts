import { SDJWTException } from '@sd-jwt/utils';
import { splitSdJwt } from '@sd-jwt/decode';

export type GeneralJSONData = {
  payload: string;
  signatures: Array<{
    protected: string;
    signature: string;
    disclosures?: Array<string>;
    kid?: string;
    kb_jwt?: string;
  }>;
};

export class GeneralJSON {
  public payload: string;
  public signatures: Array<{
    protected: string;
    signature: string;
    disclosures?: Array<string>;
    kid?: string;
    kb_jwt?: string;
  }>;

  constructor(data: GeneralJSONData) {
    this.payload = data.payload;
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
      signatures: [
        {
          protected: protectedHeader,
          signature,
          disclosures,
          kb_jwt: kbJwt,
        },
      ],
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
            disclosures: s.disclosures,
            kid: s.kid,
            kb_jwt: s.kb_jwt,
          },
          protected: s.protected,
          signature: s.signature,
        };
      }),
    };
  }
}
