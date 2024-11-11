import { SDJWTException, uint8ArrayToBase64Url } from '@sd-jwt/utils';
import { Jwt } from './jwt';
import { KBJwt } from './kbjwt';
import { SDJwt, pack } from './sdjwt';
import {
  type DisclosureFrame,
  type Hasher,
  type KBOptions,
  KB_JWT_TYP,
  type PresentationFrame,
  type SDJWTCompact,
  type SDJWTConfig,
  type JwtPayload,
} from '@sd-jwt/types';
import { getSDAlgAndPayload } from '@sd-jwt/decode';
import { FlattenJSON } from './flattenJSON';
import { GeneralJSON } from './generalJSON';

export * from './sdjwt';
export * from './kbjwt';
export * from './jwt';
export * from './decoy';

export type SdJwtPayload = Record<string, unknown>;

export class SDJwtInstance<ExtendedPayload extends SdJwtPayload> {
  //header type
  protected type?: string;

  public static readonly DEFAULT_hashAlg = 'sha-256';

  protected userConfig: SDJWTConfig = {};

  constructor(userConfig?: SDJWTConfig) {
    if (userConfig) {
      this.userConfig = userConfig;
    }
  }

  private async createKBJwt(
    options: KBOptions,
    sdHash: string,
  ): Promise<KBJwt> {
    if (!this.userConfig.kbSigner) {
      throw new SDJWTException('Key Binding Signer not found');
    }
    if (!this.userConfig.kbSignAlg) {
      throw new SDJWTException('Key Binding sign algorithm not specified');
    }

    const { payload } = options;
    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: this.userConfig.kbSignAlg,
      },
      payload: { ...payload, sd_hash: sdHash },
    });

    await kbJwt.sign(this.userConfig.kbSigner);
    return kbJwt;
  }

  private async SignJwt(jwt: Jwt) {
    if (!this.userConfig.signer) {
      throw new SDJWTException('Signer not found');
    }
    await jwt.sign(this.userConfig.signer);
    return jwt;
  }

  private async VerifyJwt(jwt: Jwt) {
    if (!this.userConfig.verifier) {
      throw new SDJWTException('Verifier not found');
    }
    return jwt.verify(this.userConfig.verifier);
  }

  public async issue<Payload extends ExtendedPayload>(
    payload: Payload,
    disclosureFrame?: DisclosureFrame<Payload>,
    options?: {
      header?: object; // This is for customizing the header of the jwt
    },
  ): Promise<SDJWTCompact> {
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }

    if (!this.userConfig.saltGenerator) {
      throw new SDJWTException('SaltGenerator not found');
    }

    if (!this.userConfig.signAlg) {
      throw new SDJWTException('sign alogrithm not specified');
    }

    if (disclosureFrame) {
      this.validateReservedFields<Payload>(disclosureFrame);
    }

    const hasher = this.userConfig.hasher;
    const hashAlg = this.userConfig.hashAlg ?? SDJwtInstance.DEFAULT_hashAlg;

    const { packedClaims, disclosures } = await pack(
      payload,
      disclosureFrame,
      { hasher, alg: hashAlg },
      this.userConfig.saltGenerator,
    );
    const alg = this.userConfig.signAlg;
    const OptionHeader = options?.header ?? {};
    const CustomHeader = this.userConfig.omitTyp
      ? OptionHeader
      : { typ: this.type, ...OptionHeader };
    const header = { ...CustomHeader, alg };
    const jwt = new Jwt({
      header,
      payload: {
        ...packedClaims,
        _sd_alg: disclosureFrame ? hashAlg : undefined,
      },
    });
    await this.SignJwt(jwt);

    const sdJwt = new SDJwt({
      jwt,
      disclosures,
    });

    return sdJwt.encodeSDJwt();
  }

  /**
   * Validates if the disclosureFrame contains any reserved fields. If so it will throw an error.
   * @param disclosureFrame
   * @returns
   */
  protected validateReservedFields<T extends ExtendedPayload>(
    disclosureFrame: DisclosureFrame<T>,
  ) {
    return;
  }

  public async present<T extends Record<string, unknown>>(
    encodedSDJwt: string,
    presentationFrame?: PresentationFrame<T>,
    options?: {
      kb?: KBOptions;
    },
  ): Promise<SDJWTCompact> {
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }
    const hasher = this.userConfig.hasher;

    const sdjwt = await SDJwt.fromEncode(encodedSDJwt, hasher);

    if (!sdjwt.jwt?.payload) throw new SDJWTException('Payload not found');
    const presentSdJwtWithoutKb = await sdjwt.present(
      presentationFrame,
      hasher,
    );

    if (!options?.kb) {
      return presentSdJwtWithoutKb;
    }

    const sdHashStr = await this.calculateSDHash(
      presentSdJwtWithoutKb,
      sdjwt,
      hasher,
    );

    sdjwt.kbJwt = await this.createKBJwt(options.kb, sdHashStr);
    return sdjwt.present(presentationFrame, hasher);
  }

  // This function is for verifying the SD JWT
  // If requiredClaimKeys is provided, it will check if the required claim keys are presentation in the SD JWT
  // If requireKeyBindings is true, it will check if the key binding JWT is presentation and verify it
  public async verify(
    encodedSDJwt: string,
    requiredClaimKeys?: string[],
    requireKeyBindings?: boolean,
  ) {
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }
    const hasher = this.userConfig.hasher;

    const sdjwt = await SDJwt.fromEncode(encodedSDJwt, hasher);
    if (!sdjwt.jwt || !sdjwt.jwt.payload) {
      throw new SDJWTException('Invalid SD JWT');
    }
    const { payload, header } = await this.validate(encodedSDJwt);

    if (requiredClaimKeys) {
      const keys = await sdjwt.keys(hasher);
      const missingKeys = requiredClaimKeys.filter((k) => !keys.includes(k));
      if (missingKeys.length > 0) {
        throw new SDJWTException(
          `Missing required claim keys: ${missingKeys.join(', ')}`,
        );
      }
    }

    if (!requireKeyBindings) {
      return { payload, header };
    }

    if (!sdjwt.kbJwt) {
      throw new SDJWTException('Key Binding JWT not exist');
    }
    if (!this.userConfig.kbVerifier) {
      throw new SDJWTException('Key Binding Verifier not found');
    }
    const kb = await sdjwt.kbJwt.verifyKB({
      verifier: this.userConfig.kbVerifier,
      payload: payload as JwtPayload,
    });
    if (!kb) {
      throw new Error('signature is not valid');
    }
    const sdHashfromKb = kb.payload.sd_hash;
    const sdjwtWithoutKb = new SDJwt({
      jwt: sdjwt.jwt,
      disclosures: sdjwt.disclosures,
    });

    const presentSdJwtWithoutKb = sdjwtWithoutKb.encodeSDJwt();
    const sdHashStr = await this.calculateSDHash(
      presentSdJwtWithoutKb,
      sdjwt,
      hasher,
    );

    if (sdHashStr !== sdHashfromKb) {
      throw new SDJWTException('Invalid sd_hash in Key Binding JWT');
    }

    return { payload, header, kb };
  }

  private async calculateSDHash(
    presentSdJwtWithoutKb: string,
    sdjwt: SDJwt,
    hasher: Hasher,
  ) {
    if (!sdjwt.jwt || !sdjwt.jwt.payload) {
      throw new SDJWTException('Invalid SD JWT');
    }
    const { _sd_alg } = getSDAlgAndPayload(sdjwt.jwt.payload);
    const sdHash = await hasher(presentSdJwtWithoutKb, _sd_alg);
    const sdHashStr = uint8ArrayToBase64Url(sdHash);
    return sdHashStr;
  }

  // This function is for validating the SD JWT
  // Just checking signature and return its the claims
  public async validate(encodedSDJwt: string) {
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }
    const hasher = this.userConfig.hasher;

    const sdjwt = await SDJwt.fromEncode(encodedSDJwt, hasher);
    if (!sdjwt.jwt) {
      throw new SDJWTException('Invalid SD JWT');
    }

    const verifiedPayloads = await this.VerifyJwt(sdjwt.jwt);
    const claims = await sdjwt.getClaims(hasher);
    return { payload: claims, header: verifiedPayloads.header };
  }

  public config(newConfig: SDJWTConfig) {
    this.userConfig = { ...this.userConfig, ...newConfig };
  }

  public encode(sdJwt: SDJwt): SDJWTCompact {
    return sdJwt.encodeSDJwt();
  }

  public decode(endcodedSDJwt: SDJWTCompact) {
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }
    return SDJwt.fromEncode(endcodedSDJwt, this.userConfig.hasher);
  }

  public async keys(endcodedSDJwt: SDJWTCompact) {
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }
    const sdjwt = await SDJwt.fromEncode(endcodedSDJwt, this.userConfig.hasher);
    return sdjwt.keys(this.userConfig.hasher);
  }

  public async presentableKeys(endcodedSDJwt: SDJWTCompact) {
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }
    const sdjwt = await SDJwt.fromEncode(endcodedSDJwt, this.userConfig.hasher);
    return sdjwt.presentableKeys(this.userConfig.hasher);
  }

  public async getClaims(endcodedSDJwt: SDJWTCompact) {
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }
    const sdjwt = await SDJwt.fromEncode(endcodedSDJwt, this.userConfig.hasher);
    return sdjwt.getClaims(this.userConfig.hasher);
  }

  public toFlattenJSON(endcodedSDJwt: SDJWTCompact) {
    return FlattenJSON.fromEncode(endcodedSDJwt);
  }

  public toGeneralJSON(endcodedSDJwt: SDJWTCompact) {
    return GeneralJSON.fromEncode(endcodedSDJwt);
  }
}
