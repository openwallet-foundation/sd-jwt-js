import { createHashMapping, getSDAlgAndPayload, unpack } from '@sd-jwt/decode';
import { transformPresentationFrame } from '@sd-jwt/present';
import {
  type DisclosureFrame,
  type Hasher,
  type HasherAndAlg,
  type kbHeader,
  type kbPayload,
  type PresentationFrame,
  type SaltGenerator,
  SD_DECOY,
  SD_DIGEST,
  SD_LIST_KEY,
  SD_SEPARATOR,
  type SDJWTCompact,
} from '@sd-jwt/types';
import { Disclosure, SDJWTException } from '@sd-jwt/utils';
import { createDecoy } from './decoy';
import { Jwt } from './jwt';
import { KBJwt } from './kbjwt';

export type SDJwtData<
  Header extends Record<string, unknown>,
  Payload extends Record<string, unknown>,
  KBHeader extends kbHeader = kbHeader,
  KBPayload extends kbPayload = kbPayload,
> = {
  jwt?: Jwt<Header, Payload>;
  disclosures?: Array<Disclosure>;
  kbJwt?: KBJwt<KBHeader, KBPayload>;
};

export class SDJwt<
  Header extends Record<string, unknown> = Record<string, unknown>,
  Payload extends Record<string, unknown> = Record<string, unknown>,
  KBHeader extends kbHeader = kbHeader,
  KBPayload extends kbPayload = kbPayload,
> {
  public jwt?: Jwt<Header, Payload>;
  public disclosures?: Array<Disclosure>;
  public kbJwt?: KBJwt<KBHeader, KBPayload>;

  constructor(data?: SDJwtData<Header, Payload, KBHeader, KBPayload>) {
    this.jwt = data?.jwt;
    this.disclosures = data?.disclosures;
    this.kbJwt = data?.kbJwt;
  }

  public static async decodeSDJwt<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
    KBHeader extends kbHeader = kbHeader,
    KBPayload extends kbPayload = kbPayload,
  >(
    sdjwt: SDJWTCompact,
    hasher: Hasher,
  ): Promise<{
    jwt: Jwt<Header, Payload>;
    disclosures: Array<Disclosure>;
    kbJwt?: KBJwt<KBHeader, KBPayload>;
  }> {
    const [encodedJwt, ...encodedDisclosures] = sdjwt.split(SD_SEPARATOR);
    const jwt = Jwt.fromEncode<Header, Payload>(encodedJwt);

    if (!jwt.payload) {
      throw new Error('Payload is undefined on the JWT. Invalid state reached');
    }

    if (encodedDisclosures.length === 0) {
      return {
        jwt,
        disclosures: [],
      };
    }

    const encodedKeyBindingJwt = encodedDisclosures.pop();
    const kbJwt = encodedKeyBindingJwt
      ? KBJwt.fromKBEncode<KBHeader, KBPayload>(encodedKeyBindingJwt)
      : undefined;

    const { _sd_alg } = getSDAlgAndPayload(jwt.payload);

    const disclosures = await Promise.all(
      (encodedDisclosures as Array<string>).map((ed) =>
        Disclosure.fromEncode(ed, { alg: _sd_alg, hasher }),
      ),
    );

    return {
      jwt,
      disclosures,
      kbJwt,
    };
  }

  public static async extractJwt<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
  >(encodedSdJwt: SDJWTCompact): Promise<Jwt<Header, Payload>> {
    const [encodedJwt, ..._encodedDisclosures] =
      encodedSdJwt.split(SD_SEPARATOR);

    return Jwt.fromEncode(encodedJwt);
  }

  public static async fromEncode<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
    KBHeader extends kbHeader = kbHeader,
    KBPayload extends kbPayload = kbPayload,
  >(
    encodedSdJwt: SDJWTCompact,
    hasher: Hasher,
  ): Promise<SDJwt<Header, Payload>> {
    const { jwt, disclosures, kbJwt } = await SDJwt.decodeSDJwt<
      Header,
      Payload,
      KBHeader,
      KBPayload
    >(encodedSdJwt, hasher);

    return new SDJwt<Header, Payload, KBHeader, KBPayload>({
      jwt,
      disclosures,
      kbJwt,
    });
  }

  public async present<T extends Record<string, unknown>>(
    presentFrame: PresentationFrame<T> | undefined,
    hasher: Hasher,
  ): Promise<SDJWTCompact> {
    const disclosures = await this.getPresentDisclosures(presentFrame, hasher);
    const presentSDJwt = new SDJwt({
      jwt: this.jwt,
      disclosures,
      kbJwt: this.kbJwt,
    });
    return presentSDJwt.encodeSDJwt();
  }

  public async getPresentDisclosures<T extends Record<string, unknown>>(
    presentFrame: PresentationFrame<T> | undefined,
    hasher: Hasher,
  ): Promise<Disclosure<unknown>[]> {
    if (!this.jwt?.payload || !this.disclosures) {
      throw new SDJWTException('Invalid sd-jwt: jwt or disclosures is missing');
    }
    const { _sd_alg: alg } = getSDAlgAndPayload(this.jwt.payload);
    const hash = { alg, hasher };
    const hashmap = await createHashMapping(this.disclosures, hash);
    const { disclosureKeymap } = await unpack(
      this.jwt.payload,
      this.disclosures,
      hasher,
    );

    const keys = presentFrame
      ? transformPresentationFrame(presentFrame)
      : await this.presentableKeys(hasher);
    const disclosures = keys
      .map((k) => hashmap[disclosureKeymap[k]])
      .filter((d) => d !== undefined);
    return disclosures;
  }

  public encodeSDJwt(): SDJWTCompact {
    const data: string[] = [];

    if (!this.jwt) {
      throw new SDJWTException('Invalid sd-jwt: jwt is missing');
    }

    const encodedJwt = this.jwt.encodeJwt();
    data.push(encodedJwt);

    if (this.disclosures && this.disclosures.length > 0) {
      const encodeddisclosures = this.disclosures
        .map((dc) => dc.encode())
        .join(SD_SEPARATOR);
      data.push(encodeddisclosures);
    }

    data.push(this.kbJwt ? this.kbJwt.encodeJwt() : '');
    return data.join(SD_SEPARATOR);
  }

  public async keys(hasher: Hasher): Promise<string[]> {
    return listKeys(await this.getClaims(hasher)).sort();
  }

  public async presentableKeys(hasher: Hasher): Promise<string[]> {
    if (!this.jwt?.payload || !this.disclosures) {
      throw new SDJWTException('Invalid sd-jwt: jwt or disclosures is missing');
    }
    const { disclosureKeymap } = await unpack(
      this.jwt?.payload,
      this.disclosures,
      hasher,
    );
    return Object.keys(disclosureKeymap).sort();
  }

  public async getClaims<T>(hasher: Hasher): Promise<T> {
    if (!this.jwt?.payload || !this.disclosures) {
      throw new SDJWTException('Invalid sd-jwt: jwt or disclosures is missing');
    }
    const { unpackedObj } = await unpack(
      this.jwt.payload,
      this.disclosures,
      hasher,
    );
    return unpackedObj as T;
  }
}

export const listKeys = (obj: Record<string, unknown>, prefix = '') => {
  const keys: string[] = [];
  for (const key in obj) {
    if (obj[key] === undefined) continue;
    const newKey = prefix ? `${prefix}.${key}` : key;
    keys.push(newKey);

    if (obj[key] && typeof obj[key] === 'object' && obj[key] !== null) {
      keys.push(...listKeys(obj[key] as Record<string, unknown>, newKey));
    }
  }
  return keys;
};

export const pack = async <T extends Record<string, unknown>>(
  claims: T,
  disclosureFrame: DisclosureFrame<T> | undefined,
  hash: HasherAndAlg,
  saltGenerator: SaltGenerator,
): Promise<{
  packedClaims: Record<string, unknown> | Array<Record<string, unknown>>;
  disclosures: Array<Disclosure>;
}> => {
  if (!disclosureFrame) {
    return {
      packedClaims: claims,
      disclosures: [],
    };
  }

  const sd = disclosureFrame[SD_DIGEST] ?? [];
  const decoyCount = disclosureFrame[SD_DECOY] ?? 0;

  if (Array.isArray(claims)) {
    const packedClaims: Array<Record<typeof SD_LIST_KEY, string>> = [];
    const disclosures: Array<Disclosure> = [];
    const recursivePackedClaims: Record<number, unknown> = {};

    for (const key in disclosureFrame) {
      if (key !== SD_DIGEST) {
        const idx = Number.parseInt(key, 10);
        const packed = await pack(
          claims[idx],
          disclosureFrame[idx],
          hash,
          saltGenerator,
        );
        recursivePackedClaims[idx] = packed.packedClaims;
        disclosures.push(...packed.disclosures);
      }
    }

    for (let i = 0; i < claims.length; i++) {
      const claim = recursivePackedClaims[i]
        ? recursivePackedClaims[i]
        : claims[i];
      /** This part is set discloure for array items.
       *  The example of disclosureFrame of an Array is
       *
       *  const claims = {
       *    array: ['a', 'b', 'c']
       *  }
       *
       *  diclosureFrame: DisclosureFrame<typeof claims> = {
       *    array: {
       *      _sd: [0, 2]
       *    }
       *  }
       *
       *  It means that we want to disclose the first and the third item of the array
       *
       *  So If the index `i` is in the disclosure list(sd), then we create a disclosure for the claim
       */
      // @ts-expect-error
      if (sd.includes(i)) {
        const salt = await saltGenerator(16);
        const disclosure = new Disclosure([salt, claim]);
        const digest = await disclosure.digest(hash);
        packedClaims.push({ [SD_LIST_KEY]: digest });
        disclosures.push(disclosure);
      } else {
        packedClaims.push(claim);
      }
    }
    for (let j = 0; j < decoyCount; j++) {
      const decoyDigest = await createDecoy(hash, saltGenerator);
      packedClaims.push({ [SD_LIST_KEY]: decoyDigest });
    }
    return { packedClaims, disclosures };
  }

  const packedClaims: Record<string, unknown> = {};
  const disclosures: Array<Disclosure> = [];
  const recursivePackedClaims: Record<string, unknown> = {};

  for (const key in disclosureFrame) {
    if (key !== SD_DIGEST) {
      const packed = await pack(
        // @ts-expect-error
        claims[key],
        disclosureFrame[key],
        hash,
        saltGenerator,
      );
      recursivePackedClaims[key] = packed.packedClaims;
      disclosures.push(...packed.disclosures);
    }
  }

  const _sd: string[] = [];

  for (const key in claims) {
    const claim = recursivePackedClaims[key]
      ? recursivePackedClaims[key]
      : claims[key];
    if (sd.includes(key)) {
      const salt = await saltGenerator(16);
      const disclosure = new Disclosure([salt, key, claim]);
      const digest = await disclosure.digest(hash);

      _sd.push(digest);
      disclosures.push(disclosure);
    } else {
      packedClaims[key] = claim;
    }
  }

  for (let j = 0; j < decoyCount; j++) {
    const decoyDigest = await createDecoy(hash, saltGenerator);
    _sd.push(decoyDigest);
  }

  if (_sd.length > 0) {
    packedClaims[SD_DIGEST] = _sd.sort();
  }
  return { packedClaims, disclosures };
};
