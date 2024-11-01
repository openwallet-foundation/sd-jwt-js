import { createDecoy } from './decoy';
import {
  SDJWTException,
  Disclosure,
  base64urlEncode,
  base64urlDecode,
} from '@sd-jwt/utils';
import { Jwt } from './jwt';
import { KBJwt } from './kbjwt';
import {
  type DisclosureFrame,
  type Hasher,
  type HasherAndAlg,
  type PresentationFrame,
  type SDJWTCompact,
  SD_DECOY,
  SD_DIGEST,
  SD_LIST_KEY,
  SD_SEPARATOR,
  type SaltGenerator,
  type kbHeader,
  type kbPayload,
} from '@sd-jwt/types';
import { createHashMapping, getSDAlgAndPayload, unpack } from '@sd-jwt/decode';
import { transformPresentationFrame } from '@sd-jwt/present';
import type { Serialization, SerializationJson } from '.';

type Signature = {
  // The "protected" member MUST be present and contain the value BASE64URL(UTF8(JWS Protected Header)) when the JWS Protected Header value is non-empty; otherwise, it MUST be absent.  These Header Parameter values are integrity protected.
  protected: string;
  // The "header" member MUST be present and contain the value JWS Unprotected Header when the JWS Unprotected Header value is non-empty; otherwise, it MUST be absent.  This value is represented as an unencoded JSON object, rather than as a string.  These Header Parameter values are not integrity protected.
  header: {
    // only included in the first signature of the signature array
    disclosures: string[];
    kid?: string;
    // only included in the first signature of the signature array
    kb_jwt?: string;
  };
  // The "signature" member MUST be present and contain the value BASE64URL(JWS Signature).
  signature: string;
};

/**
 * General Json serialization of a SD-JWT based on https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1 for JWT and extended
 */
export type SDJJWTJson = {
  // the "payload" member MUST be present and contain the value BASE64URL(JWS Payload).
  payload: string;
  // The "signatures" member value MUST be an array of JSON objects. Each object represents a signature or MAC over the JWS Payload and the JWS Protected Header.
  signatures: Array<Signature>;
};

export type SDJWTJsonFlattened = {
  header?: {
    // An array of strings where each element is an individual Disclosure as described in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-09.html#creating_disclosures
    disclosures?: Array<string>;
    // Present only in an SD-JWT+KB, the Key Binding JWT as described in https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-09.html#kb-jwt
    kb_jwt?: string;
  };
  // the "payload" member MUST be present and contain the value BASE64URL(JWS Payload).
  payload: string;
  protected: string;
  signature: string;
};

export type SDJWTType = SDJJWTJson | SDJWTJsonFlattened | SDJWTCompact;

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

  /**
   * Decode a SDJwt from a compact string or a JSON object
   * @param sdjwt
   * @param hasher
   * @returns
   */
  public static async decodeSDJwt<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
    KBHeader extends kbHeader = kbHeader,
    KBPayload extends kbPayload = kbPayload,
  >(
    sdjwt: SDJWTType,
    hasher: Hasher,
  ): Promise<{
    jwt: Jwt<Header, Payload>;
    disclosures: Array<Disclosure>;
    kbJwt?: KBJwt<KBHeader, KBPayload>;
  }> {
    if (typeof sdjwt === 'string') {
      const [encodedJwt, ...encodedDisclosures] = sdjwt.split(SD_SEPARATOR);
      const jwt = Jwt.fromEncode<Header, Payload>(encodedJwt);

      if (!jwt.payload) {
        throw new Error(
          'Payload is undefined on the JWT. Invalid state reached',
        );
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
    if (typeof (sdjwt as SDJJWTJson).signatures !== 'undefined') {
      const sdJJWTJson = sdjwt as SDJJWTJson;
      const payload = JSON.parse(base64urlDecode(sdJJWTJson.payload));
      //TODO: unclear if this is the correct way to parse the header
      const header = JSON.parse(
        base64urlDecode(sdJJWTJson.signatures[0].protected),
      );
      const kbJwt = sdJJWTJson.signatures[0].header.kb_jwt
        ? KBJwt.fromKBEncode<KBHeader, KBPayload>(
            sdJJWTJson.signatures[0].header.kb_jwt,
          )
        : undefined;
      //TODO: with the current implementation, only one signature is returned since it has to be a jwt
      const jwt = new Jwt<Header, Payload>({
        header,
        payload,
        signature: sdJJWTJson.signatures[0].signature,
      });
      const { _sd_alg } = getSDAlgAndPayload(payload);
      return {
        jwt,
        disclosures: await SDJwt.decodeDisclosures(
          sdJJWTJson.signatures[0].header.disclosures,
          _sd_alg,
          hasher,
        ),
        kbJwt,
      };
    }
    const sdjwtJson = sdjwt as SDJWTJsonFlattened;
    const header = JSON.parse(base64urlDecode(sdjwtJson.protected));
    const payload = JSON.parse(base64urlDecode(sdjwtJson.payload));
    const jwt = new Jwt<Header, Payload>({
      header,
      payload,
      signature: sdjwtJson.signature,
    });

    const { _sd_alg } = getSDAlgAndPayload(jwt.payload as Payload);
    const kbJwt = sdjwtJson.header?.kb_jwt
      ? KBJwt.fromKBEncode<KBHeader, KBPayload>(sdjwtJson.header.kb_jwt)
      : undefined;

    return {
      jwt,
      disclosures: await SDJwt.decodeDisclosures(
        header.disclosures || [],
        _sd_alg,
        hasher,
      ),
      kbJwt,
    };
  }

  private static decodeDisclosures(
    encodedDisclosures: string[],
    _sd_alg: string,
    hasher: Hasher,
  ): Promise<Disclosure[]> {
    return Promise.all(
      (encodedDisclosures as Array<string>).map((ed) =>
        Disclosure.fromEncode(ed, { alg: _sd_alg, hasher }),
      ),
    );
  }

  public static async fromEncode<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
    KBHeader extends kbHeader = kbHeader,
    KBPayload extends kbPayload = kbPayload,
  >(encodedSdJwt: SDJWTType, hasher: Hasher): Promise<SDJwt<Header, Payload>> {
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
    type: Serialization = 'compact',
  ): Promise<SDJWTType> {
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
    const presentSDJwt = new SDJwt({
      jwt: this.jwt,
      disclosures,
      kbJwt: this.kbJwt,
    });
    if (type === 'compact') {
      return presentSDJwt.encodeSDJwt();
    }
    return presentSDJwt.encodeSDJwtJson(type);
  }

  /**
   * Encodes the SDJwt to a compact string
   * @returns
   */
  public encodeSDJwt(): SDJWTCompact {
    //TODO: when we have multiple signatures, we are not able to encode it to a compact string and should throw an error
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

  /**
   * Encodes the SDJwt to a JSON object according to sd-jwt spec, either general or flattened
   * @returns
   */
  public encodeSDJwtJson(
    type: SerializationJson = 'json',
  ): SDJWTJsonFlattened | SDJJWTJson {
    // check if disclosures should be empty or not included if not present
    const disclosures = this.disclosures?.map((d) => d.encode()) ?? [];
    if (type === 'json-flattended') {
      return {
        header: {
          disclosures,
        },
        payload: base64urlEncode(JSON.stringify(this.jwt?.payload)),
        protected: base64urlEncode(JSON.stringify(this.jwt?.header)),
        signature: this.jwt?.signature as string,
      };
    }
    const signatures: Array<Signature> = [];

    signatures.push({
      // unproctected header
      header: {
        disclosures,
        //TODO: validate if this is the correct kid
        kid: this.jwt?.header?.kid as string,
        kb_jwt: (this.kbJwt?.encodeJwt() as string) || undefined,
      },
      // protected header
      protected: base64urlEncode(JSON.stringify(this.jwt?.header)),
      // signature of the proctected header and payload
      signature: this.jwt?.signature as string,
    });
    //TODO: add support for multiple signatures, right now only one is supported
    return {
      payload: base64urlEncode(JSON.stringify(this.jwt?.payload as unknown)),
      signatures,
    };
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
        const idx = Number.parseInt(key);
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
      // @ts-ignore
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
        // @ts-ignore
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
    // @ts-ignore
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
