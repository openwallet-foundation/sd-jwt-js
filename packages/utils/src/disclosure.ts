import type {
  DisclosureData,
  HasherAndAlg,
  HasherAndAlgSync,
} from '@sd-jwt/types';
import {
  base64urlDecode,
  base64urlEncode,
  uint8ArrayToBase64Url,
} from './base64url';
import { SDJWTException } from './error';

export class Disclosure<T = unknown> {
  public salt: string;
  public key?: string;
  public value: T;
  public _digest: string | undefined;
  private _encoded: string | undefined;

  public constructor(
    data: DisclosureData<T>,
    _meta?: { digest: string; encoded: string },
  ) {
    // If the meta is provided, then we assume that the data is already encoded and digested
    this._digest = _meta?.digest;
    this._encoded = _meta?.encoded;

    if (data.length === 2) {
      this.salt = data[0];
      this.value = data[1];
      return;
    }
    if (data.length === 3) {
      this.salt = data[0];
      this.key = data[1] as string;
      this.value = data[2];
      return;
    }
    throw new SDJWTException('Invalid disclosure data');
  }

  // We need to digest of the original encoded data.
  // After decode process, we use JSON.stringify to encode the data.
  // This can be different from the original encoded data.
  public static async fromEncode<T>(s: string, hash: HasherAndAlg) {
    const { hasher, alg } = hash;
    const digest = await hasher(s, alg);
    const digestStr = uint8ArrayToBase64Url(digest);
    const item = JSON.parse(base64urlDecode(s)) as DisclosureData<T>;
    return Disclosure.fromArray<T>(item, { digest: digestStr, encoded: s });
  }

  public static fromEncodeSync<T>(s: string, hash: HasherAndAlgSync) {
    const { hasher, alg } = hash;
    const digest = hasher(s, alg);
    const digestStr = uint8ArrayToBase64Url(digest);
    const item = JSON.parse(base64urlDecode(s)) as DisclosureData<T>;
    return Disclosure.fromArray<T>(item, { digest: digestStr, encoded: s });
  }

  public static fromArray<T>(
    item: DisclosureData<T>,
    _meta?: { digest: string; encoded: string },
  ) {
    return new Disclosure(item, _meta);
  }

  public encode() {
    if (!this._encoded) {
      // we use JSON.stringify to encode the data
      // It's the most reliable and universal way to encode JSON object
      this._encoded = base64urlEncode(JSON.stringify(this.decode()));
    }
    return this._encoded;
  }

  public decode(): DisclosureData<T> {
    return this.key
      ? [this.salt, this.key, this.value]
      : [this.salt, this.value];
  }

  public async digest(hash: HasherAndAlg): Promise<string> {
    const { hasher, alg } = hash;
    if (!this._digest) {
      const hash = await hasher(this.encode(), alg);
      this._digest = uint8ArrayToBase64Url(hash);
    }

    return this._digest;
  }

  public digestSync(hash: HasherAndAlgSync): string {
    const { hasher, alg } = hash;
    if (!this._digest) {
      const hash = hasher(this.encode(), alg);
      this._digest = uint8ArrayToBase64Url(hash);
    }

    return this._digest;
  }
}
