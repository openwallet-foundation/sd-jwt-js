import { Base64 } from 'js-base64';

export const base64urlEncode = Base64.encodeURI;

export const base64urlDecode = Base64.decode;

export const uint8ArrayToBase64Url = (input: Uint8Array): string =>
  Base64.fromUint8Array(input, true);

export const base64UrlToUint8Array = (input: string): Uint8Array =>
  Base64.toUint8Array(input);
