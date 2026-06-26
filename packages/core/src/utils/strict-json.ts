import { base64UrlToUint8Array } from './base64url';
import { SDJWTException } from './error';

const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

export const decodeBase64urlJsonStrict = <T>(
  encoded: string,
  errorMessage: string,
): T => {
  try {
    const bytes = base64UrlToUint8Array(encoded);
    const decoded = utf8Decoder.decode(bytes);
    return JSON.parse(decoded) as T;
  } catch {
    throw new SDJWTException(errorMessage);
  }
};
