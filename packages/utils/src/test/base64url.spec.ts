import {
  base64urlDecode,
  base64urlEncode,
  uint8ArrayToBase64Url,
  base64UrlToUint8Array,
} from '../base64url';
import { describe, expect, test } from 'vitest';

describe('Base64url', () => {
  const raw = 'abcdefghijklmnopqrstuvwxyz';
  const encoded = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo';
  test('Encode', () => {
    expect(base64urlEncode(raw)).toStrictEqual(encoded);
  });
  test('Decode', () => {
    expect(base64urlDecode(encoded)).toStrictEqual(raw);
  });
  test('Encode and decode', () => {
    const str = 'hello world';
    expect(base64urlDecode(base64urlEncode(str))).toStrictEqual(str);
  });
  test('Uint8Array', () => {
    const str = 'hello world';
    const uint8 = new TextEncoder().encode(str);
    expect(uint8ArrayToBase64Url(uint8)).toStrictEqual(base64urlEncode(str));
  });

  test('Base64Url to Uint8Array', () => {
    const str = 'hello world';
    const uint8 = new TextEncoder().encode(str);
    expect(base64UrlToUint8Array(base64urlEncode(str))).toStrictEqual(uint8);
  });
});
