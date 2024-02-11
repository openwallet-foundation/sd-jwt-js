import { Base64Url } from '../base64url';

describe('Base64url', () => {
  const raw = 'abcdefghijklmnopqrstuvwxyz';
  const encoded = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo';
  test('Encode', () => {
    expect(Base64Url.encode(raw)).toStrictEqual(encoded);
  });
  test('Decode', () => {
    expect(Base64Url.decode(encoded)).toStrictEqual(raw);
  });
  test('Encode and decode', () => {
    const str = 'hello world';
    expect(Base64Url.decode(Base64Url.encode(str))).toStrictEqual(str);
  });
});
