import { Disclosure } from '@sd-jwt/utils';
import { Jwt } from '../jwt';
import { SDJwt, listKeys, pack } from '../sdjwt';
import Crypto from 'node:crypto';
import { describe, test, expect, beforeAll } from 'vitest';
import type { DisclosureFrame, Signer } from '@sd-jwt/types';
import { generateSalt, digest as hasher } from '@sd-jwt/crypto-nodejs';
import { unpack, createHashMapping } from '@sd-jwt/decode';

const hash = { alg: 'SHA256', hasher };

describe('SD JWT', () => {
  let privateKey: Crypto.KeyObject;

  beforeAll(async () => {
    const key = {
      crv: 'Ed25519',
      d: 'ae3x8nwFurD3HSsUFs8dVeeOV9PGduQ_C3kvWd876uo',
      x: '6XoweLGtj3SHJBHyw1CF-q-2lLgXHGoybW_7iADkg8Y',
      kty: 'OKP',
    };
    privateKey = await Crypto.createPrivateKey({
      key,
      format: 'jwk',
    });
  });

  test('create and encode', async () => {
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA', kid: 'key1' },
      payload: { foo: 'bar' },
    });

    await jwt.sign(testSigner);
    const sdJwt = new SDJwt({
      jwt,
      disclosures: [],
    });
    expect(sdJwt).toBeDefined();

    // test compact encoding
    const encoded = sdJwt.encodeSDJwt();

    expect(encoded).toBe(
      'eyJhbGciOiJFZERTQSIsImtpZCI6ImtleTEifQ.eyJmb28iOiJiYXIifQ.kHjXb8fplSbRTv51xm5NJm4TQHr6TtqWj8anpPd9hMPCf8RMO_J2j5wp8TWJbVt2PXYQdiIQmcVEnB-h9TOKBQ~',
    );

    // test json serialization
    const encodedJson = sdJwt.encodeSDJwtJson('json');
    expect(encodedJson).toEqual({
      payload: 'eyJmb28iOiJiYXIifQ',
      signatures: [
        {
          header: {
            disclosures: [],
            kid: 'key1',
          },
          protected: 'eyJhbGciOiJFZERTQSIsImtpZCI6ImtleTEifQ',
          signature:
            'kHjXb8fplSbRTv51xm5NJm4TQHr6TtqWj8anpPd9hMPCf8RMO_J2j5wp8TWJbVt2PXYQdiIQmcVEnB-h9TOKBQ',
        },
      ],
    });

    // test json serialization flattened
    const encodedJsonFlattened = sdJwt.encodeSDJwtJson('json-flattended');
    expect(encodedJsonFlattened).toEqual({
      header: {
        disclosures: [],
      },
      payload: 'eyJmb28iOiJiYXIifQ',
      protected: 'eyJhbGciOiJFZERTQSIsImtpZCI6ImtleTEifQ',
      signature:
        'kHjXb8fplSbRTv51xm5NJm4TQHr6TtqWj8anpPd9hMPCf8RMO_J2j5wp8TWJbVt2PXYQdiIQmcVEnB-h9TOKBQ',
    });
  });

  test('decode', async () => {
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar', _sd_alg: 'sha-256' },
    });

    await jwt.sign(testSigner);
    const sdJwt = new SDJwt({
      jwt,
      disclosures: [],
    });

    const encoded = sdJwt.encodeSDJwt();
    const newSdJwt = await SDJwt.fromEncode(encoded, hasher);
    expect(newSdJwt).toBeDefined();
    const newJwt = newSdJwt.jwt;
    expect(newJwt?.header).toEqual(jwt.header);
    expect(newJwt?.payload).toEqual(jwt.payload);
    expect(newJwt?.signature).toEqual(jwt.signature);

    const encodedJson = sdJwt.encodeSDJwtJson('json');
    const newSdJwtJson = await SDJwt.fromEncode(encodedJson, hasher);
    expect(newSdJwtJson).toBeDefined();
    const newJwt1 = newSdJwt.jwt;
    expect(newJwt1?.header).toEqual(jwt.header);
    expect(newJwt1?.payload).toEqual(jwt.payload);
    expect(newJwt1?.signature).toEqual(jwt.signature);

    const encodedJsonFlattened = sdJwt.encodeSDJwtJson('json-flattended');
    const newSdJwtJsonFlattended = await SDJwt.fromEncode(
      encodedJsonFlattened,
      hasher,
    );
    expect(newSdJwtJsonFlattended).toBeDefined();
    const newJwt2 = newSdJwtJsonFlattended.jwt;
    expect(newJwt2?.header).toEqual(jwt.header);
    expect(newJwt2?.payload).toEqual(jwt.payload);
    expect(newJwt2?.signature).toEqual(jwt.signature);
  });

  //not clear why we need this test
  test('decode compatibilty', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    await jwt.sign(testSigner);
    const sdJwt = new SDJwt({
      jwt,
      disclosures: [],
    });

    const encoded = sdJwt.encodeSDJwt();

    const newSdJwt = await SDJwt.fromEncode(encoded, hasher);
    expect(newSdJwt).toBeDefined();
    const newJwt = newSdJwt.jwt;
    expect(newJwt?.header).toEqual(jwt.header);
    expect(newJwt?.payload).toEqual(jwt.payload);
    expect(newJwt?.signature).toEqual(jwt.signature);
  });

  test('keys', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    await jwt.sign(testSigner);
    const sdJwt = new SDJwt({
      jwt,
      disclosures: [],
    });

    const keys = await sdJwt.keys(hasher);
    expect(keys).toBeDefined();
    expect(keys).toEqual(['foo']);
  });

  test('presentable keys', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    await jwt.sign(testSigner);
    const sdJwt = new SDJwt({
      jwt,
      disclosures: [],
    });

    const keys = await sdJwt.presentableKeys(hasher);
    expect(keys).toBeDefined();
    expect(keys).toEqual([]);
  });

  test('claims', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    await jwt.sign(testSigner);
    const sdJwt = new SDJwt({
      jwt,
      disclosures: [],
    });

    const claims = await sdJwt.getClaims(hasher);
    expect(claims).toBeDefined();
    expect(claims).toEqual({
      foo: 'bar',
    });
  });

  test('pack', async () => {
    const claim = {
      firstname: 'John',
      lastname: 'Doe',
    };

    const { packedClaims, disclosures } = await pack(
      claim,
      {
        _sd: ['firstname'],
      },
      hash,
      generateSalt,
    );

    expect(disclosures).toBeDefined();
    expect(packedClaims).toBeDefined();

    expect(disclosures.length).toEqual(1);
    expect(disclosures[0].key).toEqual('firstname');
    expect(disclosures[0].value).toEqual('John');

    expect(packedClaims._sd).toBeDefined();
    expect(packedClaims._sd.length).toEqual(1);
    expect(packedClaims.lastname).toEqual('Doe');
  });

  test('list keys', () => {
    const data = {
      a: {
        b: {
          c: 1,
        },
        d: [
          {
            e: 'fasfdsa',
            f: 1234,
          },
          3,
          4,
        ],
      },
      g: [['h'], 'i'],
    };

    const keys = listKeys(data);
    expect(keys).toEqual([
      'a',
      'a.b',
      'a.b.c',
      'a.d',
      'a.d.0',
      'a.d.0.e',
      'a.d.0.f',
      'a.d.1',
      'a.d.2',
      'g',
      'g.0',
      'g.0.0',
      'g.1',
    ]);
  });

  test('presentable keys', async () => {
    const claim = {
      firstname: 'John',
      lastname: 'Doe',
    };

    const { packedClaims, disclosures } = await pack(
      claim,
      {
        _sd: ['firstname'],
      },
      hash,
      generateSalt,
    );

    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: packedClaims,
    });

    await jwt.sign(testSigner);
    const sdJwt = new SDJwt({
      jwt,
      disclosures,
    });

    const keys = await sdJwt.presentableKeys(hasher);

    expect(keys).toBeDefined();
    expect(keys).toEqual(['firstname']);
  });

  test('hash map', async () => {
    const claim = {
      firstname: 'John',
      lastname: 'Doe',
    };

    const { disclosures } = await pack(
      claim,
      {
        _sd: ['firstname'],
      },
      hash,
      generateSalt,
    );

    const mapping = await createHashMapping(disclosures, hash);
    expect(mapping).toBeDefined();
    expect(Object.keys(mapping).length).toEqual(1);
    expect(mapping[Object.keys(mapping)[0]]).toBeInstanceOf(Disclosure);
  });

  test('unpack', async () => {
    const claim = {
      firstname: 'John',
      lastname: 'Doe',
    };

    const { packedClaims, disclosures } = await pack(
      claim,
      {
        _sd: ['firstname'],
      },
      hash,
      generateSalt,
    );

    const { disclosureKeymap, unpackedObj } = await unpack(
      packedClaims,
      disclosures,
      hasher,
    );
    expect(disclosureKeymap).toBeDefined();
    expect(unpackedObj).toBeDefined();
    expect(unpackedObj).toEqual({
      firstname: 'John',
      lastname: 'Doe',
    });
    expect(disclosureKeymap.firstname).toBeDefined();
    expect(typeof disclosureKeymap.firstname).toEqual('string');
  });

  test('pack and unpack', async () => {
    const claims = {
      firstname: 'John',
      lastname: 'Doe',
      ssn: '123-45-6789',
      id: '1234',
      data: {
        firstname: 'John',
        lastname: 'Doe',
        ssn: '123-45-6789',
        list: [{ r: '1' }, 'b', 'c'],
      },
      data2: {
        hi: 'bye',
      },
    };

    const disclosureFrame: DisclosureFrame<typeof claims> = {
      _sd: ['firstname', 'id', 'data2'],
      data: {
        _sd: ['list'],
        _sd_decoy: 2,
        list: {
          _sd: [0, 2],
          _sd_decoy: 1,
          0: {
            _sd: ['r'],
          },
        },
      },
      data2: {
        _sd: ['hi'],
      },
    };

    const { packedClaims, disclosures } = await pack(
      claims,
      disclosureFrame,
      hash,
      generateSalt,
    );
    const { unpackedObj } = await unpack(packedClaims, disclosures, hasher);

    expect(unpackedObj).toEqual(claims);
  });

  test('no disclosures', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    await jwt.sign(testSigner);
    const sdJwt = new SDJwt({
      jwt,
      disclosures: [],
    });

    const credential = sdJwt.encodeSDJwt();
    const decoded = await SDJwt.decodeSDJwt(credential, hasher);
    expect(jwt.header).toEqual(decoded.jwt.header);
    expect(jwt.payload).toEqual(decoded.jwt.payload);
    expect(jwt.signature).toEqual(decoded.jwt.signature);
    expect(decoded.disclosures).toEqual([]);
  });
});
