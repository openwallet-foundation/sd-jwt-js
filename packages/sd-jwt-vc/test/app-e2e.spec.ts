import Crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import type {
  DisclosureFrame,
  PresentationFrame,
  Signer,
  Verifier,
} from '@sd-jwt/types';
import { describe, expect, test } from 'vitest';
import { SDJwtVcInstance } from '../src/index';

const createSignerVerifier = () => {
  const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
  const signer: Signer = async (data: string) => {
    const sig = Crypto.sign(null, Buffer.from(data), privateKey);
    return Buffer.from(sig).toString('base64url');
  };
  const verifier: Verifier = async (data: string, sig: string) => {
    return Crypto.verify(
      null,
      Buffer.from(data),
      publicKey,
      Buffer.from(sig, 'base64url'),
    );
  };
  return { signer, verifier };
};

const iss = 'ExampleIssuer';
const vct = 'ExampleCredentials';
const iat = Math.floor(Date.now() / 1000); // current time in seconds

describe('App', () => {
  test('Example', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtVcInstance({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
    });

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
      iat,
      iss,
      vct,
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

    const encodedSdjwt = await sdjwt.issue(claims, disclosureFrame);
    expect(encodedSdjwt).toBeDefined();
    const validated = await sdjwt.validate(encodedSdjwt);
    expect(validated).toBeDefined();

    const decoded = await sdjwt.decode(encodedSdjwt);
    const keys = await decoded.keys(digest);
    expect(keys).toEqual([
      'data',
      'data.firstname',
      'data.lastname',
      'data.list',
      'data.list.0',
      'data.list.0.r',
      'data.list.1',
      'data.list.2',
      'data.ssn',
      'data2',
      'data2.hi',
      'firstname',
      'iat',
      'id',
      'iss',
      'lastname',
      'ssn',
      'vct',
    ]);
    const payloads = await decoded.getClaims(digest);
    expect(payloads).toEqual(claims);
    const presentableKeys = await decoded.presentableKeys(digest);
    expect(presentableKeys).toEqual([
      'data.list',
      'data.list.0',
      'data.list.0.r',
      'data.list.2',
      'data2',
      'data2.hi',
      'firstname',
      'id',
    ]);

    const presentationFrame = {
      firstname: true,
      id: true,
    };
    const presentedSDJwt = await sdjwt.present<typeof claims>(
      encodedSdjwt,
      presentationFrame,
    );
    expect(presentedSDJwt).toBeDefined();

    const presentationClaims = await sdjwt.getClaims(presentedSDJwt);
    expect(presentationClaims).toBeDefined();
    expect(presentationClaims).toEqual({
      lastname: 'Doe',
      ssn: '123-45-6789',
      data: { firstname: 'John', lastname: 'Doe', ssn: '123-45-6789' },
      id: '1234',
      firstname: 'John',
      iat,
      iss,
      vct,
    });

    const requiredClaimKeys = ['firstname', 'id', 'data.ssn'];
    const verified = await sdjwt.verify(encodedSdjwt, {
      requiredClaimKeys,
    });
    expect(verified).toBeDefined();
  });

  test('From JSON (complex)', async () => {
    await JSONtest('./complex.json');
  });

  test('From JSON (array_data_types)', async () => {
    await JSONtest('./array_data_types.json');
  });

  test('From JSON (array_full_sd)', async () => {
    await JSONtest('./array_full_sd.json');
  });

  test('From JSON (array_in_sd)', async () => {
    await JSONtest('./array_in_sd.json');
  });

  test('From JSON (array_recursive_sd_some_disclosed)', async () => {
    await JSONtest('./array_recursive_sd_some_disclosed.json');
  });

  test('From JSON (header_mod)', async () => {
    await JSONtest('./header_mod.json');
  });

  test('From JSON (json_serialization)', async () => {
    await JSONtest('./json_serialization.json');
  });

  test('From JSON (key_binding)', async () => {
    await JSONtest('./key_binding.json');
  });

  test('From JSON (no_sd)', async () => {
    await JSONtest('./no_sd.json');
  });

  test('From JSON (object_data_types)', async () => {
    await JSONtest('./object_data_types.json');
  });

  test('From JSON (recursions)', async () => {
    await JSONtest('./recursions.json');
  });

  test('From JSON (array_recursive_sd)', async () => {
    await JSONtest('./array_recursive_sd.json');
  });

  test('From JSON (array_of_scalars)', async () => {
    await JSONtest('./array_of_scalars.json');
  });

  test('From JSON (array_of_objects)', async () => {
    await JSONtest('./array_of_objects.json');
  });

  test('From JSON (array_of_nulls)', async () => {
    await JSONtest('./array_of_nulls.json');
  });

  test('From JSON (array_nested_in_plain)', async () => {
    await JSONtest('./array_nested_in_plain.json');
  });
});

async function JSONtest(filename: string) {
  const test = loadTestJsonFile(filename);
  const { signer, verifier } = createSignerVerifier();
  const sdjwt = new SDJwtVcInstance({
    signer,
    signAlg: 'EdDSA',
    verifier,
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
  });

  const payload = { iss, vct, iat, ...test.claims };
  const encodedSdjwt = await sdjwt.issue(payload, test.disclosureFrame);

  expect(encodedSdjwt).toBeDefined();

  const validated = await sdjwt.validate(encodedSdjwt);

  expect(validated).toBeDefined();
  expect(validated).toStrictEqual({
    header: { alg: 'EdDSA', typ: 'dc+sd-jwt' },
    payload,
  });

  const presentedSDJwt = await sdjwt.present(
    encodedSdjwt,
    test.presentationFrames,
  );

  expect(presentedSDJwt).toBeDefined();

  const presentationClaims = await sdjwt.getClaims(presentedSDJwt);

  expect(presentationClaims).toEqual({
    ...test.presentedClaims,
    iat,
    iss,
    vct,
  });

  const verified = await sdjwt.verify(encodedSdjwt, {
    requiredClaimKeys: test.requiredClaimKeys,
  });

  expect(verified).toBeDefined();
  expect(verified).toStrictEqual({
    header: { alg: 'EdDSA', typ: 'dc+sd-jwt' },
    kb: undefined,
    payload,
  });
}

type TestJson = {
  claims: object;
  disclosureFrame: DisclosureFrame<{}>;
  presentationFrames: PresentationFrame<{}>;
  presentedClaims: object;
  requiredClaimKeys: string[];
};

function loadTestJsonFile(filename: string) {
  const filepath = path.join(__dirname, filename);
  const fileContents = fs.readFileSync(filepath, 'utf8');
  return JSON.parse(fileContents) as TestJson;
}
