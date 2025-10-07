import Crypto from 'node:crypto';
import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import {
  createHeaderAndPayload,
  StatusList,
  type StatusListJWTHeaderParameters,
} from '@sd-jwt/jwt-status-list';
import type {
  DisclosureFrame,
  JwtPayload,
  Signer,
  Verifier,
} from '@sd-jwt/types';
import { SignJWT } from 'jose';
import { describe, expect, test } from 'vitest';
import { SDJwtVcInstance } from '..';
import type { SdJwtVcPayload } from '../sd-jwt-vc-payload';

const iss = 'ExampleIssuer';
const vct = 'ExampleCredentialType';
const iat = Math.floor(Date.now() / 1000);

const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');

//create a separate keypair for the status list
const { privateKey: statusListPrivateKey, publicKey: statusListPublicKey } =
  Crypto.generateKeyPairSync('ed25519');

//TODO: to simulate a hosted status list, use the same appraoch as in vct.spec.ts

const createSignerVerifier = () => {
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

const generateStatusList = async (): Promise<string> => {
  const statusList = new StatusList([0, 1, 0, 0, 0, 0, 1, 1], 1);
  const payload: JwtPayload = {
    iss: 'https://example.com',
    sub: 'https://example.com/status/1',
    iat: Math.floor(Date.now() / 1000),
  };
  const header: StatusListJWTHeaderParameters = {
    alg: 'EdDSA',
    typ: 'statuslist+jwt',
  };
  const values = createHeaderAndPayload(statusList, payload, header);
  return new SignJWT(values.payload)
    .setProtectedHeader(values.header)
    .sign(statusListPrivateKey);
};

const statusListJWT = await generateStatusList();

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
    };
    const disclosureFrame = {
      _sd: ['firstname', 'iss'],
    };

    const expectedPayload: SdJwtVcPayload = { iat, iss, vct, ...claims };
    const encodedSdjwt = sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>,
    );
    expect(encodedSdjwt).rejects.toThrowError();
  });
});

describe('Revocation', () => {
  const { signer, verifier } = createSignerVerifier();
  const sdjwt = new SDJwtVcInstance({
    signer,
    signAlg: 'EdDSA',
    verifier,
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
    statusListFetcher(_uri: string) {
      // we emulate fetching the status list from the uri. Validation of the JWT is not done here in the test but should be done in the implementation.
      return Promise.resolve(statusListJWT);
    },
    // statusValidator(status: number) {
    //   // we are only accepting status 0
    //   if (status === 0) return Promise.resolve();
    //   throw new Error('Status is not valid');
    // },
    statusVerifier: async (data: string, sig: string) => {
      //we could also look into the data to extract the public key from the x5c when provided
      return Crypto.verify(
        null,
        Buffer.from(data),
        statusListPublicKey,
        Buffer.from(sig, 'base64url'),
      );
    },
  });

  test('Test with a non revcoked credential', async () => {
    const claims = {
      firstname: 'John',
      status: {
        status_list: {
          uri: 'https://example.com/status-list',
          idx: 0,
        },
      },
    };
    const expectedPayload: SdJwtVcPayload = { iat, iss, vct, ...claims };
    const encodedSdjwt = await sdjwt.issue(expectedPayload);
    const result = await sdjwt.verify(encodedSdjwt);
    expect(result).toBeDefined();
  });

  test('Test with a revoked credential', async () => {
    const claims = {
      firstname: 'John',
      status: {
        status_list: {
          uri: 'https://example.com/status-list',
          idx: 1,
        },
      },
    };
    const expectedPayload: SdJwtVcPayload = { iat, iss, vct, ...claims };
    const encodedSdjwt = await sdjwt.issue(expectedPayload);
    const result = sdjwt.verify(encodedSdjwt);
    expect(result).rejects.toThrowError('Status is not valid');
  });

  test('test to fetch the statuslist', async () => {
    //TODO: not implemented yet since we need to either mock the fetcher or use a real fetcher
  });

  test('test with an expired status list', async () => {
    //TODO: needs to be implemented
  });
});
