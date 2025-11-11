import Crypto from 'node:crypto';
import { afterEach } from 'node:test';
import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import type { DisclosureFrame, Signer, Verifier } from '@sd-jwt/types';
import { HttpResponse, http } from 'msw';
import { setupServer } from 'msw/node';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { SDJwtVcInstance } from '..';
import type { SdJwtVcPayload } from '../sd-jwt-vc-payload';
import type { TypeMetadataFormat } from '../sd-jwt-vc-type-metadata-format';

const exampleVctm = {
  vct: 'http://example.com/example',
  name: 'ExampleCredentialType',
  description: 'An example credential type',  
};

const restHandlers = [  
  http.get('http://example.com/example', () => {
    const res: TypeMetadataFormat = exampleVctm;
    return HttpResponse.json(res);
  }),
  http.get('http://example.com/timeout', () => {
    return new Promise((resolve) => {
      setTimeout(() => {
        resolve(HttpResponse.json({}));
      }, 10000);
    });
  }),
];

//this value could be generated on demand to make it easier when changing the values
const vctIntegrity =
  'sha256-e8bf419e6b860595f385611fc6172f1e95c18de3c80eef57c865f49e03747637';

const server = setupServer(...restHandlers);

const iss = 'ExampleIssuer';
const vct = 'http://example.com/example';
const iat = Math.floor(Date.now() / 1000); // current time in seconds

const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');

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

describe('App', () => {
  const { signer, verifier } = createSignerVerifier();

  const sdjwt = new SDJwtVcInstance({
    signer,
    signAlg: 'EdDSA',
    verifier,
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
    loadTypeMetadataFormat: true,
    timeout: 1000,
  });

  const claims = {
    firstname: 'John',
  };
  const disclosureFrame = {
    _sd: ['firstname'],
  };

  beforeAll(() => server.listen({ onUnhandledRequest: 'warn' }));

  afterAll(() => server.close());

  afterEach(() => server.resetHandlers());

  test('VCT Validation', async () => {
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct,
      'vct#Integrity': vctIntegrity,
      ...claims,
    };
    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>,
    );

    await sdjwt.verify(encodedSdjwt);
  });

  test('VCT from JWT header Validation', async () => {
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct,
      'vct#Integrity': vctIntegrity,
      ...claims,
    };
    const header = {
      vctm: [Buffer.from(JSON.stringify(exampleVctm)).toString('base64url')],
    };
    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>,
      { header },
    );

    await sdjwt.verify(encodedSdjwt);
  });

  test('VCT Validation with timeout', async () => {
    const vct = 'http://example.com/timeout';
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct,
      ...claims,
    };
    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>,
    );

    expect(sdjwt.verify(encodedSdjwt)).rejects.toThrowError(
      `Request to ${vct} timed out`,
    );
  });

  test('VCT Metadata retrieval', async () => {
    const expectedPayload: SdJwtVcPayload = {
      iat,
      iss,
      vct,
      'vct#Integrity': vctIntegrity,
      ...claims,
    };
    const encodedSdjwt = await sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>,
    );

    const typeMetadataFormat = await sdjwt.getVct(encodedSdjwt);
    expect(typeMetadataFormat).to.deep.eq({
      description: 'An example credential type',
      name: 'ExampleCredentialType',      
      vct: 'http://example.com/example',
    });
  });

  //TODO: we need tests with an embedded schema, extended and maybe also to test the errors when schema information is not available or the integrity is not valid
});
