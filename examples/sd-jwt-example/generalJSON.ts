import {
  GeneralJSON,
  SDJwtGeneralJSONInstance,
  SDJwtInstance,
} from '@sd-jwt/core';
import type { DisclosureFrame } from '@sd-jwt/types';
import { createSignerVerifier, digest, generateSalt, ES256 } from './utils';

(async () => {
  const { signer, verifier } = await createSignerVerifier();

  // Create SDJwt instance for use
  const sdjwt = new SDJwtInstance({
    signer,
    signAlg: ES256.alg,
    verifier,
    hasher: digest,
    saltGenerator: generateSalt,
    kbSigner: signer,
    kbSignAlg: ES256.alg,
    kbVerifier: verifier,
  });
  const generalJSONSdJwt = new SDJwtGeneralJSONInstance({
    hasher: digest,
    verifier,
  });
  const claims = {
    firstname: 'John',
    lastname: 'Doe',
    ssn: '123-45-6789',
    id: '1234',
  };
  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['firstname', 'id'],
  };

  const kbPayload = {
    iat: Math.floor(Date.now() / 1000),
    aud: 'https://example.com',
    nonce: '1234',
    custom: 'data',
  };

  const encodedSdjwt = await sdjwt.issue(claims, disclosureFrame);
  console.log('encodedSdjwt:', encodedSdjwt);

  const generalJSON = GeneralJSON.fromEncode(encodedSdjwt);
  console.log('generalJSON(credential): ', generalJSON.toJson());

  const presentedSdJwt = await sdjwt.present<typeof claims>(
    encodedSdjwt,
    { id: true },
    {
      kb: {
        payload: kbPayload,
      },
    },
  );

  const generalPresentationJSON = GeneralJSON.fromEncode(presentedSdJwt);

  await generalPresentationJSON.addSignature(
    {
      alg: 'ES256',
      typ: 'sd+jwt',
      kid: 'key-1',
    },
    signer,
    'key-1',
  );

  console.log(
    'flattenJSON(presentation): ',
    JSON.stringify(generalPresentationJSON.toJson(), null, 2),
  );

  const verified = await sdjwt.verify(presentedSdJwt, {
    requiredClaimKeys: ['firstname', 'id'],
    keyBindingNonce: '1234',
  });
  console.log(verified);

  const generalVerified = await generalJSONSdJwt.verify(generalJSON);
  console.log(generalVerified);
})();
