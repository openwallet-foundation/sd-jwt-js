import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { DisclosureFrame } from '@sd-jwt/types';
import { createSignerVerifier, digest, ES256, generateSalt } from './utils';

(async () => {
  const { signer, verifier } = await createSignerVerifier();

  // Create SDJwt instance for use
  const sdjwt = new SDJwtVcInstance({
    signer,
    verifier,
    signAlg: ES256.alg,
    hasher: digest,
    hashAlg: 'SHA-256',
    saltGenerator: generateSalt,
  });
  // Issuer Define the claims object with the user's information
  const claims = {
    lastname: 'Doe',
    ssn: '123-45-6789',
    id: '1234',
  };

  // Issuer Define the disclosure frame to specify which claims can be disclosed
  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['id'],
    _sd_decoy: 1, // 1 decoy digest will be added in SD JWT
  };
  const credential = await sdjwt.issue(
    {
      iss: 'Issuer',
      iat: new Date().getTime(),
      vct: 'ExampleCredentials',
      ...claims,
    },
    disclosureFrame,
  );
  console.log('encodedSdjwt:', credential);

  // You can check the decoy digest in the SD JWT by decoding it
  const sdJwtToken = await sdjwt.decode(credential);
  console.log(sdJwtToken);
})();
