import type { DisclosureFrame, SDJWTConfig, Verifier } from '@sd-jwt/types';
import { createSignerVerifier, digest, ES256, generateSalt } from './utils';
import { SDJwtInstance } from '@sd-jwt/core';

// 1. Define your extended options type
type TrustListOptions = {
  trustAnchors: string[];
};

(async () => {
  const { signer, verifier } = await createSignerVerifier();

  // 2. Create an extended verifier that uses the options
  const extendedVerifier: Verifier<TrustListOptions> = async (
    data: string,
    signature: string,
    options?: TrustListOptions,
  ) => {
    // Example: check trustAnchors
    if (
      !options?.trustAnchors?.includes('trusted-issuer')
    ) {
      return false;
    }
    return verifier(data, signature);
  };

  const sdjwt = new SDJwtInstance<typeof claims, TrustListOptions>({
    signer,
    verifier: extendedVerifier, // use the extended verifier
    signAlg: ES256.alg,
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
  });

  // Issuer Define the claims object with the user's information
  const claims = {
    firstname: 'John',
    lastname: 'Doe',
    ssn: '123-45-6789',
    id: '1234',
  };

  // Issuer Define the disclosure frame to specify which claims can be disclosed
  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['firstname', 'lastname', 'ssn'],
  };

  // Issue a signed JWT credential with the specified claims and disclosures
  // Return a Encoded SD JWT. Issuer send the credential to the holder
  const credential = await sdjwt.issue(
    {
      iss: 'Issuer',
      iat: Math.floor(Date.now() / 1000),
      vct: 'ExampleCredentials',
      ...claims,
    },
    disclosureFrame,
  );

  // Holder Receive the credential from the issuer and validate it
  // Return a result of header and payload
  const _valid = await sdjwt.validate(credential);

  // Holder Define the presentation frame to specify which claims should be presented
  // The list of presented claims must be a subset of the disclosed claims
  // the presentation frame is determined by the verifier or the protocol that was agreed upon between the holder and the verifier
  const presentationFrame = { firstname: true, id: true, ssn: true };

  // Create a presentation using the issued credential and the presentation frame
  // return a Encoded SD JWT. Holder send the presentation to the verifier
  const presentation = await sdjwt.present<typeof claims>(
    credential,
    presentationFrame,
  );

  // Verifier Define the required claims that need to be verified in the presentation
  const requiredClaims = ['firstname', 'ssn', 'id'];

  // Verify the presentation using the public key and the required claims
  // return a boolean result
  const verified = await sdjwt.verify(credential, {
    requiredClaimKeys: requiredClaims,
    trustAnchors: ['trusted-issuer'],
  });
  console.log(verified);
})();
