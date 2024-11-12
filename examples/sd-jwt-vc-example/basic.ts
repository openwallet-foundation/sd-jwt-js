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
      iat: new Date().getTime(),
      vct: 'ExampleCredentials',
      ...claims,
    },
    disclosureFrame,
  );

  // Holder Receive the credential from the issuer and validate it
  // Return a result of header and payload
  const valid = await sdjwt.validate(credential);

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
  const verified = await sdjwt.verify(presentation, requiredClaims);
  console.log(verified);
})();
