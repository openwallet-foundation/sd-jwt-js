![License](https://img.shields.io/github/license/openwallet-foundation/sd-jwt-js.svg)
![NPM](https://img.shields.io/npm/v/%40sd-jwt%2Fcore)
![Release](https://img.shields.io/github/v/release/openwallet-foundation/sd-jwt-js)
![Stars](https://img.shields.io/github/stars/openwallet-foundation/sd-jwt-js)

# SD-JWT Implementation in JavaScript (TypeScript)

## SD-JWT-VC

### About

SD-JWT-VC format based on the core functions

Check the detail description in our github [repo](https://github.com/openwallet-foundation/sd-jwt-js).

### Installation

To install this project, run the following command:

```bash
# using npm
npm install @sd-jwt/sd-jwt-vc

# using yarn
yarn add @sd-jwt/sd-jwt-vc

# using pnpm
pnpm install @sd-jwt/sd-jwt-vc
```

Ensure you have Node.js installed as a prerequisite.

### Usage

Here's a basic example of how to use this library:

```jsx
import { DisclosureFrame } from '@sd-jwt/sd-jwt-vc';

// identifier of the issuer
const iss = 'University';

// issuance time
const iat = Math.floor(Date.now() / 1000); // current time in seconds

//unique identifier of the schema
const vct = 'University-Degree';

// Issuer defines the claims object with the user's information
const claims = {
  firstname: 'John',
  lastname: 'Doe',
  ssn: '123-45-6789',
  id: '1234',
};

// Issuer defines the disclosure frame to specify which claims can be disclosed/undisclosed
const disclosureFrame: DisclosureFrame<typeof claims> = {
  _sd: ['firstname', 'lastname', 'ssn'],
};

// Issuer issues a signed JWT credential with the specified claims and disclosure frame
// returns an encoded JWT
const credential = await sdjwt.issue(
  { iss, iat, vct, ...claims },
  disclosureFrame,
);

// Holder may validate the credential from the issuer
const valid = await sdjwt.validate(credential);

// Holder defines the presentation frame to specify which claims should be presented
// The list of presented claims must be a subset of the disclosed claims
const presentationFrame = { firstname: true, ssn: true };

// Holder creates a presentation using the issued credential and the presentation frame
// returns an encoded SD JWT.
const presentation = await sdjwt.present(credential, presentationFrame);

// Verifier can verify the presentation using the Issuer's public key
const verified = await sdjwt.verify(presentation);
```

Check out more details in our [documentation](https://github.com/openwallet-foundation/sd-jwt-js/tree/main/docs) or [examples](https://github.com/openwallet-foundation/sd-jwt-js/tree/main/examples)

### Revocation

To add revocation capabilities, you can use the `@sd-jwt/jwt-status-list` library to create a JWT Status List and include it in the SD-JWT-VC.

You can pass a dedicated `statusVerifier` function in the configuration to verify the signature of the payload of the JWT of the statuslist. If no function is provided, it will fallback to the verifier that is also used for the sd-jwt-vc.

### Type Metadata

By setting the `loadTypeMetadataFormat` to `true` like this:

```typescript
const sdjwt = new SDJwtVcInstance({
  signer,
  signAlg: 'EdDSA',
  verifier,
  hasher: digest,
  hashAlg: 'sha-256',
  saltGenerator: generateSalt,
  loadTypeMetadataFormat: true,
});
```

The library will load load the type metadata format based on the `vct` value according to the [SD-JWT-VC specification](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-08.html#name-sd-jwt-vc-type-metadata) and validate this schema.

Since at this point the display is not yet implemented, the library will only validate the schema and return the type metadata format. In the future the values of the type metadata can be fetched via a function call.

### Verification

The library provides two verification approaches:

#### Standard Verification (Fail-Fast)

The `verify()` method throws an error immediately when the first validation failure is encountered:

```typescript
try {
  const result = await sdjwt.verify(presentation);
  console.log('Verified payload:', result.payload);
} catch (error) {
  console.error('Verification failed:', error.message);
}
```

#### Safe Verification (Collect All Errors)

The `safeVerify()` method collects all validation errors instead of failing on the first one. This is useful when you want to show users all issues with a credential at once, including signature, status (revocation), and VCT metadata validation:

```typescript
import type { SafeVerifyResult, VerificationError } from '@sd-jwt/types';

const result = await sdjwt.safeVerify(presentation);

if (result.success) {
  // Verification succeeded
  console.log('Verified payload:', result.payload);
  console.log('Header:', result.header);
  if (result.kb) {
    console.log('Key binding:', result.kb);
  }
  if (result.typeMetadata) {
    console.log('Type metadata:', result.typeMetadata);
  }
} else {
  // Verification failed - inspect all errors
  for (const error of result.errors) {
    console.error(`[${error.code}] ${error.message}`);
    if (error.details) {
      console.error('Details:', error.details);
    }
  }
}
```

##### SD-JWT-VC Specific Error Codes

In addition to the [core error codes](../core/README.md#error-codes), `safeVerify()` in SD-JWT-VC can return:

| Code | Description |
|------|-------------|
| `STATUS_VERIFICATION_FAILED` | Status list fetch or verification failed |
| `STATUS_INVALID` | Credential status indicates revocation |
| `VCT_VERIFICATION_FAILED` | VCT type metadata fetch or validation failed |

### Dependencies

- @sd-jwt/core
- @sd-jwt/types
- @sd-jwt/utils
- @sd-jwt/jwt-status-list
