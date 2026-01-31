![License](https://img.shields.io/github/license/openwallet-foundation/sd-jwt-js.svg)
![NPM](https://img.shields.io/npm/v/%40sd-jwt%2Fhash)
![Release](https://img.shields.io/github/v/release/openwallet-foundation/sd-jwt-js)
![Stars](https://img.shields.io/github/stars/openwallet-foundation/sd-jwt-js)

# SD-JWT Implementation in JavaScript (TypeScript)

## jwt-status-list

An implementation of the [Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/) for both JWT and CWT (CBOR) representations.
This library helps to verify the status of a specific entry in a JWT or CWT, and to generate a status list and pack it into a signed token. It does not provide any functions to manage the status list itself.

## Installation

To install this project, run the following command:

```bash
# using npm
npm install @sd-jwt/jwt-status-list

# using yarn
yarn add @sd-jwt/jwt-status-list

# using pnpm
pnpm install @sd-jwt/jwt-status-list
```

Ensure you have Node.js installed as a prerequisite.

## Usage

### JWT Status List

Creation of a JWT Status List:

```typescript
// pass the list as an array and the amount of bits per entry.
const list = new StatusList([1, 0, 1, 1, 1], 1);
const iss = 'https://example.com';
const payload: JWTPayload = {
    iss,
    sub: `${iss}/statuslist/1`,
    iat: Math.floor(Date.now() / 1000), // issued at time in seconds
    ttl: 3000, // time to live in seconds, optional
    exp: Math.floor(Date.now() / 1000) + 3600, // expiration time in seconds, optional
};
const header: JWTHeaderParameters = { alg: 'ES256' };

const jwt = createHeaderAndPayload(list, payload, header);

// Sign the JWT with the private key, e.g. using the `jose` library
const jwt = await new SignJWT(values.payload)
      .setProtectedHeader(values.header)
      .sign(privateKey);

```

Interaction with a JWT status list on low level:

```typescript
//validation of the JWT is not provided by this library!!!

// jwt that includes the status list reference
const reference = getStatusListFromJWT(jwt);

// download the status list
const list = await fetch(reference.uri);

//TODO: validate that the list jwt is signed by the issuer and is not expired!!!

//extract the status list
const statusList = getListFromStatusListJWT(list);

//get the status of a specific entry
const status = statusList.getStatus(reference.idx);
```

### CWT Status List (CBOR)

The library also supports CWT (CBOR Web Token) format as specified in [draft-ietf-oauth-status-list](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html).

Creation of a CWT Status List payload:

```typescript
import {
  StatusList,
  createStatusListCWTPayload,
  createStatusListCWTHeader,
  encodeCWTPayload,
  COSEAlgorithms,
} from '@sd-jwt/jwt-status-list';

// Create the status list
const list = new StatusList([1, 0, 1, 1, 1], 1);
const subject = 'https://example.com/statuslists/1';
const issuedAt = Math.floor(Date.now() / 1000);

// Create CWT payload with numeric claim keys per spec
const payload = createStatusListCWTPayload(list, subject, issuedAt, {
  exp: issuedAt + 86400, // optional: expiration in 1 day
  ttl: 43200, // optional: time to live in seconds
});

// Create CWT header (simple form with just kid)
const header = createStatusListCWTHeader(COSEAlgorithms.ES256, 'key-id-1');

// Create CWT header with X.509 key resolution options
const headerWithX509 = createStatusListCWTHeader(COSEAlgorithms.ES256, {
  kid: 'key-id-1',
  x5chain: certificateChain, // X.509 certificate chain
  x5t: certificateThumbprint, // SHA-256 thumbprint
  x5u: 'https://example.com/certs', // URL to certificates
});

// Encode to CBOR (for use in COSE_Sign1 or COSE_Mac0)
const cborPayload = encodeCWTPayload(list, subject, issuedAt, {
  exp: issuedAt + 86400,
  ttl: 43200,
});

// The COSE signing is not provided by this library.
// Use a COSE library like 'cose-js' to create the signed CWT.
```

Interaction with a CWT status list:

```typescript
import {
  getListFromStatusListCWT,
  getStatusListFromCWT,
  decodeCWTPayload,
} from '@sd-jwt/jwt-status-list';

// CWT payload validation is not provided by this library!!!

// Extract status list from CWT payload (CBOR bytes)
const statusList = getListFromStatusListCWT(cwtPayloadBytes);

// Get status of a specific entry
const status = statusList.getStatus(idx);

// Or decode the full CWT payload
const decoded = decodeCWTPayload(cwtPayloadBytes);
console.log(decoded.subject);
console.log(decoded.issuedAt);
console.log(decoded.statusList.getStatus(0));
```

For referenced tokens with status claims:

```typescript
import {
  createCWTStatusClaim,
  encodeCWTStatusClaim,
  getStatusListFromCWT,
} from '@sd-jwt/jwt-status-list';

// Create a status claim for a referenced token
const statusClaim = createCWTStatusClaim(0, 'https://example.com/statuslists/1');

// Or encode it directly to CBOR
const encodedClaim = encodeCWTStatusClaim(0, 'https://example.com/statuslists/1');

// Extract status list reference from a referenced token CWT
const reference = getStatusListFromCWT(referencedTokenPayload);
console.log(reference.idx, reference.uri);
```

#### CWT Claim Keys

The CWT format uses numeric claim keys as defined in the spec:

| Claim | Key | Description |
|-------|-----|-------------|
| sub | 2 | Subject (URI of the Status List Token) |
| exp | 4 | Expiration time |
| iat | 6 | Issued at time |
| ttl | 65534 | Time to live (seconds) |
| status_list | 65533 | Status list data |
| status | 65535 | Status claim (for referenced tokens) |

#### COSE Algorithm Constants

The library exports common COSE algorithm identifiers:

```typescript
import { COSEAlgorithms } from '@sd-jwt/jwt-status-list';

COSEAlgorithms.ES256;  // -7
COSEAlgorithms.ES384;  // -35
COSEAlgorithms.ES512;  // -36
COSEAlgorithms.EdDSA;  // -8
COSEAlgorithms.PS256;  // -37
COSEAlgorithms.RS256;  // -257
```

### Constants and Type Definitions

The library exports various constants for easier reference when building applications.

#### Status Types

Status type values as defined in Section 7 of the spec:

```typescript
import { StatusTypes } from '@sd-jwt/jwt-status-list';

StatusTypes.VALID;       // 0x00 - Token is valid
StatusTypes.INVALID;     // 0x01 - Token is revoked/invalid
StatusTypes.SUSPENDED;   // 0x02 - Token is temporarily suspended

// Application-specific values
StatusTypes.APPLICATION_SPECIFIC_3;           // 0x03
StatusTypes.APPLICATION_SPECIFIC_RANGE_START; // 0x0C
StatusTypes.APPLICATION_SPECIFIC_RANGE_END;   // 0x0F

// Example: Check if a token is valid
const status = statusList.getStatus(idx);
if (status === StatusTypes.VALID) {
  console.log('Token is valid');
} else if (status === StatusTypes.INVALID) {
  console.log('Token has been revoked');
} else if (status === StatusTypes.SUSPENDED) {
  console.log('Token is temporarily suspended');
}
```

#### Media Types

Media types for HTTP content negotiation:

```typescript
import { MediaTypes } from '@sd-jwt/jwt-status-list';

MediaTypes.STATUS_LIST_JWT;  // 'application/statuslist+jwt'
MediaTypes.STATUS_LIST_CWT;  // 'application/statuslist+cwt'

// Example: Fetch status list with correct Accept header
const response = await fetch(uri, {
  headers: {
    'Accept': MediaTypes.STATUS_LIST_JWT
  }
});
```

#### JWT Constants

```typescript
import { JWT_STATUS_LIST_TYPE, JWTClaimNames } from '@sd-jwt/jwt-status-list';

JWT_STATUS_LIST_TYPE;  // 'statuslist+jwt' - for the typ header

JWTClaimNames.STATUS;           // 'status'
JWTClaimNames.STATUS_LIST;      // 'status_list'
JWTClaimNames.TTL;              // 'ttl'
JWTClaimNames.IDX;              // 'idx'
JWTClaimNames.URI;              // 'uri'
JWTClaimNames.BITS;             // 'bits'
JWTClaimNames.LST;              // 'lst'
JWTClaimNames.AGGREGATION_URI;  // 'aggregation_uri'
```

#### CWT Constants

```typescript
import { CWT_STATUS_LIST_TYPE, CWTClaimKeys, COSEHeaderKeys } from '@sd-jwt/jwt-status-list';

CWT_STATUS_LIST_TYPE;  // 'application/statuslist+cwt' - for COSE type header

// CWT claim keys (numeric)
CWTClaimKeys.SUB;          // 2
CWTClaimKeys.EXP;          // 4
CWTClaimKeys.IAT;          // 6
CWTClaimKeys.TTL;          // 65534
CWTClaimKeys.STATUS_LIST;  // 65533
CWTClaimKeys.STATUS;       // 65535

// COSE header keys
COSEHeaderKeys.ALG;       // 1
COSEHeaderKeys.KID;       // 4
COSEHeaderKeys.TYPE;      // 16
COSEHeaderKeys.X5CHAIN;   // 33 - X.509 certificate chain
COSEHeaderKeys.X5T;       // 34 - X.509 SHA-256 thumbprint
COSEHeaderKeys.X5U;       // 35 - X.509 URL
```

### Integration into sd-jwt-vc

The status list can be integrated into the [sd-jwt-vc](../sd-jwt-vc/README.md) library to provide a way to verify the status of a credential. In the [test folder](../sd-jwt-vc/src/test/index.spec.ts) you will find an example how to add the status reference to a credential and also how to verify the status of a credential.

### Caching the status list

Depending on the  `ttl` field if provided the status list can be cached for a certain amount of time. This library has no internal cache mechanism, so it is up to the user to implement it for example by providing a custom `fetchStatusList` function.

## Development

Install the dependencies:

```bash
pnpm install
```

Run the tests:

```bash
pnpm test
```

