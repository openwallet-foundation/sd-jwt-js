![License](https://img.shields.io/github/license/openwallet-foundation/sd-jwt-js.svg)
![NPM](https://img.shields.io/npm/v/%40sd-jwt%2Fhash)
![Release](https://img.shields.io/github/v/release/openwallet-foundation/sd-jwt-js)
![Stars](https://img.shields.io/github/stars/openwallet-foundation/sd-jwt-js)

# SD-JWT Implementation in JavaScript (TypeScript)

## jwt-status-list

An implementation of the [Token Status List](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/) for a JWT representation, not for CBOR.
This library helps to verify the status of a specific entry in a JWT, and to generate a status list and pack it into a signed JWT. It does not provide any functions to manage the status list itself.

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
