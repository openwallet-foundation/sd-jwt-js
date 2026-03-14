![Coverage](https://img.shields.io/codecov/c/github/openwallet-foundation/sd-jwt-js)
![License](https://img.shields.io/github/license/openwallet-foundation/sd-jwt-js.svg)
![NPM](https://img.shields.io/npm/v/%40sd-jwt%2Fcore)
![Release](https://img.shields.io/github/v/release/openwallet-foundation/sd-jwt-js)
![Stars](https://img.shields.io/github/stars/openwallet-foundation/sd-jwt-js)

# SD-JWT Implementation in JavaScript (TypeScript)

A framework-agnostic, production-ready implementation of [Selective Disclosure for JWTs (SD-JWT)](https://www.rfc-editor.org/rfc/rfc9901.html) in TypeScript. Works with Node.js, React, React Native, and browser environments. Optimised for compact QR code payloads.

> **Note:** This repository has been restructured to focus exclusively on SD-JWT and SD-JWT-VC. The previous utility packages (`@sd-jwt/types`, `@sd-jwt/utils`, `@sd-jwt/decode`, `@sd-jwt/present`, `@sd-jwt/hash`, `@sd-jwt/crypto-nodejs`, `@sd-jwt/crypto-browser`) have been consolidated into `@sd-jwt/core`. The Token Status List package (`@sd-jwt/jwt-status-list`) has been moved to the [identity-common-ts](https://github.com/openwallet-foundation/identity-common-ts) project as `@owf/token-status-list`.

Compliant with:

- **[SD-JWT — RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html)**
- **[SD-JWT-VC — draft-ietf-oauth-sd-jwt-vc-15](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/15/)**

## Quick Start

```bash
npm install @sd-jwt/core
# or: pnpm install @sd-jwt/core
```

```typescript
import Crypto from 'node:crypto';
import { SDJwtInstance } from '@sd-jwt/core';

// Bring your own crypto – any Signer / Verifier / Hasher that fits the interface
const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');

const sdjwt = new SDJwtInstance({
  signer: async (data) => {
    const sig = Crypto.sign(null, Buffer.from(data), privateKey);
    return Buffer.from(sig).toString('base64url');
  },
  verifier: async (data, sig) => {
    return Crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(sig, 'base64url'));
  },
  signAlg: 'EdDSA',
  hasher: async (data, alg) => {
    return new Uint8Array(Crypto.createHash(alg.replace('-', '')).update(data).digest());
  },
  hashAlg: 'sha-256',
  saltGenerator: async () => Crypto.randomBytes(16).toString('base64url'),
});

// Issue
const credential = await sdjwt.issue(
  { firstname: 'John', lastname: 'Doe', ssn: '123-45-6789' },
  { _sd: ['firstname', 'lastname', 'ssn'] },
);

// Present (disclose only firstname)
const presentation = await sdjwt.present(credential, { firstname: true });

// Verify
const { payload } = await sdjwt.verify(presentation);
console.log(payload); // { firstname: 'John', ... }
```

See the [examples/](./examples/) directory for more detailed usage.

## Packages

| Package | Description |
|---------|-------------|
| [@sd-jwt/core](./packages/core/README.md) | Core library — encoding, decoding, selective disclosure, presentation, and verification |
| [@sd-jwt/sd-jwt-vc](./packages/sd-jwt-vc/README.md) | SD-JWT Verifiable Credentials format built on top of `@sd-jwt/core` |

Both packages are versioned in sync.

## Online Debugging Tool

Inspect and debug SD-JWTs in the browser: **https://sdjwt.co**

## Development

**Prerequisites:** Node.js >= 20, pnpm >= 9

```bash
pnpm install
pnpm run build
```

### Testing

```bash
pnpm test
```

We use [Vitest](https://vitest.dev/) and [CodeCov](https://app.codecov.io/gh/openwallet-foundation/sd-jwt-js) for coverage.

## Security

- [x] [Mandatory Signing of the Issuer-signed JWT](https://www.rfc-editor.org/rfc/rfc9901.html#name-mandatory-signing-of-the-is)
- [x] [Manipulation of Disclosures](https://www.rfc-editor.org/rfc/rfc9901.html#name-manipulation-of-disclosures)
- [x] [Entropy of the salt](https://www.rfc-editor.org/rfc/rfc9901.html#name-entropy-of-the-salt)
- [x] [Minimum length of the salt](https://www.rfc-editor.org/rfc/rfc9901.html#name-minimum-length-of-the-salt)
- [x] [Choice of a Hash Algorithm](https://www.rfc-editor.org/rfc/rfc9901.html#name-choice-of-a-hash-algorithm)
- [x] [Key Binding](https://www.rfc-editor.org/rfc/rfc9901.html#name-key-binding)
- [x] [Blinding Claim Names](https://www.rfc-editor.org/rfc/rfc9901.html#name-blinding-claim-names)
- [x] [Selectively-Disclosable Validity Claims](https://www.rfc-editor.org/rfc/rfc9901.html#name-selectively-disclosable-val)
- [x] [Issuer Signature Key Distribution and Rotation](https://www.rfc-editor.org/rfc/rfc9901.html#name-issuer-signature-key-distri)
- [x] [Forwarding Credentials](https://www.rfc-editor.org/rfc/rfc9901.html#name-forwarding-credentials)
- [x] [Integrity of Presentation](https://www.rfc-editor.org/rfc/rfc9901.html#name-integrity-of-presentation)
- [x] [Explicit Typing](https://www.rfc-editor.org/rfc/rfc9901.html#name-explicit-typing)
- [x] [Duplicate Digest Rejection (Section 7.1 step 4)](https://www.rfc-editor.org/rfc/rfc9901.html#section-7.1)
- [x] [Unreferenced Disclosure Rejection (Section 7.1 step 5)](https://www.rfc-editor.org/rfc/rfc9901.html#section-7.1)
- [x] [Claim Name Collision Detection (Section 7.1 step 3c.ii.3)](https://www.rfc-editor.org/rfc/rfc9901.html#section-7.1)

## Contributing

Contributions are welcome! Please read our [contributing guidelines](./CONTRIBUTING.md) before making pull requests.

## License

This project is licensed under the [Apache 2.0 License](./LICENSE).

## Contact

For support or contributions, find us in [OpenWallet Foundation Discord](https://discord.com/invite/yjvGPd5FCU).

## Acknowledgments

Special thanks to all the contributors and the OpenWallet Foundation community for their invaluable input.
