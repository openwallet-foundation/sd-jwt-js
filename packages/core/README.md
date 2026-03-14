![License](https://img.shields.io/github/license/openwallet-foundation/sd-jwt-js.svg)
![NPM](https://img.shields.io/npm/v/%40sd-jwt%2Fcore)
![Release](https://img.shields.io/github/v/release/openwallet-foundation/sd-jwt-js)
![Stars](https://img.shields.io/github/stars/openwallet-foundation/sd-jwt-js)

# SD-JWT Implementation in JavaScript (TypeScript)

## SD-JWT Core

### About

Core library for [Selective Disclosure for JWTs (SD-JWT) — RFC 9901](https://www.rfc-editor.org/rfc/rfc9901.html).

This package provides types, utilities, encoding/decoding, presentation, and the main `SDJwtInstance` class — everything needed to issue, present, and verify SD-JWTs.

Check the detail description in our github [repo](https://github.com/openwallet-foundation/sd-jwt-js).

### Installation

To install this project, run the following command:

```bash
# using npm
npm install @sd-jwt/core

# using yarn
yarn add @sd-jwt/core

# using pnpm
pnpm install @sd-jwt/core
```

Ensure you have Node.js installed as a prerequisite.

### Usage

The library can be used to create sd-jwt based credentials. To be compliant with the `sd-jwt-vc` standard, you can use the `@sd-jwt/sd-jwt-vc` that is implementing this spec.
If you want to use the pure sd-jwt class or implement your own sd-jwt credential approach, you can use this library.

### Dependencies

- [@owf/identity-common](https://www.npmjs.com/package/@owf/identity-common)

### Verification

The library provides two verification approaches:

#### Standard Verification (Fail-Fast)

The `verify()` method throws an error immediately when the first validation failure is encountered:

```typescript
try {
  const result = await sdjwt.verify(credential);
  console.log('Verified payload:', result.payload);
} catch (error) {
  console.error('Verification failed:', error.message);
}
```

#### Safe Verification (Collect All Errors)

The `safeVerify()` method collects all validation errors instead of failing on the first one. This is useful when you want to show users all issues with a credential at once:

```typescript
import type { SafeVerifyResult, VerificationError } from '@sd-jwt/core';

const result = await sdjwt.safeVerify(credential);

if (result.success) {
  // Verification succeeded
  console.log('Verified payload:', result.data.payload);
  console.log('Header:', result.data.header);
  if (result.data.kb) {
    console.log('Key binding:', result.data.kb);
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

##### Error Codes

The `safeVerify()` method returns errors with the following codes:

| Code | Description |
|------|-------------|
| `HASHER_NOT_FOUND` | Hasher function not configured |
| `VERIFIER_NOT_FOUND` | Verifier function not configured |
| `INVALID_SD_JWT` | SD-JWT structure is invalid or cannot be decoded |
| `INVALID_JWT_FORMAT` | JWT format is malformed |
| `JWT_NOT_YET_VALID` | JWT `iat` or `nbf` claim is in the future |
| `JWT_EXPIRED` | JWT `exp` claim is in the past |
| `INVALID_JWT_SIGNATURE` | Signature verification failed |
| `MISSING_REQUIRED_CLAIMS` | Required claim keys are not present |
| `KEY_BINDING_JWT_MISSING` | Key binding JWT required but not present |
| `KEY_BINDING_VERIFIER_NOT_FOUND` | Key binding verifier not configured |
| `KEY_BINDING_SIGNATURE_INVALID` | Key binding signature verification failed |
| `KEY_BINDING_SD_HASH_INVALID` | Key binding `sd_hash` does not match |
| `UNKNOWN_ERROR` | An unexpected error occurred |
