![License](https://img.shields.io/github/license/openwallet-foundation/sd-jwt-js.svg)
![NPM](https://img.shields.io/npm/v/%40sd-jwt%2Ftypes)
![Release](https://img.shields.io/github/v/release/openwallet-foundation/sd-jwt-js)
![Stars](https://img.shields.io/github/stars/openwallet-foundation/sd-jwt-js)

# SD-JWT Implementation in JavaScript (TypeScript)

## SD-JWT Browser Types

### About

Types for SD JWT

Check the detail description in our github [repo](https://github.com/openwallet-foundation/sd-jwt-js).

### Installation

To install this project, run the following command:

```bash
# using npm
npm install @sd-jwt/types

# using yarn
yarn add @sd-jwt/types

# using pnpm
pnpm install @sd-jwt/types
```

Ensure you have Node.js installed as a prerequisite.

### Usage

Check out more details in our [documentation](https://github.com/openwallet-foundation/sd-jwt-js/tree/main/docs) or [examples](https://github.com/openwallet-foundation/sd-jwt-js/tree/main/examples)

### Verification Types

The package exports types for safe verification that collects all errors:

```typescript
import type {
  SafeVerifyResult,
  VerificationError,
  VerificationErrorCode,
} from '@sd-jwt/types';

// SafeVerifyResult<T> is a discriminated union:
// - { success: true; data: T } on success
// - { success: false; errors: VerificationError[] } on failure

// VerificationError contains:
// - code: VerificationErrorCode (e.g., 'INVALID_JWT_SIGNATURE')
// - message: string
// - details?: unknown
```

### Dependencies

None
