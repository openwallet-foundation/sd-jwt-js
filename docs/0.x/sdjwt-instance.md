## Create new Instance of SDJwtInstance

You can create a new instance of sdjwt with a custom config.

```ts
import sdjwtInstance from '@sd-jwt/core';

const sdjwt = new SDJwtInstance({
  signer,
  verifier,
  signAlg: 'EdDSA',
  hasher: digest,
  hashAlg: 'sha-256',
  saltGenerator: generateSalt,
});
```

You can change the instances config by using config method.

## Configurations

```ts
sdjwt.config({
  hasher: CustomHasher,
});
```

- The config type

```ts
type SDJWTConfig = {
  // omit typ property in JWT header
  omitTyp?: boolean;
  // hash function: (data: string) => Promise<string> or string;
  hasher?: Hasher;
  // hash algorithm string (e.g. 'sha-256')
  hashAlg?: string;
  // salt generate function: (length: number) => Promise<string> or string;
  saltGenerator?: SaltGenerator;
  // sign function: (data: string) => Promise<string> or string;
  signer?: Signer;
  // sign algorithm string (e.g. 'EdDSA')
  signAlg?: string;
  // verify function: (data: string, signature: string) => Promise<boolean> or boolean;
  verifier?: Verifier;
  // optional key binding sign function
  kbSigner?: Signer;
  // optional key binding sign algorithm
  kbSignAlg?: string;
  // optional key binding verify function: (data: string, sig: string, payload: JwtPayload) => Promise<boolean> or boolean;
  // JwtPayload: { cnf?: { jwk: JsonWebKey } }
  kbVerifier?: KbVerifier;
};
```

## Methods

- issue(payload[, disclosureFrame, options])
- present(encodedSDJwt[, presentationFrame, options])
- validate(encodedSDJwt)
- verify(encodedSDJwt[, verifierConfig])
- config(newConfig)
- encode(sdJwt)
- decode(encodedSDJwt)
- keys(encodedSDJwt)
- presentableKeys(encodedSDJwt)
- getClaims(encodedSDJwt)
