# SD JWT VCDM Typescript

> ⚠️ **Platform Support**: This package currently supports Node.js environments only.

Typescript implementation of SD JWT VCDM profile.

A library that integrates SD-JWT with W3C Verifiable Credentials Data Model and implements JAdES digital signature standards.

## Features

### SD-JWT VCDM Data Model Profile

This library provides interoperability between SD-JWT (Selective Disclosure JWT) and W3C Verifiable Credentials Data Model:

- Issue Verifiable Digital Credentials in SD-JWT VC format while maintaining W3C VCDM compliance
- Support for Selective Disclosure capabilities
- Seamless integration with standard VC verification processes

### JAdES Digital Signature Integration

Implements JAdES (JSON Advanced Electronic Signatures) standard for SD-JWT with support for the following signature profiles:

- **B-B (Basic - Baseline)**: Basic signature format
- **B-T (Basic with Time)**: Signatures with timestamp
- **B-LT (Basic Long-Term)**: Signatures with validation data for long-term preservation
- **B-LTA (Basic Long-Term with Archive timestamps)**: Long-term preservation with periodic timestamp renewal

## Installation

```bash
pnpm add sd-jwt-vcdm
```

## Usage

### B-B

```typescript
import { JAdES, parseCerts, createKidFromCert } from 'sd-jwt-jades';
import * as fs from 'fs';
import { createPrivateKey } from 'node:crypto';

(async () => {
  const jades = new JAdES.Sign({ data: 'data 1', target: 'data 2' });

  const certPem = fs.readFileSync('./fixtures/certificate.crt', 'utf-8');
  const certs = parseCerts(certPem);
  const kid = createKidFromCert(certs[0]);

  const keyPem = fs.readFileSync('./fixtures/private.pem', 'utf-8');
  const privateKey = createPrivateKey(keyPem);

  await jades
    .setProtectedHeader({
      alg: 'RS256',
      typ: 'jades',
    })
    .setX5c(certs)
    .setDisclosureFrame({
      _sd: ['data'],
    })
    .setSignedAt()
    .sign(privateKey, kid);

  const serialized = jades.toJSON();
  console.log(serialized);
})();
```

### B-T

```typescript
import { JAdES, parseCerts, createKidFromCert } from 'sd-jwt-jades';
import * as fs from 'fs';
import { createPrivateKey } from 'node:crypto';

(async () => {
  const jades = new JAdES.Sign({ data: 'data 1', target: 'data 2' });

  const certPem = fs.readFileSync('./fixtures/certificate.crt', 'utf-8');
  const certs = parseCerts(certPem);
  const kid = createKidFromCert(certs[0]);

  const keyPem = fs.readFileSync('./fixtures/private.pem', 'utf-8');
  const privateKey = createPrivateKey(keyPem);

  await jades
    .setProtectedHeader({
      alg: 'RS256',
      typ: 'jades',
    })
    .setX5c(certs)
    .setDisclosureFrame({
      _sd: ['data'],
    })
    .setSignedAt()
    .setUnprotectedHeader({
      etsiU: [
        {
          sigTst: {
            tstTokens: [
              {
                val: 'Base64-encoded RFC 3161 Timestamp Token',
              },
            ],
          },
        },
      ],
    })
    .sign(privateKey, kid);

  const serialized = jades.toJSON();
  console.log(serialized);
})();
```

### B-LT

```typescript
import { JAdES, parseCerts, createKidFromCert } from 'sd-jwt-jades';
import * as fs from 'fs';
import { createPrivateKey } from 'node:crypto';

(async () => {
  const jades = new JAdES.Sign({ data: 'data 1', target: 'data 2' });

  const certPem = fs.readFileSync('./fixtures/certificate.crt', 'utf-8');
  const certs = parseCerts(certPem);
  const kid = createKidFromCert(certs[0]);

  const keyPem = fs.readFileSync('./fixtures/private.pem', 'utf-8');
  const privateKey = createPrivateKey(keyPem);

  await jades
    .setProtectedHeader({
      alg: 'RS256',
      typ: 'jades',
    })
    .setX5c(certs)
    .setDisclosureFrame({
      _sd: ['data'],
    })
    .setSignedAt()
    .setUnprotectedHeader({
      etsiU: [
        {
          sigTst: {
            tstTokens: [
              {
                val: 'Base64-encoded RFC 3161 Timestamp Token',
              },
            ],
          },
        },
        {
          xVals: [
            { x509Cert: 'Base64-encoded Trust Anchor' },
            { x509Cert: 'Base64-encoded CA Certificate' },
          ],
        },
        {
          rVals: {
            crlVals: ['Base64-encoded CRL'],
            ocspVals: ['Base64-encoded OCSP Response'],
          },
        },
      ],
    })
    .sign(privateKey, kid);

  const serialized = jades.toJSON();
  console.log(serialized);
})();
```

### B-LTA

```typescript
import { JAdES, parseCerts, createKidFromCert } from 'sd-jwt-jades';
import * as fs from 'fs';
import { createPrivateKey } from 'node:crypto';

(async () => {
  const jades = new JAdES.Sign({ data: 'data 1', target: 'data 2' });

  const certPem = fs.readFileSync('./fixtures/certificate.crt', 'utf-8');
  const certs = parseCerts(certPem);
  const kid = createKidFromCert(certs[0]);

  const keyPem = fs.readFileSync('./fixtures/private.pem', 'utf-8');
  const privateKey = createPrivateKey(keyPem);

  await jades
    .setProtectedHeader({
      alg: 'RS256',
      typ: 'jades',
    })
    .setX5c(certs)
    .setDisclosureFrame({
      _sd: ['data'],
    })
    .setSignedAt()
    .sign(privateKey, kid);

  const serialized = jades.toJSON();
  console.log(serialized);
})();
```

## License

Apache License 2.0

## References

- [SD-JWT VC Data Model](https://github.com/danielfett/sd-jwt-vc-dm)
- [OpenID4VC HAIP Profile](https://github.com/openid/oid4vc-haip/pull/147/files#diff-762ef65fd82909517226ac1bb7e8855792bb57021abc1637c15b8557154dbbf1)
- [ETSI TS 119 182-1 - JAdES Baseline Signatures](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.02.01_60/ts_11918201v010201p.pdf)
