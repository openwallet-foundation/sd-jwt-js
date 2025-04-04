## Overview

```ts
const encodedSdjwt = await sdjwt.issue(payload, disclosureFrame, options);
```

## Parameters

- payload: the payload of SD JWT [Object]
- disclosureFrame: to define which properties should be selectively diclosable (optional, if not provided, there is no disclosure)
- options: (optional)

```ts
options?: {
  header: object; // this is custom header of JWT.
},
```

## Returns

encoded SDJWT string

- hash_alg: sha-256
