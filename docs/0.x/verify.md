```ts
const verified = await sdjwt.verify(
  encodedSdjwt,
  {
    requiredClaims: ['id', 'ssn'], // required claims to verify
    keyBindingNonce: 'secure_none'
  }
);
```

## Parameters

- encodedSdjwt: encoded SD JWT [string]
- requiredClaimKeys: required JSON properties to verify [Array<string>] (optional)
- requireKeyBindings: required verify Key Binding JWT [boolean] (optional)

```ts
{
  data: {
    arr: ['value'];
  }
}

// The JSON Path of value 'value' is 'data.arr.0'
```

## Return

- object
  - header: header of SD JWT [object]
  - payload: payload of SD JWT [object]
  - kb: keybinding JWT [object] (optional)
    - header: header of keybinding JWT [object]
    - payload: payload of keybinding JWT [object]

if verify failed, throw exception.

## Keys

You can check all JSON Path by `keys` method

```ts
const keys = await sdjwt.keys(encodedSdjwt);
// return all JSON Path keys in claims [string[]]
```
