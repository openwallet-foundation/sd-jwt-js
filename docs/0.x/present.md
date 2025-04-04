```ts
const presentedSDJwt = await sdjwt.present(encodedSdjwt, presentationFrame, options);
```

## Parameters

- encodedSdjwt: encoded SD JWT [string]
- presentationFrame: Represent the properties that should be selectively disclosed [object]
- options: (optional)

```ts
options?: {
  kb?: KBOptions; // options for Key Binding
},
```

### PresentationFrame

```ts
const claims = {
  data: {
    arr: 'value';
  }
}

// To present 'arr' property
const presentationFrame = {
  data: {
    arr: true
  }
}
```

```ts
const claims = {
  data: {
    arr: 'value';
  }
}

// To present 'data' property
const presentationFrame = {
  data: true,
}
```

```ts
const claims = {
  data: ['A', 'B'],
};

// To present 1st element of 'data' property
const presentationFrame = {
  data: {
    0: true,
  },
};
```

## Returns

selectively disclosed encoded SD JWT string.

## presentationKeys

You can check the available presentationKeys by using `presentableKeys` method

```ts
const keys = await sdjwt.presentableKeys();
// return string[]
```
