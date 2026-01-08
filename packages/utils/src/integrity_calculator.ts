import type {
  _StripDot,
  Integrity,
  IntegrityDigest,
  IntegrityKeys,
  IntegrityMetadata,
} from './integrity';

type GetValue<T, K> = K extends keyof T ? T[K] : never;
type PathValue<T, P extends string> = P extends `['${infer K}']${infer Rest}`
  ? PathValue<GetValue<T, K>, _StripDot<Rest>>
  : P extends `["${infer K}"]${infer Rest}`
    ? PathValue<GetValue<T, K>, _StripDot<Rest>>
    : // Bracket Wildcard [*] -> Return Element Type
      P extends `[*]${infer Rest}`
      ? T extends readonly unknown[]
        ? PathValue<T[number], _StripDot<Rest>>
        : PathValue<GetValue<T, keyof T>, _StripDot<Rest>>
      : // Standard Wildcard * -> Return Element Type
        P extends `*${infer Rest}`
        ? T extends readonly unknown[]
          ? PathValue<T[number], _StripDot<Rest>>
          : PathValue<GetValue<T, keyof T>, _StripDot<Rest>>
        : // Array Index [0] -> Return Element Type
          P extends `[${infer K extends number}]${infer Rest}`
          ? T extends readonly unknown[]
            ? PathValue<T[K], _StripDot<Rest>>
            : never
          : // Dot vs Bracket Split
            P extends `${infer HeadBracket}[${infer RestBracket}`
            ? P extends `${infer HeadDot}.${infer RestDot}`
              ? HeadBracket extends `${string}.${string}`
                ? PathValue<GetValue<T, HeadDot>, RestDot>
                : PathValue<GetValue<T, HeadBracket>, `[${RestBracket}`>
              : PathValue<GetValue<T, HeadBracket>, `[${RestBracket}`>
            : P extends `${infer HeadDot}.${infer RestDot}`
              ? PathValue<GetValue<T, HeadDot>, RestDot>
              : P extends keyof T
                ? T[P]
                : never;

/**
 * A strongly typed hasher.
 * Key is the union of possible keys, and value the union of possible field values to has.
 * The integrity is expected to be the content of URIs, so it is necessary to either do a web lookup or do a local lookup of the data if self hosted.
 */
export type DigestFn<T, K extends string> = (
  key: IntegrityKeys<T, K>,
  value: PathValue<T, K>,
) => Promise<IntegrityDigest> | IntegrityDigest;

/**
 * Splits a path string into segments.
 */
export function _splitPath(path: string): string[] {
  // Regex matches:
  // 1. Quoted Brackets: ['...'] or ["..."]
  // 2. Numeric Index:   [123]
  // 3. Bracket Wild:    [*]
  // 4. Dot Wild:        *
  // 5. Identifiers:     name
  const regex = /(\['[^']+']|\["[^"]+"]|\[\d+]|\[\*]|\*|[a-zA-Z0-9_$]+)/g;
  return (path.match(regex) || []).map((it) => {
    if (it === '*' || it === '[*]') return '*';
    // clean keys
    return it.startsWith('[') ? it.replace(/^\[['"]?|['"]?]$/g, '') : it;
  });
}

function resolvePaths(
  currentVal: unknown,
  segments: string[],
  currentPath: string,
): Array<{ path: string; value: unknown }> {
  if (segments.length === 0) {
    return [{ path: currentPath, value: currentVal }];
  }

  const toSegment = (key: string) =>
    /^[0-9]*$/.test(key)
      ? `[${key}]`
      : /^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(key)
        ? `.${key}`
        : `['${key}']`;

  const toNextPath = (key: string) =>
    currentPath
      ? `${currentPath}${toSegment(key)}`
      : toSegment(key).replace(/^\./, '');

  const [head, ...tail] = segments;
  const results: Array<{ path: string; value: unknown }> = [];

  // Handle Wildcard (* OR [*])
  let toResolve: { key: string; nextPath: string }[] = [];
  if (head === '*') {
    if (typeof currentVal === 'object' && currentVal !== null) {
      toResolve = Object.keys(currentVal).map((key) => ({
        key: key,
        nextPath: toNextPath(key),
      }));
    }
  } else {
    toResolve = [{ key: head, nextPath: toNextPath(head) }];
  }

  for (const { key, nextPath } of toResolve) {
    if (currentVal && typeof currentVal === 'object' && key in currentVal) {
      const obj = currentVal as Record<string, unknown>;
      results.push(...resolvePaths(obj[key], tail, nextPath));
    }
  }
  return results;
}

export async function calculateIntegrity<
  T extends Record<string, unknown>,
  const P extends readonly string[],
>(
  payload: T,
  paths: P,
  hasher: DigestFn<T, P[number]>,
): Promise<Integrity<T, P[number]>> {
  const result = { ...payload } as Integrity<T, P[number]>;

  const all = paths.flatMap((pathStr) => {
    const segments = _splitPath(pathStr);
    const matches = resolvePaths(payload, segments, '');
    return matches.map(async ({ path, value }) => {
      const key = `${path}#integrity`;
      return {
        [key]: await hasher(
          key as IntegrityKeys<T, P[number]>,
          value as PathValue<T, P[number]>,
        ),
      };
    });
  });

  for (const obj of await Promise.all(all)) {
    Object.assign(result, obj);
  }

  return result;
}
