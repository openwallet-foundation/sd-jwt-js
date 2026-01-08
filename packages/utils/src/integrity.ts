type Prettify<T> = { [K in keyof T]: T[K] } & {};

export type IntegrityHashAlg = 'sha256' | 'sha384' | 'sha512' | (string & {});
type WSP = ' ' | '\t' | '\n' | '\r';

/**
 * Represents a single SRI hash expression.
 *
 * `algorithm "-" hash-value [ "?" option-expression ]`
 *
 * @example "sha256-AbCd..."
 * @example "sha256-AbCd...?foo=bar"
 */
export type IntegrityDigest =
  | `${IntegrityHashAlg}-${string}`
  | `${IntegrityHashAlg}-${string}?${string}`;

/**
 * W3C SRI (Subresource Integrity) compatible metadata string.
 *
 * Allows for multiple whitespace-separated digest expressions.
 *
 * @see https://www.w3.org/TR/sri-2/#integrity-metadata-syntax
 */
export type IntegrityMetadata =
  | IntegrityDigest
  | `${IntegrityDigest}${WSP}${string}`;

type Digit = '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9';
type Lower0 = 'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i' | 'j';
type Lower1 = 'k' | 'l' | 'm' | 'n' | 'o' | 'p' | 'q' | 'r' | 's' | 't';
type Lower = 'u' | 'v' | 'w' | 'x' | 'y' | 'z' | Lower0 | Lower1;
type Upper = Uppercase<Lower>;
type ValidStart = Lower | Upper | '_' | '$';
type ValidChar = ValidStart | Digit;

/**
 * Recursively checks if 'S' contains ONLY valid identifier characters.
 * Returns true if safe, false if it contains special chars (-, /, :, space, etc).
 */
type IsClean<S extends string> = S extends ''
  ? true
  : S extends `${infer Char}${infer Rest}`
    ? Char extends ValidChar
      ? IsClean<Rest>
      : false // Found invalid char
    : false;

/**
 * Determines if 'S' is a valid JSONPath identifier safe for dot notation.
 * Rule: Must start with [a-zA-Z_$] and contain only [a-zA-Z0-9_$].
 */
type IsValidIdentifier<S extends string> = S extends `${infer First}${string}`
  ? First extends ValidStart
    ? IsClean<S>
    : false
  : false;

/**
 * Formats a key segment according to JSONPath/TS12 rules.
 * - Simple ID -> .key
 * - Complex ID -> ['key']
 */
type FormatSegment<Key extends string | number> = Key extends number
  ? `[${Key}]` // Literal number -> [0]
  : Key extends `${number}`
    ? `[${Key}]` // Stringified number -> [0]
    : IsValidIdentifier<Key & string> extends true
      ? `.${Key}` // Simple ID -> .key
      : `['${Key}']`; // Complex ID -> ['key']

/**
 * Helper: Removes a leading dot from the remaining path if present.
 * Used when transitioning from Bracket -> Dot (e.g. ['a'].b -> b)
 */
type StripDot<S extends string> = S extends `.${infer R}` ? R : S;
export type { StripDot as _StripDot };

/**
 * Core Parser Logic.
 * Handles:
 * 1. Bracket Start: ['key']... or ["key"]... or [*]...
 * 2. Dot Split: key.rest
 * 3. Bracket Split: key['rest']
 */
type ParsePath<T, P extends string, Out extends string = ''> = P extends `['${
  infer K // Bracket Quoted: ['key'] or ["key"]
}']${infer Rest}`
  ? HandleNext<T, K, StripDot<Rest>, Out>
  : P extends `["${infer K}"]${infer Rest}`
    ? HandleNext<T, K, StripDot<Rest>, Out>
    : // Bracket Wildcard [*] -> Treat as *
      P extends `[*]${infer Rest}`
      ? HandleNext<T, '*', StripDot<Rest>, Out>
      : // Numeric Index [0] -> Treat as key "0"
        P extends `[${infer K extends number}]${infer Rest}`
        ? HandleNext<T, `${K}`, StripDot<Rest>, Out>
        : // Dot vs Bracket Logic
          P extends `${infer HeadBracket}[${infer RestBracket}`
          ? P extends `${infer HeadDot}.${infer RestDot}`
            ? HeadBracket extends `${string}.${string}`
              ? HandleNext<T, HeadDot, RestDot, Out> // Dot is first
              : HandleNext<T, HeadBracket, `[${RestBracket}`, Out> // Bracket is first
            : HandleNext<T, HeadBracket, `[${RestBracket}`, Out> // Only Bracket
          : P extends `${infer HeadDot}.${infer RestDot}`
            ? HandleNext<T, HeadDot, RestDot, Out> // Only Dot
            : HandleNext<T, P, '', Out>; // Terminal

/**
 * Recursive Handler:
 * 1. Appends the formatted key to 'Out'.
 * 2. Recurses into T[Key].
 */
type HandleNext<
  T,
  K extends string,
  Rest extends string,
  Out extends string,
> = K extends '*'
  ? // array: Iterate generic 'number' index
    T extends readonly unknown[]
    ? Rest extends ''
      ? `${Out}[${number}]#integrity`
      : ParsePath<T[number], Rest, `${Out}[${number}]`>
    : // object: Iterate real keys
      T extends object
      ? keyof T extends infer Key
        ? Key extends keyof T & (string | number)
          ? Rest extends ''
            ? `${Out}${FormatSegment<Key>}#integrity`
            : ParsePath<T[Key], Rest, `${Out}${FormatSegment<Key>}`>
          : never
        : never
      : never
  : // 3. leaf key
    K extends keyof T
    ? Rest extends ''
      ? `${Out}${FormatSegment<K>}#integrity`
      : ParsePath<T[K], Rest, `${Out}${FormatSegment<K>}`>
    : never;

/**
 * Extracts the specific JSON keys (ending in `#integrity`) that will be added
 * to the type `T` given the input `Paths`.
 *
 * This is useful for introspection or creating derived types that need to know
 * exactly which integrity fields are expected.
 *
 * @example
 * type Keys = IntegrityKeys<Cred, 'vct' | 'claims.*'>;
 * // Result: "vct#integrity" | "claims.name#integrity" | "claims.age#integrity"
 */
export type IntegrityKeys<T, Paths extends string> = StripDot<
  ParsePath<T, Paths>
>;

/**
 * Intersects a base type `T` with integrity protection fields for specific JSON paths.
 *
 * This type utility takes a base object and a union of string paths. It maps over the
 * `Paths`, transforming them into JSON paths with the `#integrity` suffix,
 * and sets their value type to `IntegrityDigest`.
 *
 * @template T - The base object type (e.g., the credential payload).
 * @template Paths - A union of string literal paths indicating which fields require integrity protection.
 *
 * @example
 * ```ts
 * type PaymentPayload = {
 *   iss: string;
 *   sub: string;
 *   vct: string;
 *   transaction_data_types: Record<string, {
 *     schema_uri: string;
 *     ui_labels_uri: string;
 *   }>;
 * };
 *
 * type SecuredPayment = Integrity<
 *   PaymentPayload,
 *   'vct' | 'transaction_data_types.*.schema_uri' | 'transaction_data_types.*.ui_labels_uri'
 * >;
 *
 * const cred: SecuredPayment = {
 *   iss: 'https://issuer.superbank3.com',
 *   sub: '37774a3f-ab14-43c3-96bc-bb1066a30a1d',
 *
 *   vct: 'https://psd2.standard.org/payment_service_user',
 *
 *   transaction_data_types: {
 *     'https://standardsbody.org/eudiw-trx/payment': {
 *       schema_uri: 'https://schemas.org/payment-v1',
 *       ui_labels_uri: 'https://ui.org/payment-labels',
 *     }
 *   }
 *   'vct#integrity': 'sha256-9cLlJNXN-TsMk-..5ca_xGgX3c1VLmXfh-WRL5',
 *   'transaction_data_types['https://standardsbody.org/eudiw-trx/payment'].schema_uri#integrity': 'sha256-e3b0c44298fc49afbf4...a495991852b855',
 *   'transaction_data_types['https://standardsbody.org/eudiw-trx/payment'].ui_labels_uri#integrity': 'sha256-335f3750519114d2a93...5e6ed24c30c0317'
 * };
 * ```
 */
export type Integrity<T, Paths extends string> = Prettify<
  T & {
    [K in Paths as StripDot<ParsePath<T, K>>]?: IntegrityMetadata;
  }
>;
