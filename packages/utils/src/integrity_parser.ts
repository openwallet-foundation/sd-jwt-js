import type { IntegrityHashAlg, IntegrityMetadata } from './integrity';
import { _splitPath } from './integrity_calculator';

/**
 * SRI metadata digest string `alg-hash?options`.
 */
export interface IntegrityPart {
  alg: IntegrityHashAlg;
  hash: string;
  /**
   * The raw option expression string (without the leading '?').
   */
  options?: string;
}

export interface IntegrityPartError {
  /**
   * A description of the error that occurred parsing integrity or searching for the related value.
   */
  error: string;
}

/**
 * Integrity check result should be considered invalid if value is undefined, or integrity has no valid parts, or any part that doesn't match the value hash
 */
export interface IntegrityCheckResult {
  /** The specific key containing the integrity metadata */
  key: string;
  /** The raw value of the field for which the integrity exists, usually a string URI/URL */
  value: unknown;
  /** The parsed integrity parts, contains errored parts */
  integrity: (IntegrityPart | IntegrityPartError)[];
}

/**
 * Parses a single SRI string into its components.
 * Strictly follows the "Parse metadata" algorithm from W3C SRI.
 *
 * @see https://www.w3.org/TR/sri-2/#parse-metadata
 */
export function parseIntegrityString(
  input: IntegrityMetadata,
): (IntegrityPart | IntegrityPartError)[] {
  // 1. Let result be the empty set (allowing for errors).
  const result: (IntegrityPart | IntegrityPartError)[] = [];

  // 2. For each item returned by splitting metadata on spaces:
  const items = input.trim().split(/\s+/);
  for (const item of items) {
    if (!item) continue;

    // 3. Let expression-and-options be the result of splitting item on U+003F (?).
    const expressionAndOptions = item.split('?');

    // 4. Let algorithm-expression be expression-and-options[0].
    const algorithmExpression = expressionAndOptions[0];

    // 6. Let algorithm-and-value be the result of splitting algorithm-expression on U+002D (-).
    const firstHyphenIndex = algorithmExpression.indexOf('-');

    if (firstHyphenIndex === -1) {
      result.push({
        error: `Malformed integrity part '${item}': missing hyphen separator`,
      });
      continue;
    }

    // 7. Let algorithm be algorithm-and-value[0].
    const algorithm = algorithmExpression.slice(
      0,
      firstHyphenIndex,
    ) as IntegrityHashAlg;

    if (!algorithm) {
      result.push({
        error: `Malformed integrity part '${item}': missing algorithm`,
      });
      continue;
    }

    // 8. If algorithm-and-value[1] exists, set base64-value to algorithm-and-value[1].
    const base64Value = algorithmExpression.slice(firstHyphenIndex + 1);

    // 9. Let metadata be the ordered map...
    const options = expressionAndOptions[1]; // undefined if not present

    // 10. Append metadata to result.
    result.push({
      alg: algorithm,
      hash: base64Value,
      options,
    });
  }

  // 11. Return result.
  return result;
}

/**
 * Iterates over an object recursively, finds all keys ending in `#integrity`,
 * and returns their parsed values associated with the related field's value.
 * This function does not throw, it returns errors within its result.
 */
export function extractIntegrity(target: object): IntegrityCheckResult[] {
  if (!target || typeof target !== 'object') return [];

  return Object.entries(target).flatMap(([key, val]) => {
    const err = (error: string) => [
      {
        key,
        value: undefined,
        integrity: [{ error }],
      } satisfies IntegrityCheckResult,
    ];

    if (typeof val === 'object') return extractIntegrity(val);
    if (!key.endsWith('#integrity')) return [];
    const fullPath = key.replace(/#integrity$/, '');
    if (!val || typeof val !== 'string') {
      return err(
        `sd-jwt integrity '${key}' should be string 'alg-hash?opt': ${JSON.stringify(val, undefined, 2)}`,
      );
    }
    const rawValue = val as IntegrityMetadata;
    const path = _splitPath(fullPath);
    let value = target as Record<string, unknown>;
    for (const step of path) {
      if (typeof value === 'object' && step in value) {
        value = value[step] as Record<string, unknown>;
      } else {
        return err(
          `sd-jwt integrity for '${fullPath}' has no value in ${JSON.stringify(target, undefined, 2)}`,
        );
      }
    }
    return [
      {
        key,
        value: value as unknown,
        integrity: parseIntegrityString(rawValue),
      },
    ];
  });
}
