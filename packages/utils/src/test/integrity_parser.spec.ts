import { describe, expect, test } from 'vitest';
import type { IntegrityMetadata } from '../integrity';
import { extractIntegrity, parseIntegrityString } from '../integrity_parser';

describe('Integrity Parser', () => {
  describe('parseIntegrityString', () => {
    test('parses W3C SRI format correctly', () => {
      const input = 'sha256-AbCd?opt=1' as IntegrityMetadata;
      const result = parseIntegrityString(input);
      expect(result[0]).toEqual({
        alg: 'sha256',
        hash: 'AbCd',
        options: 'opt=1',
      });
    });
  });

  describe('extractIntegrity', () => {
    test('resolves simple sibling values', () => {
      const payload = {
        name: 'Alice',
        'name#integrity': 'sha256-hash1',
      };

      const results = extractIntegrity(payload);
      expect(results).toHaveLength(1);
      expect(results[0].key).toBe('name#integrity');
      expect(results[0].value).toBe('Alice');
      expect(results[0].integrity[0]).haveOwnProperty('hash', 'hash1');
    });

    test('resolves nested dot-notation paths from root', () => {
      const payload = {
        claims: {
          sub: '123',
        },
        'claims.sub#integrity': 'sha256-hashSub',
      };

      const results = extractIntegrity(payload);
      expect(results[0].key).toBe('claims.sub#integrity');
      expect(results[0].value).toBe('123'); // Resolved path claims.sub
    });

    test('resolves bracket-notation paths', () => {
      const payload = {
        claims: {
          'family-name': 'Doe',
        },
        "claims['family-name']#integrity": 'sha256-hashDoe',
      };

      const results = extractIntegrity(payload);
      expect(results[0].key).toBe("claims['family-name']#integrity");
      expect(results[0].value).toBe('Doe');
    });

    test('searches recursively at every object level', () => {
      const payload = {
        // Level 1: Root integrity
        top: 'level',
        'top#integrity': 'sha256-top',

        nested: {
          // Level 2: Nested integrity
          leaf: 'value',
          'leaf#integrity': 'sha256-leaf',

          deep: {
            // Level 3
            id: 99,
            'id#integrity': 'sha256-id',
          },
        },
      };

      const results = extractIntegrity(payload);
      expect(results).toHaveLength(3);

      const top = results.find((r) => r.key === 'top#integrity');
      expect(top?.value).toBe('level');

      const leaf = results.find((r) => r.key === 'leaf#integrity');
      expect(leaf?.value).toBe('value'); // Resolved relative to 'nested' object

      const id = results.find((r) => r.key === 'id#integrity');
      expect(id?.value).toBe(99); // Resolved relative to 'nested.deep' object
    });

    test('handles path resolution failure gracefully (undefined value)', () => {
      const payload = {
        'missing#integrity': 'sha256-hash',
      };

      const results = extractIntegrity(payload);
      expect(results[0].key).toBe('missing#integrity');
      expect(results[0].value).toBeUndefined();
    });

    test('ignores non-integrity fields', () => {
      const payload = { a: 1, b: 2 };
      expect(extractIntegrity(payload)).toEqual([]);
    });
  });
});
