import { describe, expect, test, vi } from 'vitest';
import type { IntegrityDigest } from '../integrity';
import { calculateIntegrity } from '../integrity_calculator';

// --- Mock Data Setup ---

const mockCredentials = {
  vct: 'https://example.com/vct',
  iss: 'https://example.com/iss',
  evidence: {
    type: 'document_check',
    document: {
      id: 'doc-123',
    },
  },
  claims: {
    given_name: 'John',
    'family-name': 'Doe',
  },
  bank_accounts: {
    chase: { iban: 'US123' },
    'complex-bank': { iban: 'EU456' }, // Key requiring quotes
  },
  'https://example.com/vocab': {
    description: 'A complex vocabulary',
  },
  arr: ['item1', 'item2'],
  mixed_array: [{ id: 1 }, { id: 2 }],
  nested_arrays: [
    [1, 2],
    [3, 4],
  ],
} as const;

/**
 * A generic mock hasher compatible with DigestFn<T, K>.
 * It accepts (string, unknown) which satisfies the contravariance required
 * for any specific (Key, Value) pair.
 */
const mockHasher = vi.fn(async (key: string, value: unknown) => {
  const valString =
    typeof value === 'object' && value !== null
      ? JSON.stringify(value)
      : String(value);
  return `sha256-${key}?${valString}` as IntegrityDigest;
});

describe('Integrity Calculator', () => {
  test('1. Root Level Simple Keys (Dot Notation)', async () => {
    const result = await calculateIntegrity(
      mockCredentials,
      ['vct', 'iss'],
      mockHasher,
    );

    expect(result).toHaveProperty('vct#integrity');
    expect(result['vct#integrity']).toBe(
      'sha256-vct#integrity?https://example.com/vct',
    );

    expect(result).toHaveProperty('iss#integrity');
    expect(result['iss#integrity']).toBe(
      'sha256-iss#integrity?https://example.com/iss',
    );
  });

  test('2. Deep Nesting (Dot Notation)', async () => {
    const result = await calculateIntegrity(
      mockCredentials,
      ['evidence.document.id'],
      mockHasher,
    );

    expect(result).toHaveProperty('evidence.document.id#integrity');
    expect(result['evidence.document.id#integrity']).toContain('doc-123');
  });

  test('3. Bracket Notation (Explicit Paths)', async () => {
    // Testing single quotes ['...'] and double quotes ["..."]
    const result = await calculateIntegrity(
      mockCredentials,
      ["claims['family-name']", 'claims["given_name"]'],
      mockHasher,
    );

    // 1. 'family-name' contains a hyphen (invalid identifier), so brackets MUST be preserved.
    // Matches Type: claims['family-name']#integrity
    expect(result).toHaveProperty("claims['family-name']#integrity");
    expect(result["claims['family-name']#integrity"]).toContain('Doe');

    // 2. 'given_name' is a valid identifier, so it MUST be normalized to dot notation.
    // Matches Type: claims.given_name#integrity
    expect(result).toHaveProperty('claims.given_name#integrity');
    expect(result['claims.given_name#integrity']).toContain('John');
  });

  test('4. Array Indices (Explicit)', async () => {
    const result = await calculateIntegrity(
      mockCredentials,
      ['arr[0]', 'arr[1]'],
      mockHasher,
    );

    expect(result).toHaveProperty('arr[0]#integrity');
    expect(result['arr[0]#integrity']).toContain('item1');
    expect(result['arr[1]#integrity']).toContain('item2');
  });

  test('5. Wildcard Expansion (*) on Objects (Normalization Check)', async () => {
    // This tests the normalization logic in resolvePaths for wildcards
    // It should handle simple keys (chase) -> .chase
    // And complex keys (complex-bank) -> ['complex-bank']
    const result = await calculateIntegrity(
      mockCredentials,
      ['bank_accounts.*.iban'],
      mockHasher,
    );

    // Simple Identifier
    expect(result).toHaveProperty('bank_accounts.chase.iban#integrity');
    expect(result['bank_accounts.chase.iban#integrity']).toContain('US123');

    // Complex Identifier (Normalized to brackets)
    expect(result).toHaveProperty(
      "bank_accounts['complex-bank'].iban#integrity",
    );
    expect(result["bank_accounts['complex-bank'].iban#integrity"]).toContain(
      'EU456',
    );
  });

  test('6. Wildcard Expansion [*] on Arrays', async () => {
    const result = await calculateIntegrity(
      mockCredentials,
      ['arr[*]'],
      mockHasher,
    );

    expect(result).toHaveProperty('arr[0]#integrity');
    expect(result['arr[0]#integrity']).toContain('item1');
    expect(result['arr[1]#integrity']).toContain('item2');
  });

  test('7. Mixed Dot and Bracket Notation', async () => {
    const result = await calculateIntegrity(
      mockCredentials,
      ["evidence['document'].id"], // Mixed brackets and dots
      mockHasher,
    );

    // Runtime concatenates explicitly provided mixed paths
    expect(result).toHaveProperty('evidence.document.id#integrity');
    expect(result['evidence.document.id#integrity']).toContain('doc-123');
  });

  test('8. Complex Root Keys (URI keys)', async () => {
    const result = await calculateIntegrity(
      mockCredentials,
      ["['https://example.com/vocab'].description"],
      mockHasher,
    );

    expect(result).toHaveProperty(
      "['https://example.com/vocab'].description#integrity",
    );
    expect(
      result["['https://example.com/vocab'].description#integrity"],
    ).toContain('complex vocabulary');
  });

  test('9. Missing Keys (Graceful Handling)', async () => {
    const result = await calculateIntegrity(
      mockCredentials,
      ['non_existent.field', 'evidence.missing_prop'],
      mockHasher,
    );

    // Should return the original object without crashing
    expect(result).toBeDefined();
    expect(result).not.toHaveProperty('non_existent.field#integrity');
  });

  test('10. Wildcard on Non-Object/Null (Safety Check)', async () => {
    const payload = {
      primitive: 123,
      nullVal: null,
    };

    const result = await calculateIntegrity(
      payload,
      ['primitive.*', 'nullVal.*'],
      mockHasher,
    );

    // Should not crash and not add fields
    expect(result).toEqual(payload);
  });

  test('11. Regex Edge Cases and Nested Wildcards', async () => {
    const nestedMock = {
      matrix: [
        [10, 11],
        [20, 21],
      ],
    };

    const result = await calculateIntegrity(
      nestedMock,
      ['matrix[*][*]'], // Double wildcard
      mockHasher,
    );

    expect(result).toHaveProperty('matrix[0][0]#integrity');
    expect(result).toHaveProperty('matrix[0][1]#integrity');
    expect(result).toHaveProperty('matrix[1][0]#integrity');
    expect(result).toHaveProperty('matrix[1][1]#integrity');
    expect(result['matrix[0][0]#integrity']).toContain('10');
  });

  test('12. Hasher Interaction', async () => {
    const spy = vi.fn(() => 'sha256-mock' as IntegrityDigest);
    await calculateIntegrity({ a: 1 }, ['a'], spy);

    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith('a#integrity', 1);
  });

  test('13. Wildcard Normalization with Numeric Keys', async () => {
    // Specifically testing the /^[0-9]*$/ regex branch in wildcard expansion
    const numKeyObj = {
      data: {
        '123': 'value',
        normal: 'value',
      },
    };

    const result = await calculateIntegrity(numKeyObj, ['data.*'], mockHasher);

    // Should normalize "123" to [123] NOT .123 or ['123']
    expect(result).toHaveProperty('data[123]#integrity');
    // Standard key check
    expect(result).toHaveProperty('data.normal#integrity');
  });
});
