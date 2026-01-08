import { describe, expectTypeOf, test } from 'vitest';
import type { Integrity } from '../integrity';

interface Credentials {
  vct: string;
  iss: string;
  evidence: {
    type: string;
    document: {
      id: string;
    };
  };
  claims: {
    given_name: string;
    'family-name': string;
  };
  bank_accounts: Record<
    string,
    {
      iban: string;
    }
  >;
  'https://example.com/vocab': {
    description: string;
  };
  arr: [string, string];
}

describe('Integrity Type Edge Cases', () => {
  // 1. Root Level Simple Keys (NO LEADING DOT)
  test('adds integrity fields for root properties without leading dots', () => {
    type Result = Integrity<Credentials, 'vct' | 'iss'>;

    expectTypeOf<Result>().toHaveProperty('vct#integrity');
    expectTypeOf<Result>().toHaveProperty('iss#integrity');
  });

  // 2. Deep Nesting (Dot Notation)
  test('handles deep dot notation correctly', () => {
    type Result = Integrity<Credentials, 'evidence.document.id'>;

    // Should look like "evidence.document.id#integrity", not ".evidence..."
    expectTypeOf<Result>().toHaveProperty('evidence.document.id#integrity');
  });

  // 3. Bracket Notation for Special Characters
  test('handles bracket notation for keys with hyphens', () => {
    type Result = Integrity<Credentials, "claims['family-name']">;

    // e.g. "claims['family-name']#integrity"
    expectTypeOf<Result>().toHaveProperty("claims['family-name']#integrity");
  });

  // Bracket Notation for numbers
  test('handles bracket notation for keys with hyphens', () => {
    type Result = Integrity<Credentials, 'arr[*]'>;

    // e.g. "claims['family-name']#integrity"
    expectTypeOf<Result>().toHaveProperty('arr[0]#integrity');
  });

  // 4. Wildcard Expansion (*)
  test('expands wildcards without leading dots', () => {
    interface ConcreteBanks {
      bank_accounts: {
        chase: { iban: string };
        other: { iban: string };
      };
    }
    type Result = Integrity<ConcreteBanks, 'bank_accounts.*.iban'>;

    expectTypeOf<Result>().toHaveProperty('bank_accounts.chase.iban#integrity');
    expectTypeOf<Result>().toHaveProperty('bank_accounts.other.iban#integrity');
  });

  // 5. Complex URI Keys (Root Bracket Notation)
  test('handles complex URI keys at the root', () => {
    type Result = Integrity<
      Credentials,
      "['https://example.com/vocab'].description"
    >;

    // No dot before the first bracket
    expectTypeOf<Result>().toHaveProperty(
      "['https://example.com/vocab'].description#integrity",
    );
  });

  // 6. Mixed Dot and Bracket Notation
  test('parses mixed dot and bracket paths correctly', () => {
    // Dot -> Bracket
    type Res1 = Integrity<Credentials, "evidence['type']">;
    // Normalized to dot notation if identifier is valid: "evidence.type"
    expectTypeOf<Res1>().toHaveProperty('evidence.type#integrity');

    // Bracket -> Dot
    type Res2 = Integrity<Credentials, "claims['family-name']">;
    expectTypeOf<Res2>().toHaveProperty("claims['family-name']#integrity");
  });
});
