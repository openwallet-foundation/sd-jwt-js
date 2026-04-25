import { describe, expect, test } from 'vitest';
import { unpackObj } from '../src/decode';
import { Disclosure } from '../src/utils';

/**
 * Tests for RFC 9901 validation checks added to unpackObj / unpackObjInternal.
 *
 * Section 7.1 step 4: Duplicate digest rejection
 * Section 7.1 step 5: Unreferenced disclosure rejection
 * Section 7.1 step 3c.ii.3: Claim name collision rejection
 */

const makeDisclosure = (
  digest: string,
  key: string | undefined,
  value: unknown,
) =>
  Disclosure.fromArray(key ? ['salt', key, value] : ['salt', value], {
    digest,
    encoded: `encoded-${digest}`,
  });

describe('RFC 9901 validation', () => {
  // ──────────────────────────────────────────
  // 7.1 step 4 — Duplicate digest in _sd array
  // ──────────────────────────────────────────
  test('rejects duplicate digest in _sd array', () => {
    const digest = 'abc123';
    const payload = { _sd: [digest, digest] };
    const map: Record<string, Disclosure> = {
      [digest]: makeDisclosure(digest, 'foo', 'bar'),
    };
    expect(() => unpackObj(payload, map)).toThrow(
      'Duplicate digest found in SD-JWT payload',
    );
  });

  // ──────────────────────────────────────────
  // 7.1 step 4 — Duplicate digest across nested _sd
  // ──────────────────────────────────────────
  test('rejects duplicate digest across nested _sd arrays', () => {
    const digest = 'dup1';
    const payload = {
      _sd: [digest],
      nested: {
        _sd: [digest],
      },
    };
    const map: Record<string, Disclosure> = {
      [digest]: makeDisclosure(digest, 'x', 'y'),
    };
    expect(() => unpackObj(payload, map)).toThrow(
      'Duplicate digest found in SD-JWT payload',
    );
  });

  // ──────────────────────────────────────────
  // 7.1 step 4 — Duplicate digest in array items
  // ──────────────────────────────────────────
  test('rejects duplicate digest in array element disclosures', () => {
    const digest = 'arrdup';
    const payload = {
      arr: [{ '...': digest }, { '...': digest }],
    };
    const map: Record<string, Disclosure> = {
      [digest]: makeDisclosure(digest, undefined, 'val'),
    };
    expect(() => unpackObj(payload, map)).toThrow(
      'Duplicate digest found in SD-JWT payload',
    );
  });

  // ──────────────────────────────────────────
  // 7.1 step 5 — Unreferenced disclosure
  // ──────────────────────────────────────────
  test('rejects unreferenced disclosure', () => {
    const usedDigest = 'used1';
    const unusedDigest = 'unused1';
    const payload = { _sd: [usedDigest] };
    const map: Record<string, Disclosure> = {
      [usedDigest]: makeDisclosure(usedDigest, 'a', 1),
      [unusedDigest]: makeDisclosure(unusedDigest, 'b', 2),
    };
    expect(() => unpackObj(payload, map)).toThrow(
      'Unreferenced disclosure(s) detected in SD-JWT',
    );
  });

  test('rejects when no digests exist in payload but disclosures provided', () => {
    const payload = { plain: 'value' };
    const map: Record<string, Disclosure> = {
      orphan: makeDisclosure('orphan', 'k', 'v'),
    };
    expect(() => unpackObj(payload, map)).toThrow(
      'Unreferenced disclosure(s) detected in SD-JWT',
    );
  });

  // ──────────────────────────────────────────
  // 7.1 step 3c.ii.3 — Claim name collision
  // ──────────────────────────────────────────
  test('rejects disclosed claim name that conflicts with plaintext key', () => {
    const digest = 'col1';
    // The payload has both a plaintext "name" and a disclosure that would add "name"
    const payload = { name: 'Alice', _sd: [digest] };
    const map: Record<string, Disclosure> = {
      [digest]: makeDisclosure(digest, 'name', 'Mallory'),
    };
    expect(() => unpackObj(payload, map)).toThrow(
      'Disclosed claim name "name" conflicts with existing payload key',
    );
  });

  // ──────────────────────────────────────────
  // Positive: valid SD-JWT unpacks without error
  // ──────────────────────────────────────────
  test('unpacks valid SD-JWT without errors', () => {
    const d1 = 'digest1';
    const d2 = 'digest2';
    const payload = { _sd: [d1, d2], plain: 'hello' };
    const map: Record<string, Disclosure> = {
      [d1]: makeDisclosure(d1, 'foo', 'bar'),
      [d2]: makeDisclosure(d2, 'baz', 42),
    };
    const { unpackedObj, disclosureKeymap } = unpackObj(payload, map);
    expect(unpackedObj).toEqual({ plain: 'hello', foo: 'bar', baz: 42 });
    expect(disclosureKeymap).toEqual({ foo: d1, baz: d2 });
  });

  test('unpacks valid SD-JWT with array disclosures', () => {
    const d1 = 'arrdig1';
    const d2 = 'arrdig2';
    const payload = {
      arr: [{ '...': d1 }, 'plainItem', { '...': d2 }],
    };
    const map: Record<string, Disclosure> = {
      [d1]: makeDisclosure(d1, undefined, 'secret1'),
      [d2]: makeDisclosure(d2, undefined, 'secret2'),
    };
    const { unpackedObj } = unpackObj(payload, map);
    expect(unpackedObj).toEqual({ arr: ['secret1', 'plainItem', 'secret2'] });
  });

  test('allows empty disclosure map with no _sd in payload', () => {
    const payload = { plain: 'value' };
    const map: Record<string, Disclosure> = {};
    const { unpackedObj } = unpackObj(payload, map);
    expect(unpackedObj).toEqual({ plain: 'value' });
  });
});
