import { describe, expect, test } from 'vitest';
import { SDJWTException } from '../error';

describe('Error tests', () => {
  test('Detail', () => {
    try {
      throw new SDJWTException('msg', { details: 'details' });
    } catch (e: unknown) {
      const exception = e as SDJWTException;
      expect(exception.getFullMessage()).toEqual(
        'SDJWTException: msg - "details"',
      );
    }
  });
});
