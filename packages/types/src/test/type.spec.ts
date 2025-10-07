import { describe, expect, test } from 'vitest';
import {
  type DisclosureFrame,
  KB_JWT_TYP,
  type PresentationFrame,
  SD_DECOY,
  SD_DIGEST,
  SD_LIST_KEY,
  SD_SEPARATOR,
} from '../index';

const claims = {
  firstname: 'John',
  lastname: 'Doe',
  ssn: '123-45-6789',
  id: '1234',
  data: {
    firstname: 'John',
    lastname: 'Doe',
    ssn: '123-45-6789',
    list: [{ r: 'd' }, 'b', 'c'],
    list2: ['1', '2', '3'],
    list3: ['1', null, 2],
  },
  data2: {
    hi: 'bye',
  },
};

describe('Variable tests', () => {
  test('SD_SEPARATOR', () => {
    expect(SD_SEPARATOR).toBe('~');
  });

  test('SD_LIST_KEY', () => {
    expect(SD_LIST_KEY).toBe('...');
  });

  test('SD_DIGEST', () => {
    expect(SD_DIGEST).toBe('_sd');
  });

  test('SD_DECOY', () => {
    expect(SD_DECOY).toBe('_sd_decoy');
  });

  test('KB_JWT_TYP', () => {
    expect(KB_JWT_TYP).toBe('kb+jwt');
  });

  test('DisclosureFrameType test', () => {
    const disclosureFrame: DisclosureFrame<typeof claims> = {
      _sd: ['data', 'firstname', 'data2'],
      data: {
        _sd: ['list', 'ssn'],
        _sd_decoy: 2,
        list: {
          _sd: [0, 2],
          0: {
            _sd: ['r'],
          },
        },
      },
    };
    expect(disclosureFrame).toBeDefined();
  });

  test('PresentationFrameType test', () => {
    const presentationFrame: PresentationFrame<typeof claims> = {
      firstname: true,
      data: {
        firstname: true,
        list: {
          1: true,
          0: {
            r: true,
          },
        },
        list2: {
          1: true,
        },
        list3: true,
      },
      data2: true,
    };
    expect(presentationFrame).toBeDefined();
  });
});
