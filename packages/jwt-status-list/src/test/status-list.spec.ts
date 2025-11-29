import { describe, expect, it, test } from 'vitest';
import { StatusList } from '../index';
import type { BitsPerStatus } from '../types';

describe('StatusList', () => {
  const listLength = 10000;

  it('test from the example with 1 bit status', () => {
    const status: number[] = [];
    status[0] = 1;
    status[1] = 0;
    status[2] = 0;
    status[3] = 1;
    status[4] = 1;
    status[5] = 1;
    status[6] = 0;
    status[7] = 1;
    status[8] = 1;
    status[9] = 1;
    status[10] = 0;
    status[11] = 0;
    status[12] = 0;
    status[13] = 1;
    status[14] = 0;
    status[15] = 1;
    const manager = new StatusList(status, 1);
    const encoded = manager.compressStatusList();
    expect(encoded).toBe('eNrbuRgAAhcBXQ');
    const list = StatusList.decompressStatusList(encoded, 1);
    for (let i = 0; i < status.length; i++) {
      expect(list.getStatus(i)).toBe(status[i]);
    }

    //get the whole list and check if it is equal
    for (let i = 0; i < list.statusList.length; i++) {
      expect(list.statusList[i]).toBe(status[i]);
    }
  });

  it('test from the example with 2 bit status', () => {
    const status: number[] = [];
    status[0] = 1;
    status[1] = 2;
    status[2] = 0;
    status[3] = 3;
    status[4] = 0;
    status[5] = 1;
    status[6] = 0;
    status[7] = 1;
    status[8] = 1;
    status[9] = 2;
    status[10] = 3;
    status[11] = 3;
    const manager = new StatusList(status, 2);
    const encoded = manager.compressStatusList();
    expect(encoded).toBe('eNo76fITAAPfAgc');
    const l = StatusList.decompressStatusList(encoded, 2);
    for (let i = 0; i < status.length; i++) {
      expect(l.getStatus(i)).toBe(status[i]);
    }
  });

  // Test with different bitsPerStatus values
  describe.each([
    [1 as BitsPerStatus],
    [2 as BitsPerStatus],
    [4 as BitsPerStatus],
    [8 as BitsPerStatus],
  ])('with %i bitsPerStatus', (bitsPerStatus) => {
    let manager: StatusList;

    function createListe(
      length: number,
      bitsPerStatus: BitsPerStatus,
    ): number[] {
      const list: number[] = [];
      for (let i = 0; i < length; i++) {
        list.push(Math.floor(Math.random() * 2 ** bitsPerStatus));
      }
      return list;
    }

    it('should pass an incorrect list with wrong entries', () => {
      expect(() => {
        new StatusList([2 ** bitsPerStatus + 1], bitsPerStatus);
      }).toThrowError();
    });

    it('should compress and decompress status list correctly', () => {
      const statusList = createListe(listLength, bitsPerStatus);
      manager = new StatusList(statusList, bitsPerStatus);
      const compressedStatusList = manager.compressStatusList();
      const decodedStatuslist = StatusList.decompressStatusList(
        compressedStatusList,
        bitsPerStatus,
      );
      checkIfEqual(decodedStatuslist, statusList);
    });

    it('should return the bitsPerStatus value', () => {
      const statusList = createListe(
        listLength,
        bitsPerStatus as BitsPerStatus,
      );
      manager = new StatusList(statusList, bitsPerStatus as BitsPerStatus);
      expect(manager.getBitsPerStatus()).toBe(bitsPerStatus);
    });

    it('getStatus returns the correct status', () => {
      const statusList = createListe(
        listLength,
        bitsPerStatus as BitsPerStatus,
      );
      manager = new StatusList(statusList, bitsPerStatus as BitsPerStatus);

      for (let i = 0; i < statusList.length; i++) {
        expect(manager.getStatus(i)).toBe(statusList[i]);
      }
    });

    it('setStatus sets the correct status', () => {
      const statusList = createListe(
        listLength,
        bitsPerStatus as BitsPerStatus,
      );
      manager = new StatusList(statusList, bitsPerStatus as BitsPerStatus);

      const newValue = Math.floor(Math.random() * 2 ** bitsPerStatus);
      manager.setStatus(0, newValue);
      expect(manager.getStatus(0)).toBe(newValue);
    });

    it('getStatus throws an error for out of bounds index', () => {
      const statusList = createListe(
        listLength,
        bitsPerStatus as BitsPerStatus,
      );
      manager = new StatusList(statusList, bitsPerStatus as BitsPerStatus);

      expect(() => manager.getStatus(-1)).toThrow('Index out of bounds');
      expect(() => manager.getStatus(listLength)).toThrow(
        'Index out of bounds',
      );
    });

    it('setStatus throws an error for out of bounds index', () => {
      const statusList = createListe(
        listLength,
        bitsPerStatus as BitsPerStatus,
      );
      manager = new StatusList(statusList, bitsPerStatus as BitsPerStatus);

      expect(() => manager.setStatus(-1, 5)).toThrow('Index out of bounds');
      expect(() => manager.setStatus(listLength, 6)).toThrow(
        'Index out of bounds',
      );
    });

    it('decompressStatusList throws an error when decompression fails', () => {
      const statusList = createListe(
        listLength,
        bitsPerStatus as BitsPerStatus,
      );
      manager = new StatusList(statusList, bitsPerStatus as BitsPerStatus);

      const invalidCompressedData = 'invalid data';

      expect(() =>
        StatusList.decompressStatusList(invalidCompressedData, bitsPerStatus),
      ).toThrowError();
    });

    test('encodeStatusList covers remaining bits in last byte', () => {
      const bitsPerStatus = 1;
      const totalStatuses = 10; // Not a multiple of 8
      const statusList = Array(totalStatuses).fill(0);
      const manager = new StatusList(statusList, bitsPerStatus);
      const encoded = manager.compressStatusList();
      const decoded = StatusList.decompressStatusList(encoded, bitsPerStatus);
      //technially we need to validate all the status but we are just checking the length
      checkIfEqual(decoded, statusList);
    });

    /**
     * Check if the status list is equal to the given list.
     * @param statuslist1
     * @param rawStatusList
     */
    function checkIfEqual(statuslist1: StatusList, rawStatusList: number[]) {
      for (let i = 0; i < rawStatusList.length; i++) {
        expect(statuslist1.getStatus(i)).toBe(rawStatusList[i]);
      }
    }

    describe('constructor', () => {
      test.each<[number]>([
        [3], // Invalid bitsPerStatus value
        [5], // Invalid bitsPerStatus value
        [6], // Invalid bitsPerStatus value
        [7], // Invalid bitsPerStatus value
        [9], // Invalid bitsPerStatus value
        [10], // Invalid bitsPerStatus value
      ])('throws an error for invalid bitsPerStatus value (%i)', (bitsPerStatus) => {
        expect(() => {
          new StatusList([], bitsPerStatus as BitsPerStatus);
        }).toThrowError('bitsPerStatus must be 1, 2, 4, or 8');
      });

      test.each<[BitsPerStatus]>([
        [1], // Valid bitsPerStatus value
        [2], // Valid bitsPerStatus value
        [4], // Valid bitsPerStatus value
        [8], // Valid bitsPerStatus value
      ])('does not throw an error for valid bitsPerStatus value (%i)', (bitsPerStatus) => {
        expect(() => {
          new StatusList([], bitsPerStatus);
        }).not.toThrowError();
      });
    });
  });
});
