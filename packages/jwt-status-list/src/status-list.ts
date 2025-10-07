import base64Url from 'base64url';
import { deflate, inflate } from 'pako';
import type { BitsPerStatus } from './types';
/**
 * StatusListManager is a class that manages a list of statuses with variable bit size.
 */
export class StatusList {
  private _statusList: number[];
  private bitsPerStatus: BitsPerStatus;
  private totalStatuses: number;

  /**
   * Create a new StatusListManager instance.
   * @param statusList
   * @param bitsPerStatus
   */
  constructor(statusList: number[], bitsPerStatus: BitsPerStatus) {
    if (![1, 2, 4, 8].includes(bitsPerStatus)) {
      throw new Error('bitsPerStatus must be 1, 2, 4, or 8');
    }
    //check that the entries in the statusList are within the range of the bitsPerStatus
    for (let i = 0; i < statusList.length; i++) {
      if (statusList[i] > 2 ** bitsPerStatus) {
        throw Error(
          `Status value out of range at index ${i} with value ${statusList[i]}`,
        );
      }
    }
    this._statusList = statusList;
    this.bitsPerStatus = bitsPerStatus;
    this.totalStatuses = statusList.length;
  }

  /**
   * Get the status list.
   */
  get statusList(): number[] {
    return this._statusList;
  }

  /**
   * Get the number of statuses.
   * @returns
   */
  getBitsPerStatus(): BitsPerStatus {
    return this.bitsPerStatus;
  }

  /**
   * Get the status at a specific index.
   * @param index
   */
  getStatus(index: number): number {
    if (index < 0 || index >= this.totalStatuses) {
      throw new Error('Index out of bounds');
    }
    return this._statusList[index];
  }

  /**
   * Set the status at a specific index.
   * @param index
   * @param value
   */
  setStatus(index: number, value: number): void {
    if (index < 0 || index >= this.totalStatuses) {
      throw new Error('Index out of bounds');
    }
    this._statusList[index] = value;
  }

  /**
   * Compress the status list.
   */
  compressStatusList(): string {
    const byteArray = this.encodeStatusList();
    const compressed = deflate(byteArray, { level: 9 });
    return base64Url.encode(compressed as Buffer);
  }

  /**
   * Decompress the compressed status list and return a new StatusList instance.
   * @param compressed
   * @param bitsPerStatus
   */
  static decompressStatusList(
    compressed: string,
    bitsPerStatus: BitsPerStatus,
  ): StatusList {
    const decoded = new Uint8Array(
      base64Url
        .decode(compressed, 'binary')
        .split('')
        .map((c) => c.charCodeAt(0)),
    );
    try {
      const decompressed = inflate(decoded);
      const statusList = StatusList.decodeStatusList(
        decompressed,
        bitsPerStatus,
      );
      return new StatusList(statusList, bitsPerStatus);
    } catch (err: unknown) {
      throw new Error(`Decompression failed: ${err}`);
    }
  }

  /**
   * Encode the status list into a byte array.
   * @returns
   **/
  public encodeStatusList(): Uint8Array {
    const numBits = this.bitsPerStatus;
    const numBytes = Math.ceil((this.totalStatuses * numBits) / 8);
    const byteArray = new Uint8Array(numBytes);
    let byteIndex = 0;
    let bitIndex = 0;
    let currentByte = '';
    for (let i = 0; i < this.totalStatuses; i++) {
      const status = this._statusList[i];
      // Place bits from status into currentByte, starting from the most significant bit.
      currentByte = status.toString(2).padStart(numBits, '0') + currentByte;
      bitIndex += numBits;

      // If currentByte is full or this is the last status, add it to byteArray and reset currentByte and bitIndex.
      if (bitIndex >= 8 || i === this.totalStatuses - 1) {
        // If this is the last status and bitIndex is not a multiple of 8, shift currentByte to the left.
        if (i === this.totalStatuses - 1 && bitIndex % 8 !== 0) {
          currentByte = currentByte.padStart(8, '0');
        }
        byteArray[byteIndex] = Number.parseInt(currentByte, 2);
        currentByte = '';
        bitIndex = 0;
        byteIndex++;
      }
    }

    return byteArray;
  }

  /**
   * Decode the byte array into a status list.
   * @param byteArray
   * @param bitsPerStatus
   * @returns
   */
  private static decodeStatusList(
    byteArray: Uint8Array,
    bitsPerStatus: BitsPerStatus,
  ): number[] {
    const numBits = bitsPerStatus;
    const totalStatuses = (byteArray.length * 8) / numBits;
    const statusList = new Array<number>(totalStatuses);
    let bitIndex = 0; // Current position in byte
    for (let i = 0; i < totalStatuses; i++) {
      const byte = byteArray[Math.floor((i * numBits) / 8)];
      let byteString = byte.toString(2);
      if (byteString.length < 8) {
        byteString = '0'.repeat(8 - byteString.length) + byteString;
      }
      const status = byteString.slice(bitIndex, bitIndex + numBits);
      const group = Math.floor(i / (8 / numBits));
      const indexInGroup = i % (8 / numBits);
      const position =
        group * (8 / numBits) + (8 / numBits + -1 - indexInGroup);
      statusList[position] = Number.parseInt(status, 2);
      bitIndex = (bitIndex + numBits) % 8;
    }
    return statusList;
  }
}
