import * as cbor from 'cbor-x';
import { describe, expect, it } from 'vitest';
import { StatusList } from '../status-list';
import {
  COSEAlgorithms,
  createCWTStatusClaim,
  createStatusListCWTHeader,
  createStatusListCWTPayload,
  decodeCWTPayload,
  decodeCWTStatusClaim,
  decodeStatusListFromCBOR,
  encodeCWTPayload,
  encodeCWTStatusClaim,
  encodeStatusListToCBOR,
  getListFromStatusListCWT,
  getStatusListFromCWT,
} from '../status-list-cwt';
import { COSEHeaderKeys, CWT_STATUS_LIST_TYPE, CWTClaimKeys } from '../types';

describe('CWTStatusList', () => {
  describe('createStatusListCWTPayload', () => {
    it('should create a valid CWT payload with required fields', () => {
      const statusList = new StatusList([1, 0, 1, 1, 0], 1);
      const subject = 'https://example.com/statuslists/1';
      const issuedAt = Math.floor(Date.now() / 1000);

      const payload = createStatusListCWTPayload(statusList, subject, issuedAt);

      expect(payload[CWTClaimKeys.SUB]).toBe(subject);
      expect(payload[CWTClaimKeys.IAT]).toBe(issuedAt);
      expect(payload[CWTClaimKeys.STATUS_LIST]).toBeDefined();
      expect(payload[CWTClaimKeys.STATUS_LIST].bits).toBe(1);
      expect(payload[CWTClaimKeys.STATUS_LIST].lst).toBeInstanceOf(Uint8Array);
    });

    it('should create a CWT payload with optional exp and ttl', () => {
      const statusList = new StatusList([1, 0, 1, 1, 0], 1);
      const subject = 'https://example.com/statuslists/1';
      const issuedAt = Math.floor(Date.now() / 1000);
      const exp = issuedAt + 86400; // 1 day
      const ttl = 43200; // 12 hours

      const payload = createStatusListCWTPayload(
        statusList,
        subject,
        issuedAt,
        {
          exp,
          ttl,
        },
      );

      expect(payload[CWTClaimKeys.EXP]).toBe(exp);
      expect(payload[CWTClaimKeys.TTL]).toBe(ttl);
    });

    it('should include aggregation_uri when provided', () => {
      const statusList = new StatusList([1, 0, 1, 1, 0], 1);
      const subject = 'https://example.com/statuslists/1';
      const issuedAt = Math.floor(Date.now() / 1000);
      const aggregationUri = 'https://example.com/status-aggregation';

      const payload = createStatusListCWTPayload(
        statusList,
        subject,
        issuedAt,
        {
          aggregationUri,
        },
      );

      expect(payload[CWTClaimKeys.STATUS_LIST].aggregation_uri).toBe(
        aggregationUri,
      );
    });

    it('should throw error when subject is missing', () => {
      const statusList = new StatusList([1, 0, 1, 1, 0], 1);
      const issuedAt = Math.floor(Date.now() / 1000);

      expect(() =>
        createStatusListCWTPayload(statusList, '', issuedAt),
      ).toThrow('subject is required');
    });

    it('should throw error when issuedAt is missing', () => {
      const statusList = new StatusList([1, 0, 1, 1, 0], 1);
      const subject = 'https://example.com/statuslists/1';

      expect(() => createStatusListCWTPayload(statusList, subject, 0)).toThrow(
        'issuedAt is required',
      );
    });
  });

  describe('createStatusListCWTHeader', () => {
    it('should create a valid CWT header', () => {
      const header = createStatusListCWTHeader(COSEAlgorithms.ES256);

      expect(header[COSEHeaderKeys.ALG]).toBe(COSEAlgorithms.ES256);
      expect(header[COSEHeaderKeys.TYPE]).toBe(CWT_STATUS_LIST_TYPE);
    });

    it('should include kid when provided as string', () => {
      const header = createStatusListCWTHeader(COSEAlgorithms.ES256, '12');

      expect(header[COSEHeaderKeys.KID]).toBe('12');
    });

    it('should include kid when provided as Uint8Array', () => {
      const kidBytes = new Uint8Array([0x31, 0x32]); // "12"
      const header = createStatusListCWTHeader(COSEAlgorithms.ES256, kidBytes);

      expect(header[COSEHeaderKeys.KID]).toBe(kidBytes);
    });

    it('should include key resolution options when provided', () => {
      const x5chain = new Uint8Array([0x01, 0x02, 0x03]);
      const x5t = new Uint8Array([0x04, 0x05, 0x06]);
      const x5u = 'https://example.com/certs';

      const header = createStatusListCWTHeader(COSEAlgorithms.ES256, {
        kid: 'key-1',
        x5chain,
        x5t,
        x5u,
      });

      expect(header[COSEHeaderKeys.ALG]).toBe(COSEAlgorithms.ES256);
      expect(header[COSEHeaderKeys.TYPE]).toBe(CWT_STATUS_LIST_TYPE);
      expect(header[COSEHeaderKeys.KID]).toBe('key-1');
      expect(header[33]).toBe(x5chain); // x5chain
      expect(header[34]).toBe(x5t); // x5t
      expect(header[35]).toBe(x5u); // x5u
    });
  });

  describe('encodeStatusListToCBOR / decodeStatusListFromCBOR', () => {
    it('should roundtrip encode and decode status list', () => {
      const originalList = [1, 0, 1, 1, 0, 1, 0, 1];
      const statusList = new StatusList(originalList, 1);

      const encoded = encodeStatusListToCBOR(statusList);
      const decoded = decodeStatusListFromCBOR(encoded);

      for (let i = 0; i < originalList.length; i++) {
        expect(decoded.getStatus(i)).toBe(originalList[i]);
      }
    });

    it('should handle 2-bit status values', () => {
      const originalList = [0, 1, 2, 3, 1, 2];
      const statusList = new StatusList(originalList, 2);

      const encoded = encodeStatusListToCBOR(statusList);
      const decoded = decodeStatusListFromCBOR(encoded);

      for (let i = 0; i < originalList.length; i++) {
        expect(decoded.getStatus(i)).toBe(originalList[i]);
      }
    });

    it('should handle 4-bit status values', () => {
      const originalList = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15];
      const statusList = new StatusList(originalList, 4);

      const encoded = encodeStatusListToCBOR(statusList);
      const decoded = decodeStatusListFromCBOR(encoded);

      for (let i = 0; i < originalList.length; i++) {
        expect(decoded.getStatus(i)).toBe(originalList[i]);
      }
    });

    it('should handle 8-bit status values', () => {
      const originalList = [0, 1, 127, 128, 255, 42];
      const statusList = new StatusList(originalList, 8);

      const encoded = encodeStatusListToCBOR(statusList);
      const decoded = decodeStatusListFromCBOR(encoded);

      for (let i = 0; i < originalList.length; i++) {
        expect(decoded.getStatus(i)).toBe(originalList[i]);
      }
    });
  });

  describe('encodeCWTPayload / decodeCWTPayload', () => {
    it('should roundtrip encode and decode CWT payload', () => {
      const originalList = [1, 0, 1, 1, 0, 1, 0, 1];
      const statusList = new StatusList(originalList, 1);
      const subject = 'https://example.com/statuslists/1';
      const issuedAt = Math.floor(Date.now() / 1000);
      const exp = issuedAt + 86400;
      const ttl = 43200;

      const encoded = encodeCWTPayload(statusList, subject, issuedAt, {
        exp,
        ttl,
      });
      const decoded = decodeCWTPayload(encoded);

      expect(decoded.subject).toBe(subject);
      expect(decoded.issuedAt).toBe(issuedAt);
      expect(decoded.exp).toBe(exp);
      expect(decoded.ttl).toBe(ttl);

      for (let i = 0; i < originalList.length; i++) {
        expect(decoded.statusList.getStatus(i)).toBe(originalList[i]);
      }
    });

    it('should handle payload without optional fields', () => {
      const originalList = [1, 0, 1, 1, 0];
      const statusList = new StatusList(originalList, 1);
      const subject = 'https://example.com/statuslists/1';
      const issuedAt = Math.floor(Date.now() / 1000);

      const encoded = encodeCWTPayload(statusList, subject, issuedAt);
      const decoded = decodeCWTPayload(encoded);

      expect(decoded.subject).toBe(subject);
      expect(decoded.issuedAt).toBe(issuedAt);
      expect(decoded.exp).toBeUndefined();
      expect(decoded.ttl).toBeUndefined();
    });
  });

  describe('getListFromStatusListCWT', () => {
    it('should extract status list from CWT payload', () => {
      const originalList = [1, 0, 1, 1, 0, 1, 0, 1];
      const statusList = new StatusList(originalList, 1);
      const subject = 'https://example.com/statuslists/1';
      const issuedAt = Math.floor(Date.now() / 1000);

      const encoded = encodeCWTPayload(statusList, subject, issuedAt);
      const extractedList = getListFromStatusListCWT(encoded);

      for (let i = 0; i < originalList.length; i++) {
        expect(extractedList.getStatus(i)).toBe(originalList[i]);
      }
    });
  });

  describe('CWT Status Claim for Referenced Tokens', () => {
    it('should create and encode status claim', () => {
      const idx = 0;
      const uri = 'https://example.com/statuslists/1';

      const claim = createCWTStatusClaim(idx, uri);
      expect(claim.status_list.idx).toBe(idx);
      expect(claim.status_list.uri).toBe(uri);

      const encoded = encodeCWTStatusClaim(idx, uri);
      const decoded = decodeCWTStatusClaim(encoded);

      expect(decoded.idx).toBe(idx);
      expect(decoded.uri).toBe(uri);
    });

    it('should extract status list entry from referenced token CWT', () => {
      const idx = 42;
      const uri = 'https://example.com/statuslists/1';

      // Create a CWT payload for a referenced token
      const payload = new Map<number, unknown>();
      payload.set(2, 'subject'); // sub
      payload.set(6, Math.floor(Date.now() / 1000)); // iat

      const statusClaim = new Map<string, unknown>();
      const statusListInfo = new Map<string, unknown>();
      statusListInfo.set('idx', idx);
      statusListInfo.set('uri', uri);
      statusClaim.set('status_list', statusListInfo);
      payload.set(65535, statusClaim); // status claim

      const encoded = cbor.encode(payload);
      const extracted = getStatusListFromCWT(encoded);

      expect(extracted.idx).toBe(idx);
      expect(extracted.uri).toBe(uri);
    });
  });

  describe('Spec compliance - Test vectors', () => {
    it('should match spec example for 1-bit status list', () => {
      // From spec: status[0] = 1, status[1] = 0, ...
      // byte_array = [0xb9, 0xa3]
      // The spec shows 16 statuses with specific values
      const statuses = new Array(16).fill(0);
      statuses[0] = 1;
      statuses[3] = 1;
      statuses[4] = 1;
      statuses[5] = 1;
      statuses[7] = 1;
      statuses[8] = 1;
      statuses[9] = 1;
      statuses[13] = 1;
      statuses[15] = 1;

      const list = new StatusList(statuses, 1);
      const encoded = list.encodeStatusList();

      // The uncompressed byte array should be [0xb9, 0xa3]
      expect(encoded[0]).toBe(0xb9);
      expect(encoded[1]).toBe(0xa3);
    });

    it('should produce CBOR-encoded status list with correct structure', () => {
      const statuses = [1, 0, 1, 1, 0, 1, 0, 1];
      const list = new StatusList(statuses, 1);

      const cborEncoded = encodeStatusListToCBOR(list);
      const decoded = cbor.decode(cborEncoded);

      // Check that the structure has 'bits' and 'lst' keys
      expect(decoded.bits).toBe(1);
      expect(decoded.lst).toBeInstanceOf(Uint8Array);
    });
  });

  describe('COSEAlgorithms constants', () => {
    it('should have correct algorithm values', () => {
      expect(COSEAlgorithms.ES256).toBe(-7);
      expect(COSEAlgorithms.ES384).toBe(-35);
      expect(COSEAlgorithms.ES512).toBe(-36);
      expect(COSEAlgorithms.EdDSA).toBe(-8);
      expect(COSEAlgorithms.PS256).toBe(-37);
      expect(COSEAlgorithms.RS256).toBe(-257);
    });
  });
});
