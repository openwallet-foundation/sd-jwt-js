import { describe, expect, it } from 'vitest';
import {
  COSEHeaderKeys,
  CWT_STATUS_LIST_TYPE,
  CWTClaimKeys,
  JWT_STATUS_LIST_TYPE,
  JWTClaimNames,
  MediaTypes,
  StatusTypes,
} from '../types';

describe('Status List Type Constants', () => {
  describe('StatusTypes', () => {
    it('should have correct status type values per spec', () => {
      // From Section 7 of the spec
      expect(StatusTypes.VALID).toBe(0x00);
      expect(StatusTypes.INVALID).toBe(0x01);
      expect(StatusTypes.SUSPENDED).toBe(0x02);
      expect(StatusTypes.APPLICATION_SPECIFIC_3).toBe(0x03);
      expect(StatusTypes.APPLICATION_SPECIFIC_RANGE_START).toBe(0x0c);
      expect(StatusTypes.APPLICATION_SPECIFIC_RANGE_END).toBe(0x0f);
    });

    it('should allow using status types with StatusList', () => {
      // Verify the values can be used as status values
      expect(StatusTypes.VALID).toBeLessThan(256);
      expect(StatusTypes.INVALID).toBeLessThan(256);
      expect(StatusTypes.SUSPENDED).toBeLessThan(256);
    });
  });

  describe('MediaTypes', () => {
    it('should have correct media type values for HTTP content negotiation', () => {
      // From Section 14.7 of the spec
      expect(MediaTypes.STATUS_LIST_JWT).toBe('application/statuslist+jwt');
      expect(MediaTypes.STATUS_LIST_CWT).toBe('application/statuslist+cwt');
    });
  });

  describe('JWT Constants', () => {
    it('should have correct JWT type header value', () => {
      // From Section 5.1 of the spec
      expect(JWT_STATUS_LIST_TYPE).toBe('statuslist+jwt');
    });

    it('should have correct JWT claim names', () => {
      // From Section 14.1 of the spec
      expect(JWTClaimNames.STATUS).toBe('status');
      expect(JWTClaimNames.STATUS_LIST).toBe('status_list');
      expect(JWTClaimNames.TTL).toBe('ttl');
      expect(JWTClaimNames.IDX).toBe('idx');
      expect(JWTClaimNames.URI).toBe('uri');
      expect(JWTClaimNames.BITS).toBe('bits');
      expect(JWTClaimNames.LST).toBe('lst');
      expect(JWTClaimNames.AGGREGATION_URI).toBe('aggregation_uri');
    });
  });

  describe('CWT Constants', () => {
    it('should have correct CWT type value', () => {
      // From Section 5.2 of the spec
      expect(CWT_STATUS_LIST_TYPE).toBe('application/statuslist+cwt');
    });

    it('should have correct CWT claim keys', () => {
      // From Section 14.3 of the spec
      expect(CWTClaimKeys.SUB).toBe(2);
      expect(CWTClaimKeys.EXP).toBe(4);
      expect(CWTClaimKeys.IAT).toBe(6);
      expect(CWTClaimKeys.TTL).toBe(65534);
      expect(CWTClaimKeys.STATUS_LIST).toBe(65533);
      expect(CWTClaimKeys.STATUS).toBe(65535);
    });

    it('should have correct COSE header keys', () => {
      // From IANA COSE registry
      expect(COSEHeaderKeys.ALG).toBe(1);
      expect(COSEHeaderKeys.CRIT).toBe(2);
      expect(COSEHeaderKeys.CONTENT_TYPE).toBe(3);
      expect(COSEHeaderKeys.KID).toBe(4);
      expect(COSEHeaderKeys.TYPE).toBe(16);
      expect(COSEHeaderKeys.X5CHAIN).toBe(33);
      expect(COSEHeaderKeys.X5T).toBe(34);
      expect(COSEHeaderKeys.X5U).toBe(35);
    });
  });
});
