import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { X509Certificate, createPrivateKey, KeyObject } from 'crypto';
import { Sign } from '../sign';
import { DisclosureFrame } from '@sd-jwt/types';
import { ProtectedHeader } from '../type';
import { base64urlDecode } from '@sd-jwt/utils';
import { parseCerts } from '../utils';
import { GeneralJSON, SDJwtGeneralJSONInstance } from '@sd-jwt/core';
import { digest } from '@sd-jwt/crypto-nodejs';
import { JWTVerifier } from '../verify';

describe('Sign', () => {
  let testCert: X509Certificate[];
  let privateKey: KeyObject;

  beforeAll(() => {
    const certPath = path.join(__dirname, 'fixtures', 'certificate.crt');
    const certPem = fs.readFileSync(certPath, 'utf-8');
    testCert = parseCerts(certPem);

    const keyPath = path.join(__dirname, 'fixtures', 'private.pem');
    const keyPem = fs.readFileSync(keyPath, 'utf-8');
    privateKey = createPrivateKey(keyPem);
  });

  describe('constructor', () => {
    it('should create instance with payload', () => {
      const payload = { test: 'value' };
      const sign = new Sign(payload);
      expect(sign).toBeInstanceOf(Sign);
    });

    it('should create instance without payload', () => {
      const sign = new Sign();
      expect(sign).toBeInstanceOf(Sign);
    });
  });

  describe('setProtectedHeader', () => {
    it('should set valid protected header', () => {
      const sign = new Sign({ test: 'value' });
      const header: ProtectedHeader = {
        alg: 'ES256',
        typ: 'JWT',
      };
      const result = sign.setProtectedHeader(header);
      expect(result).toBe(sign); // Should return this for chaining
    });

    it('should throw error when alg is none', () => {
      const sign = new Sign({ test: 'value' });
      const header = {
        alg: 'none',
        typ: 'JWT',
      };
      expect(() =>
        sign.setProtectedHeader(header as ProtectedHeader),
      ).toThrow();
    });

    it('should throw error when alg is missing', () => {
      const sign = new Sign({ test: 'value' });
      const header = {
        typ: 'JWT',
      };
      expect(() =>
        sign.setProtectedHeader(header as ProtectedHeader),
      ).toThrow();
    });
  });

  describe('setDisclosureFrame', () => {
    it('should set disclosure frame', () => {
      const sign = new Sign({ test: 'value' });
      const frame: DisclosureFrame<{ test: string }> = {
        _sd: ['test'],
      };
      const result = sign.setDisclosureFrame(frame);
      expect(result).toBe(sign); // Should return this for chaining
    });
  });

  describe('setB64', () => {
    it('should set b64 to undefined when true', () => {
      const sign = new Sign({ test: 'value' });
      const result = sign.setB64(true);
      // @ts-expect-error accessing private field for testing
      expect(sign.protectedHeader.b64).toBeUndefined();
      expect(result).toBe(sign);
    });

    it('should set b64 to false when false', () => {
      const sign = new Sign({ test: 'value' });
      const result = sign.setB64(false);
      // @ts-expect-error accessing private field for testing
      expect(sign.protectedHeader.b64).toBe(false);
      expect(result).toBe(sign);
    });
  });

  describe('setIssuedAt', () => {
    it('should set custom issued at time', () => {
      const sign = new Sign({ test: 'value' });
      const timestamp = Math.floor(Date.now() / 1000);
      const result = sign.setIssuedAt(timestamp);
      // @ts-expect-error accessing private field for testing
      expect(sign.protectedHeader.iat).toBe(timestamp);
      expect(result).toBe(sign);
    });

    it('should set current time when no timestamp provided', () => {
      const sign = new Sign({ test: 'value' });
      const before = Math.floor(Date.now() / 1000);
      const result = sign.setIssuedAt();
      // @ts-expect-error accessing private field for testing
      const iat = sign.protectedHeader.iat as number;
      const after = Math.floor(Date.now() / 1000);

      expect(iat).toBeGreaterThanOrEqual(before);
      expect(iat).toBeLessThanOrEqual(after);
      expect(result).toBe(sign);
    });
  });

  describe('sign', () => {
    it('should throw when alg is not set', async () => {
      const sign = new Sign({ test: 'value' });
      await expect(sign.sign({} as KeyObject, 'kid')).rejects.toThrow();
    });

    it('should sign payload with RS256', async () => {
      const payload = { test: 'value' };
      const sign = new Sign(payload);
      sign
        .setProtectedHeader({
          alg: 'RS256',
          typ: 'JWT',
        })
        .setX5c(testCert);

      const result = await sign.sign(privateKey, 'test-kid');
      // @ts-expect-error accessing private field for testing
      const serialized = result.serialized;

      expect(serialized).toBeDefined();
      expect(serialized?.signatures).toHaveLength(1);
      expect(serialized?.signatures[0].protected).toBeDefined();
      expect(serialized?.signatures[0].signature).toBeDefined();

      // Verify the protected header
      const protectedHeader = JSON.parse(
        base64urlDecode(serialized?.signatures[0].protected ?? '').toString(),
      );
      expect(protectedHeader.alg).toBe('RS256');
      expect(protectedHeader.kid).toBe('test-kid');
      expect(protectedHeader.x5c).toBeDefined();
      expect(protectedHeader.x5c).toHaveLength(1);
    });

    it('should create detached signature when payload is undefined', async () => {
      const sign = new Sign();
      sign
        .setProtectedHeader({
          alg: 'RS256',
          typ: 'JWT',
        })
        .setX5c(testCert);

      const result = await sign.sign(privateKey, 'test-kid');
      // @ts-expect-error accessing private field for testing
      const serialized = result.serialized;

      expect(serialized).toBeDefined();
      expect(serialized?.payload).toBe('');
      expect(serialized?.signatures).toHaveLength(1);
      expect(serialized?.signatures[0].protected).toBeDefined();
      expect(serialized?.signatures[0].signature).toBeDefined();
    });

    it('should append multiple signatures', async () => {
      const payload = { test: 'value' };
      const sign = new Sign(payload);
      sign
        .setProtectedHeader({
          alg: 'RS256',
          typ: 'JWT',
        })
        .setX5c(testCert);

      await sign.sign(privateKey, 'kid1');
      await sign.sign(privateKey, 'kid2');

      // @ts-expect-error accessing private field for testing
      const serialized = sign.serialized;

      expect(serialized?.signatures).toHaveLength(2);
      expect(serialized?.signatures[0].protected).toBeDefined();
      expect(serialized?.signatures[1].protected).toBeDefined();

      // Verify different kids
      const header1 = JSON.parse(
        base64urlDecode(serialized?.signatures[0].protected ?? '').toString(),
      );
      const header2 = JSON.parse(
        base64urlDecode(serialized?.signatures[1].protected ?? '').toString(),
      );
      expect(header1.kid).toBe('kid1');
      expect(header2.kid).toBe('kid2');
      expect(header1.x5c).toBeDefined();
      expect(header2.x5c).toBeDefined();
    });

    it('should sign with disclosure frame', async () => {
      const payload = { test: 'value', sensitive: 'data' };
      const sign = new Sign(payload);
      const result = await sign
        .setProtectedHeader({
          alg: 'RS256',
          typ: 'JWT',
        })
        .setX5c(testCert)
        .setDisclosureFrame({
          _sd: ['sensitive'],
        })
        .sign(privateKey, 'test-kid');

      // @ts-expect-error accessing private field for testing
      const serialized = result.serialized;

      expect(serialized).toBeDefined();
      expect(serialized?.signatures).toHaveLength(1);

      // The payload should contain _sd array with hash
      const decodedPayload = JSON.parse(
        base64urlDecode(serialized?.payload ?? '').toString(),
      );
      expect(decodedPayload._sd).toBeDefined();
      expect(Array.isArray(decodedPayload._sd)).toBe(true);
      expect(decodedPayload.test).toBe('value');
      expect(decodedPayload.sensitive).toBeUndefined();
    });
  });

  describe('verify', () => {
    it('verify signed JAdES', async () => {
      const payload = { test: 'value', sensitive: 'data' };
      const sign = new Sign(payload);
      const result = await sign
        .setProtectedHeader({
          alg: 'RS256',
          typ: 'JWT',
        })
        .setX5c(testCert)
        .setDisclosureFrame({
          _sd: ['sensitive'],
        })
        .sign(privateKey, 'test-kid');

      const serialized = result.toJSON();

      expect(serialized).toBeDefined();
      const instance = new SDJwtGeneralJSONInstance({
        hasher: digest,
        verifier: JWTVerifier.verifier,
      });
      const verifiedData = await instance.verify(
        GeneralJSON.fromSerialized(serialized),
      );
      expect(verifiedData).toBeDefined();
      expect(verifiedData.payload).toEqual(payload);
    });
  });

  describe('error cases', () => {
    it('should throw when attempting to append signature without serialization', async () => {
      const sign = new Sign({ test: 'value' });
      // @ts-expect-error: Testing private method
      await expect(sign.appendSignature(null, 'kid')).rejects.toThrow();
    });

    it('should throw when alg is not set', async () => {
      const sign = new Sign({ test: 'value' });
      // @ts-expect-error: Testing private method
      await expect(sign.createSignature(null, 'kid')).rejects.toThrow();
    });
  });
});
