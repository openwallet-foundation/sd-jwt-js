import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  type X509Certificate,
  createPrivateKey,
  type KeyObject,
  createSign,
  createHash,
} from 'node:crypto';
import { Sign } from '../sign';
import type { DisclosureFrame } from '@sd-jwt/types';
import type { ProtectedHeader } from '../type';
import { base64urlDecode } from '@sd-jwt/utils';
import { parseCerts } from '../utils';
import { ALGORITHMS } from '../constant';

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

  // Helper function to create signature using Node.js crypto
  function createTestSignature(
    data: string,
    alg: string,
    privateKey: KeyObject,
  ): string {
    const algorithm = ALGORITHMS[alg as keyof typeof ALGORITHMS];
    const signer = createSign(algorithm.hash);
    signer.update(data);

    let signature: Buffer;
    if (alg.startsWith('RS') || alg.startsWith('PS')) {
      signature = signer.sign({
        key: privateKey,
        padding: (algorithm as { padding: number }).padding,
      });
    } else if (alg.startsWith('ES')) {
      signature = signer.sign({
        key: privateKey,
        dsaEncoding: 'ieee-p1363',
      });
    } else {
      signature = signer.sign({ key: privateKey });
    }

    return signature.toString('base64url');
  }

  describe('getHash and addSignature', () => {
    it('should get hash and add signature for payload', async () => {
      const payload = { test: 'value' };
      const sign = new Sign(payload);
      sign
        .setProtectedHeader({
          alg: 'RS256',
          typ: 'JWT',
        })
        .setX5c(testCert);

      // Get hash for HSM signing
      const hash = await sign.getHash('RS256', 'test-kid');
      expect(hash).toBeInstanceOf(Uint8Array);
      expect(hash.length).toBeGreaterThan(0);

      // Create signature (simulating HSM response)
      // In real usage, this would be done by HSM
      const signingInput = sign.getSignPayload('test-kid');
      const signature = createTestSignature(signingInput, 'RS256', privateKey);

      // Add the signature
      const result = await sign.addSignature(signature, 'test-kid');
      expect(result).toBe(sign);

      const serialized = sign.toJSON();
      expect(serialized).toBeDefined();
      expect(serialized.signatures).toHaveLength(1);
      expect(serialized.signatures[0].protected).toBeDefined();
      expect(serialized.signatures[0].signature).toBe(signature);

      // Verify the protected header
      const protectedHeader = JSON.parse(
        base64urlDecode(serialized.signatures[0].protected).toString(),
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

      const hash = await sign.getHash('RS256', 'test-kid');
      expect(hash).toBeInstanceOf(Uint8Array);

      const signingInput = sign.getSignPayload('test-kid');
      const signature = createTestSignature(signingInput, 'RS256', privateKey);

      const result = await sign.addSignature(signature, 'test-kid');
      const serialized = result.toJSON();

      expect(serialized).toBeDefined();
      expect(serialized.payload).toBe('');
      expect(serialized.signatures).toHaveLength(1);
      expect(serialized.signatures[0].protected).toBeDefined();
      expect(serialized.signatures[0].signature).toBe(signature);
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

      // First signature
      const hash1 = await sign.getHash('RS256', 'kid1');
      const signingInput1 = sign.getSignPayload('kid1');
      const signature1 = createTestSignature(
        signingInput1,
        'RS256',
        privateKey,
      );
      await sign.addSignature(signature1, 'kid1');

      // Second signature
      const hash2 = await sign.getHash('RS256', 'kid2');
      const signingInput2 = sign.getSignPayload('kid2');
      const signature2 = createTestSignature(
        signingInput2,
        'RS256',
        privateKey,
      );
      await sign.addSignature(signature2, 'kid2');

      const serialized = sign.toJSON();

      expect(serialized.signatures).toHaveLength(2);
      expect(serialized.signatures[0].protected).toBeDefined();
      expect(serialized.signatures[1].protected).toBeDefined();

      // Verify different kids
      const header1 = JSON.parse(
        base64urlDecode(serialized.signatures[0].protected).toString(),
      );
      const header2 = JSON.parse(
        base64urlDecode(serialized.signatures[1].protected).toString(),
      );
      expect(header1.kid).toBe('kid1');
      expect(header2.kid).toBe('kid2');
      expect(header1.x5c).toBeDefined();
      expect(header2.x5c).toBeDefined();
    });

    it('should work with different algorithms', async () => {
      const payload = { test: 'value' };
      const algorithms = [
        'RS256',
        'RS384',
        'RS512',
        'PS256',
        'PS384',
        'PS512',
      ] as const;

      for (const alg of algorithms) {
        const sign = new Sign(payload);
        sign
          .setProtectedHeader({
            alg,
            typ: 'JWT',
          })
          .setX5c(testCert);

        const hash = await sign.getHash(alg, 'test-kid');
        expect(hash).toBeInstanceOf(Uint8Array);
        expect(hash.length).toBeGreaterThan(0);

        const signingInput = sign.getSignPayload('test-kid');
        const signature = createTestSignature(signingInput, alg, privateKey);
        await sign.addSignature(signature, 'test-kid');

        const serialized = sign.toJSON();
        expect(serialized.signatures).toHaveLength(1);

        const protectedHeader = JSON.parse(
          base64urlDecode(serialized.signatures[0].protected).toString(),
        );
        expect(protectedHeader.alg).toBe(alg);
      }
    });

    it('should return correct hash value', async () => {
      const payload = { test: 'value', data: 'example' };
      const sign = new Sign(payload);
      const kid = 'test-kid';
      const alg = 'RS256';

      sign
        .setProtectedHeader({
          alg,
          typ: 'JWT',
        })
        .setX5c(testCert);

      // Get hash from the Sign class
      const actualHash = await sign.getHash(alg, kid);

      // Calculate expected hash manually
      const signingInput = sign.getSignPayload(kid);
      const expectedHash = createHash('sha256').update(signingInput).digest();

      // Compare the hashes
      expect(actualHash).toEqual(new Uint8Array(expectedHash));
      expect(actualHash.length).toBe(32); // SHA-256 produces 32 bytes
    });

    it('should return correct hash for different algorithms', async () => {
      const payload = { test: 'value' };
      const kid = 'test-kid';
      const testCases = [
        { alg: 'RS256', hashAlg: 'sha256', expectedLength: 32 },
        { alg: 'RS384', hashAlg: 'sha384', expectedLength: 48 },
        { alg: 'RS512', hashAlg: 'sha512', expectedLength: 64 },
        { alg: 'PS256', hashAlg: 'sha256', expectedLength: 32 },
        { alg: 'PS384', hashAlg: 'sha384', expectedLength: 48 },
        { alg: 'PS512', hashAlg: 'sha512', expectedLength: 64 },
      ] as const;

      for (const { alg, hashAlg, expectedLength } of testCases) {
        const sign = new Sign(payload);
        sign
          .setProtectedHeader({
            alg,
            typ: 'JWT',
          })
          .setX5c(testCert);

        // Get hash from the Sign class
        const actualHash = await sign.getHash(alg, kid);

        // Calculate expected hash manually
        const signingInput = sign.getSignPayload(kid);
        const expectedHash = createHash(hashAlg).update(signingInput).digest();

        // Verify hash correctness and length
        expect(actualHash).toEqual(new Uint8Array(expectedHash));
        expect(actualHash.length).toBe(expectedLength);
      }
    });

    it('should return different hashes for different payloads', async () => {
      const kid = 'test-kid';
      const alg = 'RS256';

      // Create two different payloads
      const payload1 = { test: 'value1' };
      const payload2 = { test: 'value2' };

      const sign1 = new Sign(payload1);
      sign1.setProtectedHeader({ alg, typ: 'JWT' }).setX5c(testCert);

      const sign2 = new Sign(payload2);
      sign2.setProtectedHeader({ alg, typ: 'JWT' }).setX5c(testCert);

      const hash1 = await sign1.getHash(alg, kid);
      const hash2 = await sign2.getHash(alg, kid);

      // Hashes should be different for different payloads
      expect(hash1).not.toEqual(hash2);
    });

    it('should return different hashes for different kids', async () => {
      const payload = { test: 'value' };
      const alg = 'RS256';

      const sign = new Sign(payload);
      sign.setProtectedHeader({ alg, typ: 'JWT' }).setX5c(testCert);

      const hash1 = await sign.getHash(alg, 'kid1');
      const hash2 = await sign.getHash(alg, 'kid2');

      // Hashes should be different for different kids
      expect(hash1).not.toEqual(hash2);
    });
  });
});
