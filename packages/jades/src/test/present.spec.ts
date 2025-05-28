import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { X509Certificate, createPrivateKey, KeyObject } from 'crypto';
import { Sign } from '../sign';
import { Present } from '../present';
import { parseCerts } from '../utils';
import { GeneralJSON, SDJwtGeneralJSONInstance } from '@sd-jwt/core';
import { digest } from '@sd-jwt/crypto-nodejs';
import { JWTVerifier } from '../verify';

describe('Present', () => {
  let testCert: X509Certificate[];
  let privateKey: KeyObject;
  let signedCredentialJson: any;
  let signedCredentialJsonWithoutSD: any;

  // Create a credential to use in tests
  beforeAll(async () => {
    // Load test certificates and keys
    const certPath = path.join(__dirname, 'fixtures', 'certificate.crt');
    const certPem = fs.readFileSync(certPath, 'utf-8');
    testCert = parseCerts(certPem);

    const keyPath = path.join(__dirname, 'fixtures', 'private.pem');
    const keyPem = fs.readFileSync(keyPath, 'utf-8');
    privateKey = createPrivateKey(keyPem);

    // Create a test credential with selective disclosure
    const payload = {
      vct: 'https://credentials.example.com/drivers_license',
      iss: 'https://dmv.example.gov',
      iat: 1683000000,
      exp: 1793000000,
      given_name: 'Jane',
      family_name: 'Doe',
      license_number: 'DL123456789',
      license_class: 'C',
      address: {
        street_address: '456 Oak Ave',
        locality: 'Springfield',
        region: 'State',
        country: 'US',
      },
      birthdate: '1985-05-15',
    };

    const sign = new Sign(payload);
    const result = await sign
      .setProtectedHeader({
        alg: 'RS256',
        typ: 'jades',
      })
      .setX5c(testCert)
      .setDisclosureFrame({
        _sd: ['given_name', 'family_name', 'license_number', 'license_class'],
      })
      .sign(privateKey, 'test-kid');

    signedCredentialJson = result.toJSON();

    const sign2 = new Sign(payload);
    const result2 = await sign2
      .setProtectedHeader({
        alg: 'RS256',
        typ: 'jades',
      })
      .setX5c(testCert)
      .setDisclosureFrame({
        _sd: [],
      })
      .sign(privateKey, 'test-kid');

    signedCredentialJsonWithoutSD = result2.toJSON();
  });

  describe('present method', () => {
    it('should create a presentation with selective disclosure', async () => {
      // Present with only names disclosed
      const presentationFrame = {
        given_name: true,
        family_name: true,
      };

      const presentedCredentialJson = await Present.present(
        signedCredentialJson,
        presentationFrame,
      );

      // Convert the JSON result back to GeneralJSON for verification
      const presentedCredential = GeneralJSON.fromSerialized(
        presentedCredentialJson,
      );

      // Verify the presented credential
      const instance = new SDJwtGeneralJSONInstance({
        hasher: digest,
        verifier: JWTVerifier.verifier,
      });

      const verifiedData = await instance.verify(presentedCredential);

      expect(verifiedData).toBeDefined();
      expect(verifiedData.payload).toHaveProperty('address');
      expect(verifiedData.payload).toHaveProperty('birthdate');
      expect(verifiedData.payload).toHaveProperty('given_name');
      expect(verifiedData.payload).toHaveProperty('family_name');
      expect(verifiedData.payload).not.toHaveProperty('license_number');
      expect(verifiedData.payload).not.toHaveProperty('license_class');
    });

    it('should handle JSON input as a string', async () => {
      // Present with only name and license_class disclosed
      const presentationFrame = {
        given_name: true,
        family_name: true,
        license_class: true,
      };

      const jsonString = JSON.stringify(signedCredentialJson, null, 2);

      const presentedCredentialJson = await Present.present(
        jsonString,
        presentationFrame,
      );

      // Convert the JSON result back to GeneralJSON for verification
      const presentedCredential = GeneralJSON.fromSerialized(
        presentedCredentialJson,
      );

      // Verify the presented credential
      const instance = new SDJwtGeneralJSONInstance({
        hasher: digest,
        verifier: JWTVerifier.verifier,
      });

      const verifiedData = await instance.verify(presentedCredential);

      expect(verifiedData).toBeDefined();
      expect(verifiedData.payload).toHaveProperty('given_name');
      expect(verifiedData.payload).toHaveProperty('family_name');
      expect(verifiedData.payload).toHaveProperty('license_class');
      expect(verifiedData.payload).not.toHaveProperty('license_number');
    });

    it('should create a presentation without SD', async () => {
      const presentedCredentialJson = await Present.present(
        signedCredentialJsonWithoutSD,
      );

      // Verify the result is returned correctly
      expect(presentedCredentialJson).toBeDefined();

      // Verify that the presented credential is the same as the original
      // (compare key properties since we're getting back a plain object now)
      expect(presentedCredentialJson.payload).toEqual(
        signedCredentialJsonWithoutSD.payload,
      );
      expect(presentedCredentialJson.signatures).toEqual(
        signedCredentialJsonWithoutSD.signatures,
      );
    });

    it('should handle JSON without SD input as a string', async () => {
      const jsonString = JSON.stringify(signedCredentialJsonWithoutSD, null, 2);

      const presentedCredentialJson = await Present.present(jsonString);

      // Verify the result is returned correctly
      expect(presentedCredentialJson).toBeDefined();

      // Verify that the presented credential has the same structure as the original
      expect(presentedCredentialJson.payload).toEqual(
        signedCredentialJsonWithoutSD.payload,
      );
      expect(presentedCredentialJson.signatures).toEqual(
        signedCredentialJsonWithoutSD.signatures,
      );
    });
  });
});
