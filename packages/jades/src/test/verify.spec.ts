import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { X509Certificate, createPrivateKey, KeyObject } from 'crypto';
import { Sign } from '../sign';
import { parseCerts } from '../utils';
import { JWTVerifier } from '../verify';

describe('Verify', () => {
  let testCert: X509Certificate[];
  let privateKey: KeyObject;
  let signedCredentialJson: any;

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

  // Create a credential to use in tests
  beforeAll(async () => {
    // Load test certificates and keys
    const certPath = path.join(__dirname, 'fixtures', 'certificate.crt');
    const certPem = fs.readFileSync(certPath, 'utf-8');
    testCert = parseCerts(certPem);

    const keyPath = path.join(__dirname, 'fixtures', 'private.pem');
    const keyPem = fs.readFileSync(keyPath, 'utf-8');
    privateKey = createPrivateKey(keyPem);

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
  });

  describe('verify method', () => {
    it('should verify a credential', async () => {
      const verifiedData = await JWTVerifier.verify(signedCredentialJson);
      expect(verifiedData).toBeDefined();
      expect(verifiedData.payload).toEqual(payload);
    });
  });
});
