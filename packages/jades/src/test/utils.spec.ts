import { X509Certificate } from 'crypto';

import { describe, it, expect, beforeAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import { createKidFromCert } from '../utils';

describe('createKidFromCert', () => {
  let testCert: X509Certificate;

  beforeAll(() => {
    const certPath = path.join(__dirname, 'fixtures', 'pkijs-test-cert.crt');
    const certPem = fs.readFileSync(certPath, 'utf-8');
    testCert = new X509Certificate(certPem);
  });

  it('should create a valid base64 encoded kid', () => {
    const kid = createKidFromCert(testCert);

    console.log(kid);
    // Check if output is defined
    expect(kid).toBeDefined();
    // Check if output is base64 encoded
    expect(() => Buffer.from(kid, 'base64')).not.toThrow();
  });

  it('should throw for invalid certificate', () => {
    const invalidCert = {} as X509Certificate;
    expect(() => createKidFromCert(invalidCert)).toThrow();
  });
});
