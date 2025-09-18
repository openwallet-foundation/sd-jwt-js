import { describe, expect, test, it, beforeAll } from 'vitest';
import { Signer, decode } from '../sign'; // Adjusted path to '../sign'
import { generateKeyPairSync, type KeyObject } from 'node:crypto';
import type { JsonLdDocument } from 'jsonld';

// Sample data (will be expanded)
const sampleDoc: JsonLdDocument = {
  '@context': 'https://www.w3.org/2018/credentials/v1',
  id: 'urn:uuid:12345678-1234-5678-1234-567812345678',
  type: ['VerifiableCredential', 'UniversityDegreeCredential'],
  issuer: 'https://example.edu/issuers/14',
  issuanceDate: '2023-01-01T00:00:00Z',
  credentialSubject: {
    id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
    degree: {
      type: 'BachelorDegree',
      name: 'Bachelor of Science in Computer Science',
    },
  },
};

const vct = 'UniversityDegreeCredential';

let es256KeyPair: { publicKey: KeyObject; privateKey: KeyObject };
let rs256KeyPair: { publicKey: KeyObject; privateKey: KeyObject };
let ed25519KeyPair: { publicKey: KeyObject; privateKey: KeyObject };

describe('Signer and Decode Tests', () => {
  beforeAll(() => {
    es256KeyPair = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    rs256KeyPair = generateKeyPairSync('rsa', {
      modulusLength: 2048,
    });
    ed25519KeyPair = generateKeyPairSync('ed25519');
  });

  describe('Signer Class', () => {
    it('should correctly initialize with constructor', () => {
      const signer = new Signer(sampleDoc, vct);
      expect(signer).toBeInstanceOf(Signer);
      // @ts-expect-error access private member for test
      expect(signer.doc).toEqual(sampleDoc);
      // @ts-expect-error access private member for test
      expect(signer.vct).toEqual(vct);
      // @ts-expect-error access private member for test
      expect(signer.signAlg).toEqual('ES256'); // Default
    });

    it('should set signAlg', () => {
      const signer = new Signer(sampleDoc, vct);
      signer.setSignAlg('RS256');
      // @ts-expect-error access private member for test
      expect(signer.signAlg).toEqual('RS256');
    });

    it('should set disclosureFrame', () => {
      const signer = new Signer(sampleDoc, vct);
      const frame = { credentialSubject: { _sd: ['degree'] } };
      signer.setDisclosureFrame(frame as any);
      // @ts-expect-error access private member for test
      expect(signer.disclosureFrame).toEqual(frame);
    });

    it('should set header', () => {
      const signer = new Signer(sampleDoc, vct);
      const header = { typ: 'vc+sd-jwt' };
      signer.setHeader(header);
      // @ts-expect-error access private member for test
      expect(signer.header).toEqual(header);
    });

    it('should set iss', () => {
      const signer = new Signer(sampleDoc, vct);
      const iss = 'https://example.com/issuer';
      signer.setIss(iss);
      // @ts-expect-error access private member for test
      expect(signer.iss).toEqual(iss);
    });

    it('should set exp', () => {
      const signer = new Signer(sampleDoc, vct);
      const exp = Math.floor(Date.now() / 1000) + 3600;
      signer.setExp(exp);
      // @ts-expect-error access private member for test
      expect(signer.exp).toEqual(exp);
    });

    it('should set nbf', () => {
      const signer = new Signer(sampleDoc, vct);
      const nbf = Math.floor(Date.now() / 1000);
      signer.setNbf(nbf);
      // @ts-expect-error access private member for test
      expect(signer.nbf).toEqual(nbf);
    });

    describe('sign method', () => {
      const iss = 'https://example.com/issuer';
      const exp = Math.floor(Date.now() / 1000) + 3600;
      const nbf = Math.floor(Date.now() / 1000);

      it('should throw error if iss is not set', async () => {
        const signer = new Signer(sampleDoc, vct);
        signer.setExp(exp);
        signer.setNbf(nbf);
        await expect(signer.sign(es256KeyPair.privateKey)).rejects.toThrow(
          'iss must be set when signing',
        );
      });

      it('should throw error if exp is not set', async () => {
        const signer = new Signer(sampleDoc, vct);
        signer.setIss(iss);
        signer.setNbf(nbf);
        await expect(signer.sign(es256KeyPair.privateKey)).rejects.toThrow(
          'exp must be set when signing',
        );
      });

      it('should throw error if nbf is not set', async () => {
        const signer = new Signer(sampleDoc, vct);
        signer.setIss(iss);
        signer.setExp(exp);
        await expect(signer.sign(es256KeyPair.privateKey)).rejects.toThrow(
          'nbf must be set when signing',
        );
      });

      it('should sign successfully with ES256', async () => {
        const signer = new Signer(sampleDoc, vct);
        signer.setIss(iss);
        signer.setExp(exp);
        signer.setNbf(nbf);
        signer.setSignAlg('ES256');
        const compactJwt = await signer.sign(es256KeyPair.privateKey);
        expect(compactJwt).toBeTypeOf('string');
        expect(compactJwt.split('.').length).toBeGreaterThanOrEqual(3); // JWT.Disclosures...
      });

      it('should sign successfully with RS256', async () => {
        const signer = new Signer(sampleDoc, vct);
        signer.setIss(iss);
        signer.setExp(exp);
        signer.setNbf(nbf);
        signer.setSignAlg('RS256');
        const compactJwt = await signer.sign(rs256KeyPair.privateKey);
        expect(compactJwt).toBeTypeOf('string');
        expect(compactJwt.split('.').length).toBeGreaterThanOrEqual(3);
      });

      it('should sign successfully with PS256', async () => {
        const signer = new Signer(sampleDoc, vct);
        signer.setIss(iss);
        signer.setExp(exp);
        signer.setNbf(nbf);
        signer.setSignAlg('PS256');
        const compactJwt = await signer.sign(rs256KeyPair.privateKey); // RSA key can be used for PS256
        expect(compactJwt).toBeTypeOf('string');
        expect(compactJwt.split('.').length).toBeGreaterThanOrEqual(3);
      });
    });
  });

  describe('decode function', () => {
    const iss = 'https://example.com/issuer';
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const nbf = Math.floor(Date.now() / 1000);
    const disclosureFrame = {
      credentialSubject: { _sd: ['degree'] },
    } as any;

    it('should decode a signed JWT (ES256) and verify claims', async () => {
      const signer = new Signer(sampleDoc, vct);
      signer.setIss(iss);
      signer.setExp(exp);
      signer.setNbf(nbf);
      signer.setSignAlg('ES256');
      signer.setDisclosureFrame(disclosureFrame);

      const compactJwt = await signer.sign(es256KeyPair.privateKey);
      const { claims, ld } = decode(compactJwt);

      expect(claims.iss).toEqual(iss);
      expect(claims.exp).toEqual(exp);
      expect(claims.nbf).toEqual(nbf);
      expect(claims.vct).toEqual(vct);
      expect(ld).toBeDefined();
      // @ts-expect-error ld is checked
      expect(ld.credentialSubject.degree).toBeDefined(); // Check selectively disclosed part
      // @ts-expect-error ld is checked
      expect(ld.id).toEqual(sampleDoc.id);
    });

    it('should decode a signed JWT (RS256) and verify claims', async () => {
      const signer = new Signer(sampleDoc, vct);
      signer.setIss(iss);
      signer.setExp(exp);
      signer.setNbf(nbf);
      signer.setSignAlg('RS256');
      signer.setDisclosureFrame(disclosureFrame);

      const compactJwt = await signer.sign(rs256KeyPair.privateKey);
      const { claims, ld } = decode(compactJwt);

      expect(claims.iss).toEqual(iss);
      expect(claims.exp).toEqual(exp);
      expect(claims.nbf).toEqual(nbf);
      expect(claims.vct).toEqual(vct);
      expect(ld).toBeDefined();
      // @ts-expect-error ld is checked
      expect(ld.credentialSubject.degree).toBeDefined();
      // @ts-expect-error ld is checked
      expect(ld.id).toEqual(sampleDoc.id);
    });

    it('should decode a signed JWT without disclosures', async () => {
      const signer = new Signer(sampleDoc, vct);
      signer.setIss(iss);
      signer.setExp(exp);
      signer.setNbf(nbf);
      signer.setSignAlg('ES256');
      // No disclosureFrame set

      const compactJwt = await signer.sign(es256KeyPair.privateKey);
      const { claims, ld } = decode(compactJwt);

      expect(claims.iss).toEqual(iss);
      expect(claims.exp).toEqual(exp);
      expect(claims.nbf).toEqual(nbf);
      expect(claims.vct).toEqual(vct);
      expect(ld).toBeDefined();
      // @ts-expect-error ld is checked
      expect(ld?.credentialSubject?.degree?.name).toEqual(
        (sampleDoc?.credentialSubject as any)?.degree?.name,
      ); // Entire degree object should be present
      // @ts-expect-error ld is checked
      expect(ld?.id).toEqual(sampleDoc?.id);
    });
  });
});
