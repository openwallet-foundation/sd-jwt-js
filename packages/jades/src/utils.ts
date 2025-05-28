import { X509Certificate } from 'crypto';
import { Sequence, CharacterString, Integer } from 'asn1js';
import { GeneralJSON } from '@sd-jwt/core';
import { GeneralJWS } from './type';
import { SDJWTException } from '@sd-jwt/utils';

export const parseCerts = (chainPem: string): X509Certificate[] => {
  return chainPem
    .split(/(?=-----BEGIN CERTIFICATE-----)/g)
    .filter((cert) => cert.trim().length > 0)
    .map((cert) => new X509Certificate(cert));
};

/**
 * Creates a JAdES-compliant kid from X.509 certificate
 * According to TS 119 182-1 v1.2.1 section 5.1.4
 */
export const createKidFromCert = (cert: X509Certificate) => {
  /*

	KID = base64url(derEncodeSequence(IssuerSerial))

	IssuerSerial ::= SEQUENCE {
		issuer                   GeneralNames,
		serialNumber             CertificateSerialNumber
	}

	GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName

	GeneralName ::= CHOICE {
		  otherName                       [0]     OtherName,
		  rfc822Name                      [1]     IA5String,
		  dNSName                         [2]     IA5String,
		  x400Address                     [3]     ORAddress,
		  directoryName                   [4]     Name,
		  ediPartyName                    [5]     EDIPartyName,
		  uniformResourceIdentifier       [6]     IA5String,
		  iPAddress                       [7]     OCTET STRING,
		  registeredID                    [8]     OBJECT IDENTIFIER 
  }

	CertificateSerialNumber ::= INTEGER

	issuer
		contains the issuer name of the certificate.  For non-attribute
		certificates, the issuer MUST contain only the issuer name from
		the certificate encoded in the directoryName choice of
		GeneralNames.  For attribute certificates, the issuer MUST contain
		the issuer name field from the attribute certificate.

	serialNumber
		holds the serial number that uniquely identifies the certificate
		for the issuer.
	*/

  // Get issuer and serial from certificate
  const issuer = cert.issuer;
  const serialNumber = cert.serialNumber;

  // Create an instance of the Sequence ASN.1 class
  const sequence = new Sequence({
    value: [
      // issuer
      new CharacterString({
        value: issuer,
      }),
      // serialNumber
      new Integer({
        // Passing the serial number as a string is not supported by the library
        valueHex: new Uint8Array(Buffer.from(serialNumber, 'hex')),
      }),
    ],
  });

  // DER-encode the sequence
  const derEncoded = sequence.toBER(false);

  // Return the base64 encoding of the DER-encoded sequence
  return Buffer.from(derEncoded).toString('base64');
};

export const getGeneralJSONFromJWSToken = (
  credential: GeneralJWS | string,
): GeneralJSON => {
  if (typeof credential === 'string') {
    try {
      const parsed = JSON.parse(credential);
      return GeneralJSON.fromSerialized(parsed);
    } catch (error) {
      throw new SDJWTException(
        'Invalid credential format: not a valid JSON',
        error,
      );
    }
  }
  return GeneralJSON.fromSerialized(credential);
};
