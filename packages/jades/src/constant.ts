import { constants } from 'crypto';

export const ALGORITHMS = {
  // RSA
  RS256: { hash: 'sha256', padding: constants.RSA_PKCS1_PADDING },
  RS384: { hash: 'sha384', padding: constants.RSA_PKCS1_PADDING },
  RS512: { hash: 'sha512', padding: constants.RSA_PKCS1_PADDING },

  // RSA-PSS
  PS256: { hash: 'sha256', padding: constants.RSA_PKCS1_PSS_PADDING },
  PS384: { hash: 'sha384', padding: constants.RSA_PKCS1_PSS_PADDING },
  PS512: { hash: 'sha512', padding: constants.RSA_PKCS1_PSS_PADDING },

  // ECDSA
  ES256: { hash: 'sha256', namedCurve: 'P-256' },
  ES384: { hash: 'sha384', namedCurve: 'P-384' },
  ES512: { hash: 'sha512', namedCurve: 'P-521' },

  // EdDSA
  EdDSA: { curves: ['ed25519', 'ed448'] },
};

export enum CommitmentOIDs {
  proofOfOrigin = '1.2.840.113549.1.9.16.6.1',
  proofOfReceipt = '1.2.840.113549.1.9.16.6.2',
  proofOfDelivery = '1.2.840.113549.1.9.16.6.3',
  proofOfSender = '1.2.840.113549.1.9.16.6.4',
  proofOfApproval = '1.2.840.113549.1.9.16.6.5',
  proofOfCreation = '1.2.840.113549.1.9.16.6.6',
}
