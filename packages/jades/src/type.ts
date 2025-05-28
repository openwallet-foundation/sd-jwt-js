import { ALGORITHMS, CommitmentOIDs } from './constant';

export type ProtectedHeader = {
  alg: Alg;
  typ?: string;

  // TODO: define other headers
  [key: string]: unknown;
};

export type SigD = {
  mId: string;
  pars: [string, string];
  hash: string;
};

export type Alg = keyof typeof ALGORITHMS;

export type GeneralJWS = {
  payload: string;
  signatures: Array<{
    protected: string;
    signature: string;

    /**
     * This is a optional unprotected header.
     *
     */
    header: {
      disclosures?: Array<string>;
      kid?: string;
      kb_jwt?: string;

      /**
       * TODO: add JAdES unprotected header
       */
      etsiU?: any;
    };
  }>;
};

export type CommitmentOption = Array<{
  commId: string | CommitmentOIDs;
  commQuals?: Array<Record<string, unknown>>;
}>;

export type UnprotectedHeader = {
  etsiU?: EtsiU;
};

export type EtsiU =
  | [sigTst] // B-T profile
  | [sigTst, XVal, rVal] // B-LT profile
  | [sigTst, XVal, rVal, ArcTst]; // B-LTA profile

export type TstToken = {
  tstTokens: Array<{ val: string }>;
};

export type sigTst = {
  sigTst: TstToken;
};

export type XVal = {
  xVals: Array<{ x509Cert: string }>;
};

export type rVal = {
  rVals: {
    crlVals: Array<string>;
    ocspVals: Array<string>;
  };
};

export type ArcTst = {
  arcTst: TstToken & {
    canonAlg: string;
  };
};
