import type { SdJwtPayload } from '@sd-jwt/core';
import type { SDJWTVCStatusReference } from './sd-jwt-vc-status-reference';

export interface SdJwtVcPayload extends SdJwtPayload {
  // OPTIONAL. The Issuer of the Verifiable Credential. The value is a case-sensitive string containing a StringOrURI value. See [RFC7519] for more information.
  iss?: string;
  // OPTIONAL. The time before which the Verifiable Credential MUST NOT be accepted before validating. See [RFC7519] for more information.
  nbf?: number;
  // OPTIONAL. The expiry time of the Verifiable Credential after which the Verifiable Credential is no longer valid. See [RFC7519] for more information.
  exp?: number;
  // OPTIONAL unless cryptographic Key Binding is to be supported, in which case it is REQUIRED. Contains the confirmation method identifying the proof of possession key as defined in [RFC7800]. It is RECOMMENDED that this contains a JWK as defined in Section 3.2 of [RFC7800]. For proof of cryptographic Key Binding, the Key Binding JWT in the presentation of the SD-JWT MUST be signed by the key identified in this claim.
  cnf?: unknown;
  // REQUIRED. The type of the Verifiable Credential, e.g., https://credentials.example.com/identity_credential, as defined in Section 3.2.2.1.1.
  vct: string;
  // OPTIONAL. If passed, the loaded type metadata format has to be validated according to https://www.w3.org/TR/SRI/
  'vct#integrity'?: string;
  // OPTIONAL. The information on how to read the status of the Verifiable Credential. See [https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html] for more information.
  status?: SDJWTVCStatusReference;
  // OPTIONAL. The identifier of the Subject of the Verifiable Credential. The Issuer MAY use it to provide the Subject identifier known by the Issuer. There is no requirement for a binding to exist between sub and cnf claims.
  sub?: string;
  // OPTIONAL. The time of issuance of the Verifiable Credential. See [RFC7519] for more information.
  iat?: number;
}
