/**
 * B.3.7. SD-JWT VCLD

SD-JWT VCLD (SD-JWT Verifiable Credentials with JSON-LD) extends the IETF SD-JWT VC [I-D.ietf-oauth-sd-jwt-vc] Credential format and allows to incorporate existing data models that use Linked Data, e.g., W3C VCDM [VC_DATA], while enabling a consistent and uncomplicated approach to selective disclosure.
Information contained in SD-JWT VCLD Credentials can be processed using a JSON-LD [JSON-LD] processor after the SD-JWT VC processing.When IETF SD-JWT VC is mentioned in this specification, SD-JWT VCLD defined in this section MAY be used.

B.3.7.1. Format

SD-JWT VCLD Credentials are valid SD-JWT VCs and all requirements from [I-D.ietf-oauth-sd-jwt-vc] apply. Additionally, the requirements listed in this section apply.
For compatibility with JWT processors, the following registered Claims from [RFC7519] and [I-D.ietf-oauth-sd-jwt-vc] MUST be used instead of any respective counterpart properties from W3C VCDM or elsewhere:

- vct to represent the type of the Credential.
- exp and nbf to represent the validity period of SD-JWT VCLD (i.e., cryptographic signature). 
- iss to represent the Credential Issuer. status to represent the information to obtain the status of the Credential.

IETF SD-JWT VC is extended with the following claim:

- ld: OPTIONAL. Contains a JSON-LD [JSON-LD] object in compact form, e.g., [VC_DATA].

B.3.7.2. Processing

The following outlines a suggested non-normative set of processing steps for SD-JWT VCLD:

B.3.7.2.1. Step 1: SD-JWT VC Processing

- A receiver (holder or verifier) of an SD-JWT VCLD applies the processing rules outlined in Section 4 of [I-D.ietf-oauth-sd-jwt-vc], including verifying signatures, validity periods, status information, etc.
- If the vct value is associated with any SD-JWT VC Type Metadata, schema validation of the entire SD-JWT VCLD is performed, including the nested ld claim.
- Additionally, trust framework rules are applied, such as ensuring the Credential Issuer is authorized to issue SD-JWT VCLDs for the specified vct value.

B.3.7.2.2. Step 2: Business Logic Processing

- Once the SD-JWT VC is verified and trusted by the SD-JWT VC processor, and if the ld claim is present, the receiver extracts the JSON-LD object from the ld claim and uses this for the business logic object. 
  If the ld claim is not present, the entire SD-JWT VC is considered to represent the business logic object.
- The business logic object is then passed on for further use case-specific processing and validation. 
  The business logic assumes that all security-critical functions (e.g., signature verification, trusted issuer) have already been performed during the previous step. 
  Additional schema validation is applied if provided in the ld claim, e.g., to support SHACL schemas. Note that while a vct claim is required, SD-JWT VC type metadata resolution and related schema validation is optional in certain cases. 

 */

import { Present } from './present';
import { decode, Signer } from './sign';
import { JWTVerifier } from './verify';

export * from './type';

export const VCld = {
  Signer,
  decode,
  Present,
  Verify: JWTVerifier,
};
