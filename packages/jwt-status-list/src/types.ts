import type { JwtPayload } from '@sd-jwt/types';

// ==================== Common Types & Constants ====================

/**
 * Status Type values as defined in the spec.
 * These represent the possible status values for a Referenced Token.
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-7
 */
export const StatusTypes = {
  /** The status of the Referenced Token is valid, correct or legal. */
  VALID: 0x00,
  /** The status of the Referenced Token is revoked, annulled, taken back, recalled or cancelled. */
  INVALID: 0x01,
  /** The status of the Referenced Token is temporarily invalid, hanging, debarred from privilege. This status is usually temporary. */
  SUSPENDED: 0x02,
  /** Application-specific status (0x03). The processing is application specific. */
  APPLICATION_SPECIFIC_3: 0x03,
  /** Application-specific status range start (0x0C). Values 0x0C-0x0F are reserved for application specific use. */
  APPLICATION_SPECIFIC_RANGE_START: 0x0c,
  /** Application-specific status range end (0x0F). Values 0x0C-0x0F are reserved for application specific use. */
  APPLICATION_SPECIFIC_RANGE_END: 0x0f,
} as const;

export type StatusType =
  | (typeof StatusTypes)[keyof typeof StatusTypes]
  | number;

/**
 * Media types for Status List Tokens
 * Used for HTTP Content-Type and Accept headers
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-14.7
 */
export const MediaTypes = {
  /** Media type for JWT-based Status List Token */
  STATUS_LIST_JWT: 'application/statuslist+jwt',
  /** Media type for CWT-based Status List Token */
  STATUS_LIST_CWT: 'application/statuslist+cwt',
} as const;

// ==================== JWT Types & Constants ====================

/**
 * JWT type header value for Status List Token
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-5.1
 */
export const JWT_STATUS_LIST_TYPE = 'statuslist+jwt';

/**
 * JWT claim names for Status List
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-14.1
 */
export const JWTClaimNames = {
  /** Status claim - contains a reference to a status mechanism */
  STATUS: 'status',
  /** Status list claim - contains the status list data */
  STATUS_LIST: 'status_list',
  /** Time to live claim */
  TTL: 'ttl',
  /** Index field in status_list reference */
  IDX: 'idx',
  /** URI field in status_list reference */
  URI: 'uri',
  /** Bits field in status_list */
  BITS: 'bits',
  /** List field in status_list (base64url encoded) */
  LST: 'lst',
  /** Aggregation URI field */
  AGGREGATION_URI: 'aggregation_uri',
} as const;

/**
 * Reference to a status list entry.
 */
export interface StatusListEntry {
  idx: number;
  uri: string;
}

/**
 * Payload for a JWT
 */
export interface JWTwithStatusListPayload extends JwtPayload {
  status: {
    status_list: StatusListEntry;
  };
}

/**
 * Payload for a JWT with a status list.
 */
export interface StatusListJWTPayload extends JwtPayload {
  ttl?: number;
  status_list: {
    bits: BitsPerStatus;
    lst: string;
  };
}

/**
 * BitsPerStatus type.
 */
export type BitsPerStatus = 1 | 2 | 4 | 8;

/**
 * Header parameters for a JWT Status List Token.
 */
export type StatusListJWTHeaderParameters = {
  alg: string;
  typ: typeof JWT_STATUS_LIST_TYPE;
  [key: string]: unknown;
};

// ==================== CWT Types ====================

/**
 * CWT Claim Keys as defined in draft-ietf-oauth-status-list
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-5.2
 */
export const CWTClaimKeys = {
  /** Subject claim (sub) */
  SUB: 2,
  /** Expiration time claim (exp) */
  EXP: 4,
  /** Issued at claim (iat) */
  IAT: 6,
  /** Time to live claim (ttl) */
  TTL: 65534,
  /** Status list claim */
  STATUS_LIST: 65533,
  /** Status claim for referenced tokens */
  STATUS: 65535,
} as const;

/**
 * CWT Status List map keys
 */
export const CWTStatusListKeys = {
  /** bits field in status_list */
  BITS: 'bits',
  /** lst field in status_list (compressed byte array) */
  LST: 'lst',
  /** aggregation_uri field in status_list */
  AGGREGATION_URI: 'aggregation_uri',
} as const;

/**
 * CWT Status List Info keys (for referenced tokens)
 */
export const CWTStatusListInfoKeys = {
  /** idx field */
  IDX: 'idx',
  /** uri field */
  URI: 'uri',
} as const;

/**
 * COSE Header type parameter value for Status List CWT (string form)
 * The type can be either this media type string OR the registered CoAP Content-Format ID.
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-5.2
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-14.8
 */
export const CWT_STATUS_LIST_TYPE = 'application/statuslist+cwt';

/**
 * CoAP Content-Format ID for Status List CWT (numeric form)
 * This is a placeholder - the actual value is TBD in the IANA registry.
 * Once assigned, this can be used as an alternative to CWT_STATUS_LIST_TYPE string.
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-14.8
 */
export const CWT_STATUS_LIST_CONTENT_FORMAT_ID: number | undefined = undefined;

/**
 * COSE Header parameter keys
 * @see https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-11.3
 */
export const COSEHeaderKeys = {
  /** Algorithm */
  ALG: 1,
  /** Critical */
  CRIT: 2,
  /** Content Type */
  CONTENT_TYPE: 3,
  /** Key ID */
  KID: 4,
  /** IV (Initialization Vector) */
  IV: 5,
  /** Partial IV */
  PARTIAL_IV: 6,
  /** Type (from RFC 9596) */
  TYPE: 16,
  /** X.509 certificate chain (for key resolution) */
  X5CHAIN: 33,
  /** X.509 certificate SHA-256 thumbprint (for key resolution) */
  X5T: 34,
  /** X.509 URL (for key resolution) */
  X5U: 35,
} as const;

/**
 * Status List in CBOR format
 * The lst field is a raw byte string (not base64url encoded like in JWT)
 */
export interface StatusListCBOR {
  bits: BitsPerStatus;
  lst: Uint8Array;
  aggregation_uri?: string;
}

/**
 * CWT Claims Set for a Status List Token
 * Uses numeric keys as defined in the spec
 */
export interface StatusListCWTPayload {
  /** Subject (claim key 2) - URI of the Status List Token */
  [CWTClaimKeys.SUB]: string;
  /** Issued at (claim key 6) - Unix timestamp */
  [CWTClaimKeys.IAT]: number;
  /** Expiration time (claim key 4) - Unix timestamp (optional but recommended) */
  [CWTClaimKeys.EXP]?: number;
  /** Time to live (claim key 65534) - seconds (optional but recommended) */
  [CWTClaimKeys.TTL]?: number;
  /** Status list (claim key 65533) */
  [CWTClaimKeys.STATUS_LIST]: StatusListCBOR;
}

/**
 * CWT Claims Set for a Referenced Token with status
 */
export interface CWTwithStatusListPayload {
  /** Subject (claim key 2) */
  [CWTClaimKeys.SUB]?: string;
  /** Issued at (claim key 6) */
  [CWTClaimKeys.IAT]?: number;
  /** Expiration time (claim key 4) */
  [CWTClaimKeys.EXP]?: number;
  /** Status (claim key 65535) */
  [CWTClaimKeys.STATUS]: {
    status_list: StatusListEntry;
  };
}

/**
 * COSE protected header for Status List CWT
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-5.2
 * @see https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-16.html#section-11.3
 */
export interface StatusListCWTHeader {
  /** Algorithm (key 1) - REQUIRED */
  [COSEHeaderKeys.ALG]: number;
  /** Type (key 16) - REQUIRED. Should be 'application/statuslist+cwt' or CoAP Content-Format ID */
  [COSEHeaderKeys.TYPE]: string | number;
  /** Key ID (key 4) - optional, for key resolution */
  [COSEHeaderKeys.KID]?: Uint8Array | string;
  /** X.509 certificate chain (key 33) - optional, for key resolution */
  [COSEHeaderKeys.X5CHAIN]?: Uint8Array | Uint8Array[];
  /** X.509 certificate SHA-256 thumbprint (key 34) - optional, for key resolution */
  [COSEHeaderKeys.X5T]?: Uint8Array;
  /** X.509 URL (key 35) - optional, for key resolution */
  [COSEHeaderKeys.X5U]?: string;
}
