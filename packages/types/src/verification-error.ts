/**
 * Error codes for SD-JWT verification errors.
 */
export type VerificationErrorCode =
  | 'HASHER_NOT_FOUND'
  | 'VERIFIER_NOT_FOUND'
  | 'INVALID_SD_JWT'
  | 'INVALID_JWT_FORMAT'
  | 'JWT_NOT_YET_VALID'
  | 'JWT_EXPIRED'
  | 'INVALID_JWT_SIGNATURE'
  | 'MISSING_REQUIRED_CLAIMS'
  | 'KEY_BINDING_JWT_MISSING'
  | 'KEY_BINDING_VERIFIER_NOT_FOUND'
  | 'KEY_BINDING_SIGNATURE_INVALID'
  | 'KEY_BINDING_SD_HASH_INVALID'
  | 'STATUS_VERIFICATION_FAILED'
  | 'STATUS_INVALID'
  | 'VCT_VERIFICATION_FAILED'
  | 'UNKNOWN_ERROR';

/**
 * Represents a single verification error.
 */
export type VerificationError = {
  /**
   * The error code identifying the type of error.
   */
  code: VerificationErrorCode;

  /**
   * Human-readable error message.
   */
  message: string;

  /**
   * Optional additional details about the error.
   */
  details?: unknown;
};

/**
 * Result type for safe verification that collects all errors.
 */
export type SafeVerifyResult<T> =
  | {
      success: true;
      data: T;
      errors?: never;
    }
  | {
      success: false;
      data?: never;
      errors: VerificationError[];
    };
