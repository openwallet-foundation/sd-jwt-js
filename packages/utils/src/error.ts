export class SDJWTException extends Error {
  public details?: unknown;
  public override cause?: Error;

  constructor(message: string, options?: { details?: unknown; cause?: Error }) {
    super(message, { cause: options?.cause });
    Object.setPrototypeOf(this, SDJWTException.prototype);
    this.name = 'SDJWTException';
    this.details = options?.details;

    // Capture stack trace for better debugging
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, SDJWTException);
    }
  }

  getFullMessage(): string {
    return `${this.name}: ${this.message} ${
      this.details ? `- ${JSON.stringify(this.details)}` : ''
    }`;
  }

  /**
   * Returns a string representation including the full error chain
   */
  override toString(): string {
    let result = this.getFullMessage();

    if (this.stack) {
      result += `\n${this.stack}`;
    }

    // Include the cause chain
    if (this.cause) {
      result += `\n\nCaused by: ${this.cause.toString()}`;
      if (this.cause.stack) {
        result += `\n${this.cause.stack}`;
      }
    }

    return result;
  }
}
