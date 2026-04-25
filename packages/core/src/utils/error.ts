export class SDJWTException extends Error {
  public details?: unknown;

  constructor(message: string, details?: unknown) {
    super(message);
    Object.setPrototypeOf(this, SDJWTException.prototype);
    this.name = 'SDJWTException';
    this.details = details;
  }

  getFullMessage(): string {
    return `${this.name}: ${this.message} ${
      this.details ? `- ${JSON.stringify(this.details)}` : ''
    }`;
  }
}

/**
 * Narrows an unknown caught value to an Error instance.
 */
export function ensureError(value: unknown): Error {
  if (value instanceof Error) return value;
  if (typeof value === 'string') return new Error(value);
  return new Error(String(value));
}
