/**
 * SLException is a custom error class for Status List related exceptions.
 */
export class SLException extends Error {
  public details?: unknown;

  constructor(message: string, details?: unknown) {
    super(message);
    Object.setPrototypeOf(this, SLException.prototype);
    this.name = 'SLException';
    this.details = details;
  }

  getFullMessage(): string {
    return `${this.name}: ${this.message} ${
      this.details ? `- ${JSON.stringify(this.details)}` : ''
    }`;
  }
}
