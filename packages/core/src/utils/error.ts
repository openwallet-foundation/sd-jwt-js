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
