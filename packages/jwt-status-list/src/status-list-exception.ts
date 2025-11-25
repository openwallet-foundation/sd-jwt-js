/**
 * StatusListException is a custom error class for Status List related exceptions.
 */
export class StatusListException extends Error {
  public details?: unknown;

  constructor(message: string, details?: unknown) {
    super(message);
    Object.setPrototypeOf(this, StatusListException.prototype);
    this.name = 'StatusListException';
    this.details = details;
  }

  getFullMessage(): string {
    return `${this.name}: ${this.message} ${
      this.details ? `- ${JSON.stringify(this.details)}` : ''
    }`;
  }
}
