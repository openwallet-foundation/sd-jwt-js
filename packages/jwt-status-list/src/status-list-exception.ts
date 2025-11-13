/**
 * SLException is a custom error class for Status List related exceptions.
 */
export declare class SLException extends Error {
    details?: unknown;
    constructor(message: string, details?: unknown);
    getFullMessage(): string;
}