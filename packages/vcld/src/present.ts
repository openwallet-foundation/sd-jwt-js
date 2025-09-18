import { SDJwtInstance } from '@sd-jwt/core';
import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { type PresentationFrame } from '@sd-jwt/types';

export const Present = {
  async present<T extends Record<string, unknown>>(
    credential: string,
    presentationFrame?: PresentationFrame<T>,
    options?: Record<string, unknown>,
  ): Promise<string> {
    // Initialize the SD JWT instance with proper configuration
    const sdJwtInstance = new SDJwtInstance({
      hashAlg: 'sha-256',
      hasher: digest,
      saltGenerator: generateSalt,
    });

    // Use the instance's present method for the core SD-JWT functionality
    const presentedCredential = await sdJwtInstance.present(
      credential,
      presentationFrame,
    );

    return presentedCredential;
  },
};
