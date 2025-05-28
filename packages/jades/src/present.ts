import { SDJwtGeneralJSONInstance } from '@sd-jwt/core';
import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { PresentationFrame } from '@sd-jwt/types';
import { GeneralJWS } from './type';
import { getGeneralJSONFromJWSToken } from './utils';

export class Present {
  public static async present<T extends Record<string, unknown>>(
    credential: GeneralJWS | string,
    presentationFrame?: PresentationFrame<T>,
    options?: Record<string, unknown>,
  ): Promise<GeneralJWS> {
    // Initialize the SD JWT instance with proper configuration
    const sdJwtInstance = new SDJwtGeneralJSONInstance({
      hashAlg: 'sha-256',
      hasher: digest,
      saltGenerator: generateSalt,
    });

    // Convert string to GeneralJSON if needed
    const generalJsonCredential = getGeneralJSONFromJWSToken(credential);

    // If there are no disclosures, return the credential as is
    // This prevents errors from the core library when handling credentials without SD claims
    if (
      !generalJsonCredential.disclosures ||
      generalJsonCredential.disclosures.length === 0
    ) {
      console.log(
        'Credential has no selective disclosure claims, returning as is',
      );
      return generalJsonCredential.toJson();
    }

    // Use the instance's present method for the core SD-JWT functionality
    const presentedCredential = await sdJwtInstance.present(
      generalJsonCredential,
      presentationFrame,
    );

    return presentedCredential.toJson();
  }
}
