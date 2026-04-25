import type { HasherAndAlg, SaltGenerator } from './types';
import { uint8ArrayToBase64Url } from './utils';

// This function creates a decoy value that can be used to obscure SD JWT payload.
// The value is basically a hash of a random salt. So the value is not predictable.
// return value is a base64url encoded string.
export const createDecoy = async (
  hash: HasherAndAlg,
  saltGenerator: SaltGenerator,
): Promise<string> => {
  const { hasher, alg } = hash;
  const salt = await saltGenerator(16);
  const decoy = await hasher(salt, alg);
  return uint8ArrayToBase64Url(decoy);
};
