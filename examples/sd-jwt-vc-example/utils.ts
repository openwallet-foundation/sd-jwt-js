import { digest, ES256, generateSalt } from '@owf/crypto';

export { digest, ES256, generateSalt };

export const createSignerVerifier = async () => {
  const { privateKey, publicKey } = await ES256.generateKeyPair();
  return {
    signer: await ES256.getSigner(privateKey),
    verifier: await ES256.getVerifier(publicKey),
  };
};
