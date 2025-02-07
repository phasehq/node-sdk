import { PhaseKeyPair, Secret } from "../../types";
import { encryptAsymmetric, digest, decryptAsymmetric } from "./general";



/**
 * Encrypts environment secret key and value pairs using asymmetric encryption.
 *
 * @param {Object[]} plaintextSecrets - Array of plaintext secrets to encrypt
 * @param {PhaseKeyPair} envKeys - Keypair containing public key for encryption
 * @returns {Promise<Secret[]>} - Array of encrypted secrets
 */
export const encryptEnvSecrets = async (
  plaintextSecrets: Partial<Secret>[],
  envKeys: PhaseKeyPair,
  envSalt: string
): Promise<Partial<Secret>[]> => {
  const encryptedSecrets = await Promise.all(
    plaintextSecrets.map(async (secret) => {
      const encryptedSecret = structuredClone(secret);

      // Encrypt sensitive fields
      if (secret.key !== undefined) {
        encryptedSecret.key = await encryptAsymmetric(
          secret.key!.toUpperCase(),
          envKeys.publicKey
        );
        encryptedSecret.keyDigest = await digest(secret.key!, envSalt);
      }

      if (secret.value !== undefined) {
        encryptedSecret.value = await encryptAsymmetric(
          secret.value!,
          envKeys.publicKey
        );
      }

      if (secret.comment !== undefined) {
        encryptedSecret.comment = await encryptAsymmetric(
          secret.comment,
          envKeys.publicKey
        );
      }
      else {
        encryptedSecret.comment = await encryptAsymmetric(
          "",
          envKeys.publicKey
        );
      }

      if (secret.override?.value !== undefined) {
        encryptedSecret.override!.value = await encryptAsymmetric(
          secret.override.value,
          envKeys.publicKey
        );
      }

      

      return encryptedSecret;
    })
  );

  return encryptedSecrets;
};

/**
 * Decrypts environment secret key and value pairs.
 *
 * @param {Secret[]} encryptedSecrets - An array of encrypted secrets.
 * @param {{ publicKey: string; privateKey: string }} envKeys - The environment keys for decryption.
 * @returns {Promise<Secret[]>} - An array of decrypted secrets.
 */
export const decryptEnvSecrets = async (
  encryptedSecrets: Secret[],
  envKeys: { publicKey: string; privateKey: string }
) => {
  return Promise.all(
    encryptedSecrets.map(async (secret: Secret) => {
      try {
        const decryptedSecret = structuredClone(secret);

        decryptedSecret.key = await decryptAsymmetric(
          secret.key,
          envKeys.privateKey,
          envKeys.publicKey
        );

        decryptedSecret.value = await decryptAsymmetric(
          secret.value,
          envKeys.privateKey,
          envKeys.publicKey
        );

        decryptedSecret.comment = secret.comment
          ? await decryptAsymmetric(secret.comment, envKeys.privateKey, envKeys.publicKey)
          : secret.comment;

        if (secret.override) {
          decryptedSecret.override!.value = await decryptAsymmetric(
            secret.override.value,
            envKeys.privateKey,
            envKeys.publicKey
          );
        }

        return decryptedSecret;
      } catch (error) {
        throw new Error(`Decryption failed: ${error instanceof Error ? error.message : String(error)}`);
      }
    })
  );
};
