import { PhaseKeyPair, Secret } from "../../types";
import { encryptAsymmetric, digest } from "./general";

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
      encryptedSecret.key = await encryptAsymmetric(
        secret.key!.toUpperCase(),
        envKeys.publicKey
      );
      encryptedSecret.value = await encryptAsymmetric(
        secret.value!,
        envKeys.publicKey
      );

      if (secret.comment) {
        encryptedSecret.comment = await encryptAsymmetric(
          secret.comment,
          envKeys.publicKey
        );
      }

      encryptedSecret.keyDigest = await digest(secret.key!, envSalt);

      return encryptedSecret;
    })
  );

  return encryptedSecrets;
};
