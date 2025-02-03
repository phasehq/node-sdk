import { PhaseKeyPair, Secret } from "../../types";
import { decryptAsymmetric, decryptRaw } from "./general";
import { reconstructSecret } from "./secretSplitting";

const _sodium = require("libsodium-wrappers");

export const getUserKxPublicKey = async (signingPublicKey: string) => {
    await _sodium.ready;
    const sodium = _sodium;
  
    return sodium.to_hex(
      sodium.crypto_sign_ed25519_pk_to_curve25519(
        sodium.from_hex(signingPublicKey)
      )
    );
  };
  
  export const getUserKxPrivateKey = async (signingPrivateKey: string) => {
    await _sodium.ready;
    const sodium = _sodium;
  
    return sodium.to_hex(
      sodium.crypto_sign_ed25519_sk_to_curve25519(
        sodium.from_hex(signingPrivateKey)
      )
    );
  };
  
  /**
   * Derives an env keyring from the given seed
   *
   * @param {string} envSeed - Env seed as a hex string
   * @returns {Promise<PhaseKeyPair>}
   */
  export const envKeyring = async (envSeed: string): Promise<PhaseKeyPair> => {
    await _sodium.ready;
    const sodium = _sodium;
  
    const seedBytes = sodium.from_hex(envSeed);
    const envKeypair = sodium.crypto_kx_seed_keypair(seedBytes);
  
    const { publicKey, privateKey } = envKeypair;
  
    return {
      publicKey: sodium.to_hex(publicKey),
      privateKey: sodium.to_hex(privateKey),
    };
  };
  
  /**
   * Unwraps environment secrets for a user.
   *
   * @param {string} wrappedSeed - The wrapped environment seed.
   * @param {string} wrappedSalt - The wrapped environment salt.
   * @param {PhaseKeyPair} keyring - The keyring of the user.
   * @returns {Promise<{ publicKey: string; privateKey: string; salt: string }>} - An object containing the unwrapped environment secrets.
   */
  export const unwrapEnvKeys = async (
    wrappedSeed: string,
    wrappedSalt: string,
    keyring: PhaseKeyPair
  ) => {
    const salt = await decryptAsymmetric(
      wrappedSalt,
      keyring.privateKey,
      keyring.publicKey
    );
  
    const seed = await decryptAsymmetric(
      wrappedSeed,
      keyring.privateKey,
      keyring.publicKey
    );
  
    const { publicKey, privateKey } = await envKeyring(seed);
  
    return {
      seed,
      publicKey,
      privateKey,
      salt,
    };
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
    const decryptedSecrets = await Promise.all(
      encryptedSecrets.map(async (secret: Secret) => {
        const decryptedSecret = structuredClone(secret)
        decryptedSecret.key = await decryptAsymmetric(
          secret.key,
          envKeys?.privateKey,
          envKeys?.publicKey
        )
  
        decryptedSecret.value = await decryptAsymmetric(
          secret.value,
          envKeys?.privateKey,
          envKeys?.publicKey
        )
  
        decryptedSecret.comment = secret.comment ? await decryptAsymmetric(
          secret.comment,
          envKeys?.privateKey,
          envKeys?.publicKey
        ) : secret.comment
  
        return decryptedSecret
      })
    )
    return decryptedSecrets
  }

  export const reconstructPrivateKey = async (wrappedKeyShare: string, token: string) => {

    await _sodium.ready
    const sodium = _sodium
  
    const clientKeyShare = token.split(":")[4]
    const wrappingKey = token.split(":")[5]
    
    // Decrypt the wrapped key share from the server
    const serverKeyShare = await decryptRaw(
      sodium.from_hex(wrappedKeyShare),
      sodium.from_hex(wrappingKey) // wrappingKey from the token
    );
  
    // Reconstruct the private key
    const privateKey = await reconstructSecret([
      clientKeyShare, // clientKeyShare from the token
      sodium.to_string(serverKeyShare),
    ]);
  
    return sodium.to_hex(privateKey)
  
  }