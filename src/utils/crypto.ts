const _sodium = require("libsodium-wrappers");
import { KeyPair } from "libsodium-wrappers";
import { PhaseKeyPair, Secret } from "../types";

export const VERSION = 1

/**
 * XChaCha20-Poly1305 encrypt
 *
 * @param {String} plaintext
 * @param {Uint8Array} key
 * @returns {Uint8Array} - Ciphertext with appended nonce
 */
export const encryptRaw = async (plaintext: String, key: Uint8Array) => {
  await _sodium.ready;
  const sodium = _sodium;

  let nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);
  try {
    let ciphertext3 = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      plaintext,
      null,
      null,
      nonce,
      key
    );
    return new Uint8Array([...ciphertext3, ...nonce]);
  } catch (e) {
    throw "Encrypt error";
  }
};

/**
 * XChaCha20-Poly1305 decrypt
 *
 * @param {Uint8Array} encryptedMessage - Ciphertext + Nonce
 * @param {Uint8Array} key - Decryption key
 * @returns {Promise<Uint8Array>}
 */
export const decryptRaw = async (
  encryptedMessage: Uint8Array,
  key: Uint8Array
): Promise<Uint8Array> => {
  await _sodium.ready;
  const sodium = _sodium;

  const messageLen = encryptedMessage.length - 24;
  const nonce = encryptedMessage.slice(messageLen);
  const ciphertext = encryptedMessage.slice(0, messageLen);

  try {
    const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null,
      ciphertext,
      null,
      nonce,
      key
    );

    return plaintext;
  } catch (e) {
    throw "Decrypt error";
  }
};

/**
 * Encrypts a single string with the given key. Returns the ciphertext as a hex string
 *
 * @param {string} plaintext - Plaintext string to encrypt
 * @param {Uint8Array} key - Symmetric encryption key
 * @returns {string}
 */
export const encryptString = async (plaintext: string, key: Uint8Array) => {
  await _sodium.ready;
  const sodium = _sodium;

  return sodium.to_base64(
    await encryptRaw(sodium.from_string(plaintext), key),
    sodium.base64_variants.ORIGINAL
  );
};

/**
 * Decrypts a single hex ciphertext string with the given key. Returns the plaintext as a string
 *
 * @param cipherText - Hex string ciphertext with appended nonce
 * @param key - Symmetric encryption key
 * @returns {string}
 */
export const decryptString = async (cipherText: string, key: Uint8Array) => {
  await _sodium.ready;
  const sodium = _sodium;

  return sodium.to_string(
    await decryptRaw(
      sodium.from_base64(cipherText, sodium.base64_variants.ORIGINAL),
      key
    )
  );
};

/**
 * Returns an random key exchange keypair
 *
 * @returns {KeyPair}
 */
export const randomKeyPair = async () => {
  await _sodium.ready;
  const sodium = _sodium;
  const keypair = await sodium.crypto_kx_keypair();

  return keypair;
};

/**
 * Carries out diffie-hellman key exchange for client and returns a pair of symmetric encryption keys
 *
 * @param {KeyPair} ephemeralKeyPair
 * @param {Uint8Array} recipientPubKey
 * @returns
 */
export const clientSessionKeys = async (
  ephemeralKeyPair: KeyPair,
  recipientPubKey: Uint8Array
) => {
  await _sodium.ready;
  const sodium = _sodium;

  const keys = await sodium.crypto_kx_client_session_keys(
    ephemeralKeyPair.publicKey,
    ephemeralKeyPair.privateKey,
    recipientPubKey
  );
  return keys;
};

/**
 * Carries out diffie-hellman key exchange for server and returns a pair of symmetric encryption keys
 *
 * @param {KeyPair} ephemeralKeyPair
 * @param {Uint8Array} recipientPubKey
 * @returns
 */
export const serverSessionKeys = async (
  appKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array },
  dataPubKey: Uint8Array
) => {
  await _sodium.ready;
  const sodium = _sodium;
  const keys = await sodium.crypto_kx_server_session_keys(
    appKeyPair.publicKey,
    appKeyPair.privateKey,
    dataPubKey
  );
  return keys;
};

/**
 * Computes the xor of two Uint8Arrays, byte by byte and returns the result
 *
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {Uint8Array} The xor of Uint8Arrays a and b
 */
const xorUint8Arrays = (a: Uint8Array, b: Uint8Array): Uint8Array => {
  return Uint8Array.from(a.map((byte, i) => byte ^ b[i]));
};

/**
 * Reconstructs a secret given an array of shares
 *
 * @param {string[]} shares Array of shares encoded as hex string
 * @returns {Uint8Array} The reconstructed secret
 */
export const reconstructSecret = async (
  shares: string[]
): Promise<Uint8Array> => {
  await _sodium.ready;
  const sodium = _sodium;
  const byteShares = shares.map((share) => sodium.from_hex(share));

  const secret = byteShares.reduce((prev, curr) => xorUint8Arrays(prev, curr));

  return secret;
};


/**
 * Encrypts a string using the given public key
 * 
 * @param {string} plaintext 
 * @param {string} publicKey - hex encoded public key
 * @returns 
 */
export const encryptAsymmetric = async (plaintext: string, publicKey: string): Promise<string> => {
  await _sodium.ready
  const sodium = _sodium

  return new Promise<string>(async (resolve, reject) => {
    try {
      const oneTimeKeyPair = await randomKeyPair()

      const symmetricKeys = await clientSessionKeys(oneTimeKeyPair, sodium.from_hex(publicKey))

      const ciphertext = await encryptString(plaintext, symmetricKeys.sharedTx)

      // Use sodium.memzero to wipe the keys from memory
      sodium.memzero(oneTimeKeyPair.privateKey)
      sodium.memzero(symmetricKeys.sharedTx)
      sodium.memzero(symmetricKeys.sharedRx)

      resolve(`ph:v${VERSION}:${sodium.to_hex(oneTimeKeyPair.publicKey)}:${ciphertext}`)
    } catch (error) {
      reject(`Something went wrong: ${error}`)
    }
  })
}

/**
 * 
 * @param ciphertextString 
 * @param privateKey 
 * @param publicKey 
 * @returns 
 */
export const decryptAsymmetric = async (
  ciphertextString: string,
  privateKey: string,
  publicKey: string
): Promise<string> => {
  await _sodium.ready;
  const sodium = _sodium;

  return new Promise<string>(async (resolve, reject) => {
    const ciphertextSegments = ciphertextString.split(":");

    if (ciphertextSegments.length !== 4) reject("Invalid ciphertext");

    const ciphertext = {
      prefix: ciphertextSegments[0],
      version: ciphertextSegments[1],
      pubKey: ciphertextSegments[2],
      data: ciphertextSegments[3],
    };

    try {
      const sessionKeys = await serverSessionKeys(
        {
          publicKey: sodium.from_hex(publicKey) as Uint8Array,
          privateKey: sodium.from_hex(privateKey) as Uint8Array,
        },
        sodium.from_hex(ciphertext.pubKey)
      );

      const plaintext = await decryptString(
        ciphertext.data,
        sessionKeys.sharedRx
      );

      // Use sodium.memzero to wipe the keys from memory
      sodium.memzero(sessionKeys.sharedRx);
      sodium.memzero(sessionKeys.sharedTx);

      resolve(plaintext);
    } catch (error) {
      reject(`Something went wrong: ${error}`);
    }
  });
};

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
      encryptedSecret.key = await encryptAsymmetric(secret.key!.toUpperCase(), envKeys.publicKey);
      encryptedSecret.value = await encryptAsymmetric(secret.value!, envKeys.publicKey);
      
      if (secret.comment) {
        encryptedSecret.comment = await encryptAsymmetric(secret.comment, envKeys.publicKey);
      }

      encryptedSecret.keyDigest = await digest(secret.key!, envSalt)

      return encryptedSecret;
    })
  );

  return encryptedSecrets;
};

export const digest = async (input: string, salt: string) => {
  await _sodium.ready
  const sodium = _sodium

  const hash = await sodium.crypto_generichash(32, input, salt)
  return sodium.to_hex(hash)
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