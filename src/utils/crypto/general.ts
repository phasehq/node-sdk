const _sodium = require("libsodium-wrappers");
import { KeyPair } from "libsodium-wrappers";
import { VERSION } from "./constants";

/**
 * XChaCha20-Poly1305 encrypt
 *
 * @param {String} plaintext
 * @param {Uint8Array} key
 * @returns {Promise<Uint8Array>} - Ciphertext with appended nonce
 */
export const encryptRaw = async (plaintext: string, key: Uint8Array): Promise<Uint8Array> => {
  await _sodium.ready
  const sodium = _sodium

  let nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
  let ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    plaintext,
    null,
    null,
    nonce,
    key
  )
  return new Uint8Array([...ciphertext, ...nonce])
}

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
  await _sodium.ready
  const sodium = _sodium

  const messageLen = encryptedMessage.length - 24
  const nonce = encryptedMessage.slice(messageLen)
  const ciphertext = encryptedMessage.slice(0, messageLen)

  const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
    null,
    ciphertext,
    null,
    nonce,
    key
  )

  return plaintext
}

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
 * Encrypts a string using the given public key
 *
 * @param {string} plaintext
 * @param {string} publicKey - hex encoded public key
 * @returns
 */
export const encryptAsymmetric = async (
  plaintext: string,
  publicKey: string
): Promise<string> => {
  await _sodium.ready;
  const sodium = _sodium;

  return new Promise<string>(async (resolve, reject) => {
    try {
      const oneTimeKeyPair = await randomKeyPair();

      const symmetricKeys = await clientSessionKeys(
        oneTimeKeyPair,
        sodium.from_hex(publicKey)
      );

      const ciphertext = await encryptString(plaintext, symmetricKeys.sharedTx);

      // Use sodium.memzero to wipe the keys from memory
      sodium.memzero(oneTimeKeyPair.privateKey);
      sodium.memzero(symmetricKeys.sharedTx);
      sodium.memzero(symmetricKeys.sharedRx);

      resolve(
        `ph:v${VERSION}:${sodium.to_hex(
          oneTimeKeyPair.publicKey
        )}:${ciphertext}`
      );
    } catch (error) {
      reject(`Something went wrong: ${error}`);
    }
  });
};

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

export const digest = async (input: string, salt: string) => {
  await _sodium.ready;
  const sodium = _sodium;

  const hash = await sodium.crypto_generichash(32, input, salt);
  return sodium.to_hex(hash);
};
