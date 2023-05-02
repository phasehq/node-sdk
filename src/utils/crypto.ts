const _sodium = require("libsodium-wrappers");
import { KeyPair } from "libsodium-wrappers";

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
