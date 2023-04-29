import { KeyPair } from "libsodium-wrappers";
const _sodium = require("libsodium-wrappers");
import { LIB_VERSION } from "../version";

const PH_VERSION = "v1";
type PhaseCiphertext = `ph:${string}:${string}:${string}:${string}`;
type PhaseAppId = `phApp:${string}:${string}`;
type PhaseAppSecret = `pss:${string}:${string}:${string}${string}`;

/**
 * Returns an random key exchange keypair
 *
 * @returns {KeyPair}
 */
const randomKeyPair = async () => {
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
const clientSessionKeys = async (
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
const serverSessionKeys = async (
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
 * XChaCha20-Poly1305 encrypt
 *
 * @param {String} plaintext
 * @param {Uint8Array} key
 * @returns {Uint8Array} - Ciphertext with appended nonce
 */
const encryptRaw = async (plaintext: String, key: Uint8Array) => {
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
const encryptString = async (plaintext: string, key: Uint8Array) => {
  await _sodium.ready;
  const sodium = _sodium;

  return sodium.to_hex(await encryptRaw(sodium.from_string(plaintext), key));
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

  return sodium.to_string(await decryptRaw(sodium.from_hex(cipherText), key));
};

/**
 * Fetches and unwraps an app key share from the phase backend
 *
 * @param {string} appToken
 * @param {string} wrapKey
 * @returns {string} - Unwrapped app key share
 */
const fetchAppKey = async (
  appToken: string,
  wrapKey: string,
  appId: string,
  dataSize: number
) => {
  await _sodium.ready;
  const sodium = _sodium;

  const PHASE_KMS_URI = `https://kms.phase.dev/${appId}`;

  const headers = {
    Authorization: `Bearer ${appToken}`,
    EventType: "decrypt",
    PhaseNode: `node-js:${LIB_VERSION}`,
    PhSize: `${dataSize}`,
  };

  return new Promise<string>((resolve, reject) => {
    fetch(PHASE_KMS_URI, {
      headers,
    }).then((response) => {
      if (response.status === 404) reject("Invalid app token");
      else {
        response.json().then(async (json) => {
          const wrappedKeyShare = json.wrappedKeyShare;
          const wrappedKeyBytes = sodium.from_hex(wrappedKeyShare);
          const keyBytes = sodium.from_hex(wrapKey);

          const unwrappedKey = await decryptRaw(wrappedKeyBytes, keyBytes);
          resolve(sodium.to_string(unwrappedKey));
        });
      }
    });
  });
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
 * @returns {string} The reconstructed secret as a hex-encoded string
 */
const reconstructSecret = async (shares: string[]): Promise<string> => {
  await _sodium.ready;
  const sodium = _sodium;
  const byteShares = shares.map((share) => sodium.from_hex(share));

  const secret = byteShares.reduce((prev, curr) => xorUint8Arrays(prev, curr));

  return sodium.to_hex(secret);
};

export default class Phase {
  appId: string;
  appPubKey: string;
  appSecret: {
    prefix: string;
    pssVersion: string;
    appToken: string;
    keyshare0: string;
    keyshare1UnwrapKey: string;
  };

  constructor(appId: string, appSecret: string) {
    const appIdRegex = /^phApp:v(\d+):([a-fA-F0-9]{64})$/;
    // Update regex after switching to XOR based shares
    const appSecretRegex =
      /^pss:v(\d+):([a-fA-F0-9]{64}):([a-fA-F0-9]{64,128}):([a-fA-F0-9]{64})/gm;

    if (!appIdRegex.test(appId)) {
      throw new Error("Invalid Phase appID");
    }

    this.appId = appId;
    this.appPubKey = appId.split(":")[2];

    const appSecretSegments = appSecret.split(":");

    if (!appSecretRegex.test(appSecret)) {
      throw new Error("Invalid Phase AppSecret");
    }

    this.appSecret = {
      prefix: appSecretSegments[0],
      pssVersion: appSecretSegments[1],
      appToken: appSecretSegments[2],
      keyshare0: appSecretSegments[3],
      keyshare1UnwrapKey: appSecretSegments[4],
    };
  }

  encrypt = async (
    plaintext: string,
    tag: string = ""
  ): Promise<PhaseCiphertext> => {
    await _sodium.ready;
    const sodium = _sodium;

    return new Promise<PhaseCiphertext>(async (resolve, reject) => {
      try {
        const oneTimeKeyPair = await randomKeyPair();

        const symmetricKeys = await clientSessionKeys(
          oneTimeKeyPair,
          sodium.from_hex(this.appPubKey)
        );

        const ciphertext = await encryptString(
          plaintext,
          symmetricKeys.sharedTx
        );

        resolve(
          `ph:${PH_VERSION}:${sodium.to_hex(
            oneTimeKeyPair.publicKey
          )}:${ciphertext}:${tag}`
        );
      } catch (error) {
        reject(`Something went wrong: ${error}`);
      }
    });
  };

  decrypt = async (phaseCiphertext: PhaseCiphertext): Promise<string> => {
    await _sodium.ready;
    const sodium = _sodium;

    return new Promise<string>(async (resolve, reject) => {
      const ciphertextSegments = phaseCiphertext.split(":");
      if (ciphertextSegments.length !== 5 || ciphertextSegments[0] !== "ph")
        reject("Invalid phase ciphertext");

      const ciphertext = {
        prefix: ciphertextSegments[0],
        pubKey: ciphertextSegments[2],
        data: ciphertextSegments[3],
        tag: ciphertextSegments[4],
      };

      try {
        const keyshare1 = await fetchAppKey(
          this.appSecret.appToken,
          this.appSecret.keyshare1UnwrapKey,
          this.appId,
          ciphertext.data.length / 2
        );

        const appPrivKey = await reconstructSecret([
          this.appSecret.keyshare0,
          keyshare1,
        ]);

        const sessionKeys = await serverSessionKeys(
          {
            publicKey: sodium.from_hex(this.appPubKey) as Uint8Array,
            privateKey: sodium.from_hex(appPrivKey) as Uint8Array,
          },
          sodium.from_hex(ciphertext.pubKey)
        );

        const plaintext = await decryptString(
          ciphertext.data,
          sessionKeys.sharedRx
        );

        resolve(plaintext);
      } catch (error) {
        reject(`Something went wrong: ${error}`);
      }
    });
  };
}
