const _sodium = require("libsodium-wrappers");

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

  