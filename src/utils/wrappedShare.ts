const _sodium = require("libsodium-wrappers");
import { LIB_VERSION } from "./../../version";
import { decryptRaw } from "./crypto";

/**
 * Fetches and unwraps an app key share from the phase backend
 *
 * @param {string} appToken
 * @param {string} wrapKey
 * @returns {string} - Unwrapped app key share
 */
export const fetchAppKeyShare = async (
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
