const _sodium = require("libsodium-wrappers");
import { fetchAppKeyShare } from "./utils/wrappedShare";
import {
  clientSessionKeys,
  decryptString,
  encryptString,
  randomKeyPair,
  reconstructSecret,
  serverSessionKeys,
} from "./utils/crypto";

const PH_VERSION = "v1";
type PhaseCiphertext = `ph:${string}:${string}:${string}:${string}`;
type PhaseAppId = `phApp:${string}:${string}`;
type PhaseAppSecret = `pss:${string}:${string}:${string}${string}`;

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

        // Use sodium.memzero to wipe the keys from memory
        sodium.memzero(oneTimeKeyPair.privateKey);
        sodium.memzero(symmetricKeys.sharedTx);
        sodium.memzero(symmetricKeys.sharedRx);

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
        const keyshare1 = await fetchAppKeyShare(
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
            privateKey: appPrivKey,
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
        sodium.memzero(appPrivKey);

        resolve(plaintext);
      } catch (error) {
        reject(`Something went wrong: ${error}`);
      }
    });
  };
}
