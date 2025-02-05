import {
  getUserKxPublicKey,
  getUserKxPrivateKey,
  envKeyring,
  unwrapEnvKeys,
  reconstructPrivateKey,
} from "../../../src/utils/crypto";
import * as generalUtils from "../../../src/utils/crypto/general";
import * as secretSplittingUtils from "../../../src/utils/crypto/secretSplitting";

const _sodium = require("libsodium-wrappers");

describe("Crypto Utility Functions", () => {
  beforeAll(async () => {
    await _sodium.ready;
  });

  test("getUserKxPublicKey converts a signing public key correctly", async () => {
    const signingKey = _sodium.to_hex(_sodium.crypto_sign_keypair().publicKey);
    const kxPublicKey = await getUserKxPublicKey(signingKey);
    expect(kxPublicKey).toBeDefined();
    expect(typeof kxPublicKey).toBe("string");
  });

  test("getUserKxPrivateKey converts a signing private key correctly", async () => {
    const signingKey = _sodium.to_hex(_sodium.crypto_sign_keypair().privateKey);
    const kxPrivateKey = await getUserKxPrivateKey(signingKey);
    expect(kxPrivateKey).toBeDefined();
    expect(typeof kxPrivateKey).toBe("string");
  });

  test("envKeyring derives a keypair from a given seed", async () => {
    const seed = _sodium.to_hex(_sodium.randombytes_buf(32));
    const keyring = await envKeyring(seed);
    expect(keyring).toHaveProperty("publicKey");
    expect(keyring).toHaveProperty("privateKey");
    expect(typeof keyring.publicKey).toBe("string");
    expect(typeof keyring.privateKey).toBe("string");
  });

  test("unwrapEnvKeys decrypts and derives correct keyring", async () => {
    const seed = _sodium.to_hex(_sodium.randombytes_buf(32));
    const salt = _sodium.to_hex(_sodium.randombytes_buf(16));
    const keyring = await envKeyring(seed);

    jest
      .spyOn(generalUtils, "decryptAsymmetric")
      .mockResolvedValueOnce(salt)
      .mockResolvedValueOnce(seed);

    const unwrapped = await unwrapEnvKeys(
      "wrappedSeed",
      "wrappedSalt",
      keyring
    );

    expect(unwrapped.seed).toBe(seed);
    expect(unwrapped.salt).toBe(salt);
    expect(unwrapped.publicKey).toBeDefined();
    expect(unwrapped.privateKey).toBeDefined();
  });

  test("reconstructPrivateKey correctly reconstructs the private key", async () => {
    const privateKey =
      "900d0f3f65fa2a95e41c268fe326642667fc1febcc4b864344f783978513555e";
    const token =
      "pss_user:v1:6759ecdb7307cb2a1994fe397bd690725cdfabbda952e4cc568fc5e3e0286a3d:b8f2214246b79a20dfcd62870e7e6a48343f9c7fcdfb7d664175ac11a76bce10:451f1dce52290ee0a4d8f4b8f9fe0a946447e288ff1b10b494fdd5fe28ed4ab8:959c5fe47a3b35cd8278890ce208a318d5411aa1cf06d5fc2cbe8af41904544e";
    const keyShare =
      "e2101a6796a2960571cfced645f5c721ed5597d257f91c3fe891ddb02231ba4817f7123d2ec2f1d353ba1f178424ead02b624d1862e3aa55498a47a02c4a07a446852791c89c4b7640f20471c5ede0d97b276a68158847c348ba90ee4f302a603812c6c1df7cfa6f";

    const constructedPrivateKey = await reconstructPrivateKey(keyShare, token);
    expect(constructedPrivateKey).toBeDefined();
    expect(constructedPrivateKey).toEqual(privateKey);
  });

  test("unwrapEnvKeys throws an error when decryption fails", async () => {
    jest
      .spyOn(generalUtils, "decryptAsymmetric")
      .mockRejectedValue(new Error("Decryption failed"));

    await expect(
      unwrapEnvKeys("invalidSeed", "invalidSalt", {
        publicKey: "fake",
        privateKey: "fake",
      })
    ).rejects.toThrow("Decryption failed");
  });
});
