import _sodium from "libsodium-wrappers";
import { Secret } from "../../../src/types";
import {
  randomKeyPair,
  encryptEnvSecrets,
  decryptEnvSecrets,
  digest,
} from "../../../src/utils/crypto";

describe("Environment Secrets Encryption", () => {
  let keyPair: { publicKey: string; privateKey: string };
  let envSalt: string;

  beforeAll(async () => {
    await _sodium.ready;
    const sodium = _sodium;

    const generatedKeyPair = await randomKeyPair();
    keyPair = {
      publicKey: sodium.to_hex(generatedKeyPair.publicKey),
      privateKey: sodium.to_hex(generatedKeyPair.privateKey),
    };
    envSalt = "random_salt_value";
  });

  test("Encrypt and decrypt a single secret", async () => {
    const secret: Partial<Secret> = {
      key: "SECRET_KEY",
      value: "myvalue",
      comment: "comment",
      override: { value: "override_value", isActive: true },
    };

    const encryptedSecrets = await encryptEnvSecrets(
      [secret],
      keyPair,
      envSalt
    );
    expect(encryptedSecrets[0].key).not.toEqual(secret.key);
    expect(encryptedSecrets[0].value).not.toEqual(secret.value);
    expect(encryptedSecrets[0].keyDigest).toBeDefined();

    const decryptedSecrets = await decryptEnvSecrets(
      encryptedSecrets as Secret[],
      keyPair
    );

    expect(decryptedSecrets[0].key).toEqual(secret.key);
    expect(decryptedSecrets[0].value).toEqual(secret.value);
  });

  test("Ensure key digest is correct", async () => {
    const secret: Partial<Secret> = { key: "TEST_KEY" };

    const encryptedSecrets = await encryptEnvSecrets(
      [secret],
      keyPair,
      envSalt
    );
    const expectedDigest = await digest(secret.key!, envSalt);

    expect(encryptedSecrets[0].keyDigest).toEqual(expectedDigest);
  });

  test("Encrypt and decrypt multiple secrets", async () => {
    const secrets: Partial<Secret>[] = [
      { key: "API_KEY", value: "12345" },
      { key: "DATABASE_URL", value: "postgres://user:pass@localhost" },
      { key: "EMPTY_VALUE", value: "" },
    ];

    const encryptedSecrets = await encryptEnvSecrets(secrets, keyPair, envSalt);
    expect(encryptedSecrets.length).toBe(secrets.length);

    const decryptedSecrets = await decryptEnvSecrets(
      encryptedSecrets as Secret[],
      keyPair
    );

    decryptedSecrets.forEach((dec, i) => {
      expect(dec.key).toEqual(secrets[i].key);
      expect(dec.value).toEqual(secrets[i].value);
    });
  });

  test("Decrypt fails with incorrect private key", async () => {
    const secret: Partial<Secret> = { key: "SENSITIVE" };

    const encryptedSecrets = await encryptEnvSecrets(
      [secret],
      keyPair,
      envSalt
    );

    const wrongKeyPair = await randomKeyPair();
    const wrongPrivateKey = _sodium.to_hex(wrongKeyPair.privateKey);

    await expect(
      decryptEnvSecrets(encryptedSecrets as Secret[], {
        publicKey: keyPair.publicKey,
        privateKey: wrongPrivateKey,
      })
    ).rejects.toThrow();
  });

  test("Tampered encrypted secret should not decrypt correctly", async () => {
    const secret: Partial<Secret> = { key: "TAMPERED" };

    const encryptedSecrets = await encryptEnvSecrets(
      [secret],
      keyPair,
      envSalt
    );

    // Modify the encrypted key (tamper with ciphertext)
    encryptedSecrets[0].key = encryptedSecrets[0].key!.slice(0, -1) + "X";

    await expect(
      decryptEnvSecrets(encryptedSecrets as Secret[], keyPair)
    ).rejects.toThrow();
  });

  test("Handles empty array input", async () => {
    const encryptedSecrets = await encryptEnvSecrets([], keyPair, envSalt);
    expect(encryptedSecrets).toEqual([]);

    const decryptedSecrets = await decryptEnvSecrets([], keyPair);
    expect(decryptedSecrets).toEqual([]);
  });
});
