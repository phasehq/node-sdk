import { ready as sodiumReady } from "libsodium-wrappers";

const fetchAppKey = jest.fn(async () => {
  const unwrappedKey =
    "e35ae9560207c90fa3dd68a8715e13a1ef988bffa284db73f04328df17f37cfe";
  return Promise.resolve(unwrappedKey);
});

jest.mock("../src/index", () => {
  const originalModule = jest.requireActual("../src/index");
  return {
    __esModule: true,
    ...originalModule,
    fetchAppKey: fetchAppKey,
  };
});

const Phase = require("../src/index").default;

describe("Phase", () => {
  beforeAll(async () => {
    await sodiumReady;
  });

  describe("Initialization", () => {
    const APP_ID =
      "phApp:v1:cd2d579490fd794f1640590220de86a3676fa7979d419056bc631741b320b701";
    const APP_SECRET =
      "pss:v1:a7a0822aa4a4e4d37919009264200ba6ab978d92c8b4f7db5ae9ce0dfaf604fe:801605dfb89822ff52957abe39949bcfc44b9058ad81de58dd54fb0b110037b4b2bbde5a1143d31bbb3895f72e4ee52f5bd:625d395987f52c37022063eaf9b6260cad9ca03c99609213f899cae7f1bb04e7";

    test("Should throw an error with an invalid appId", () => {
      const invalidAppId =
        "phApp:version:cd2d579490fd794f1640590220de86a3676fa7979d419056bc631741b320b701";
      expect(
        () => new Phase(invalidAppId as any, APP_SECRET as any)
      ).toThrowError("Invalid Phase appID");
    });

    test("Should throw an error with an invalid appSecret", () => {
      const invalidAppSecret =
        "pss:v1:00000000000000000000000000000000:00000000000000000000000000000000:00000000000000000000000000000000";
      expect(() => new Phase(APP_ID, invalidAppSecret as any)).toThrowError(
        "Invalid Phase AppSecret"
      );
    });
  });

  describe("Encryption", () => {
    test("Check if Phase encrypt returns a valid ph", async () => {
      const APP_ID =
        "phApp:v1:cd2d579490fd794f1640590220de86a3676fa7979d419056bc631741b320b701";
      const APP_SECRET =
        "pss:v1:a7a0822aa4a4e4d37919009264200ba6ab978d92c8b4f7db5ae9ce0dfaf604fe:801605dfb89822ff52957abe39949bcfc44b9058ad81de58dd54fb0b110037b4b2bbde5a1143d31bbb3895f72e4ee52f5bd:625d395987f52c37022063eaf9b6260cad9ca03c99609213f899cae7f1bb04e7";
      const phase = new Phase(APP_ID, APP_SECRET);
      const plaintext = "Signal";
      const tag = "Phase Tag";
      const PH_VERSION = "v1";
      const ciphertext = await phase.encrypt(plaintext, tag);
      expect(ciphertext).toBeDefined();
      const segments = (ciphertext as string).split(":");
      expect(segments.length).toBe(5);
      expect(segments[0]).toBe("ph");
      expect(segments[1]).toBe(PH_VERSION);
      expect(segments[4]).toBe(tag);
      // Check if the one-time public key and ciphertext are valid hex strings
      expect(segments[2]).toMatch(/^[0-9a-f]+$/);
      expect(segments[3]).toMatch(/^[0-9a-f]+$/);
    });
  });

  describe("Decryption", () => {
    test("Check if Phase decrypt returns the correct plaintext", async () => {
      const APP_ID =
        "phApp:v1:e0e50cb9a1953c610126b4092093b1beca51d08d91fc3d9f8d90482a32853215";
      const APP_SECRET =
        "pss:v1:d261abecb6708c18bebdb8b2748ee574e2b0bdeaf19b081a5f10006cc83d48d0:d146c8c6d326a7842ff9b2da0da455b3f7f568a70808e2eb0cfc5143d4fe170f:59e413612e06d75d251e3416361d0743345a9c9eda1cbcf2b1ef16e3077c011c";

      const phase = new Phase(APP_ID, APP_SECRET);
      const data = "Signal";
      const ciphertext = await phase.encrypt(data);
      expect(ciphertext).toBeDefined();

      const plaintext = await phase.decrypt(ciphertext);
      expect(plaintext).toBeDefined();
      expect(plaintext).toBe(data);
    });

    test("Check if Phase decrypt rejects the promise when the app secret is incorrect", async () => {
      const APP_ID =
        "phApp:v1:e0e50cb9a1953c610126b4092093b1beca51d08d91fc3d9f8d90482a32853215";
      const APP_SECRET_INCORRECT =
        "pss:v1:d261abecb6708c18bebdb8b2748ee574e2b0bdeaf19b081a5f10006cc83d48d0:d146c8c6d326a7842ff9b2da0da455b3f7f568a70808e2eb0cfc5143d4fe170f:59e413612e06d75d251e3416361d0743345a9c9eda1cbcf2b1ef16e3077c011d";

      const phase = new Phase(APP_ID, APP_SECRET_INCORRECT);
      const data = "Signal";
      const ciphertext = await phase.encrypt(data);
      expect(() => phase.decrypt(ciphertext)).rejects.toBeDefined();
    });
  });
});
