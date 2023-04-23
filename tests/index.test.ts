import { KeyPair } from "libsodium-wrappers";
import Phase from "../index";
import { decryptRaw, decryptString } from "../index";
import { ready as sodiumReady } from "libsodium-wrappers";

describe("Phase", () => {
  beforeAll(async () => {
    await sodiumReady;
  });

  describe("Phase", () => {
    const appId = "phApp:v1:cd2d579490fd794f1640590220de86a3676fa7979d419056bc631741b320b701";
    const appSecret = "pss:v1:a7a0822aa4a4e4d37919009264200ba6ab978d92c8b4f7db5ae9ce0dfaf604fe:801605dfb89822ff52957abe39949bcfc44b9058ad81de58dd54fb0b110037b4b2bbde5a1143d31bbb3895f72e4ee52f5bd:625d395987f52c37022063eaf9b6260cad9ca03c99609213f899cae7f1bb04e7";
    
    test("Should throw an error with an invalid appId", () => {
      const invalidAppId = "phApp:version:cd2d579490fd794f1640590220de86a3676fa7979d419056bc631741b320b701";
      expect(() => new Phase(invalidAppId as any, appSecret as any)).toThrowError("Invalid Phase appID");
    });

    test("Should throw an error with an invalid appSecret", () => {
      const invalidAppSecret = "pss:v1:00000000000000000000000000000000:00000000000000000000000000000000:00000000000000000000000000000000";
      expect(() => new Phase(appId, invalidAppSecret as any)).toThrowError("Invalid Phase AppSecret");
    });

    test("Check if Phase encrypt returns a valid ph", async () => {
      const phase = new Phase(appId, appSecret);
      const plaintext = "Signal";
      const tag = "Phase Tag";
      const PH_VERSION = "v1"
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

});