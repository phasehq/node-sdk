import axios from "axios";
import Phase from "../../src";

jest.mock("axios");
// jest.mock("../src/utils/crypto", () => ({
//   reconstructPrivateKey: jest.fn(),
//   unwrapEnvKeys: jest.fn(),
// }));

describe("Phase SDK - init() failure modes", () => {
  const validUserToken =
    "pss_user:v1:6759ecdb7307cb2a1994fe397bd690725cdfabbda952e4cc568fc5e3e0286a3d:b8f2214246b79a20dfcd62870e7e6a48343f9c7fcdfb7d664175ac11a76bce10:451f1dce52290ee0a4d8f4b8f9fe0a946447e288ff1b10b494fdd5fe28ed4ab8:959c5fe47a3b35cd8278890ce208a318d5411aa1cf06d5fc2cbe8af41904544e";
  const validServiceToken =
    "pss_service:v2:048c9daa773b2d9bb21a1dda69a56f2b895401fded26889c7063c72224a61f65:fc065f7e5e1093292b20d0c917968cbe3badfb2e82bf1caa70649b72d0017905:1bb35376aacb277fd2792d781dbff5d0e9f7547da3544f4d394ff027d91436d5:4a04b7a5100c67cbf6376f8dae1ca936ca17bcbc119a4a84f8e3727696460925";
  const mockHost = "http://localhost";

  const mockResponse = {
    wrapped_key_share:
      "e2101a6796a2960571cfced645f5c721ed5597d257f91c3fe891ddb02231ba4817f7123d2ec2f1d353ba1f178424ead02b624d1862e3aa55498a47a02c4a07a446852791c89c4b7640f20471c5ede0d97b276a68158847c348ba90ee4f302a603812c6c1df7cfa6f",
    user_id: "59c68014-d1b9-4896-8a88-8b1088165dde",
    offline_enabled: false,
    organisation: {
      id: "79a36b56-b0a1-4fa2-bd00-6c031868fb10",
      name: "test",
    },
    apps: [
      {
        id: "3b7443aa-3a7c-4791-849a-42aafc9cbe66",
        name: "test",
        encryption: "E2E",
        environment_keys: [
          {
            id: "8b226ced-d51c-4954-b8cb-de86d5c0c2eb",
            environment: {
              id: "52db76e0-16a0-4b39-b2a9-bb518cd1b6a6",
              name: "Development",
              env_type: "DEV",
            },
            paths: null,
            identity_key:
              "2d1eb10b8406cc4a2ef0287053cd21da408a24fbfb65d8002f56132fbe46cc20",
            wrapped_seed:
              "ph:v1:59c2f1b02713effee170712a105a751863339d82554b9a0a7d966f6a6111c63d:+uHF+qN1SRRo7l3wga4WdjJpclLXQjjLP8L+FOaYc9RfZPjb5CSYaYon8SZW1fSII9YNiUFTXKnFo22bsLBIwaBDK7b/xBdcFREb5G2RfAKiBb6j1Es1ux3f3ZFz/bul/6msAuQKK6E=",
            wrapped_salt:
              "ph:v1:6ddd5db0fca06cf54bf86ec5de403d4c11871e4124d84b0983e0ab0ba865e728:nJ2rYnvoWzsG2CPXbkLyWTANh8LlNn222axOwGjf+UE8hKBjocT7XigS0zPNRsu8+V/YEKVngEOV2dupKqGtlsgkW3Mbd17T2YMkExx/x/TJgZXKoNamc2vuLYUtTlamhB8XHfsa41E=",
            created_at: "2025-02-01T16:51:25.941911Z",
            updated_at: "2025-02-01T16:51:25.941916Z",
            deleted_at: null,
            user: "59c68014-d1b9-4896-8a88-8b1088165dde",
            service_account: null,
          },
          {
            id: "2c136678-cb87-4ed7-aa43-f1dcd7c5ba9f",
            environment: {
              id: "c290c2ea-7611-49e8-b7fd-c1046bccaa61",
              name: "Staging",
              env_type: "STAGING",
            },
            paths: null,
            identity_key:
              "d80ad5a145b4c5477473965c5b832e8856a51b612baea1b8da2028616217540a",
            wrapped_seed:
              "ph:v1:30b919477e01468a5477929888e91fd62a3a71382ef01747e1c3f2bc799dd83c:MGyxo5DT+6dcGgZZoD9rOgch/3KLHA9wfYBqnjnGKxHv6/l9FtL7ZHOt8TRAExluPr+ebjMQuqKMKn6c5Z9lDZSbREM4+dQb9hq6DAuejpTlEEqYhIZhUqritLiiHK+zZW+Xw0Xy/Gs=",
            wrapped_salt:
              "ph:v1:d62677ecf0713e99242af3330d9807d2d13f0c44c1f69314538eb8fba66f9305:3oX1QNtZkPv8f9ViyeBiBDMT1tZhOS2k8tvoG1WALYG0t5sDSBtmXjXKiYZw9cm8hHvI3cjDT20XrhG3/79QYVeDbFA1WkLyg8cFickXjiucHahhmKXyEJm1qrLcksYsBho6moLOWkM=",
            created_at: "2025-02-01T16:51:25.956031Z",
            updated_at: "2025-02-01T16:51:25.956036Z",
            deleted_at: null,
            user: "59c68014-d1b9-4896-8a88-8b1088165dde",
            service_account: null,
          },
          {
            id: "3dd91343-46de-44d9-be47-a8a4ca471458",
            environment: {
              id: "c55ed69f-edd6-420a-8156-8b8daa86e713",
              name: "Production",
              env_type: "PROD",
            },
            paths: null,
            identity_key:
              "700e79e28535aac9a8fe960744ca8c9468dc10cca9f6ff31447beb1f1b51ee4d",
            wrapped_seed:
              "ph:v1:f750279a24a074bb713313bdf8db256c3ae326f24b1e1da52e3740fd3f0dbc11:Rdmvc/O6YMg9LEC0UXtcBN9i9W1ELh77BlB/sZc1TMoUWxzEQF0ONt/ILUCOBTmAcVi2xWOtJfR6XH0wT2jygZm/VTmBSyVopxzQzSXaNWmgeXjgm8+8xEbZx8pkJPQMSmIXTBVd2aA=",
            wrapped_salt:
              "ph:v1:3f44a6cadb8341eba84a15dfb9c47880db5d48fa862d3718b0d34efcb5290d1f:Y5htuo04TV73RxzqpXtO3ooI9qeEpp4wbVS9PeCWEKNFJUw5NGX7NovblQojcGKcit0Ku8JMLMEn4P6/Gfn54164Lu8PEs3q0Z6h5pCsTYu+hKuIuD83onx5qc9ARgXI7ga7HWyB2Oc=",
            created_at: "2025-02-01T16:51:25.966753Z",
            updated_at: "2025-02-01T16:51:25.966759Z",
            deleted_at: null,
            user: "59c68014-d1b9-4896-8a88-8b1088165dde",
            service_account: null,
          },
        ],
      },
    ],
  };

  beforeEach(() => {
    jest.clearAllMocks();
    (axios.get as jest.Mock).mockResolvedValue({
      status: 200,
      data: mockResponse,
    });
  });

  it("should throw an error if no token is provided", async () => {
    expect(() => new Phase("", mockHost)).toThrow(
      "Invalid token format. Token does not match the expected pattern."
    );
  });

  it("should throw an error if token format is invalid", async () => {
    const invalidToken = "invalid-token-format";
    expect(() => new Phase(invalidToken, mockHost)).toThrow(
      "Invalid token format"
    );
  });

  it("should fail if the API returns a 400 Bad Request", async () => {
    (axios.get as jest.Mock).mockRejectedValue({
      response: { status: 400, data: "Bad Request" },
    });

    const phase = new Phase(validUserToken, mockHost);

    await expect(phase.init()).rejects.toThrow("Failed to initialize session");
  });

  it("should fail if the API returns a 500 Internal Server Error", async () => {
    (axios.get as jest.Mock).mockRejectedValue({
      response: { status: 500, data: "Internal Server Error" },
    });

    const phase = new Phase(validUserToken, mockHost);

    await expect(phase.init()).rejects.toThrow("Failed to initialize session");
  });

  it("should fail with a network error", async () => {
    (axios.get as jest.Mock).mockRejectedValue(new Error("Network error"));

    const phase = new Phase(validUserToken, mockHost);

    await expect(phase.init()).rejects.toThrow("Failed to initialize session");
  });
});

describe("Phase SDK - init() with valid user token", () => {
  const validUserToken =
    "pss_user:v1:6759ecdb7307cb2a1994fe397bd690725cdfabbda952e4cc568fc5e3e0286a3d:b8f2214246b79a20dfcd62870e7e6a48343f9c7fcdfb7d664175ac11a76bce10:451f1dce52290ee0a4d8f4b8f9fe0a946447e288ff1b10b494fdd5fe28ed4ab8:959c5fe47a3b35cd8278890ce208a318d5411aa1cf06d5fc2cbe8af41904544e";
  const validServiceToken =
    "pss_service:v2:048c9daa773b2d9bb21a1dda69a56f2b895401fded26889c7063c72224a61f65:fc065f7e5e1093292b20d0c917968cbe3badfb2e82bf1caa70649b72d0017905:1bb35376aacb277fd2792d781dbff5d0e9f7547da3544f4d394ff027d91436d5:4a04b7a5100c67cbf6376f8dae1ca936ca17bcbc119a4a84f8e3727696460925";
  const mockHost = "http://localhost";

  const mockResponse = {
    wrapped_key_share:
      "e2101a6796a2960571cfced645f5c721ed5597d257f91c3fe891ddb02231ba4817f7123d2ec2f1d353ba1f178424ead02b624d1862e3aa55498a47a02c4a07a446852791c89c4b7640f20471c5ede0d97b276a68158847c348ba90ee4f302a603812c6c1df7cfa6f",
    user_id: "59c68014-d1b9-4896-8a88-8b1088165dde",
    offline_enabled: false,
    organisation: {
      id: "79a36b56-b0a1-4fa2-bd00-6c031868fb10",
      name: "test",
    },
    apps: [
      {
        id: "3b7443aa-3a7c-4791-849a-42aafc9cbe66",
        name: "test",
        encryption: "E2E",
        environment_keys: [
          {
            id: "8b226ced-d51c-4954-b8cb-de86d5c0c2eb",
            environment: {
              id: "52db76e0-16a0-4b39-b2a9-bb518cd1b6a6",
              name: "Development",
              env_type: "DEV",
            },
            paths: null,
            identity_key:
              "2d1eb10b8406cc4a2ef0287053cd21da408a24fbfb65d8002f56132fbe46cc20",
            wrapped_seed:
              "ph:v1:59c2f1b02713effee170712a105a751863339d82554b9a0a7d966f6a6111c63d:+uHF+qN1SRRo7l3wga4WdjJpclLXQjjLP8L+FOaYc9RfZPjb5CSYaYon8SZW1fSII9YNiUFTXKnFo22bsLBIwaBDK7b/xBdcFREb5G2RfAKiBb6j1Es1ux3f3ZFz/bul/6msAuQKK6E=",
            wrapped_salt:
              "ph:v1:6ddd5db0fca06cf54bf86ec5de403d4c11871e4124d84b0983e0ab0ba865e728:nJ2rYnvoWzsG2CPXbkLyWTANh8LlNn222axOwGjf+UE8hKBjocT7XigS0zPNRsu8+V/YEKVngEOV2dupKqGtlsgkW3Mbd17T2YMkExx/x/TJgZXKoNamc2vuLYUtTlamhB8XHfsa41E=",
            created_at: "2025-02-01T16:51:25.941911Z",
            updated_at: "2025-02-01T16:51:25.941916Z",
            deleted_at: null,
            user: "59c68014-d1b9-4896-8a88-8b1088165dde",
            service_account: null,
          },
          {
            id: "2c136678-cb87-4ed7-aa43-f1dcd7c5ba9f",
            environment: {
              id: "c290c2ea-7611-49e8-b7fd-c1046bccaa61",
              name: "Staging",
              env_type: "STAGING",
            },
            paths: null,
            identity_key:
              "d80ad5a145b4c5477473965c5b832e8856a51b612baea1b8da2028616217540a",
            wrapped_seed:
              "ph:v1:30b919477e01468a5477929888e91fd62a3a71382ef01747e1c3f2bc799dd83c:MGyxo5DT+6dcGgZZoD9rOgch/3KLHA9wfYBqnjnGKxHv6/l9FtL7ZHOt8TRAExluPr+ebjMQuqKMKn6c5Z9lDZSbREM4+dQb9hq6DAuejpTlEEqYhIZhUqritLiiHK+zZW+Xw0Xy/Gs=",
            wrapped_salt:
              "ph:v1:d62677ecf0713e99242af3330d9807d2d13f0c44c1f69314538eb8fba66f9305:3oX1QNtZkPv8f9ViyeBiBDMT1tZhOS2k8tvoG1WALYG0t5sDSBtmXjXKiYZw9cm8hHvI3cjDT20XrhG3/79QYVeDbFA1WkLyg8cFickXjiucHahhmKXyEJm1qrLcksYsBho6moLOWkM=",
            created_at: "2025-02-01T16:51:25.956031Z",
            updated_at: "2025-02-01T16:51:25.956036Z",
            deleted_at: null,
            user: "59c68014-d1b9-4896-8a88-8b1088165dde",
            service_account: null,
          },
          {
            id: "3dd91343-46de-44d9-be47-a8a4ca471458",
            environment: {
              id: "c55ed69f-edd6-420a-8156-8b8daa86e713",
              name: "Production",
              env_type: "PROD",
            },
            paths: null,
            identity_key:
              "700e79e28535aac9a8fe960744ca8c9468dc10cca9f6ff31447beb1f1b51ee4d",
            wrapped_seed:
              "ph:v1:f750279a24a074bb713313bdf8db256c3ae326f24b1e1da52e3740fd3f0dbc11:Rdmvc/O6YMg9LEC0UXtcBN9i9W1ELh77BlB/sZc1TMoUWxzEQF0ONt/ILUCOBTmAcVi2xWOtJfR6XH0wT2jygZm/VTmBSyVopxzQzSXaNWmgeXjgm8+8xEbZx8pkJPQMSmIXTBVd2aA=",
            wrapped_salt:
              "ph:v1:3f44a6cadb8341eba84a15dfb9c47880db5d48fa862d3718b0d34efcb5290d1f:Y5htuo04TV73RxzqpXtO3ooI9qeEpp4wbVS9PeCWEKNFJUw5NGX7NovblQojcGKcit0Ku8JMLMEn4P6/Gfn54164Lu8PEs3q0Z6h5pCsTYu+hKuIuD83onx5qc9ARgXI7ga7HWyB2Oc=",
            created_at: "2025-02-01T16:51:25.966753Z",
            updated_at: "2025-02-01T16:51:25.966759Z",
            deleted_at: null,
            user: "59c68014-d1b9-4896-8a88-8b1088165dde",
            service_account: null,
          },
        ],
      },
    ],
  };

  beforeEach(() => {
    jest.clearAllMocks();
    (axios.get as jest.Mock).mockResolvedValue({
      status: 200,
      data: mockResponse,
    });
  });

  it("should correctly initialize and set class properties with a user token", async () => {
    const phase = new Phase(validUserToken, mockHost);
    await phase.init();

    expect(phase.token).toBe(validUserToken);
    expect(phase.host).toBe(mockHost);
    expect(phase.tokenType).toBe("User"); // Assuming the token is a user token
    expect(phase.version).toBe("v1");
    expect(phase.bearerToken).toBe(validUserToken.split(":")[2]); // Extracted from the token

    expect(phase.keypair).toHaveProperty("publicKey");
    expect(phase.keypair).toHaveProperty("privateKey");
    expect(phase.keypair.privateKey).toBeDefined();

    expect(phase.apps.length).toBe(mockResponse.apps.length);
    for (let i = 0; i < phase.apps.length; i++) {
      expect(phase.apps[i].id).toBe(mockResponse.apps[i].id);
      expect(phase.apps[i].name).toBe(mockResponse.apps[i].name);

      expect(phase.apps[i].environments.length).toBe(
        mockResponse.apps[i].environment_keys.length
      );

      for (let j = 0; j < phase.apps[i].environments.length; j++) {
        expect(phase.apps[i].environments[j].keypair.publicKey).toBeDefined();
        expect(phase.apps[i].environments[j].keypair.privateKey).toBeDefined();
        expect(phase.apps[i].environments[j].salt).toBeDefined();
      }
    }
  });

  it("should reconstruct the private key and decrypt environment keys correctly with a user token", async () => {
    const phase = new Phase(validUserToken, mockHost);
    await phase.init();

    // Ensure reconstructPrivateKey was called with real data
    expect(phase.keypair.privateKey).toBeDefined();
    expect(phase.keypair.publicKey).toBe(validUserToken.split(":")[3]);

    // Verify each environment key was unwrapped correctly
    for (const app of phase.apps) {
      for (const env of app.environments) {
        expect(env.keypair.publicKey).toBeDefined();
        expect(env.keypair.privateKey).toBeDefined();
        expect(env.salt).toBeDefined();
      }
    }
  });
});

describe("Phase SDK - init() with valid service token", () => {
  const validServiceToken =
    "pss_service:v2:048c9daa773b2d9bb21a1dda69a56f2b895401fded26889c7063c72224a61f65:fc065f7e5e1093292b20d0c917968cbe3badfb2e82bf1caa70649b72d0017905:1bb35376aacb277fd2792d781dbff5d0e9f7547da3544f4d394ff027d91436d5:4a04b7a5100c67cbf6376f8dae1ca936ca17bcbc119a4a84f8e3727696460925";
  const mockHost = "http://localhost";

  const mockResponse = {
    wrapped_key_share:
      "2c0ffe4625b95a8ebaa9a5bd3a2c908de33c10dd4768313226854c4e484aa6e5a2dc5e0c3b740c4f8302764d40aa64c1e4dcad7bdc9d2f6b8dacdaabab661157b62b647b83e11cac6c750bd2e4dd35a4646c26d61926bd967e1546a5ec59b8bbe6b5c5aa82e01629",
    user_id: "59c68014-d1b9-4896-8a88-8b1088165dde",
    offline_enabled: false,
    organisation: {
      id: "79a36b56-b0a1-4fa2-bd00-6c031868fb10",
      name: "test",
    },
    apps: [
      {
        id: "3b7443aa-3a7c-4791-849a-42aafc9cbe66",
        name: "test",
        encryption: "E2E",
        environment_keys: [
          {
            id: "12a6a8ab-6a4e-4c01-bb76-c1987d1c6824",
            environment: {
              id: "52db76e0-16a0-4b39-b2a9-bb518cd1b6a6",
              name: "Development",
              env_type: "DEV",
            },
            paths: null,
            identity_key:
              "2d1eb10b8406cc4a2ef0287053cd21da408a24fbfb65d8002f56132fbe46cc20",
            wrapped_seed:
              "ph:v1:7a5e6c91afc57338cee5dcd683adcac08f2be2c958a3c0d012ee60a340a65a00:SKD/QatCqjcxLWs335JyBxbSkFxeXRYLuOl5LM9/MLVR/7F5/kBsrNZFdQIyciv/avS2umpqpdbHsPzDluMDnVkHIqd//DT96QoqIqns0Iq2A+HVvW4h/xVQDCZ3c9BeSaY6WDcG/eI=",
            wrapped_salt:
              "ph:v1:f35d14371af1a6445d7ed1a4ee635124f5e64f136a3531b8ea58a80d555d6079:HMXa4x92jbs257cy5Y7M22bMc1PK5nyqWn3y+x0dLBAv2ZV1j4fNKx++7pEknYZfSg6wFkCuAbOMaYJsbwY3JIa+wbtvu4Wt9QG8qx77cPazMbLkxTfDuQe28Gl7bho5t0484Xp85fs=",
            created_at: "2025-02-01T16:52:28.852849Z",
            updated_at: "2025-02-01T16:52:28.852858Z",
            deleted_at: null,
            user: null,
            service_account: "c96b80c1-d43c-4b0a-98fb-b981b731ae63",
          },
          {
            id: "96c3b71d-76e8-4298-8fc9-053fc9b1368b",
            environment: {
              id: "c290c2ea-7611-49e8-b7fd-c1046bccaa61",
              name: "Staging",
              env_type: "STAGING",
            },
            paths: null,
            identity_key:
              "d80ad5a145b4c5477473965c5b832e8856a51b612baea1b8da2028616217540a",
            wrapped_seed:
              "ph:v1:0bedacb6cb2dd95775710516535ae43ab1503dc59414999ca5cf3649f5ff4d13:hMu1mbHuQG6GNy0IaVK2pOXDUUVE+cKQ5Bo3+C69yMh1nFjmLBG0nh7g2gZoIEvFayN/S5thARgZ9YWs0E8bsXHXkuNTTkRScKkrj0ZU5qvoD843PzHjVLcUSdNipoNik8vkZSuIq2U=",
            wrapped_salt:
              "ph:v1:1d8c5eca943096d87957ef824f14d748250d77cb87513394690c500ff9de780a:cA2nbqAOMYI7aChKymIAgBefWUSnPi8srNW/HhhjU62RxdgdBbCydV18C/nsPYLadsvw6pEvySNZJ3JfrhCFXqYCYh5APeg4u9s3W5bBsgNV3glM3I9uR0uasbHmuLNLOPb3xyzhB6o=",
            created_at: "2025-02-01T16:52:28.856257Z",
            updated_at: "2025-02-01T16:52:28.856262Z",
            deleted_at: null,
            user: null,
            service_account: "c96b80c1-d43c-4b0a-98fb-b981b731ae63",
          },
          {
            id: "4c8d94bc-2c9f-4120-a3d2-5647f9f2ef5f",
            environment: {
              id: "c55ed69f-edd6-420a-8156-8b8daa86e713",
              name: "Production",
              env_type: "PROD",
            },
            paths: null,
            identity_key:
              "700e79e28535aac9a8fe960744ca8c9468dc10cca9f6ff31447beb1f1b51ee4d",
            wrapped_seed:
              "ph:v1:827cd1026673911409d0f97cbd011db058c6dd73388a62389ac547493c5c3926:sZu9V7SeLaK/9QHDYQh5T717uqsTXLCSSamvysvVU9HC21A0iHrVGdZsNIib8QIeZz9Cadr2TTiOdks74DTHMWkAca/JObPgWZKz6k02/6Jt6ZeNjWEqcemjSb4xwPQ+9/sjJWQC4kY=",
            wrapped_salt:
              "ph:v1:418a906994764da27f93de6e40310589e8e2201a29dce6bec196186b23e4ff04:O/H2xT/1mqDlZ9oyc9cKBXHmdvEjCqf9Q/elLHrnV8rlqxZzjPoIfGBg72turuZS1b22Mk551c42dVP0ReJqcw67qQSP4GilMJM2Q5BaAglkxUJreXff66RCMTr7/RNiZohhI6CaipE=",
            created_at: "2025-02-01T16:52:28.858876Z",
            updated_at: "2025-02-01T16:52:28.858882Z",
            deleted_at: null,
            user: null,
            service_account: "c96b80c1-d43c-4b0a-98fb-b981b731ae63",
          },
        ],
      },
    ],
  };

  beforeEach(() => {
    jest.clearAllMocks();
    (axios.get as jest.Mock).mockResolvedValue({
      status: 200,
      data: mockResponse,
    });
  });

  it("should correctly initialize and set class properties with a service token", async () => {
    const phase = new Phase(validServiceToken, mockHost);
    await phase.init();

    expect(phase.token).toBe(validServiceToken);
    expect(phase.host).toBe(mockHost);
    expect(phase.tokenType).toBe("ServiceAccount");
    expect(phase.version).toBe("v2");
    expect(phase.bearerToken).toBe(validServiceToken.split(":")[2]); // Extracted from the token

    expect(phase.keypair).toHaveProperty("publicKey");
    expect(phase.keypair).toHaveProperty("privateKey");
    expect(phase.keypair.privateKey).toBeDefined();

    expect(phase.apps.length).toBe(mockResponse.apps.length);
    for (let i = 0; i < phase.apps.length; i++) {
      expect(phase.apps[i].id).toBe(mockResponse.apps[i].id);
      expect(phase.apps[i].name).toBe(mockResponse.apps[i].name);

      expect(phase.apps[i].environments.length).toBe(
        mockResponse.apps[i].environment_keys.length
      );

      for (let j = 0; j < phase.apps[i].environments.length; j++) {
        expect(phase.apps[i].environments[j].keypair.publicKey).toBeDefined();
        expect(phase.apps[i].environments[j].keypair.privateKey).toBeDefined();
        expect(phase.apps[i].environments[j].salt).toBeDefined();
      }
    }
  });

  it("should reconstruct the private key and decrypt environment keys correctly with a service token", async () => {
    const phase = new Phase(validServiceToken, mockHost);
    await phase.init();

    // Ensure reconstructPrivateKey was called with real data
    expect(phase.keypair.privateKey).toBeDefined();
    expect(phase.keypair.publicKey).toBe(validServiceToken.split(":")[3]);

    // Verify each environment key was unwrapped correctly
    for (const app of phase.apps) {
      for (const env of app.environments) {
        expect(env.keypair.publicKey).toBeDefined();
        expect(env.keypair.privateKey).toBeDefined();
        expect(env.salt).toBeDefined();
      }
    }
  });
});
