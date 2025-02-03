import {
  decryptEnvSecrets,
  digest,
  encryptEnvSecrets,
  reconstructPrivateKey,
  unwrapEnvKeys,
} from "./utils/crypto";
import axios from "axios";
import {
  App,
  Environment,
  GetSecretOptions,
  PhaseKeyPair,
  Secret,
  CreateSecretOptions,
  SessionResponse,
  DeleteSecretOptions,
  UpdateSecretOptions,
} from "./types";
import {
  normalizeKey,
  resolveSecretReferences,
  SecretFetcher,
} from "./utils/secrets";
import { LIB_VERSION } from "../version";

const DEFAULT_HOST = "https://console.phase.dev";

export default class Phase {
  token: string;
  host: string;
  tokenType: string | null = null;
  version: string | null = null;
  bearerToken: string | null = null;
  keypair: PhaseKeyPair = {} as PhaseKeyPair;
  apps: App[] = [];

  constructor(token: string, host?: string) {
    this.host = host || DEFAULT_HOST;
    this.token = token;
    this.validateAndParseToken(token);
  }

  /**
   * Initializes the session by fetching data from the server and reconstructing the private key.
   * This should be called after the constructor.
   */
  public async init(): Promise<void> {
    if (!this.bearerToken) {
      throw new Error(
        "Token validation failed. Bearer token or public key is missing."
      );
    }

    try {
      // Fetch wrapped key data, apps, and envs for this token
      const response = await axios.get(`${this.host}/service/secrets/tokens/`, {
        headers: this.getAuthHeaders(),
      });

      if (response.status !== 200) {
        throw new Error(`Failed to fetch session data: ${response.statusText}`);
      }

      const data: SessionResponse = response.data;

      // Set the keypair for the class instance
      this.keypair = {
        publicKey: this.token.split(":")[3],
        privateKey: await reconstructPrivateKey(
          data.wrapped_key_share,
          this.token
        ),
      };

      const appPromises: Promise<App>[] = data.apps.map(async (app) => {
        const { id, name } = app;

        const environmentPromises: Promise<Environment>[] =
          app.environment_keys.map(async (envData) => {
            const { publicKey, privateKey, salt } = await unwrapEnvKeys(
              envData.wrapped_seed,
              envData.wrapped_salt,
              this.keypair
            );

            const { id, name } = envData.environment;

            const { paths } = envData;

            return {
              id,
              name,
              paths,
              keypair: {
                publicKey,
                privateKey,
              },
              salt,
            };
          });

        const environments = await Promise.all(environmentPromises);

        return { id, name, environments };
      });

      const apps: App[] = await Promise.all(appPromises);
      this.apps = apps;
    } catch (error) {
      console.error("Error initializing session:", error);
      throw new Error(
        "Failed to initialize session. Please check your token and network connection."
      );
    }
  }

  /**
   * Validates and parses the token.
   * Throws an error if the token is invalid.
   * Sets the following class properties: tokenType, version, bearerToken,
   */
  private validateAndParseToken(token: string): void {
    // Regex to match the token format
    const tokenRegex =
      /^(pss_(user|service)):v\d+:[a-fA-F0-9]{64}:[a-fA-F0-9]{64}:[a-fA-F0-9]{64}:[a-fA-F0-9]{64}$/;

    // Test the token against the regex
    if (!tokenRegex.test(token)) {
      throw new Error(
        "Invalid token format. Token does not match the expected pattern."
      );
    }

    // Split the token into its components
    const [tokenType, version, bearerToken] = token.split(":");

    // Assign the parsed values to the instance properties
    this.tokenType = tokenType.includes("user")
      ? "User"
      : version === "v1"
      ? "Service"
      : "ServiceAccount";
    this.version = version;
    this.bearerToken = bearerToken;
  }

  private getAuthHeaders() {
    return {
      Authorization: `Bearer ${this.tokenType} ${this.bearerToken}`,
      Accept: "application/json",
      "User-agent": `phase-node-sdk/${LIB_VERSION}`,
    };
  }

  async get(options: GetSecretOptions): Promise<Secret[]> {
    return new Promise<Secret[]>(async (resolve, reject) => {
      const cache = new Map<string, string>();

      const app = this.apps.find((app) => app.id === options.appId);
      if (!app) {
        reject("Invalid app id");
        return;
      }

      const env = app?.environments.find(
        (env) => env.name.toLowerCase() === options.envName.toLowerCase()
      );
      if (!env) {
        reject(`Invalid environment name: ${options.envName}`);
        return;
      }

      try {
        const queryHeaders = {
          environment: env.id,
          path: options.path || "/",
          keyDigest: null,
        };

        if (options.key) {
          const keyDigest = await digest(options.key.toUpperCase(), env.salt);
          queryHeaders.keyDigest = keyDigest;
        }

        const res = await axios({
          url: `${this.host}/service/secrets/`,
          method: "get",
          headers: {
            ...queryHeaders,
            ...this.getAuthHeaders(),
          },
        });

        let secretsToDecrypt = res.data
          .filter((secret: Secret) =>
            options.path ? secret.path === options.path : true
          )
          .filter((secret: Secret) =>
            options.tags
              ? secret.tags.some((tag) => options.tags?.includes(tag))
              : true
          );

        // Decrypt fetched secrets
        const secrets = await decryptEnvSecrets(secretsToDecrypt, env.keypair);

        const secretLookup = new Map<string, Secret>(
          secrets.map((s) => [normalizeKey(env.name, s.path, s.key), s])
        );

        // 🛠 Fetch local and cross-environment secrets as needed
        const fetcher: SecretFetcher = async (
          envName: string,
          path: string,
          key: string
        ) => {
          const cacheKey = normalizeKey(envName, path, key);

          if (cache.has(cacheKey)) {
            return {
              id: "",
              key,
              value: cache.get(cacheKey)!,
              comment: "",
              environment: envName,
              folder: undefined,
              path,
              tags: [],
              keyDigest: "",
              createdAt: undefined,
              updatedAt: new Date().toISOString(),
              version: 1,
            };
          }

          let secret = secretLookup.get(cacheKey);

          if (!secret) {
            // 🔄 Fetch cross-environment secret dynamically
            const crossEnvSecrets = await this.get({
              ...options,
              envName,
              path,
              tags: undefined,
            });

            secret = crossEnvSecrets.find((s) => s.key === key);
            if (!secret)
              throw new Error(`Missing secret: ${envName}:${path}:${key}`);

            // Store for future lookups
            secretLookup.set(cacheKey, secret);
          }

          cache.set(cacheKey, secret.value);
          return secret;
        };

        // Resolve references in secret values
        const resolvedSecrets = await Promise.all(
          secrets.map(async (secret) => ({
            ...secret,
            value: await resolveSecretReferences(
              secret.value,
              options.envName,
              options.path || "/",
              fetcher,
              cache
            ),
          }))
        );

        resolve(resolvedSecrets);
      } catch (err) {
        console.log(`Error fetching secrets: ${err}`);
        reject(err);
      }
    });
  }

  

  create = async (options: CreateSecretOptions): Promise<void> => {
    return new Promise<void>(async (resolve, reject) => {
      const { appId, envName } = options;

      const app = this.apps.find((app) => app.id === appId);
      if (!app) {
        throw "Invalid app id";
      }

      const env = app?.environments.find((env) => env.name === envName);
      if (!env) {
        throw "Invalid environment name";
      }

      try {
        if (options.secrets.some((secret) => secret.key?.length === 0)) {
          throw "Secret keys cannot be blank";
        }

        const encryptedSecrets = await encryptEnvSecrets(
          options.secrets,
          env.keypair,
          env.salt
        );

        encryptedSecrets.forEach((secret) => {
          if (!secret.tags) secret.tags = [];
          if (!secret.path) secret.path = "/";
        });

        try {
          const requestHeaders = { environment: env.id };

          const requestBody = JSON.stringify({ secrets: encryptedSecrets });

          const res = await axios({
            url: `${this.host}/service/secrets/`,
            method: "post",
            headers: {
              ...requestHeaders,
              ...this.getAuthHeaders(),
            },
            data: requestBody,
          });

          if (res.status === 200) resolve();
        } catch (err) {
          console.log(`Error creating secrets: ${err}`);
        }
      } catch (err) {
        console.log("Something went wrong");
        reject;
        return;
      }
    });
  };

  update = async (options: UpdateSecretOptions): Promise<void> => {
    return new Promise<void>(async (resolve, reject) => {
      const { appId, envName } = options;

      const app = this.apps.find((app) => app.id === appId);
      if (!app) {
        throw "Invalid app id";
      }

      const env = app?.environments.find((env) => env.name === envName);
      if (!env) {
        throw "Invalid environment name";
      }

      try {
        if (options.secrets.some((secret) => secret.key?.length === 0)) {
          throw "Secret keys cannot be blank";
        }

        const encryptedSecrets = await encryptEnvSecrets(
          options.secrets,
          env.keypair,
          env.salt
        );

        encryptedSecrets.forEach((secret) => {
          if (!secret.tags) secret.tags = [];
          if (!secret.path) secret.path = "/";
        });

        try {
          const requestHeaders = { environment: env.id };

          const requestBody = JSON.stringify({ secrets: encryptedSecrets });

          const res = await axios({
            url: `${this.host}/service/secrets/`,
            method: "put",
            headers: {
              ...requestHeaders,
              ...this.getAuthHeaders(),
            },
            data: requestBody,
          });

          if (res.status === 200) resolve();
        } catch (err) {
          console.log(`Error creating secrets: ${err}`);
        }
      } catch (err) {
        console.log("Something went wrong");
        reject;
        return;
      }
    });
  };

  delete = async (options: DeleteSecretOptions): Promise<void> => {
    return new Promise<void>(async (resolve, reject) => {
      if (options.secretIds.length > 0) {
        try {
          const { appId, envName } = options;

          const app = this.apps.find((app) => app.id === appId);
          if (!app) {
            throw "Invalid app id";
          }

          const env = app?.environments.find((env) => env.name === envName);
          if (!env) {
            throw "Invalid environment name";
          }

          const requestHeaders = { environment: env.id };

          const res = await axios({
            url: `${this.host}/service/secrets/`,
            method: "delete",
            headers: {
              ...requestHeaders,
              ...this.getAuthHeaders(),
            },
            data: JSON.stringify({ secrets: options.secretIds }),
          });

          if (res.status === 200) resolve();
        } catch (err) {
          console.log(`Error deleting secrets: ${err}`);
          reject;
          return;
        }
      }
    });
  };
}
