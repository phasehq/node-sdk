import { StringifyOptions } from "querystring";

export type PhaseKeyPair = {
  publicKey: string;
  privateKey: string;
};

export type EnvironmentKey = {
  id: string;
  environment: {
    id: string;
    name: string;
    env_type: string;
  };
  paths: string[] | null;
  identity_key: string;
  wrapped_seed: string;
  wrapped_salt: string;
  created_at: string;
  updated_at: string;
  deleted_at: string | null;
  user: string;
  service_account: string | null;
};

export type Environment = {
  id: string;
  name: string;
  paths: string[] | null;
  keypair: PhaseKeyPair;
  salt: string;
};

export type AppData = {
  id: string;
  name: string;
  encryption: "SSE" | "E2E";
  environment_keys: EnvironmentKey[];
};

export type App = {
  id: string;
  name: string;
  environments: Environment[];
};

export type SessionResponse = {
  wrapped_key_share: string;
  apps: AppData[];
};

export type SecretValueOverride = {
  value: string
  isActive: boolean
}

export type Secret = {
  id: string;
  key: string;
  value: string;
  comment: string;
  environment: string;
  folder?: string;
  path: string;
  tags: string[];
  keyDigest: string;
  override?: SecretValueOverride;
  createdAt?: string;
  updatedAt?: string;
  version: number;
};

export type GetSecretOptions = {
  appId: string;
  envName: string;
  path?: string;
  key?: string;
  tags?: string[];
};

export type SecretInput = {
  key: string;
  value: string;
  comment: string;
  path?: string;
};

export type CreateSecretOptions = {
  appId: string;
  envName: string;
  secrets: SecretInput[];
};

export type DeleteSecretOptions = {
  appId: string;
  envName: string;
  secretIds: string[];
};

export type UpdateSecretOptions = {
  appId: string;
  envName: string;
  secrets: (SecretInput & { id: string, override?: SecretValueOverride })[];
};
