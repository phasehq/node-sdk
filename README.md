# Node.js SDK for Phase

SDK to integrate Phase in server-side applications running Node.js

## Install

`npm i @phase.dev/phase-node` or `yarn add @phase.dev/phase-node`

## Import

```js
const Phase = require("@phase.dev/phase-node");
```

## Initialize

Initialize the SDK with your PAT or service account token:

```typescript
const token = 'pss_service...'

const phase = new Phase(token)
```

## Usage

### Get Secrets

Get all secrets in an environment:

```typescript
const getOptions: GetSecretOptions = {
  appId: "3b7443aa-3a7c-4791-849a-42aafc9cbe66",
  envName: "Development",
};

const secrets = await phase.get(getOptions);
```

Get a specific key:

```typescript
const getOptions: GetSecretOptions = {
  appId: "3b7443aa-3a7c-4791-849a-42aafc9cbe66",
  envName: "Development",
  key: "foo"
};

const secrets = await phase.get(getOptions);
```

### Create Secrets

Create one or more secrets in a specified application and environment:

```typescript
import { CreateSecretOptions } from "phase";

const createOptions: CreateSecretOptions = {
  appId: "3b7443aa-3a7c-4791-849a-42aafc9cbe66",
  envName: "Development",
  secrets: [
    {
      key: "API_KEY",
      value: "your-api-key",
      comment: 'test key for dev'
    },
    {
      key: "DB_PASSWORD",
      value: "your-db-password",
      path: "/database",
    }
  ]
};

await phase.create(createOptions);
```

### Update Secrets

Update existing secrets in a specified application and environment:



```typescript
import { UpdateSecretOptions } from "phase";

const updateOptions: UpdateSecretOptions = {
  appId: "3b7443aa-3a7c-4791-849a-42aafc9cbe66",
  envName: "Development",
  secrets: [
    {
      id: "28f5d66e-b006-4d34-8e32-88e1d3478299",
      value: 'newvalue'
    },
  ],
};

await phase.update(updateOptions);
```
### Delete Secrets

Delete one or more secrets from a specified application and environment:

```typescript
import { DeleteSecretOptions } from "phase";

const secretsToDelete = secrets.map((secret) => secret.id);

const deleteOptions: DeleteSecretOptions = {
  appId: "3b7443aa-3a7c-4791-849a-42aafc9cbe66",
  envName: "Development",
  secretIds: secretsToDelete,
};

await phase.delete(deleteOptions);
```

## Development

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for more information on how to contribute.
