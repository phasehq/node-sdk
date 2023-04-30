# Node.js SDK for Phase

SDK to integrate Phase in server-side applications running Node.js

## Install

`npm i @phase.dev/phase-node` or `yarn add @phase.dev/phase-node`

## Import

```js
const Phase = require("@phase.dev/phase-node");
```

## Initialize

Initialize the SDK with your `APP_ID` and `APP_SECRET`:

```js
const phase = new Phase(APP_ID, APP_SECRET);
```

## Usage

### Encrypt

```js
const ciphertext = await phase.encrypt("hello world");
```

### Decrypt

```js
const plaintext = await phase.decrypt(ciphertext);
```

## Development

### Install dependencies

`npm install`

### Build

`npm run build`

### Run tests

`npm test`
