# Contributing Guide

Thank you for your interest in contributing to the Phase Node.js SDK! We welcome all contributions, whether it's fixing bugs, adding new features, or improving documentation.

## Getting Started

1. **Fork the repository** on GitHub.
2. **Clone your fork** to your local machine:
   ```sh
   git clone https://github.com/your-username/node-sdk.git
   cd node-sdk
   ```
3. **Install dependencies**:
   ```sh
   yarn install
   ```
4. **Build the package**:
   ```sh
   yarn build
   ```
5. **Run tests**:
   ```sh
   yarn test
   ```

## Making Changes

- Follow the existing code style (Prettier and ESLint are configured).
- Write clear commit messages following the [Conventional Commits](https://www.conventionalcommits.org/) format.
- Ensure all tests pass before submitting a pull request.
- If adding a new feature, consider writing tests to cover your changes.
- Consider if your changes require an update to [docs](https://github.com/phasehq/docs).
- Bump the package version in `package.json` and `version.ts`. Use the semver standard to bump the major, minor or patch version depending on the type of change you're making.

## Setting Up a Test Project

To test your local changes in a real project, follow these steps:

1. **Create a new test project:**
   ```sh
   mkdir test-project && cd test-project
   yarn init -y
   ```

2. **Link the local SDK package:**
    In the SDK root, run:
   ```sh
   yarn link
   ```
   Then in your test project, 
   ```sh
   yarn link '@phase.dev/phase-node'
   ```


3. **Use the SDK in your test project:**
   ```js
   const Phase = require('@phase.dev/phase-node')
   ```

## Submitting a Pull Request

1. **Create a new branch:**
   ```sh
   git checkout -b feature/your-feature
   ```
2. **Make and commit your changes:**
   ```sh
   git commit -m "feat: add new feature"
   ```
3. **Push to your fork:**
   ```sh
   git push origin feature/your-feature
   ```
4. **Open a Pull Request** on GitHub against the `main` branch.

## Useful Links

[Phase Quickstart](https://docs.phase.dev/quickstart)

[SDK Docs](https://docs.phase.dev/sdks/node)

[Docs repo](https://github.com/phasehq/docs)

[Community Slack](https://slack.phase.dev)


