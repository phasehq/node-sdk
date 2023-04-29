import babel from "rollup-plugin-babel";
import ts from "rollup-plugin-typescript2";
import replace from "@rollup/plugin-replace";
import { nodeResolve } from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import terser from "@rollup/plugin-terser";
import json from "@rollup/plugin-json";

import pkg from "./package.json";

const PLUGINS = [
  nodeResolve({ browser: true, preferBuiltins: true }),
  ts({
    tsconfigOverride: {
      exclude: ["**/*.test.ts", "./tests", "jest.config.ts"],
    },
  }),
  babel({
    extensions: [".ts", ".js", ".tsx", ".jsx"],
    exclude: "node_modules/**",
  }),
  replace({
    _VERSION: JSON.stringify(pkg.version),
  }),
  commonjs({
    transformMixedEsModules: true,
  }),
  json(),
];

export default [
  {
    input: {
      index: "src/index.ts",
    },
    output: [{ dir: "dist", format: "cjs", name: "phase" }],
    plugins: PLUGINS,
  },
];
