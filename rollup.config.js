import babel from "rollup-plugin-babel";
import ts from "rollup-plugin-typescript2";
import replace from "@rollup/plugin-replace";
import { nodeResolve } from "@rollup/plugin-node-resolve";
import commonjs from '@rollup/plugin-commonjs';
import terser from '@rollup/plugin-terser';
import json from '@rollup/plugin-json';

import pkg from "./package.json";

const PLUGINS = [
    nodeResolve({ browser:true, preferBuiltins: true }),
    ts({
        tsconfigOverride: { exclude: ["**/*.test.ts", "./example"] },
    }),
    babel({
        extensions: [".ts", ".js", ".tsx", ".jsx"],
        exclude: 'node_modules/**',
    }),
    replace({
        _VERSION: JSON.stringify(pkg.version),
    }),
    commonjs({
        transformMixedEsModules: true
    }),
    json()
];

export default [
  {
    input: {
      index: "index.ts",
    },
    output: [
      { dir: "dist", format: "cjs", name: "phase"},
      // { dir: "dist/module", format: "es" },
      // { dir: "dist/browser", format: "iife", name: "phase", plugins: [terser()]},
    ],
    plugins: PLUGINS,
  },
];
