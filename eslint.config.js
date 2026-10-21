import typescriptEslint from "@typescript-eslint/eslint-plugin";
import typescriptParser from "@typescript-eslint/parser";
import googleConfig from "eslint-config-google";
import js from "@eslint/js";

export default [
  js.configs.recommended,
  {
    files: ["safety-guard/**/*.ts"],
    languageOptions: {
      parser: typescriptParser,
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        process: "readonly",
        console: "readonly",
        Buffer: "readonly",
        TextDecoder: "readonly"
      }
    },
    plugins: {
      "@typescript-eslint": typescriptEslint
    },
    rules: {
      ...typescriptEslint.configs.recommended.rules,
      ...googleConfig.rules,
      "require-jsdoc": "off",
      "valid-jsdoc": "off",
      "@typescript-eslint/no-unused-vars": ["error", { "argsIgnorePattern": "^_" }],
      "no-console": "error",
      "indent": ["error", "tab", { "SwitchCase": 1 }],
      "quotes": ["error", "double"],
      "max-len": ["error", { "code": 120, "ignoreUrls": true }],
      "object-curly-spacing": ["error", "always"],
      "comma-dangle": ["error", "only-multiline"],
      "new-cap": "off"
    }
  },
  {
    ignores: ["node_modules/", "dist/", "deploy-safety-guard.sh"]
  }
];
