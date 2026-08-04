/**
 * Author: John Grimes
 */

import js from "@eslint/js";
import vitest from "@vitest/eslint-plugin";
import importPlugin from "eslint-plugin-import";
import jsdoc from "eslint-plugin-jsdoc";
import jsxA11y from "eslint-plugin-jsx-a11y";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import unicorn from "eslint-plugin-unicorn";
import tseslint from "typescript-eslint";
// eslint-plugin-vitest was renamed to @vitest/eslint-plugin; this is the maintained package.

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/coverage/**",
      "**/node_modules/**",
      "**/storybook-static/**",
      "**/playwright-report/**",
      "**/test-results/**",
      "**/drizzle/**",
    ],
  },

  js.configs.recommended,
  ...tseslint.configs.recommendedTypeChecked,
  jsdoc.configs["flat/recommended-typescript"],
  unicorn.configs.recommended,

  {
    languageOptions: {
      parserOptions: {
        projectService: {
          // Build and test configs sit outside every package tsconfig; without
          // this the type-aware rules cannot resolve a program for them.
          allowDefaultProject: [
            "*.js",
            "*.ts",
            "*/*/*.config.ts",
            "scripts/*.mjs",
          ],
          // The root tsconfig is a solution file of project references, which is
          // the arrangement this warning asks for.
          noWarnOnMultipleProjects: true,
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: { import: importPlugin },
    settings: {
      "import/resolver": {
        typescript: { alwaysTryTypes: true, project: ["./*/*/tsconfig.json"] },
      },
      react: { version: "detect" },
    },
    rules: {
      "import/order": [
        "error",
        {
          groups: [
            ["builtin", "external"],
            "internal",
            ["parent", "sibling", "index"],
            "type",
          ],
          "newlines-between": "always",
          alphabetize: { order: "asc", caseInsensitive: true },
        },
      ],

      "jsdoc/require-jsdoc": [
        "warn",
        {
          publicOnly: true,
          require: {
            FunctionDeclaration: true,
            MethodDefinition: true,
            ArrowFunctionExpression: true,
            FunctionExpression: true,
          },
        },
      ],
      // The signature already carries parameter and return types; repeating them
      // in prose adds a second thing to keep in sync. Prose documents intent.
      "jsdoc/require-param": "off",
      "jsdoc/require-returns": "off",
      "jsdoc/tag-lines": "off",

      // This is an auth server: an unawaited promise is a security bug, not a style nit.
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
      // A `default` clause is a legitimate way to be exhaustive: several switches
      // here handle the interesting `typeof` cases and deliberately fall through
      // for the rest.
      "@typescript-eslint/switch-exhaustiveness-check": [
        "error",
        { considerDefaultExhaustiveForUnions: true },
      ],
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],

      // Domain vocabulary here is FHIR/OAuth abbreviations (jwks, iss, aud, pkce).
      "unicorn/prevent-abbreviations": "off",
      "unicorn/no-null": "off",
      // The TypeScript conventions for this codebase specify lowerCamelCase
      // filenames, not unicorn's kebab-case default.
      "unicorn/filename-case": ["error", { case: "camelCase" }],
      // FHIR canonical URLs are identifiers, not fetchable addresses, and are
      // canonically `http://` (e.g. http://terminology.hl7.org/CodeSystem/...).
      // Rewriting them to https would change their meaning.
      "unicorn/prefer-https": "off",
      // `.map(formatScope)` is clearer than wrapping a single-argument pure
      // function in an arrow just to satisfy the extra-arguments concern.
      "unicorn/no-array-callback-reference": "off",
      // Prettier lower-cases hex digits, and unicorn's default wants them upper.
      // Formatting belongs to Prettier, so the rule is aligned to it rather than
      // left to fight it on every `0xff` in the address classifier.
      "unicorn/number-literal-case": [
        "error",
        { hexadecimalValue: "lowercase" },
      ],
    },
  },

  // React surfaces only.
  {
    files: ["apps/web/**/*.{ts,tsx}"],
    ...react.configs.flat.recommended,
    settings: { react: { version: "detect" } },
  },
  {
    files: ["apps/web/**/*.{ts,tsx}"],
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
      "jsx-a11y": jsxA11y,
    },
    languageOptions: {
      parserOptions: { ecmaFeatures: { jsx: true } },
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      ...jsxA11y.flatConfigs.recommended.rules,
      "react/prop-types": "off",
      "react/react-in-jsx-scope": "off",
      "react/jsx-pascal-case": "error",
      "react/jsx-boolean-value": ["error", "never"],
      "react/self-closing-comp": "error",
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      "react-refresh/only-export-components": [
        "warn",
        { allowConstantExport: true },
      ],
    },
  },

  // Process entry points. Exiting non-zero on a configuration error is the
  // correct behaviour for a server: a stack trace would bury the message.
  {
    files: ["apps/*/src/index.ts"],
    rules: { "unicorn/no-process-exit": "off" },
  },

  // Build-time CLI tooling. These are plain Node scripts run by the Dockerfile
  // and by npm scripts, outside any package's tsconfig, so type-aware rules have
  // no program to work from and `console`/`process` are the intended interface.
  {
    files: ["scripts/**/*.mjs", "scripts/**/*.js"],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      globals: { console: "readonly", process: "readonly" },
    },
    rules: {
      ...tseslint.configs.disableTypeChecked.rules,
      "no-undef": "off",
      "jsdoc/require-jsdoc": "off",
      "unicorn/no-process-exit": "off",
    },
  },

  // The stub SMART app served by the compose stack. Browser code, run by a
  // browser, with no build step and no tsconfig - so type-aware rules have no
  // program and the DOM globals are the whole point of the file.
  {
    files: ["deploy/compose/app/**/*.js"],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      globals: {
        atob: "readonly",
        btoa: "readonly",
        crypto: "readonly",
        document: "readonly",
        fetch: "readonly",
        sessionStorage: "readonly",
        TextDecoder: "readonly",
        TextEncoder: "readonly",
        URL: "readonly",
        URLSearchParams: "readonly",
      },
    },
    rules: {
      ...tseslint.configs.disableTypeChecked.rules,
      // The selector is a literal in the same file, not user input.
      "unicorn/require-css-escape": "off",
    },
  },

  // The data layer.
  {
    files: ["packages/db/**/*.ts"],
    rules: {
      // Drizzle's insert builder exposes `.values()`, which this rule mistakes
      // for `Array#values()` and reports as a discarded return - the builder is
      // awaited, so the finding is spurious throughout the package.
      "unicorn/no-unused-array-method-return": "off",
    },
  },

  {
    files: ["**/*.test.{ts,tsx}", "**/test/**/*.ts", "e2e/**/*.ts"],
    plugins: { vitest },
    rules: {
      ...vitest.configs.recommended.rules,
      "jsdoc/require-jsdoc": "off",
      "@typescript-eslint/no-non-null-assertion": "off",
      // Vitest matcher helpers such as `expect.stringContaining` are typed `any`.
      "@typescript-eslint/no-unsafe-assignment": "off",
      // Whitespace in test fixtures is deliberate and literal.
      "unicorn/prefer-string-repeat": "off",
      "unicorn/no-useless-undefined": "off",
      // A helper scoped to the `describe` block that uses it is clearer than one
      // hoisted to module scope away from its only caller.
      "unicorn/consistent-function-scoping": "off",
      // `(await response.json()).field` is how a response is read in a test.
      // Naming an intermediate for every one of them adds lines without clarity.
      "unicorn/no-await-expression-member": "off",
    },
  },

  {
    files: ["**/*.js", "**/*.config.{ts,js}"],
    ...tseslint.configs.disableTypeChecked,
    rules: {
      // Spreading the config above brings its own `rules`; a bare `rules` key
      // here would replace them wholesale and re-enable the type-aware rules.
      ...tseslint.configs.disableTypeChecked.rules,
      "jsdoc/require-jsdoc": "off",
    },
  },
);
