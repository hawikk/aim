import js from "@eslint/js";
import tseslint from "typescript-eslint";
import globals from "globals";

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      "**/coverage/**",
      // Vendored third-party assets (e.g. chart.umd.js) — not our code.
      "**/public/vendor/**",
      // Build output: build_aim_cli.py copies our own sources in here to vendor
      // them into the aim CLI wheel. It is gitignored, so a clean CI checkout
      // never has it and `eslint .` passed by accident — while anyone who has
      // actually built the CLI lints the same files twice and eats ~112
      // phantom errors. Ignoring it makes local lint match CI lint.
      "packaging/aim-cli/src/aim/_vendor/**",
      // GitHub Actions CJS helpers use require(); keep them out of the TS rule set.
      ".github/scripts/**",
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: {
        ...globals.node,
      },
    },
    rules: {
      // Convention: prefix intentionally-unused bindings with underscore
      // (params *and* vars — e.g. `const { _tileId, ...rest } = x` omits).
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
  {
    // Landing page client scripts (demo renderer) run in the browser.
    files: ["apps/landing/**/*.{js,mjs}"],
    languageOptions: {
      globals: {
        ...globals.browser,
      },
    },
  },
  {
    // Node tests that exercise browser helpers via jsdom (document/window).
    files: ["apps/web/test/**/*.{js,mjs}"],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
  },
  {
    // Dashboard frontend runs in the browser.
    files: ["apps/web/public/**/*.js"],
    ignores: ["apps/web/public/vendor/**"],
    languageOptions: {
      globals: {
        ...globals.browser,
        Chart: "readonly",
      },
    },
  },
  {
    // Landing sample demo is pure browser JS (document/window).
    // Without browser globals, default node env fails static checks on main.
    files: ["apps/landing/**/*.js"],
    languageOptions: {
      globals: {
        ...globals.browser,
      },
    },
  },
  {
    // Playwright screenshot helper evaluates browser code strings.
    // page.evaluate bodies touch browser APIs; the runner itself is Node.
    files: ["apps/web/scripts/**/*.{js,mjs,cjs}"],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
  },
  {
    // Dashboard unit tests mount JSDOM and use browser globals (document, etc.).
    files: ["apps/web/test/**/*.{js,mjs,cjs}"],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
  },
  {
    // Landing demo is browser-side.
    files: ["apps/landing/**/*.{js,mjs,cjs}"],
    languageOptions: {
      globals: {
        ...globals.browser,
      },
    },
  },
);
