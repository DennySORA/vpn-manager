// Strict static gate for the web owner (docs/development.md, 「靜態檢查」): typed ESLint with the strict
// type-checked rules, React hooks (with the React Compiler checks), accessibility and security lints, at zero
// warnings (`pnpm lint` runs with --max-warnings 0). Formatting belongs to Prettier (`pnpm format:check`).
// The type information comes from the TypeScript 6 API (`typescript`); the type check itself runs on the
// native TypeScript 7 compiler (`typescript-native`), which has the same type system.
import js from "@eslint/js";
import jsxA11y from "eslint-plugin-jsx-a11y";
import noUnsanitized from "eslint-plugin-no-unsanitized";
import reactHooks from "eslint-plugin-react-hooks";
import security from "eslint-plugin-security";
import type { Linter } from "eslint";
import { defineConfig } from "eslint/config";
import globals from "globals";
import tseslint from "typescript-eslint";

// CJK script as an esquery regular expression: CJK punctuation and kana, ideographs, full-width forms.
const CJK = "/[\\u3000-\\u30ff\\u3400-\\u9fff\\uff00-\\uffef]/";
const VISIBLE_TEXT = "Visible text belongs in a messages.ts table (src/i18n), one entry per language.";
const ENGLISH_TABLE = "The English table must not contain CJK text.";

// These two plugins ship no types: name the one config each provides.
const a11yStrict = (jsxA11y as { flatConfigs: { strict: Linter.Config } }).flatConfigs.strict;
const unsanitized = (noUnsanitized as { configs: { recommended: Linter.Config } }).configs.recommended;

export default defineConfig(
  { ignores: ["dist/**", "node_modules/**", "src/api/generated/**"] },
  {
    linterOptions: { reportUnusedDisableDirectives: "error", reportUnusedInlineConfigs: "error" },
  },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: { ...globals.browser },
      parserOptions: {
        projectService: { allowDefaultProject: ["eslint.config.ts"] },
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
  reactHooks.configs.flat["recommended-latest"],
  a11yStrict,
  security.configs.recommended,
  unsanitized,
  {
    rules: {
      // Numbers and booleans in template literals are ordinary in labels ("3 條連線").
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true, allowBoolean: false }],
      "@typescript-eslint/consistent-type-imports": ["error", { fixStyle: "inline-type-imports" }],
      "@typescript-eslint/no-import-type-side-effects": "error",
      "@typescript-eslint/switch-exhaustiveness-check": "error",
      eqeqeq: ["error", "always"],
      // Flags every `record[key]`; here keys are typed unions or array indexes checked by
      // noUncheckedIndexedAccess, and no object is ever built from untrusted keys. The XSS sinks stay covered by
      // no-unsanitized and the other security rules.
      "security/detect-object-injection": "off",
      "no-console": ["error", { allow: ["warn", "error"] }],
    },
  },
  {
    files: ["*.config.ts"],
    languageOptions: { globals: { ...globals.node } },
  },
  // Three languages (src/i18n): text a person reads lives in a `messages.ts` table, never in the code that shows
  // it. Anything written in CJK script (kana, ideographs, their punctuation and full-width forms) outside those
  // tables is such text; tests and fixtures read the Traditional Chinese table and may quote it.
  {
    files: ["src/**/*.{ts,tsx}"],
    ignores: [
      "src/**/messages.{ts,tsx}",
      "src/i18n/**",
      "src/**/*.test.{ts,tsx}",
      "src/**/test-fixtures.ts",
      "src/test/**",
      "src/api/generated/**",
    ],
    rules: {
      "no-restricted-syntax": [
        "error",
        { selector: `Literal[value=${CJK}]`, message: VISIBLE_TEXT },
        { selector: `TemplateElement[value.raw=${CJK}]`, message: VISIBLE_TEXT },
        { selector: `JSXText[value=${CJK}]`, message: VISIBLE_TEXT },
      ],
    },
  },
  // ... and the English table is English.
  {
    files: ["src/**/messages.{ts,tsx}"],
    rules: {
      "no-restricted-syntax": [
        "error",
        { selector: `Property[key.name="en"] Literal[value=${CJK}]`, message: ENGLISH_TABLE },
        { selector: `Property[key.name="en"] TemplateElement[value.raw=${CJK}]`, message: ENGLISH_TABLE },
        { selector: `Property[key.name="en"] JSXText[value=${CJK}]`, message: ENGLISH_TABLE },
      ],
    },
  },
);
