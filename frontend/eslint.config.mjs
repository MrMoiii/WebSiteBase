import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";
import security from "eslint-plugin-security";

/**
 * Lint strict : règles React/Next + TypeScript + eslint-plugin-security.
 * Le lint fait partie de la CI : tout warning bloque le build.
 */
const eslintConfig = defineConfig([
  globalIgnores([
    ".next/**",
    "out/**",
    "coverage/**",
    "node_modules/**",
    "playwright-report/**",
    "test-results/**",
    "next-env.d.ts",
  ]),
  ...nextVitals,
  ...nextTs,
  security.configs.recommended,
  {
    rules: {
      // Exigence TS strict : aucun `any` non justifié.
      "@typescript-eslint/no-explicit-any": "error",
      // Exigence XSS #3 : `dangerouslySetInnerHTML` interdit. Toute exception
      // devrait être justifiée par un commentaire ET sanitizée (DOMPurify) —
      // il n'y en a aucune dans ce projet.
      "react/no-danger": "error",
      // Interdit les hrefs javascript: (vecteur XSS via URL).
      "react/jsx-no-script-url": "error",
      "react/jsx-no-target-blank": ["error", { allowReferrer: false }],
    },
  },
]);

export default eslintConfig;
