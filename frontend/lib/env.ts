import { z } from "zod";

/**
 * Validation stricte des variables d'environnement (exigence sécurité #5).
 *
 * - Le schéma est appliqué au démarrage du serveur (via `instrumentation.ts`)
 *   et à la première importation : démarrage refusé si une variable manque
 *   ou est invalide (fail-fast, comme le backend).
 * - AUCUNE variable `NEXT_PUBLIC_*` n'est utilisée dans ce projet : rien
 *   n'est exposé au bundle client. Un check CI greppe le bundle pour
 *   vérifier qu'aucun secret ne fuit (scripts/check-bundle-secrets.sh).
 * - Ce module est importé uniquement depuis du code serveur. Il ne porte pas
 *   `import "server-only"` car `next.config.ts` et les tests unitaires
 *   l'utilisent hors contexte React — la garantie de non-fuite vient du fait
 *   que les valeurs ne sont jamais passées à un composant client.
 */

/** Schéma des variables d'environnement serveur. Exporté pour les tests. */
export const envSchema = z.object({
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default("development"),

  /**
   * URL de base de l'API Axum (réseau interne, jamais exposée au client :
   * tous les appels passent par le serveur Next — pattern BFF).
   */
  API_BASE_URL: z
    .url({ protocol: /^https?$/ })
    .refine((u) => !u.endsWith("/"), {
      message: "API_BASE_URL ne doit pas finir par '/'",
    }),

  /**
   * Secret de chiffrement du cookie de session (iron-session, AES-256-GCM
   * via scrypt). >= 32 caractères exigés, comme le JWT_SECRET du backend.
   * Générer avec : openssl rand -base64 48
   */
  SESSION_SECRET: z
    .string()
    .min(32, "SESSION_SECRET doit faire au moins 32 caractères"),

  /**
   * `true` en production (HTTPS obligatoire) : active l'attribut Secure et
   * le préfixe __Host- du cookie de session. `false` uniquement pour le
   * développement local en HTTP.
   */
  COOKIE_SECURE: z
    .enum(["true", "false"])
    .default("true")
    .transform((v) => v === "true"),

  /**
   * Origines publiques autorisées pour les Server Actions (anti-CSRF),
   * nécessaires uniquement derrière un proxy qui réécrit l'en-tête Host.
   * Liste séparée par des virgules, ex. "app.example.com".
   */
  APP_ALLOWED_ORIGINS: z.string().default(""),
});

export type Env = z.infer<typeof envSchema>;

/**
 * Analyse un dictionnaire d'environnement. Lève une erreur listant chaque
 * variable manquante/invalide SANS jamais inclure les valeurs (un secret mal
 * formé ne doit pas finir dans les logs).
 */
export function parseEnv(source: Record<string, string | undefined>): Env {
  const result = envSchema.safeParse(source);
  if (!result.success) {
    const details = result.error.issues
      .map((issue) => `  - ${issue.path.join(".")}: ${issue.message}`)
      .join("\n");
    // Message volontairement sans valeurs : uniquement noms + règle violée.
    throw new Error(
      `Configuration d'environnement invalide — démarrage refusé :\n${details}`,
    );
  }
  return result.data;
}

let cached: Env | undefined;

/** Accès paresseux et mémoïsé à l'environnement validé. */
export function env(): Env {
  cached ??= parseEnv(process.env);
  return cached;
}
