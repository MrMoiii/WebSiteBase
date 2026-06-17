import { z } from "zod";

/**
 * Schémas zod des FORMULAIRES, partagés entre client (UX : erreurs
 * immédiates) et serveur (sécurité : la validation serveur fait foi —
 * exigence #7). Bornes alignées sur les DTO `garde` du backend.
 *
 * Module pur, sans dépendance serveur (importé par des composants client).
 */

/** Email : RFC 5321 borne à 320 caractères, comme le backend. */
const emailSchema = z
  .email({ error: "Adresse email invalide." })
  .max(320, { error: "L'adresse email ne peut pas dépasser 320 caractères." });

export const loginSchema = z.object({
  email: emailSchema,
  // Au login on n'impose PAS la longueur minimale d'inscription (un ancien
  // compte pourrait différer) mais on borne contre les entrées géantes.
  password: z
    .string()
    .min(1, { error: "Le mot de passe est requis." })
    .max(128, { error: "Le mot de passe ne peut pas dépasser 128 caractères." }),
});

export type LoginInput = z.infer<typeof loginSchema>;

export const registerSchema = z.object({
  email: emailSchema,
  // Min 12 : aligné sur la politique du backend (au-delà du minimum NIST).
  password: z
    .string()
    .min(12, { error: "Le mot de passe doit faire au moins 12 caractères." })
    .max(128, { error: "Le mot de passe ne peut pas dépasser 128 caractères." }),
  displayName: z
    .string()
    .trim()
    .max(100, { error: "Le nom d'affichage ne peut pas dépasser 100 caractères." })
    // Chaîne vide -> champ omis (le backend rejette Some("")).
    .transform((v) => (v.length === 0 ? undefined : v))
    .optional(),
});

export type RegisterInput = z.infer<typeof registerSchema>;

export const profileSchema = z.object({
  displayName: z
    .string()
    .trim()
    .max(100, { error: "Le nom d'affichage ne peut pas dépasser 100 caractères." })
    // Chaîne vide -> null : efface le nom d'affichage.
    .transform((v) => (v.length === 0 ? null : v)),
});

export type ProfileInput = z.infer<typeof profileSchema>;

/**
 * Requête de recherche. La validation serveur (DTO `garde` du backend) reste
 * l'autorité ; ce schéma offre un retour immédiat côté client et borne
 * l'entrée AVANT tout appel. Bornes alignées sur le backend
 * (`OPENSEARCH_MAX_QUERY_CHARS`, défaut 256).
 */
export const searchSchema = z.object({
  q: z
    .string()
    .trim()
    .min(1, { error: "Saisissez au moins un caractère." })
    .max(256, { error: "La recherche ne peut pas dépasser 256 caractères." }),
});

export type SearchInput = z.infer<typeof searchSchema>;

/**
 * Anti-spam basique des formulaires publics (exigence #7) : champ honeypot
 * invisible pour un humain ; s'il est rempli, c'est un bot. Le backend
 * applique en plus un rate limiting par IP sur /auth/*.
 */
export const HONEYPOT_FIELD = "website";

export function isHoneypotTriggered(formData: FormData): boolean {
  const value = formData.get(HONEYPOT_FIELD);
  return typeof value === "string" && value.length > 0;
}
