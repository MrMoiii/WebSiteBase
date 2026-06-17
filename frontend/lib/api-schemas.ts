import { z } from "zod";

/**
 * Schémas zod des RÉPONSES de l'API Axum (exigence : valider toute donnée
 * entrante, y compris celle du backend — on ne lui fait pas confiance non
 * plus : un backend compromis ou bogué ne doit pas pouvoir injecter des
 * structures inattendues dans le rendu).
 *
 * Module pur (sans `server-only`) pour être testable unitairement ; il n'est
 * importé que par du code serveur.
 */

/** Profil utilisateur tel que sérialisé par le backend (snake_case). */
export const userProfileSchema = z.object({
  id: z.uuid(),
  email: z.string().max(320),
  display_name: z.string().max(100).nullable(),
  role: z.enum(["user", "admin"]),
  created_at: z.string(),
  updated_at: z.string(),
});

export type ApiUserProfile = z.infer<typeof userProfileSchema>;

/** Réponse de /auth/register, /auth/login, /auth/refresh. */
export const authResponseSchema = z.object({
  access_token: z.string().min(1),
  token_type: z.literal("Bearer"),
  expires_in: z.number().int().positive(),
  user: userProfileSchema,
});

export type ApiAuthResponse = z.infer<typeof authResponseSchema>;

/** Enveloppe paginée de GET /admin/users. */
export const paginatedUsersSchema = z.object({
  items: z.array(userProfileSchema),
  page: z.number().int().min(1),
  page_size: z.number().int().min(1).max(100),
  total: z.number().int().min(0),
});

export type ApiPaginatedUsers = z.infer<typeof paginatedUsersSchema>;

/**
 * Un résultat de recherche tel que sérialisé par le backend : `id` + `score`
 * puis les champs `_source` CONSULTABLES (aplatis). Les champs varient selon le
 * rôle (un admin voit `body`), donc ils sont optionnels. Tout champ inattendu
 * est ignoré (`.strip()` par défaut) : le backend a déjà restreint la sortie.
 */
export const searchHitSchema = z.object({
  id: z.string().max(512),
  score: z.number().nullable(),
  title: z.string().max(1024).optional(),
  tags: z.array(z.string().max(256)).max(64).optional(),
  // `created_at` est un timestamp Unix (secondes) renvoyé par le backend.
  created_at: z.number().int().optional(),
  body: z.string().optional(),
});

export type ApiSearchHit = z.infer<typeof searchHitSchema>;

/** Enveloppe paginée de GET /search. */
export const searchResultsSchema = z.object({
  items: z.array(searchHitSchema),
  total: z.number().int().min(0),
  page: z.number().int().min(1),
  page_size: z.number().int().min(1),
});

export type ApiSearchResults = z.infer<typeof searchResultsSchema>;

/** Format d'erreur générique du backend : {"error":{"code","message"}}. */
export const apiErrorBodySchema = z.object({
  error: z.object({
    code: z.string(),
    message: z.string(),
  }),
});

/**
 * Extrait la valeur du cookie `refresh_token` posé par le backend dans ses
 * en-têtes Set-Cookie. Le BFF est le « navigateur » de l'API : il capture ce
 * cookie et le scelle dans la session iron-session — il n'est jamais relayé
 * au vrai navigateur.
 *
 * Retourne `undefined` si absent ou s'il s'agit du cookie de suppression
 * (valeur vide émise au logout).
 */
export function refreshTokenFromSetCookie(
  setCookieHeaders: readonly string[],
): string | undefined {
  for (const header of setCookieHeaders) {
    const [pair] = header.split(";", 1);
    if (!pair) continue;
    const eq = pair.indexOf("=");
    if (eq === -1) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    if (name === "refresh_token" && value.length > 0) {
      return value;
    }
  }
  return undefined;
}
