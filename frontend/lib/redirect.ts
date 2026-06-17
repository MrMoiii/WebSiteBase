import type { Route } from "next";

/**
 * Anti open-redirect (exigence sécurité #4).
 *
 * Tout paramètre de redirection (`?next=`) est validé contre une LISTE
 * BLANCHE de chemins internes relatifs. Tout le reste — URL absolue,
 * protocole, `//evil.com` (scheme-relative), backslash, caractères de
 * contrôle, chemin inconnu — retombe sur la destination par défaut.
 *
 * Module pur (testé unitairement, cf. tests/redirect.test.ts).
 */

/** Destination par défaut après authentification. */
export const DEFAULT_AFTER_LOGIN: Route = "/profile";

/**
 * Chemins internes autorisés comme cible de retour post-login.
 * `exact` : correspondance stricte ; `prefix` : le chemin ou un sous-chemin.
 */
const ALLOWED_NEXT: ReadonlyArray<{ path: string; mode: "exact" | "prefix" }> = [
  { path: "/", mode: "exact" },
  { path: "/profile", mode: "exact" },
  { path: "/admin", mode: "prefix" },
];

/**
 * Valide un candidat de redirection post-login.
 * Retourne toujours un chemin interne sûr (jamais d'exception).
 *
 * Type de retour `Route` (typedRoutes) : légitime car la valeur est soit la
 * constante par défaut, soit un chemin accepté par la liste blanche interne.
 */
export function safeNextPath(raw: unknown): Route {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 512) {
    return DEFAULT_AFTER_LOGIN;
  }

  // Chemin relatif interne uniquement : commence par exactement UN '/'.
  // `//host` et `/\host` sont interprétés comme des URL scheme-relative par
  // les navigateurs -> refusés. Un ':' avant tout '/' formerait un schéma,
  // impossible ici puisque le premier caractère est '/'.
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.startsWith("/\\")) {
    return DEFAULT_AFTER_LOGIN;
  }

  // Caractères de contrôle (header splitting, %0d%0a décodés en amont…).
  if (/[\x00-\x1f\x7f]/.test(raw)) {
    return DEFAULT_AFTER_LOGIN;
  }

  // Backslash n'importe où : certains parseurs le traitent comme '/'.
  if (raw.includes("\\")) {
    return DEFAULT_AFTER_LOGIN;
  }

  // Un encodage résiduel de '/' ou '\' pourrait changer de sens après un
  // décodage ultérieur -> refus par prudence.
  if (/%2f|%5c|%00/i.test(raw)) {
    return DEFAULT_AFTER_LOGIN;
  }

  // On ne garde que le chemin (la query/le fragment sont ignorés : aucune
  // page protégée n'en a besoin au retour, et cela évite de réinjecter des
  // paramètres arbitraires).
  const pathOnly = raw.split(/[?#]/, 1)[0] ?? "";

  // Pas de traversée ni de segment vide trompeur.
  const segments = pathOnly.split("/");
  if (segments.some((s) => s === "." || s === "..")) {
    return DEFAULT_AFTER_LOGIN;
  }

  const allowed = ALLOWED_NEXT.some((entry) =>
    entry.mode === "exact"
      ? pathOnly === entry.path
      : pathOnly === entry.path || pathOnly.startsWith(`${entry.path}/`),
  );

  // Cast sûr : `pathOnly` vient d'être validé contre la liste blanche de
  // chemins internes existants (typedRoutes ne sait pas raisonner dessus).
  return allowed ? (pathOnly as Route) : DEFAULT_AFTER_LOGIN;
}
