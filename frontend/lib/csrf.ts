import "server-only";

import { headers } from "next/headers";

import { env } from "./env";
import { logger } from "./logger";

/**
 * Anti-CSRF des mutations (exigence auth #3).
 *
 * Défense en profondeur, trois couches indépendantes :
 *  1. cookie de session `SameSite=Lax` : non envoyé sur les sous-requêtes
 *     cross-site (les POST cross-origin n'ont pas de session) ;
 *  2. vérification d'Origin intégrée aux Server Actions de Next.js
 *     (Origin doit correspondre à Host, ou à `serverActions.allowedOrigins`) ;
 *  3. CETTE vérification explicite, appelée au début de chaque Server Action
 *     de mutation : elle reste effective même si la couche 2 évoluait ou
 *     était mal configurée, et elle est auditable/testable.
 *
 * Toutes les mutations passent par des Server Actions — il n'existe aucun
 * Route Handler de mutation, donc pas besoin de token double-submit.
 */

class CsrfError extends Error {
  constructor() {
    super("Vérification d'origine échouée.");
    this.name = "CsrfError";
  }
}

/** Hôtes publics supplémentaires autorisés (déploiement derrière proxy). */
function allowedOriginHosts(): ReadonlySet<string> {
  return new Set(
    env()
      .APP_ALLOWED_ORIGINS.split(",")
      .map((o) => o.trim().toLowerCase())
      .filter((o) => o.length > 0),
  );
}

/**
 * Lève une erreur si l'en-tête Origin de la requête courante ne correspond
 * ni à l'hôte servi ni à la liste blanche. Un Origin ABSENT est refusé :
 * tous les navigateurs actuels l'envoient sur les POST.
 */
export async function assertSameOrigin(): Promise<void> {
  const h = await headers();
  const origin = h.get("origin");
  // Derrière le reverse proxy documenté (README), X-Forwarded-Host porte
  // l'hôte public ; sinon Host fait foi.
  const host = h.get("x-forwarded-host") ?? h.get("host");

  if (origin === null || host === null) {
    logger.warn("mutation sans en-tête Origin/Host — rejetée", {});
    throw new CsrfError();
  }

  let originHost: string;
  try {
    originHost = new URL(origin).host.toLowerCase();
  } catch {
    logger.warn("en-tête Origin malformé — mutation rejetée", {});
    throw new CsrfError();
  }

  const expected = host.toLowerCase();
  if (originHost === expected || allowedOriginHosts().has(originHost)) {
    return;
  }

  // On ne log pas l'Origin complet (donnée non fiable) — uniquement l'alerte.
  logger.warn("origine inattendue sur une mutation — rejetée", {});
  throw new CsrfError();
}
