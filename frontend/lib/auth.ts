import "server-only";

import type { Route } from "next";
import { headers } from "next/headers";
import { redirect } from "next/navigation";

import { apiRefresh, type AuthSuccess } from "./api";
import { logger } from "./logger";
import {
  getSession,
  isAuthenticated,
  type AppSession,
  type SessionUser,
} from "./session";

/**
 * Orchestration de l'authentification côté serveur (pattern BFF).
 *
 * Toutes les décisions d'autorisation se prennent ICI, côté serveur — le
 * masquage d'UI côté client n'est jamais un contrôle de sécurité (exigence
 * auth #4). Et l'autorité FINALE reste le backend : même si une session
 * locale prétendait un rôle admin, l'API revérifie le rôle en base à chaque
 * appel.
 */

/** Correlation id de la requête courante (posé par le middleware). */
export async function currentRequestId(): Promise<string> {
  const h = await headers();
  return h.get("x-request-id") ?? crypto.randomUUID();
}

/** Marge avant expiration : on rafraîchit 30 s avant l'échéance réelle. */
const REFRESH_SKEW_MS = 30_000;

/** Scelle le résultat d'un login/register/refresh dans la session. */
export async function establishSession(
  session: AppSession,
  result: AuthSuccess,
): Promise<void> {
  const { auth, refreshToken } = result;
  session.accessToken = auth.access_token;
  session.accessTokenExpiresAt = Date.now() + auth.expires_in * 1000;
  session.refreshToken = refreshToken;
  session.user = {
    id: auth.user.id,
    email: auth.user.email,
    displayName: auth.user.display_name,
    role: auth.user.role,
  };
  await session.save();
}

export interface AuthenticatedContext {
  session: AppSession;
  user: SessionUser;
  accessToken: string;
  requestId: string;
}

/**
 * Retourne un contexte authentifié avec un access token VALIDE, en le
 * rafraîchissant si nécessaire (rotation du refresh token comprise).
 * Retourne `null` si la session est absente, invalide ou expirée — la
 * session locale est alors détruite (rien d'utilisable ne doit traîner).
 */
export async function getAuthContext(): Promise<AuthenticatedContext | null> {
  const session = await getSession();
  const requestId = await currentRequestId();

  if (!isAuthenticated(session)) {
    return null;
  }

  if (session.accessTokenExpiresAt - REFRESH_SKEW_MS > Date.now()) {
    return {
      session,
      user: session.user,
      accessToken: session.accessToken,
      requestId,
    };
  }

  // Access token expiré (ou presque) : tentative de refresh transparent.
  try {
    const refreshed = await apiRefresh(session.refreshToken, requestId);
    await establishSession(session, refreshed);
    return {
      session,
      user: session.user as SessionUser,
      accessToken: refreshed.auth.access_token,
      requestId,
    };
  } catch {
    // Refresh refusé (révoqué, expiré, rejoué) : session terminée. On NE
    // log pas le token ; l'API a déjà tracé l'événement de sécurité.
    logger.warn("refresh de session refusé, session détruite", { requestId });
    session.destroy();
    return null;
  }
}

/** Construit l'URL de login avec retour post-auth (chemin interne uniquement). */
export function loginRedirectUrl(nextPath: string, expired: boolean): Route {
  const params = new URLSearchParams({ next: nextPath });
  if (expired) {
    params.set("reason", "expired");
  }
  // Cast sûr (typedRoutes) : chemin constant /login + query encodée par
  // URLSearchParams ; `next` sera revalidé par la liste blanche au login.
  return `/login?${params.toString()}` as Route;
}

/**
 * Exige une session authentifiée pour rendre une page protégée.
 * Redirige vers /login avec retour post-auth sinon (exigence périmètre :
 * sessions expirées gérées proprement).
 */
export async function requireAuth(nextPath: string): Promise<AuthenticatedContext> {
  const session = await getSession();
  const hadSession = isAuthenticated(session);
  const ctx = await getAuthContext();
  if (ctx === null) {
    // `hadSession` distingue « jamais connecté » de « session expirée ».
    redirect(loginRedirectUrl(nextPath, hadSession));
  }
  return ctx;
}
