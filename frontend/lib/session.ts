import "server-only";

import { getIronSession, type IronSession, type SessionOptions } from "iron-session";
import { cookies } from "next/headers";

import { env } from "./env";

/**
 * Session côté serveur — cœur du pattern BFF (exigences auth #1 et #2).
 *
 * Les tokens émis par l'API Axum (access token JWT + refresh token) ne
 * quittent JAMAIS le serveur Next : ils sont scellés (chiffrés + authentifiés,
 * AES-256-GCM) par iron-session dans un cookie que le navigateur ne peut ni
 * lire ni forger :
 *
 * - `HttpOnly`  : inaccessible au JavaScript client (vol par XSS impossible) ;
 * - `Secure`    : HTTPS uniquement en production ;
 * - `SameSite=Lax` : non envoyé sur les sous-requêtes cross-site (CSRF) —
 *   les mutations sont en plus protégées par la vérification d'Origin
 *   (cf. lib/csrf.ts et SECURITY.md pour le compromis Lax vs Strict) ;
 * - préfixe `__Host-` en production : interdit Domain= et impose Path=/ +
 *   Secure, donc aucun sous-domaine ne peut écraser ce cookie.
 *
 * INTERDICTION ABSOLUE (revue + lint) : aucun token, JWT ou donnée sensible
 * dans localStorage/sessionStorage/cookie lisible en JS.
 */

/** Vue minimale de l'utilisateur embarquée dans la session (pas de hash, rien de sensible). */
export interface SessionUser {
  id: string;
  email: string;
  displayName: string | null;
  role: "user" | "admin";
}

/** Contenu scellé du cookie de session. Tous les champs sont optionnels : une session vide = non authentifié. */
export interface SessionData {
  /** JWT d'accès de l'API Axum (durée courte, ~15 min). */
  accessToken?: string;
  /** Échéance du token d'accès (epoch ms) pour rafraîchir AVANT expiration. */
  accessTokenExpiresAt?: number;
  /** Refresh token opaque de l'API (rotation à chaque refresh côté backend). */
  refreshToken?: string;
  /** Instantané du profil pour l'affichage ; l'autorité reste le backend. */
  user?: SessionUser;
}

export type AppSession = IronSession<SessionData>;

/** Durée de vie du cookie : alignée sur le TTL du refresh token backend (14 j). */
const SESSION_TTL_SECONDS = 14 * 24 * 60 * 60;

export function sessionOptions(): SessionOptions {
  const { SESSION_SECRET, COOKIE_SECURE } = env();
  return {
    password: SESSION_SECRET,
    // Le préfixe __Host- exige Secure : indisponible en dev HTTP local.
    cookieName: COOKIE_SECURE ? "__Host-wsb_session" : "wsb_session",
    ttl: SESSION_TTL_SECONDS,
    cookieOptions: {
      httpOnly: true,
      secure: COOKIE_SECURE,
      sameSite: "lax",
      path: "/",
    },
  };
}

/**
 * Réplique structurelle du type `CookieStore` attendu par iron-session (non
 * exporté par la lib). Sert UNIQUEMENT au cast ci-dessous.
 */
interface IronCookieStore {
  get: (name: string) => { name: string; value: string } | undefined;
  // Couvre les deux surcharges de `set` attendues par iron-session.
  set: (...args: readonly unknown[]) => void;
}

/** Récupère la session de la requête courante (Server Component ou Server Action). */
export async function getSession(): Promise<AppSession> {
  const cookieStore = await cookies();
  // Cast localisé et justifié : sous `exactOptionalPropertyTypes`, la
  // signature de `set()` de Next (ReadonlyRequestCookies) n'est pas
  // ASSIGNABLE au CookieStore attendu par iron-session, alors qu'elle est
  // strictement compatible à l'exécution (même surface d'appel). Aucune
  // donnée n'est réinterprétée par ce cast.
  return getIronSession<SessionData>(
    cookieStore as unknown as IronCookieStore,
    sessionOptions(),
  );
}

/** La session est-elle authentifiée (tokens + profil présents) ? */
export function isAuthenticated(
  session: SessionData,
): session is SessionData & {
  accessToken: string;
  accessTokenExpiresAt: number;
  refreshToken: string;
  user: SessionUser;
} {
  return (
    typeof session.accessToken === "string" &&
    typeof session.accessTokenExpiresAt === "number" &&
    typeof session.refreshToken === "string" &&
    session.user !== undefined
  );
}
