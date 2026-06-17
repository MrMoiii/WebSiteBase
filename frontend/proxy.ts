import { unsealData } from "iron-session";
import { NextResponse, type NextRequest } from "next/server";

import { env } from "@/lib/env";
import type { SessionData } from "@/lib/session";

/**
 * Middleware de sécurité — première ligne de défense, exécuté sur chaque
 * requête de page (exigences sécurité #1, #2 et protection de routes).
 *
 * NOTE livrable : la spécification demandait `middleware.ts`. Next.js 16 a
 * RENOMMÉ cette convention en `proxy.ts` (middleware.ts est déprécié et sera
 * retiré) — même rôle, même API, seul le nom de fichier et l'export changent.
 *
 * 1. Génère un nonce CSP unique par requête (128 bits d'aléa) ;
 * 2. Pose la CSP stricte et les en-têtes de sécurité ;
 * 3. Propage un correlation id (`x-request-id`) vers les logs et l'API ;
 * 4. Protège les routes : la session est DESCELLÉE ici (authentifiée par
 *    AES-256-GCM, donc infalsifiable) AVANT que le streaming de la page ne
 *    commence — c'est ce qui permet de renvoyer de vrais statuts 307/404.
 *    Les layouts/pages revérifient ensuite (refresh des tokens compris) et
 *    le backend revérifie rôle + token à chaque appel : le middleware n'est
 *    qu'un rideau, jamais l'autorité finale.
 */

/** Chemins exigeant une session. Doit rester cohérent avec les layouts. */
const PROTECTED_PREFIXES = ["/profile", "/admin", "/search"] as const;

/**
 * Noms possibles du cookie de session (cf. lib/session.ts) : le préfixe
 * `__Host-` (production HTTPS) impose Secure + Path=/ + pas de Domain,
 * empêchant l'écrasement du cookie par un sous-domaine compromis.
 */
const SESSION_COOKIE_NAMES = ["__Host-wsb_session", "wsb_session"] as const;

/** Doit rester aligné sur lib/session.ts (TTL du cookie scellé). */
const SESSION_TTL_SECONDS = 14 * 24 * 60 * 60;

function buildCsp(nonce: string, isDev: boolean): string {
  const directives = [
    `default-src 'self'`,
    // Scripts : uniquement même origine + nonce par requête. 'strict-dynamic'
    // autorise les scripts chargés PAR un script noncé (chunks Next.js) tout
    // en ignorant les listes d'hôtes — recommandation CSP3 / Next.js.
    // EXCEPTION DOCUMENTÉE : 'unsafe-eval' est ajouté UNIQUEMENT en
    // développement (HMR/React Refresh de Next l'exige). Jamais en production.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    // EXCEPTION DOCUMENTÉE : 'unsafe-inline' pour les STYLES uniquement.
    // React/Next posent des attributs `style` inline (hydratation, next/image)
    // que CSP3 couvre via style-src-attr ; les bloquer casse le rendu sans
    // bénéfice notable, l'injection de style seule n'exécutant pas de script.
    // Les scripts, eux, restent strictement noncés (pas de unsafe-inline).
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self'`,
    `font-src 'self'`, // fonts auto-hébergées uniquement (exigence #9)
    `connect-src 'self'`, // le client ne parle qu'au BFF, jamais à l'API Axum
    `object-src 'none'`,
    `base-uri 'self'`,
    `form-action 'self'`,
    `frame-ancestors 'none'`, // anti-clickjacking
    `frame-src 'none'`, // pas d'iframe (exigence #11)
  ];
  if (!isDev) {
    directives.push(`upgrade-insecure-requests`);
  }
  return directives.join("; ");
}

/**
 * Descelle la session depuis le cookie (lecture seule). Retourne `null` si
 * absente, falsifiée ou expirée — le scellé iron-session est chiffré ET
 * authentifié : un cookie forgé échoue ici, quoi qu'il contienne.
 */
async function readSession(request: NextRequest): Promise<SessionData | null> {
  const raw = SESSION_COOKIE_NAMES.map(
    (name) => request.cookies.get(name)?.value,
  ).find((v) => typeof v === "string" && v.length > 0);
  if (raw === undefined) {
    return null;
  }
  try {
    return await unsealData<SessionData>(raw, {
      password: env().SESSION_SECRET,
      ttl: SESSION_TTL_SECONDS,
    });
  } catch {
    // Cookie corrompu/forgé : traité comme non authentifié.
    return null;
  }
}

export default async function proxy(request: NextRequest): Promise<NextResponse> {
  // 128 bits d'aléa cryptographique par requête, encodés en base64.
  const nonceBytes = new Uint8Array(16);
  crypto.getRandomValues(nonceBytes);
  const nonce = Buffer.from(nonceBytes).toString("base64");

  // Correlation id : généré ici, propagé aux logs serveur et à l'API Axum
  // via l'en-tête X-Request-Id (exigence #6). On n'accepte PAS un id fourni
  // par le client (risque de pollution des logs) : il est toujours regénéré.
  const requestId = crypto.randomUUID();

  const isDev = process.env.NODE_ENV === "development";
  const csp = buildCsp(nonce, isDev);

  const { pathname } = request.nextUrl;

  // --- Protection de routes (premier rideau) -----------------------------
  // Les POST de Server Actions (en-tête Next-Action) ne sont PAS redirigés
  // ici : le routeur client ne sait interpréter qu'une redirection émise par
  // l'action elle-même via redirect() — une 307 brute du middleware laisserait
  // la page figée. Sans risque : chaque action revérifie la session côté
  // serveur (getAuthContext) et redirige proprement (reason=expired), et le
  // backend revérifie le token à chaque appel.
  const isServerActionPost =
    request.method === "POST" && request.headers.has("next-action");
  const isProtected = PROTECTED_PREFIXES.some(
    (p) => pathname === p || pathname.startsWith(`${p}/`),
  );
  if (isProtected && !isServerActionPost) {
    const session = await readSession(request);

    if (session?.user === undefined) {
      const loginUrl = new URL("/login", request.url);
      // `next` ne contient qu'un chemin interne ; il sera revalidé contre la
      // liste blanche au moment du login (lib/redirect.ts, anti open-redirect).
      loginUrl.searchParams.set("next", pathname);
      const redirect = NextResponse.redirect(loginUrl);
      applySecurityHeaders(redirect, csp, requestId, isDev);
      return redirect;
    }

    // Zone admin : 404 générique AVANT tout rendu pour un non-admin — on ne
    // révèle pas l'existence de la zone (statut réel, pas seulement l'UI).
    // La réécriture vise un chemin inexistant : Next rend app/not-found.tsx
    // avec un statut 404. Le rôle scellé peut être en retard sur la base ;
    // l'autorité reste le backend (403 -> notFound aussi côté page).
    if (
      (pathname === "/admin" || pathname.startsWith("/admin/")) &&
      session.user.role !== "admin"
    ) {
      const rewrite = NextResponse.rewrite(
        new URL("/__not-found__", request.url),
      );
      applySecurityHeaders(rewrite, csp, requestId, isDev);
      return rewrite;
    }
  }

  // Transmet nonce + request id aux Server Components via les en-têtes de
  // requête. Next.js détecte aussi le nonce dans la CSP de la requête et
  // l'applique automatiquement à ses propres balises <script>.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("x-request-id", requestId);
  requestHeaders.set("content-security-policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  applySecurityHeaders(response, csp, requestId, isDev);
  return response;
}

function applySecurityHeaders(
  response: NextResponse,
  csp: string,
  requestId: string,
  isDev: boolean,
): void {
  response.headers.set("Content-Security-Policy", csp);
  // HSTS avec preload (exigence #2). Émis aussi par le backend ; le reverse
  // proxy TLS doit le laisser passer. Sans effet en HTTP de dev.
  if (!isDev) {
    response.headers.set(
      "Strict-Transport-Security",
      "max-age=63072000; includeSubDomains; preload",
    );
  }
  response.headers.set("X-Content-Type-Options", "nosniff");
  response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  // Permissions minimales : aucune API capteur n'est utilisée (exigence #2).
  response.headers.set(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  );
  // Redondant avec frame-ancestors pour les vieux navigateurs.
  response.headers.set("X-Frame-Options", "DENY");
  // Isolation des fenêtres ouvertes (limite les attaques cross-window).
  response.headers.set("Cross-Origin-Opener-Policy", "same-origin");
  response.headers.set("Cross-Origin-Resource-Policy", "same-origin");
  // Correlation id renvoyé au client : seule référence à donner au support,
  // aucun détail interne ne sort (exigence #6).
  response.headers.set("X-Request-Id", requestId);
}

export const config = {
  // Tout sauf les assets statiques immuables (qui ne portent pas de HTML et
  // recevront leurs en-têtes du CDN/proxy) — la CSP s'applique à chaque page.
  matcher: [
    "/((?!_next/static|_next/image|favicon.ico|icon.svg|robots.txt).*)",
  ],
};
