# Sécurité — Frontend WebSiteBase

Ce document décrit le modèle de menace couvert par le frontend, les contrôles
implémentés (avec leur emplacement dans le code) et les limites connues. Il
complète le [`SECURITY.md` du backend](../backend/SECURITY.md) : le backend
reste **l'autorité finale** pour l'authentification et l'autorisation.

## Modèle de menace

Acteurs et scénarios considérés :

| Menace | Vecteur typique | Couverte par |
|---|---|---|
| Vol de tokens via XSS | Injection de contenu utilisateur, script tiers | Pattern BFF (aucun token côté client), CSP noncée, échappement React, zéro `dangerouslySetInnerHTML` |
| CSRF | Formulaire/fetch cross-site forgé | Cookie `SameSite=Lax`, vérification d'Origin (Next + explicite), mutations en Server Actions uniquement |
| Clickjacking | Iframe hostile | `frame-ancestors 'none'`, `X-Frame-Options: DENY` |
| Open redirect | `?next=` manipulé (phishing) | Liste blanche de chemins internes (`lib/redirect.ts`) |
| Vol/falsification de session | Cookie volé, forgé, rejoué | Cookie chiffré+authentifié (AES-256-GCM), `HttpOnly`, `Secure`, `__Host-`, TTL, rotation du refresh token côté backend |
| Énumération de comptes | Oracles de login/register | Messages génériques, miroir de l'anti-énumération backend |
| Bots / spam | Soumissions automatisées | Honeypot + rate limiting par IP du backend sur `/auth/*` |
| Supply chain | Dépendance compromise, script post-install | Lockfile épinglé, `--ignore-scripts`, audit bloquant en CI, zéro CDN/script tiers, fonts système |
| Fuite d'information | Stack traces, secrets dans le bundle | Pages d'erreur génériques, logs serveur seulement, check CI anti-fuite, validation d'env sans valeurs |
| Backend compromis/bogué | Réponse hors contrat | Validation zod de TOUTES les réponses API (`lib/api-schemas.ts`) |

Hors périmètre (assumé) : compromission du serveur Next lui-même, malware sur
la machine de l'utilisateur, attaques DDoS volumétriques (rôle de
l'infrastructure), TLS (terminé par le reverse proxy, cf. README).

## Architecture d'authentification (BFF)

```
Navigateur ──cookie scellé `__Host-wsb_session` (HttpOnly)──▶ Next.js (serveur)
                                                                │ Bearer <access JWT 15 min>
                                                                │ Cookie refresh_token (rotation)
                                                                ▼
                                                            API Axum
```

- **Aucun token ne touche le JavaScript client** : l'access token JWT et le
  refresh token de l'API sont scellés (chiffrés + authentifiés) par
  iron-session dans un cookie que seul le serveur Next sait lire
  (`lib/session.ts`). Aucune utilisation de `localStorage`/`sessionStorage` —
  vérifié par un test E2E.
- Le serveur Next joue le rôle de « navigateur » vis-à-vis de l'API : il
  capture le `Set-Cookie` du refresh token backend et le rejoue uniquement
  sur `/auth/refresh` et `/auth/logout` (`lib/api.ts`).
- **Refresh transparent** : si l'access token expire (~15 min), le serveur le
  rafraîchit avant l'appel (`lib/auth.ts`) ; le backend effectue une rotation
  (un refresh token rejoué est détecté). Si le refresh échoue, la session
  locale est détruite et l'utilisateur est renvoyé au login avec retour
  post-auth (`?next=` validé).
- **Autorisation en profondeur** : middleware (`proxy.ts`, session descellée,
  vrais statuts 307/404) → layout/page serveur (`requireAuth`, rôle) →
  backend (token + rôle revérifiés **en base** à chaque appel). Le masquage
  d'UI (lien admin caché) n'est jamais considéré comme un contrôle.

## Contrôles implémentés ↔ OWASP Top 10 côté client

### XSS

- **CSP stricte par requête** (`proxy.ts`) : `script-src 'self' 'nonce-…'
  'strict-dynamic'`, `object-src 'none'`, `base-uri 'self'`,
  `form-action 'self'`, `frame-src 'none'`. Nonce de 128 bits regénéré à
  chaque requête, appliqué par Next à toutes ses balises `<script>`.
- **Exceptions documentées** :
  - `style-src 'unsafe-inline'` : React/Next posent des attributs `style`
    inline (hydratation) ; l'injection de style seule n'exécute pas de code,
    et les scripts restent strictement noncés ;
  - `'unsafe-eval'` ajouté en **développement uniquement** (HMR).
- `dangerouslySetInnerHTML` **interdit par lint** (`react/no-danger: error`,
  zéro occurrence — DOMPurify serait requis pour toute exception future).
- Tout contenu utilisateur (nom d'affichage, emails) est rendu via JSX :
  échappement systématique par React. Test E2E avec payload
  `<script>`/`onerror` : rendu littéral, zéro exécution.
- Aucune construction d'URL/HTML par concaténation de données utilisateur :
  chemins d'API constants + `URLSearchParams` (`lib/api.ts`), liens typés
  (`typedRoutes`), `javascript:` URLs interdites par lint.

### Fuite de tokens / données sensibles

- Cookie de session : `HttpOnly`, `Secure` (prod), `SameSite=Lax`, préfixe
  `__Host-` en production (interdit `Domain=`, impose `Path=/` + Secure).
- Aucune variable `NEXT_PUBLIC_*` ; check CI qui greppe le bundle client
  (`scripts/check-bundle-secrets.sh`) : noms ET valeurs des variables
  serveur, échec du build en cas de fuite.
- Pas de données sensibles dans les URLs (les identifiants viennent de la
  session, jamais de paramètres) ni dans les logs client (les pages d'erreur
  n'affichent qu'un `digest` opaque ; `console.error` volontairement omis).
- Erreurs : détail complet loggé côté serveur en JSON avec **correlation id**
  propagé à l'API via `X-Request-Id` (généré par requête dans `proxy.ts`,
  jamais accepté du client) ; le client ne voit que des messages génériques.

### CSRF

- Mutations **uniquement** via Server Actions (POST) — aucun Route Handler de
  mutation, donc pas de surface pour un double-submit oublié.
- Trois couches : `SameSite=Lax` (pas de session sur les sous-requêtes
  cross-site), vérification d'Origin native de Next
  (`serverActions.allowedOrigins`), et vérification d'Origin **explicite** en
  tête de chaque action (`lib/csrf.ts` — auditable, testable, résiste à une
  mauvaise configuration).
- **Compromis documenté (Lax vs Strict)** : la spécification permet `Strict`
  pour les actions sensibles. `Strict` casserait l'arrivée authentifiée par
  lien externe (session invisible sur la première navigation) pour un gain
  marginal : `Lax` bloque déjà l'envoi du cookie sur les POST cross-site, et
  les seules mutations de l'application (login, logout, profil) sont toutes
  doublement protégées par la vérification d'Origin. Le cookie refresh du
  backend, lui, est bien `SameSite=Strict` (et n'est jamais vu du navigateur).

### Clickjacking

- `frame-ancestors 'none'` (CSP) + `X-Frame-Options: DENY` (vieux
  navigateurs). Aucun iframe dans l'application (`frame-src 'none'`).

### Open redirect

- `lib/redirect.ts` : tout `?next=` est validé contre une **liste blanche**
  de chemins internes (`/`, `/profile`, `/admin/*`). Rejetés : URL absolues,
  `//hôte`, backslashes, encodages `%2F`/`%5C`/`%00`, caractères de contrôle,
  traversée `..`, longueur > 512. Couvert par tests unitaires ET E2E.

### Supply chain

- Versions épinglées + lockfile ; `npm ci --ignore-scripts` (CI et Docker) ;
  `npm audit --audit-level=high` bloquant ; override npm pour `postcss`
  (GHSA-qx2v-qp2m-jg93) — **zéro vulnérabilité connue** à la date du commit.
- Zéro script tiers, zéro CDN, fonts système (`font-src 'self'`),
  `connect-src 'self'` : le navigateur ne contacte que l'origine du site.
- ESLint inclut `eslint-plugin-security` ; CI à zéro warning.

### Autres en-têtes / durcissements

- `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.
- `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`,
  `Permissions-Policy` minimale (caméra, micro, géoloc, paiement, USB
  désactivés), `Cross-Origin-Opener-Policy: same-origin`,
  `Cross-Origin-Resource-Policy: same-origin`, `X-Powered-By` supprimé.
- `next/image` : liste blanche de domaines distants **vide** (aucune image
  distante autorisée).
- Validation d'environnement zod **fail-fast** au démarrage
  (`instrumentation.ts`), messages d'erreur sans valeurs.
- Formulaires : validation zod client (UX) + serveur (sécurité), bornes de
  longueur alignées sur le backend, honeypot sur les formulaires publics ;
  limite de taille des corps de Server Actions (1 Mo, aligné backend).
- Conteneur : multi-stage, non-root, lecture seule (tmpfs `/tmp` et cache),
  `cap_drop: ALL`, `no-new-privileges`, healthcheck sans shell réseau.
- Uploads : sans objet (aucun upload dans le périmètre). Toute évolution
  devra appliquer l'exigence dédiée (magic bytes, taille, renommage, domaine
  de service séparé).

## Limites connues

1. **Fenêtre de révocation (~15 min)** : un rôle retiré ou un compte
   désactivé reste effectif jusqu'à expiration de l'access token (pas de
   liste de révocation des JWT côté backend). Atténué par le TTL court et la
   revérification du rôle en base sur les endpoints admin.
2. **Le rôle scellé en session peut être en retard** sur la base (instantané
   au login/refresh). Conséquence maximale : un ex-admin voit la coquille de
   la page admin jusqu'au prochain refresh — les **données** sont refusées
   par le backend (403, converti en 404 générique).
3. **`style-src 'unsafe-inline'`** : exception assumée (voir XSS). Une
   injection de CSS reste possible en théorie si un autre contrôle cédait ;
   elle n'exécute pas de script.
4. **Pas de rate limiting applicatif côté frontend** : l'anti-bruteforce
   repose sur le backend (rate limit IP + verrouillage de compte) et le
   honeypot. Un rate limit au niveau du reverse proxy reste recommandé.
5. **Sessions côté cookie uniquement** : pas de révocation serveur des
   sessions Next (le scellé est autoporté). La révocation effective passe par
   celle du refresh token backend + l'expiration de l'access token.
6. **Logout best effort** : si l'API est injoignable au logout, la session
   locale est détruite mais le refresh token backend reste actif jusqu'à son
   TTL (événement loggé).

## Signalement

Toute vulnérabilité supposée peut être signalée via une issue privée du
dépôt. Ne publiez pas de PoC public avant correction.
