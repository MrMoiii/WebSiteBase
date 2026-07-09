# Modèle de sécurité — Backend WebSiteBase

Ce document résume le **modèle de menace** couvert, les **contrôles
implémentés** (mappés sur l'OWASP API Security Top 10:2023) et les **limites
connues**. Il complète le code, qui est commenté aux endroits sensibles.

## Périmètre & hypothèses

- API REST JSON de gestion d'utilisateurs (inscription, login, refresh, logout,
  profil, rôles `user`/`admin`, listing admin paginé).
- **Terminaison TLS hors scope** : assurée par un reverse proxy en frontal. Le
  binaire écoute en HTTP sur un port non privilégié et fait confiance aux
  en-têtes `X-Forwarded-*` du proxy, dans la limite de `APP_TRUSTED_PROXY_HOPS`.
- Base de données et secrets considérés comme des actifs protégés ; un attaquant
  peut tenter d'accéder à l'API depuis le réseau, et un utilisateur authentifié
  peut être malveillant (abus de privilèges, IDOR).

## Acteurs de la menace

| Acteur | Capacités supposées |
|---|---|
| Anonyme réseau | Envoi de requêtes arbitraires, payloads malformés, bruteforce, énumération. |
| Utilisateur authentifié | Tente l'accès à des ressources d'autrui (IDOR) ou des endpoints admin. |
| Vol de jeton | Récupère un token d'accès (XSS, fuite log) ou un refresh token. |
| Compromission DB / Redis en lecture | Accède au contenu des tables (hashes) ou au store de sessions Redis (empreintes SHA-256 des refresh tokens). |

## Contrôles implémentés (mapping OWASP API Security Top 10:2023)

### API1 — Broken Object Level Authorization (IDOR)
- Les endpoints de profil (`/users/me`) dérivent **toujours** l'identifiant du
  **token authentifié**, jamais d'un paramètre client. Pas d'accès par id arbitraire.
- Test d'intégration dédié (`register_then_read_own_profile`, accès admin refusé).

### API2 — Broken Authentication
- Mots de passe hachés avec **Argon2id** (m=19 MiB, t=2, p=1, OWASP).
- **JWT d'accès courts** (15 min, HS256) : signature, expiration, émetteur et
  **type** (`typ=access`) vérifiés ; rejet générique (401) sinon. Chaque token
  porte un `sid` (identifiant de session).
- **Sessions Redis (source de vérité)** : les refresh tokens (valeur aléatoire
  256 bits, **stockée hachée** SHA-256) et l'état de session vivent dans **Redis**,
  avec **rotation atomique** (`GETDEL` : un seul appelant gagne, un rejeu ou une
  requête concurrente obtient `nil` ⇒ 401), TTL glissant (idle) + plafond absolu.
  Cf. [`SESSIONS.md`](./SESSIONS.md).
- **Révocation immédiate des tokens d'accès** : le `sid` est revérifié dans Redis
  à **chaque** requête authentifiée ; un logout, une révocation ciblée ou une
  « déconnexion des autres appareils » invalide le token d'accès **sans attendre
  son expiration**.
- **Anti-bruteforce distribué** : verrouillage de compte après N échecs + **rate
  limiting par IP**, tous deux portés par **Redis** (cohérents entre instances),
  en complément du `tower_governor` en mémoire (première ligne anti-rafale) sur
  `/auth/*`. Les compteurs `INCR`+`EXPIRE` sont posés atomiquement (`MULTI`) pour
  qu'une clé ne puisse jamais rester sans TTL (pas de verrouillage permanent).
- **Anti-énumération** : login renvoie une 401 générique et exécute une
  vérification factice pour égaliser le temps de réponse (utilisateur inexistant
  vs mauvais mot de passe indiscernables).

### API3 — Broken Object Property Level Authorization
- DTO d'entrée stricts avec `#[serde(deny_unknown_fields)]` : impossible
  d'injecter un champ non prévu (ex. `role`) via le body (mass assignment).
- Vues de sortie dédiées (`UserProfile`) : le `password_hash` et les compteurs
  internes ne sont **jamais** sérialisés vers le client.

### API4 — Unrestricted Resource Consumption
- **Limite de taille de corps** globale (1 Mo, configurable) → 413.
- **Timeout** par requête (15 s) → 408.
- **Pagination bornée** (`page_size` ≤ 100) sur le listing admin.
- **Rate limiting** par IP sur les endpoints sensibles : `tower_governor` en
  mémoire (par instance) **+** compteur distribué Redis (cohérent multi-instances).
- Longueur des mots de passe bornée (anti-DoS de hachage Argon2).
- Pool de connexions DB borné.

### API5 — Broken Function Level Authorization
- L'autorisation est vérifiée **au niveau du handler** via les extracteurs
  `AuthUser` / `AdminUser`, **pas seulement au routage**.
- `AuthUser` vérifie en plus que la **session est active dans Redis** (le `sid`
  porté par le token) : une session révoquée bloque l'accès immédiatement.
- `AdminUser` **recharge le rôle courant en base** : un changement de privilège
  ou une suppression de compte prend effet immédiatement (sans attendre
  l'expiration du token). Test : accès admin par un non-admin → 403.

### API6 — Unrestricted Access to Sensitive Business Flows
- Rate limiting + verrouillage de compte sur les flux d'auth.
- (Limite connue : pas de CAPTCHA ni de détection comportementale avancée.)

### API7 — Server Side Request Forgery
- L'API n'effectue **aucune requête sortante** pilotée par l'entrée utilisateur.

### API8 — Security Misconfiguration
- **En-têtes de sécurité** sur toutes les réponses : `Strict-Transport-Security`,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Content-Security-
  Policy` restrictive (`default-src 'none'`), `Referrer-Policy: no-referrer`,
  `Cross-Origin-Resource-Policy`, `Permissions-Policy`.
- **CORS** : liste blanche explicite d'origines, **jamais** de wildcard avec
  credentials.
- **Cookies** : `HttpOnly`, `Secure` (prod), `SameSite=Strict`, `Path` restreint
  → protège du vol XSS et du CSRF.
- **Gestion d'erreurs sans fuite** : type d'erreur central (`thiserror`) mappé
  vers des réponses génériques ; le détail (SQL, panique) est **loggé** côté
  serveur avec le correlation id, **jamais** renvoyé.
- **Panics** converties en 500 génériques (`CatchPanic`).
- Conteneur **distroless non-root**, filesystem **read-only**, capabilities
  retirées, `no-new-privileges`.
- **Moindre privilège DB** : le rôle runtime n'a que des droits DML (aucun DDL).

### API9 — Improper Inventory Management
- Versionnement d'API par préfixe `/api/v1`. Endpoints documentés (README).

### API10 — Unsafe Consumption of APIs
- Pas de consommation d'API tierce non fiable dans ce périmètre.

## Autres contrôles transverses

- **Zéro `unsafe`** : `#![forbid(unsafe_code)]` à la racine de la lib et du binaire.
- **Injection SQL impossible** par construction : 100 % des requêtes passent par
  `sqlx::query!`/`query_as!` (paramètres liés, vérifiés à la compilation contre
  le schéma réel). Aucun SQL concaténé.
- **Secrets via variables d'environnement** uniquement ; échec au démarrage si un
  secret obligatoire manque ; le type `Secret` empêche le log accidentel.
- **Logs SOC** : événements de sécurité structurés en JSON (login réussi/échoué,
  lockout, refus 401/403/429, refresh invalide, accès admin refusé) avec
  timestamp, IP source, user agent, user id et correlation id — **sans** secret,
  token ni mot de passe. En-têtes `Authorization`/`Cookie` marqués sensibles
  (non loggés).
- **Pas de donnée sensible dans les URLs** : les jetons transitent par en-tête
  (`Authorization`) ou cookie, jamais en query string.
- **Chaîne d'approvisionnement** : `Cargo.lock` committé ; **`cargo-deny`** comme
  autorité d'audit (advisories RustSec + licences + sources) car il raisonne sur
  le graphe de features **réellement résolu** (contrairement à `cargo audit`, qui
  lit le Cargo.lock brut) ; `clippy -D warnings` ; `fmt --check` — le tout en CI.
- **Validation par `garde`** (et non `validator`) : choix délibéré pour éviter la
  dépendance de compilation `proc-macro-error2`, non maintenue (RUSTSEC-2026-0173).

## Limites connues / travaux futurs

- **JWT HS256 (secret symétrique)** : choisi pour la simplicité. Pour une
  architecture multi-services, privilégier **RS256/EdDSA** (clé publique
  distribuable) ou la **délégation OIDC à un IdP externe** (recommandé par
  l'énoncé) — non implémenté ici par souci de périmètre.
- **Dépendance à Redis (disponibilité)** : le store de sessions Redis est
  désormais **indispensable à l'authentification** (source de vérité). Une
  indisponibilité renvoie `503` sur les requêtes authentifiées (le client peut
  réessayer) plutôt qu'un comportement dégradé — arbitrage cohérence > continuité
  assumé. Prévoir Redis en HA (`rediss://`, réplication) en production.
- **CSRF** : la protection repose sur `SameSite=Strict` + l'usage du Bearer pour
  les mutations. Si des mutations basées cookie étaient ajoutées, prévoir un
  jeton anti-CSRF explicite (double-submit / synchronizer token).
- **Vérification d'email / MFA / reset password** : hors périmètre de cette
  itération.
- **Rotation/expiration des secrets** et **chiffrement au repos** de la base :
  délégués à l'infrastructure (gestionnaire de secrets, TDE/volume chiffré).
- **`rsa` / RUSTSEC-2023-0071 (faux positif lockfile)** : la crate `rsa` figure
  dans `Cargo.lock` car le driver MySQL **optionnel** de sqlx y est listé (le
  lockfile est un sur-ensemble), mais elle n'est **jamais compilée** (PostgreSQL
  uniquement — vérifié : aucun artefact `rsa`/`sqlx-mysql` dans `target/`).
  `cargo audit` (Cargo.lock brut) comme `cargo auditable` (graphe résolu complet)
  la remonteraient à tort ; on s'appuie donc sur **`cargo deny`**, qui raisonne
  sur le graphe de features réel et ne la signale pas — **sans aucun `--ignore`**.
  À surveiller : si le driver MySQL devenait nécessaire, réévaluer le risque
  (l'attaque exige la mesure du timing de déchiffrement RSA sur le canal d'auth
  DB, réseau interne).

## Signalement de vulnérabilité

Contact sécurité : voir la politique du dépôt. Merci de ne pas divulguer
publiquement avant correction.
