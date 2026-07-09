# Sessions & cookies — store Redis

Redis est la **source de vérité** des sessions utilisateur (refresh tokens),
en remplacement de la table PostgreSQL `refresh_tokens`. PostgreSQL reste la
source de vérité des **utilisateurs** ; les sessions, elles, sont volatiles,
reconstructibles (une re-authentification suffit) et bénéficient du TTL natif
de Redis.

> Migration : la table `refresh_tokens` et les colonnes `failed_login_attempts`
> / `locked_until` de `users` (devenues inutiles, le flux de session et le
> verrouillage étant dans Redis) ont été **retirées** par la migration
> `20260709000001_drop_legacy_sessions.sql`, et le cache `.sqlx` régénéré en
> conséquence. PostgreSQL ne conserve donc plus aucune donnée de session.

## Sommaire

1. [Architecture](#1-architecture)
2. [Modèle de données Redis](#2-modèle-de-données-redis)
3. [Cycle de vie d'une session](#3-cycle-de-vie-dune-session)
4. [Révocation immédiate des access tokens](#4-révocation-immédiate-des-access-tokens)
5. [Gestion des sessions actives (endpoints)](#5-gestion-des-sessions-actives-endpoints)
6. [Cookies](#6-cookies)
7. [Verrouillage & rate limiting distribués](#7-verrouillage--rate-limiting-distribués)
8. [Configuration](#8-configuration)
9. [Sécurité & disponibilité](#9-sécurité--disponibilité)
10. [Tests](#10-tests)

---

## 1. Architecture

```
handlers::auth / middleware::auth / handlers::sessions
     │
     ▼
session::SessionStore   (create / rotate / logout / list / revoke, lockout, rate limit)
     │
     ▼
Redis  (connection-manager multiplexée ; jamais exposé au frontend)
```

- **Access token** : JWT HS256 court (~15 min), désormais porteur d'un `sid`
  (identifiant de session). Sans état par lui-même, mais **lié** à une session.
- **Session** (`sid`) : entité STABLE dans Redis, qui survit aux rotations de
  refresh token. C'est elle qu'on liste et révoque.
- **Refresh token** : valeur opaque 256 bits ; Redis n'en stocke que
  l'empreinte SHA-256 (comme avant). Il pointe vers un `sid` et **tourne** à
  chaque rafraîchissement.

## 2. Modèle de données Redis

| Clé | Type | Contenu | TTL |
|---|---|---|---|
| `sess:{sid}` | HASH | `user_id, created_at, last_seen, ua, ip, rth` | idle (glissant) |
| `rt:{token_hash}` | STRING | `sid` | idle (glissant) |
| `usess:{user_id}` | SET | `sid` des sessions actives | absolu |
| `lock:{user_id}` | STRING (compteur) | échecs de login récents | fenêtre lockout |
| `rl:auth:{ip}` | STRING (compteur) | requêtes d'auth récentes | fenêtre rate limit |

Deux horizons de durée de vie :

- **idle (glissant)** = `REFRESH_TTL_SECONDS` : rafraîchi à chaque usage
  (rotation) ; une session inactive expire seule (déconnexion par inactivité).
- **absolu** = `SESSION_ABSOLUTE_TTL_SECONDS` : plafond dur depuis `created_at` ;
  au-delà, la rotation est refusée et la session détruite (re-login exigé).

## 3. Cycle de vie d'une session

- **Login / register** → `SessionStore::create` : génère un `sid`, écrit
  `sess:{sid}`, `rt:{hash}`, ajoute le `sid` à `usess:{user_id}` (pipeline
  atomique `MULTI`), puis émet un access token portant le `sid`.
- **Refresh** → `SessionStore::rotate` : `GETDEL rt:{ancien}` **atomique** —
  un seul appelant récupère le `sid` ; un rejeu ou une requête concurrente
  obtient `nil` ⇒ 401 (équivalent de l'ancien `rows_affected == 1`). Le plafond
  absolu est vérifié, un nouveau refresh token est posé, la session prolongée.
- **Logout** → `SessionStore::logout` : `GETDEL` du refresh token, puis
  suppression de `sess:{sid}` et retrait de l'index. Idempotent.

## 4. Révocation immédiate des access tokens

Avant, un access token JWT restait valide jusqu'à son expiration (~15 min)
même après un logout. Désormais, l'extracteur `AuthUser` (à **chaque** requête
authentifiée) :

1. vérifie la signature/expiration/émetteur/type du JWT ;
2. vérifie que **`sess:{sid}` existe dans Redis** et appartient bien au `sub` ;
3. recharge l'utilisateur en base (rôle courant).

Si la session a été révoquée (logout, « déconnexion des autres », révocation
ciblée, purge), l'étape 2 échoue et l'access token est **immédiatement**
invalide — sans attendre son expiration.

## 5. Gestion des sessions actives (endpoints)

Toutes authentifiées ; l'identité et la session courante viennent du token
(jamais d'un paramètre client → pas d'IDOR).

| Méthode | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/users/me/sessions` | Liste ses sessions (UA, IP, `created_at`, `last_seen`, `current`). |
| `DELETE` | `/api/v1/users/me/sessions/{sid}` | Révoque UNE de ses sessions (204 ; 404 si absente/non possédée). |
| `POST` | `/api/v1/users/me/sessions/logout-others` | Révoque toutes SES sessions sauf la courante. |

## 6. Cookies

Le refresh token voyage dans un cookie inchangé côté attributs de sécurité —
`HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth` — désormais avec un
**`Max-Age` = TTL idle glissant** : il est repoussé à chaque rotation, alignant
la durée du cookie sur celle de la session (timeout par inactivité).

> Rappel d'architecture (pattern BFF) : ce cookie circule entre le **frontend
> Next.js (BFF)** et le backend ; le navigateur, lui, ne voit que le cookie de
> session scellé (iron-session) du frontend et n'a jamais accès aux tokens.
> Le préfixe `__Host-` n'apporterait rien ici (le BFF n'est pas un navigateur)
> et casserait le `Path` scoping — il n'est donc pas utilisé côté backend.

## 7. Verrouillage & rate limiting distribués

- **Verrouillage anti-bruteforce** (`lock:{user_id}`) : incrémenté à chaque
  échec de login, expire après `LOGIN_LOCKOUT_SECONDS` ; au-delà de
  `LOGIN_MAX_FAILED_ATTEMPTS`, le login renvoie 429. Réinitialisé au succès.
- **Rate limiting d'auth** (`rl:auth:{ip}`) : fenêtre fixe `AUTH_RATE_LIMIT_*`
  par IP sur `login`/`register`.

Ces deux mécanismes étant dans Redis, ils sont **cohérents entre plusieurs
instances** de l'API — contrairement au `tower_governor` en mémoire, qui est
conservé comme première ligne (protection anti-rafale par process).

## 8. Configuration

Variables (cf. [`.env.example`](./.env.example)) :

| Variable | Obligatoire | Défaut | Rôle |
|---|---|---|---|
| `REDIS_URL` | ✅ | — | `redis://` (dev) ou `rediss://` (TLS prod). |
| `SESSION_ABSOLUTE_TTL_SECONDS` | | `2592000` (30 j) | Plafond absolu de session. |
| `REFRESH_TTL_SECONDS` | | `1209600` (14 j) | TTL idle glissant (réutilisé). |
| `AUTH_RATE_LIMIT_MAX` | | `30` | Requêtes d'auth par fenêtre et par IP. |
| `AUTH_RATE_LIMIT_WINDOW_SECONDS` | | `60` | Fenêtre du rate limiting d'auth. |

Le démarrage **échoue** si `REDIS_URL` manque ou n'est pas `redis(s)://`.

## 9. Sécurité & disponibilité

- Refresh token jamais stocké en clair (empreinte SHA-256 uniquement).
- Redis **jamais exposé** au frontend ; en production, `rediss://` (TLS) et
  Redis protégé par mot de passe / réseau privé.
- Rotation atomique (`GETDEL`) ⇒ anti-rejeu ; plafond absolu ⇒ borne la durée.
- **Disponibilité** : Redis étant indispensable à l'auth, une indisponibilité
  renvoie `503` (le client peut réessayer) plutôt qu'un comportement dégradé.
  En dev, l'image Redis active l'AOF (persistance) pour survivre à un redémarrage.

## 10. Tests

- **Unitaires** (`cargo test --lib`) : helpers de clés namespacées, mapping des
  champs vides, claims JWT (`sid`).
- **Intégration** (`tests/integration.rs`, CI avec **Redis + PostgreSQL**) :
  register/login/refresh/logout de bout en bout, **révocation immédiate** après
  logout, liste des sessions (`current`), révocation d'une session inconnue
  (404), et « logout-others » (la session courante survit, les autres sont
  révoquées immédiatement).
