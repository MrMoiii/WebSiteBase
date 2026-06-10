# WebSiteBase — Backend (Rust / Axum)

API REST de gestion d'utilisateurs, développée avec une posture sécurité
maximale. Stack : **Axum + Tokio**, **PostgreSQL via sqlx** (requêtes vérifiées
à la compilation), **Argon2id**, **JWT courts + refresh tokens révocables**,
logs **JSON structurés** (tracing).

> Voir [`SECURITY.md`](./SECURITY.md) pour le modèle de menace, les contrôles
> implémentés (mappés sur l'OWASP API Security Top 10) et les limites connues.

## Sommaire

- [Architecture](#architecture)
- [Prérequis](#prérequis)
- [Variables d'environnement](#variables-denvironnement)
- [Démarrage rapide (Docker)](#démarrage-rapide-docker)
- [Développement local](#développement-local)
- [Base de données & migrations](#base-de-données--migrations)
- [Tests](#tests)
- [Qualité & sécurité (lint, audit, deny)](#qualité--sécurité)
- [API](#api)
- [Déploiement & reverse proxy](#déploiement--reverse-proxy)

## Architecture

```
backend/
├── src/
│   ├── main.rs            # binaire mince + sous-mode "healthcheck"
│   ├── lib.rs             # bootstrap (run): config, logs, pool, serveur
│   ├── config.rs          # chargement strict de la config (fail-fast)
│   ├── telemetry.rs       # logs JSON structurés (tracing)
│   ├── errors.rs          # type d'erreur central -> réponses HTTP génériques
│   ├── state.rs           # état applicatif partagé (config + pool)
│   ├── auth/              # mots de passe (argon2), JWT, refresh tokens
│   ├── db/                # accès données (sqlx query!/query_as!)
│   ├── models/            # DTO validés (serde + validator) et vues
│   ├── middleware/        # en-têtes sécurité, auth, contexte client, validation
│   ├── handlers/          # logique des endpoints
│   └── routes/            # assemblage du routeur + pile de middlewares
├── migrations/            # migrations SQL versionnées (sqlx)
├── .sqlx/                 # cache des requêtes pour build hors-ligne (SQLX_OFFLINE)
├── docker/initdb/         # init de la base de dev (rôle DML-only + droits)
├── tests/integration.rs   # tests d'intégration (nominal + cas d'attaque)
├── Dockerfile             # multi-stage -> image distroless non-root
├── docker-compose.yml     # Postgres + API pour le développement
├── deny.toml              # politique licences + advisories (cargo-deny)
└── .github/workflows/ci.yml
```

## Prérequis

- **Rust** stable (toolchain épinglée via `rust-toolchain.toml`).
- **PostgreSQL 16** (local) ou **Docker** + **Docker Compose**.
- Pour les migrations : `cargo install sqlx-cli --no-default-features --features native-tls,postgres`.

## Variables d'environnement

Toutes les variables sont documentées dans [`.env.example`](./.env.example).
Copier ce fichier en `.env` pour le développement local.

| Variable | Obligatoire | Défaut | Description |
|---|---|---|---|
| `APP_BIND_ADDR` | ✅ | — | Adresse d'écoute (port non privilégié), ex. `0.0.0.0:8080`. |
| `APP_TRUSTED_PROXY_HOPS` | | `1` | Nb de proxys de confiance pour résoudre l'IP cliente (`X-Forwarded-For`). |
| `DATABASE_URL` | ✅ | — | URL runtime (rôle **DML-only**). |
| `DATABASE_MIGRATION_URL` | (migrations) | — | URL des migrations (rôle propriétaire, DDL). |
| `DATABASE_MAX_CONNECTIONS` | | `10` | Taille du pool. |
| `JWT_SECRET` | ✅ | — | Secret HS256, **≥ 32 octets** (sinon refus au démarrage). |
| `JWT_ISSUER` | ✅ | — | Émetteur attendu (`iss`). |
| `JWT_ACCESS_TTL_SECONDS` | | `900` | Durée du token d'accès. |
| `REFRESH_TTL_SECONDS` | | `1209600` | Durée du refresh token. |
| `CORS_ALLOWED_ORIGINS` | ✅ | — | Liste blanche d'origines (séparées par des virgules). |
| `COOKIE_SECURE` | | `true` | `true` en prod (HTTPS). |
| `MAX_BODY_BYTES` | | `1048576` | Limite de taille du corps (1 Mo). |
| `REQUEST_TIMEOUT_SECONDS` | | `15` | Timeout par requête. |
| `LOGIN_MAX_FAILED_ATTEMPTS` | | `5` | Seuil de verrouillage de compte. |
| `LOGIN_LOCKOUT_SECONDS` | | `900` | Durée du verrouillage. |
| `LOG_FILTER` | | `info` | Filtre de logs (syntaxe `RUST_LOG`). |

Le démarrage **échoue immédiatement** si une variable obligatoire manque. Les
secrets ne sont **jamais** loggés (le type `Secret` masque sa valeur en `Debug`).

## Démarrage rapide (Docker)

```bash
cd backend
docker compose up --build
```

- La base est initialisée automatiquement (rôle DML-only + schéma).
- L'API écoute sur `http://localhost:8080`.
- Vérifier : `curl -s http://localhost:8080/health`.

L'API tourne en conteneur **distroless non-root**, **filesystem en lecture
seule**, **toutes capabilities Linux retirées** et `no-new-privileges`.

## Développement local

```bash
cd backend

# 1) Lancer une base (Docker) ou utiliser une instance locale
docker compose up -d db

# 2) Préparer .env
cp .env.example .env   # ajuster si besoin

# 3) Lancer les migrations (rôle propriétaire / DDL)
export DATABASE_URL="postgres://app_owner:owner_dev_pw@localhost:5432/websitebase"
sqlx migrate run

# 4) Lancer l'API (le runtime utilise le rôle DML-only)
export DATABASE_URL="postgres://app_user:app_dev_pw@localhost:5432/websitebase"
cargo run
```

> Si vous utilisez une instance Postgres « nue » (pas via le compose), créez le
> rôle `app_user` et ses droits DML — voir `docker/initdb/00-roles.sql`.

## Base de données & migrations

- Migrations versionnées dans `migrations/`, gérées par **sqlx**.
- Le **rôle propriétaire** (DDL) applique les migrations ; le **rôle applicatif**
  (runtime) n'a que SELECT/INSERT/UPDATE/DELETE (aucun DDL) — moindre privilège.
- L'application **n'exécute pas** les migrations (cohérent avec le moindre
  privilège) : jouez-les explicitement avec `sqlx migrate run`.

Créer une nouvelle migration :

```bash
sqlx migrate add -r <nom>
# éditer le fichier généré, puis :
sqlx migrate run --database-url "$DATABASE_MIGRATION_URL"
# régénérer le cache hors-ligne et le committer :
cargo sqlx prepare --database-url "$DATABASE_MIGRATION_URL"
```

## Tests

Les tests d'intégration nécessitent une base accessible via `DATABASE_URL`.

```bash
cd backend
export DATABASE_URL="postgres://app_user:app_dev_pw@localhost:5432/websitebase"
cargo test
```

Couverture :

- **Unitaires** : hachage/vérification Argon2, génération/empreinte des refresh
  tokens, émission/validation JWT (falsification, mauvais secret/émetteur),
  validation des DTO (`deny_unknown_fields`, bornes), en-têtes de sécurité.
- **Intégration** : flux nominaux (register/login/refresh/logout, profil, admin)
  **et cas d'attaque** : payload malformé (400), dépassement de taille (413),
  champ inconnu (rejeté), accès non authentifié (401), accès admin par un
  non-admin (403), tentative d'IDOR (l'identifiant vient du token, pas de l'URL),
  énumération d'utilisateurs (réponses génériques).

## Qualité & sécurité

```bash
cargo fmt --all --check          # formatage
cargo clippy --all-targets -- -D warnings   # lint strict (zéro warning)
cargo audit                      # advisories RustSec
cargo deny check                 # licences + advisories + sources
```

La CI (`.github/workflows/ci.yml`) exécute l'ensemble à chaque push/PR. Le build
et le lint utilisent le cache `.sqlx` (`SQLX_OFFLINE=true`) — aucune base requise
pour compiler.

## API

Base : `/api/v1`. Réponses JSON. Erreurs au format
`{"error":{"code":"...","message":"..."}}` (génériques, sans détail interne).
Un correlation id est renvoyé dans l'en-tête `x-request-id`.

| Méthode | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | — | Liveness. |
| `GET` | `/health/ready` | — | Readiness (ping DB). |
| `POST` | `/api/v1/auth/register` | — | Inscription. Renvoie un token d'accès + pose le cookie de refresh. |
| `POST` | `/api/v1/auth/login` | — | Connexion. |
| `POST` | `/api/v1/auth/refresh` | cookie | Rotation du refresh token. |
| `POST` | `/api/v1/auth/logout` | cookie | Révocation du refresh token. |
| `GET` | `/api/v1/users/me` | Bearer | Lecture de son profil. |
| `PATCH` | `/api/v1/users/me` | Bearer | Mise à jour de son profil. |
| `GET` | `/api/v1/admin/users` | Bearer (admin) | Liste paginée des utilisateurs. |

Les endpoints sensibles (`/auth/*`) sont soumis à un **rate limiting par IP**.
Le **token d'accès** est transmis via `Authorization: Bearer <token>`. Le
**refresh token** est porté par un cookie `HttpOnly; Secure; SameSite=Strict`
limité au chemin `/api/v1/auth`.

### Exemple

```bash
# Inscription
curl -i -X POST http://localhost:8080/api/v1/auth/register \
  -H 'content-type: application/json' \
  -d '{"email":"alice@example.com","password":"a-strong-password-123"}'

# Profil (avec le token renvoyé)
curl -s http://localhost:8080/api/v1/users/me \
  -H "authorization: Bearer <ACCESS_TOKEN>"
```

Promouvoir un compte admin (opération d'administration hors API) :

```sql
UPDATE users SET role = 'admin' WHERE lower(email) = lower('alice@example.com');
```

## Déploiement & reverse proxy

Le binaire écoute en **HTTP** sur un port non privilégié et suppose une
**terminaison TLS par un reverse proxy** en frontal (Nginx, Caddy, Traefik,
ingress…). Le proxy doit fournir :

- `X-Forwarded-For` : chaîne des IP clientes (l'app résout l'IP réelle selon
  `APP_TRUSTED_PROXY_HOPS`, pour ne pas faire confiance à une IP usurpée) ;
- `X-Forwarded-Proto: https` ;
- `X-Forwarded-Host` / `Host` corrects.

Configurez `CORS_ALLOWED_ORIGINS` avec les origines réelles du front et
`COOKIE_SECURE=true` (HTTPS). L'en-tête `Strict-Transport-Security` est émis par
l'application.
