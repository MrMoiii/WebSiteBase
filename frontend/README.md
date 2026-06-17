# WebSiteBase — Frontend (Next.js / TypeScript)

Frontend de l'application, développé avec une posture sécurité maximale.
Stack : **Next.js 16 (App Router, Server Components)** en **TypeScript
strict**, **zod** pour toute donnée entrante, **Tailwind CSS**,
**iron-session** (session chiffrée), **Vitest** + **Playwright**.

Il consomme l'API REST du backend Rust/Axum ([`../backend`](../backend))
selon le **pattern BFF** : les tokens de l'API ne quittent jamais le serveur
Next, le navigateur ne voit qu'un cookie de session chiffré `HttpOnly`.

> Voir [`SECURITY.md`](./SECURITY.md) pour le modèle de menace, les contrôles
> implémentés (mappés sur l'OWASP Top 10 côté client) et les limites connues.

## Sommaire

- [Architecture](#architecture)
- [Prérequis](#prérequis)
- [Variables d'environnement](#variables-denvironnement)
- [Lancement avec le backend](#lancement-avec-le-backend)
- [Développement local](#développement-local)
- [Tests](#tests)
- [Qualité & chaîne d'approvisionnement](#qualité--chaîne-dapprovisionnement)
- [Déploiement & reverse proxy](#déploiement--reverse-proxy)

## Architecture

```
frontend/
├── app/
│   ├── layout.tsx              # layout racine (fonts système, skip-link)
│   ├── page.tsx                # accueil (public)
│   ├── (auth)/
│   │   ├── login/page.tsx      # connexion (+ retour post-auth validé)
│   │   └── register/page.tsx   # inscription
│   ├── (app)/                  # périmètre AUTHENTIFIÉ
│   │   ├── layout.tsx          # vérification de session (serveur)
│   │   ├── profile/page.tsx    # profil (lecture/édition)
│   │   └── admin/
│   │       ├── layout.tsx      # rôle admin exigé (404 générique sinon)
│   │       └── users/page.tsx  # listing utilisateurs paginé
│   ├── actions/                # Server Actions (mutations, anti-CSRF)
│   ├── api/health/route.ts     # liveness (healthcheck Docker)
│   ├── error.tsx               # erreurs génériques (zéro détail interne)
│   └── not-found.tsx
├── components/                 # formulaires (client) + en-tête (serveur)
├── lib/
│   ├── env.ts                  # variables d'env validées par zod (fail-fast)
│   ├── session.ts              # session iron-session (cookie chiffré HttpOnly)
│   ├── api.ts                  # client typé de l'API Axum (server-only)
│   ├── api-schemas.ts          # schémas zod des réponses backend
│   ├── auth.ts                 # orchestration session/refresh/redirections
│   ├── csrf.ts                 # vérification d'Origin des mutations
│   ├── redirect.ts             # liste blanche anti open-redirect
│   ├── schemas.ts              # schémas zod des formulaires (client+serveur)
│   └── logger.ts               # logs JSON serveur (avec correlation id)
├── proxy.ts                    # middleware : CSP nonce, en-têtes, protection
│                               #   (équivalent Next 16 de middleware.ts)
├── instrumentation.ts          # validation d'env au démarrage (fail-fast)
├── tests/                      # unitaires Vitest (modules de sécurité)
├── e2e/                        # Playwright (nominal + cas d'attaque)
├── scripts/check-bundle-secrets.sh  # anti-fuite de secrets dans le bundle
├── Dockerfile                  # multi-stage, non-root, healthcheck
└── docker-compose.yml          # dev, réseau partagé avec le backend
```

> **Note** : la spécification du projet demandait un `middleware.ts`. Next.js
> 16 a renommé cette convention en **`proxy.ts`** (`middleware.ts` est déprécié
> et sera retiré) — même rôle, même API, seul le nom change.

## Prérequis

- **Node.js ≥ 22** et npm.
- Le **backend** ([`../backend`](../backend)) et sa base PostgreSQL pour les
  parcours authentifiés et les tests E2E.

## Variables d'environnement

Toutes les variables sont **validées par zod au démarrage** (le serveur refuse
de démarrer si une variable manque ou est invalide) et documentées dans
[`.env.example`](./.env.example). **Aucune** variable `NEXT_PUBLIC_*` n'est
utilisée : rien n'est exposé au bundle client (vérifié en CI).

| Variable | Obligatoire | Défaut | Description |
|---|---|---|---|
| `API_BASE_URL` | ✅ | — | URL de l'API Axum (réseau interne), sans slash final. Jamais exposée au navigateur. |
| `SESSION_SECRET` | ✅ | — | Secret de chiffrement du cookie de session, **≥ 32 caractères** (`openssl rand -base64 48`). |
| `COOKIE_SECURE` | | `true` | `true` en production (HTTPS, cookie `__Host-`). `false` uniquement en dev HTTP. |
| `APP_ALLOWED_ORIGINS` | | (vide) | Origines publiques pour l'anti-CSRF des Server Actions, requises seulement derrière un proxy qui réécrit `Host`. |

## Lancement avec le backend

```bash
# 1) Backend + base (crée le réseau partagé backend_default)
cd backend
docker compose up -d --build

# 2) Frontend
cd ../frontend
docker compose up --build
```

- Frontend : <http://localhost:3000> — Backend : `http://api:8080` (réseau
  interne ; le navigateur ne parle JAMAIS à l'API directement).
- Les conteneurs tournent non-root, filesystem en lecture seule, sans
  capability Linux.

Pour donner le rôle admin à un compte (opération hors API, volontairement) :

```bash
docker compose -f ../backend/docker-compose.yml exec db \
  psql -U app_owner -d websitebase \
  -c "UPDATE users SET role = 'admin' WHERE lower(email) = lower('alice@example.com');"
```

## Développement local

```bash
cd frontend
cp .env.example .env       # ajuster si besoin
npm ci
npm run dev                # http://localhost:3000
```

Le backend doit être joignable sur `API_BASE_URL` (par défaut
`http://localhost:8080`, c'est-à-dire le port publié par le compose backend).

> En mode dev, la CSP autorise `'unsafe-eval'` (exigé par le HMR de Next).
> Le build de production reste strictement noncé — les E2E le vérifient.

## Tests

```bash
npm run typecheck          # TypeScript strict
npm run lint               # ESLint (+ eslint-plugin-security), 0 warning
npm test                   # unitaires Vitest (anti open-redirect, env, schémas…)
```

### E2E (Playwright)

Prérequis : backend + base démarrés (cf. ci-dessus), build de production :

```bash
npm run build
npx playwright install chromium
npm run test:e2e
```

Les E2E couvrent les parcours nominaux ET des **cas d'attaque** : accès direct
aux routes protégées sans session, cookie de session falsifié, tentatives
d'open redirect (`?next=`), payload XSS dans les formulaires, session expirée
en cours d'action, vérification des en-têtes de sécurité et du caractère
HttpOnly de la session.

Le test du listing admin nécessite un compte promu admin :

```bash
export E2E_ADMIN_EMAIL=admin@e2e.example
export E2E_ADMIN_PASSWORD=mot-de-passe-admin-123
# créer le compte (via /register) puis le promouvoir en SQL (cf. plus haut)
```

## Qualité & chaîne d'approvisionnement

- `package-lock.json` committé, **versions épinglées** (pas de `^`/`~`).
- `npm ci --ignore-scripts` en CI et dans l'image Docker : aucun script
  post-install de dépendance n'est exécuté.
- `npm audit --audit-level=high` bloquant en CI ; un `override` npm force
  `postcss ≥ 8.5.10` (GHSA-qx2v-qp2m-jg93) dans l'arbre de Next.
- Dépendances runtime réduites au minimum justifiable : `next`, `react(-dom)`,
  `zod` (validation), `iron-session` (session scellée), `server-only`
  (garde-fou de compilation). Zéro CDN externe, zéro script tiers, fonts
  système (pas de téléchargement).
- CI ([`.github/workflows/frontend-ci.yml`](../.github/workflows/frontend-ci.yml)) :
  typecheck, ESLint (0 warning), audit, tests unitaires, build, **check
  anti-fuite de secrets dans le bundle client**, puis E2E Playwright contre le
  vrai backend Axum + PostgreSQL.

## Déploiement & reverse proxy

Le conteneur écoute en **HTTP** sur le port non privilégié `3000` et suppose
une **terminaison TLS par un reverse proxy** en frontal. Le proxy doit
fournir :

- `Host` (ou `X-Forwarded-Host`) : l'hôte public — utilisé par la
  vérification d'Origin des Server Actions (anti-CSRF). Si le proxy réécrit
  `Host`, déclarer les origines publiques dans `APP_ALLOWED_ORIGINS` ;
- `X-Forwarded-Proto: https` ;
- `X-Forwarded-For` : chaîne des IP clientes (utile aux logs et au rate
  limiting du backend).

En production : `COOKIE_SECURE=true` (active le préfixe `__Host-` du cookie),
`SESSION_SECRET` issu du gestionnaire de secrets, et HSTS est émis par
l'application (le proxy ne doit pas l'écraser). Le frontend et l'API peuvent
vivre sur des (sous-)domaines distincts : le navigateur ne dialogue qu'avec le
frontend (`connect-src 'self'`), les appels API partent du serveur Next.
