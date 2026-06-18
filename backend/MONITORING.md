# Observabilité de l'API (logs OpenSearch + métriques Prometheus)

Deux piliers complémentaires de l'observabilité des appels d'API :

- **Logs** (OpenSearch + Dashboards) : chaque requête et chaque événement
  applicatif (succès **et** erreur) est journalisé avec ses métadonnées et un
  `request_id` pour la **corrélation** — pour le debugging fin.
- **Métriques** (Prometheus) : agrégats numériques (volume de requêtes, statuts,
  **latence**, **taux d'erreur**) exposés sur `/metrics` et *scrapés* par
  Prometheus — pour les tableaux de bord et l'alerting. (Prometheus stocke des
  séries temporelles, **pas** des logs : les deux sont complémentaires.)

PostgreSQL reste la base principale ; OpenSearch n'est qu'un magasin de logs
secondaire, reconstructible et jetable.

> **Opt-in** : sans `OPENSEARCH_URL`, les LOGS sont désactivés. Les MÉTRIQUES
> Prometheus (`/metrics`), elles, sont toujours actives (peu coûteuses,
> indépendantes d'OpenSearch).

## Sommaire

1. [Architecture](#1-architecture)
2. [Flux & garanties de non-blocage](#2-flux--garanties-de-non-blocage)
3. [Modules Rust](#3-modules-rust)
4. [Documents indexés & mapping](#4-documents-indexés--mapping)
5. [Déploiement (Docker + Dashboards)](#5-déploiement-docker--dashboards)
6. [Le panneau Dashboards (debug)](#6-le-panneau-dashboards-debug)
7. [Métriques Prometheus](#7-métriques-prometheus)
8. [Sécurité & confidentialité](#8-sécurité--confidentialité)
9. [Tests](#9-tests)

---

## 1. Architecture

Chaque requête API reçoit un **`request_id`** (UUID généré par `SetRequestIdLayer`
au moment de l'appel). Deux sources alimentent OpenSearch, **toutes deux
estampillées de ce `request_id`** pour permettre la corrélation :

```
Requête HTTP  ──►  SetRequestIdLayer (génère request_id)
   │
   ├─► monitoring::layer     middleware : 1 doc de synthèse / requête (kind="access")
   │                         (méthode, chemin, statut, latence, code d'erreur, IP, UA)
   │
   └─► span http_request ───► tracing events (raises ApiError, login, métier…)
                              │
                              ▼
              monitoring::log_layer  couche tracing : 1 doc / événement (kind="event"),
                                     request_id repris du span de la requête
                 │
   les deux ──►  MonitoringHandle.record()  ── try_send NON bloquant (abandon si saturé)
                 ▼
              monitoring::shipper  tâche de fond : tampon + envoi par lots (_bulk)
                 ▼
              monitoring::client   OpenSearchClient : TLS≥1.2 / mTLS, auth, HTTP
                 ▼
              OpenSearch  ◀── OpenSearch Dashboards (le « panneau » de debug)
```

- Le **middleware** est inséré **après** `SetRequestIdLayer` mais **autour** des
  couches métier (timeout, CORS, limite…) : il capture aussi les `408`/`413`/`500`
  générés par la pile, pas seulement les réponses des handlers.
- La **couche tracing** (`log_layer`) expédie **tous** les événements `tracing`
  de la crate applicative (toutes routes, tous `raise`/erreurs `ApiError`,
  événements de sécurité/métier). Elle exclut ses propres logs (anti-boucle) et
  le bruit des dépendances. Le `request_id` provient du span `http_request`.

## 2. Flux & garanties de non-blocage

Le chemin de requête **ne doit jamais** être ralenti par l'observabilité :

- le middleware se contente d'un `try_send` sur un **canal borné** ; si le canal
  est plein (cluster lent/indisponible), l'événement est **abandonné** et
  compté — **aucune contre-pression** sur l'API ;
- une **tâche de fond** consomme le canal, met en **tampon** les événements et
  les envoie par **lots `_bulk`** (quand le lot est plein **ou** à intervalle
  régulier) ;
- les échecs d'envoi sont **loggés et abandonnés** (les logs sont best-effort),
  jamais propagés à l'utilisateur ;
- le compteur d'événements abandonnés est journalisé périodiquement
  (`monitoring_events_dropped`) — signal d'engorgement utile à l'alerting.

Paramètres (env, cf. `.env.example`) : `OPENSEARCH_BATCH_SIZE` (défaut 500),
`OPENSEARCH_FLUSH_INTERVAL_SECONDS` (2), `OPENSEARCH_CHANNEL_CAPACITY` (10000),
`OPENSEARCH_TIMEOUT_SECONDS` (5).

## 3. Modules Rust

```
backend/src/
├── monitoring/
│   ├── mod.rs       # doc d'architecture + ré-exports
│   ├── client.rs    # OpenSearchClient : TLS/mTLS, auth, _bulk, _index_template, ping
│   ├── event.rs     # LogDoc (access|event) + classification + index quotidien + mapping
│   ├── shipper.rs   # MonitoringHandle + tâche de fond (tampon, lots, abandon)
│   ├── layer.rs     # middleware Axum : métriques + doc de synthèse (kind=access)
│   ├── log_layer.rs # couche tracing : expédie tout événement applicatif (kind=event)
│   └── metrics.rs   # registre Prometheus (compteurs + histogramme) + rendu /metrics
├── handlers/metrics.rs # endpoint GET /metrics (exposition Prometheus)
├── config.rs        # MonitoringConfig (+ OpenSearchAuth) — fail-fast, https:// imposé
├── state.rs         # AppState.monitoring + AppState.metrics (Arc<Metrics>)
├── routes/mod.rs    # middleware de monitoring + route /metrics
└── errors.rs        # ErrorCode attaché en extension de réponse (lu par le middleware)
```

## 4. Documents indexés & mapping

Tout est indexé dans un index **quotidien** `api-logs-YYYY.MM.DD` (rotation ⇒
rétention/purge simple via une politique ISM). **Deux `kind`**, corrélables par
`request_id` :

**`kind = "access"`** — une synthèse par requête (middleware) :

```json
{
  "@timestamp": "2026-06-17T10:00:00Z", "kind": "access", "level": "info",
  "request_id": "0b9c…", "method": "POST", "path": "/api/v1/auth/login",
  "status": 401, "outcome": "client_error", "latency_ms": 12,
  "error_code": "unauthorized", "client_ip": "203.0.113.7", "user_agent": "Mozilla/5.0 …"
}
```

**`kind = "event"`** — un par événement `tracing` applicatif (couche `log_layer`) :

```json
{
  "@timestamp": "2026-06-17T10:00:00Z", "kind": "event", "level": "WARN",
  "request_id": "0b9c…", "target": "websitebase_backend::handlers::auth",
  "message": "échec de login", "event": "login_failed", "security.event": true,
  "client.ip": "203.0.113.7"
}
```

> **Corrélation** : pour une requête, le doc `access` et tous les docs `event`
> partagent le **même `request_id`**. Dans Dashboards, filtrer
> `request_id: "0b9c…"` reconstitue toute l'histoire de l'appel.

`outcome` ∈ `success` (`< 400`) · `client_error` (`4xx`) · `server_error`
(`5xx`) : champ pivot du tableau de bord « erreurs vs succès ».

Le mapping est appliqué automatiquement à tous les index `api-logs-*` via un
*index template* (`event::index_template`), créé au démarrage (idempotent). Un
index de **logs** utilise `dynamic: true` : les champs usuels (ci-dessous) sont
typés explicitement, et les champs structurés variables des événements
(`event`, `user.id`, `error.detail`…) sont auto-indexés.

| Champ | Type | Note |
|---|---|---|
| `@timestamp` | date | horodatage |
| `kind` | keyword | `access` ou `event` |
| `level` | keyword | niveau (`info`/`WARN`/`ERROR`…) |
| `request_id` | keyword | **clé de corrélation** (généré au call API) |
| `target`, `message` | keyword / text | source + message (docs `event`) |
| `method`, `path` | keyword | `path` **sans** query string (docs `access`) |
| `status` | short | code HTTP |
| `outcome` | keyword | `success`/`client_error`/`server_error` |
| `latency_ms` | long | latence mesurée par le middleware |
| `error_code` | keyword | code applicatif stable (si erreur) |
| `client_ip`, `user_agent` | keyword | métadonnées d'audit (UA borné à 256) |

## 5. Déploiement (Docker + Dashboards)

### Mode DEV simple (recommandé en local)

Overlay [`docker-compose.observability.yml`](./docker-compose.observability.yml) :
le **plugin de sécurité OpenSearch est désactivé** (HTTP interne, pas d'auth,
**aucun certificat à générer**). Démarre du premier coup.

```bash
cd backend
# Stack complète : API + PostgreSQL + OpenSearch + Dashboards + Prometheus.
docker compose -f docker-compose.yml -f docker-compose.observability.yml up -d --build
# Générer du trafic puis ouvrir les panneaux.
curl -s http://localhost:8080/health >/dev/null
curl -s http://localhost:8080/metrics            # métriques brutes (texte Prometheus)
#   Dashboards (logs)  : http://localhost:5601   (pas d'identifiants : sécurité désactivée)
#   Prometheus (métriques) : http://localhost:9090  (Status → Targets : api doit être UP)
```

- OpenSearch **n'expose aucun port** sur l'hôte (réseau Docker interne) ; seul
  le backend et Dashboards le joignent.
- Dashboards (panneau logs) est sur `127.0.0.1:5601`, Prometheus sur
  `127.0.0.1:9090` (opérateur uniquement).
- Le backend pointe sur `http://opensearch:9200` avec `OPENSEARCH_ALLOW_INSECURE=true`
  (toléré seulement parce que le cluster est sur le réseau interne).

> **Linux/WSL2** : si `opensearch` sort avec `vm.max_map_count [65530] is too low`,
> exécuter `sudo sysctl -w vm.max_map_count=262144`
> (Docker Desktop : `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`).

### Variante DURCIE (proche prod : TLS + plugin de sécurité)

Pour un déploiement réaliste, on active TLS et l'authentification. Le backend
exige alors `https://` (défaut : `OPENSEARCH_ALLOW_INSECURE=false`). Cette
variante nécessite une PKI et le bootstrap du plugin de sécurité :

- certificats **PKCS#8** (`BEGIN PRIVATE KEY`, via `openssl genpkey` — le PKCS#1
  fait échouer le nœud) : scripts
  [`generate-certs.sh`](./docker/opensearch/generate-certs.sh) (Linux/macOS) et
  [`generate-certs.ps1`](./docker/opensearch/generate-certs.ps1) (Windows, via
  Docker, sans openssl sur l'hôte) ;
- configs [`opensearch.yml`](./docker/opensearch/opensearch.yml) /
  [`opensearch_dashboards.yml`](./docker/opensearch/opensearch_dashboards.yml) ;
- montage des certs + `OPENSEARCH_URL=https://…`, `OPENSEARCH_CA_CERT_PATH`,
  identifiants (et `OPENSEARCH_CLIENT_IDENTITY_PATH` pour le mTLS).

> En production, privilégier un **cluster OpenSearch managé** déjà sécurisé
> plutôt que de bootstrapper le plugin de sécurité à la main.

## 6. Le panneau Dashboards (debug)

Dans OpenSearch Dashboards :

1. **Index pattern** : créer `api-logs-*` (champ temps `@timestamp`).
2. **Discover** : explorer les requêtes en direct ; filtrer p. ex.
   `outcome: server_error` pour isoler les 5xx, ou `request_id: "<id>"` pour
   retrouver une requête précise (corrélée aux logs applicatifs).
3. **Visualisations / dashboard** typiques pour le debug :
   - répartition `outcome` (succès vs erreurs) dans le temps ;
   - top `path` par `status` (où sont les erreurs) ;
   - `latency_ms` p50/p95/p99 par `path` (latence) ;
   - taux d'erreur (`server_error` / total) + alerte sur seuil/burst.

`request_id` est la clé pour croiser un événement du panneau avec les logs
JSON `tracing` du backend (même `correlation_id`).

## 7. Métriques Prometheus

Le backend expose un endpoint **`GET /metrics`** (format texte Prometheus 0.0.4,
exposeur fait main — aucune dépendance ajoutée). Le middleware
`monitoring::layer` alimente les séries pour **chaque** requête (le endpoint
`/metrics` lui-même est exclu pour ne pas s'auto-mesurer) :

| Métrique | Type | Labels | Usage |
|---|---|---|---|
| `http_requests_total` | counter | `method`, `route`, `status`, `outcome` | volume, répartition statuts, **taux d'erreur** |
| `http_request_duration_seconds` | histogram | `method`, `route` | **latence** (p50/p95/p99 via `histogram_quantile`) |

**Cardinalité bornée** (anti-explosion de séries — règle clé de Prometheus) :
`method` et `route` sont normalisés vers des ensembles **fermés** de valeurs ;
un chemin inconnu (scanner, route absente) est replié sur `route="other"`. On
n'expose **jamais** de label à haute cardinalité (pas de `request_id`, pas
d'URL brute) — ça, c'est le rôle des logs OpenSearch.

Exemples PromQL :

```promql
# Taux d'erreur 5xx (sur 5 min)
sum(rate(http_requests_total{outcome="server_error"}[5m]))
  / sum(rate(http_requests_total[5m]))

# Latence p95 par route
histogram_quantile(0.95,
  sum(rate(http_request_duration_seconds_bucket[5m])) by (le, route))

# Requêtes par seconde par statut
sum(rate(http_requests_total[1m])) by (status)
```

Prometheus *scrape* `api:8080/metrics` toutes les 15 s (cf.
[`docker/prometheus/prometheus.yml`](./docker/prometheus/prometheus.yml)) et son
UI/PromQL est exposée sur `http://localhost:9090` (cible **Status → Targets**
doit être `UP`). Brancher Grafana dessus pour des tableaux de bord si besoin.

> Le endpoint `/metrics` ne contient que des agrégats (aucune donnée sensible),
> mais reste à **restreindre au niveau réseau** (scrape interne) — ne pas
> l'exposer publiquement.

## 8. Sécurité & confidentialité

- **TLS obligatoire** backend ↔ cluster (`https_only`, TLS ≥ 1.2) ; démarrage
  refusé si `OPENSEARCH_URL` n'est pas `https://`.
- **Auth forte** : HTTP Basic ou ApiKey ; **mTLS** supporté (identité client
  PEM). Secrets jamais loggés (`Secret`/`OpenSearchAuth` caviardés en `Debug`),
  jamais exposés au frontend.
- **Aucune donnée sensible indexée** : pas de corps de requête/réponse, pas
  d'en-tête d'autorisation, **pas de query string** (qui pourrait contenir des
  termes personnels) — uniquement des métadonnées techniques.
- **Cluster non exposé** : pas de port publié ; accès interne uniquement.
- **Mapping strict** (`dynamic: strict`) : impossible d'injecter des champs
  arbitraires dans l'index de logs.
- **Best-effort & isolé** : une panne d'OpenSearch n'impacte ni la latence ni
  la disponibilité de l'API (abandon silencieux + log).

## 9. Tests

- **Unitaires** (`cargo test --lib`, module `monitoring::metrics`) :
  normalisation des labels (route/méthode inconnues → cardinalité bornée),
  rendu Prometheus (compteurs agrégés, buckets cumulatifs, `_sum`/`_count`),
  absence de label à haute cardinalité (`request_id`).
- **Unitaires** (`cargo test --lib`, module `monitoring::event`) :
  classification d'issue (`success`/`client_error`/`server_error`), nom d'index
  quotidien, sérialisation (présence de `@timestamp`, **absence** de champ
  corps/secret, `error_code` omis si absent), NDJSON `_bulk` (action `create`
  + source par document, routage vers l'index du jour).
- **Intégration HTTP** (`tests/integration.rs`, CI avec PostgreSQL) : avec le
  monitoring **désactivé** (cas par défaut des tests), tous les endpoints
  conservent leur comportement — le middleware n'altère ni les statuts ni les
  réponses.
- **Bout-en-bout (manuel, cluster requis)** : démarrer la stack (§5), générer
  du trafic (succès + erreurs), puis vérifier l'arrivée des documents :
  ```bash
  curl -s http://localhost:8080/api/v1/users/me           # 401 attendu
  curl -s http://localhost:8080/health                    # 200
  # Dans Dashboards (Discover, index api-logs-*), ou via l'API du cluster :
  # GET api-logs-*/_search -> doit contenir les deux appels avec leur `outcome`.
  ```
