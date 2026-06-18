# Monitoring d'API via OpenSearch (observabilité & debug)

Panneau d'**observabilité des appels d'API** : chaque requête (succès **et**
erreur) est journalisée dans OpenSearch avec ses métadonnées techniques, puis
visualisée et filtrée dans **OpenSearch Dashboards** pour le debugging.

PostgreSQL reste la base principale ; OpenSearch n'est utilisé **que** comme
magasin de logs secondaire, reconstructible et jetable.

> Fonctionnalité **opt-in** : sans `OPENSEARCH_URL`, le monitoring est désactivé
> et l'application fonctionne exactement comme avant (aucun envoi, zéro surcoût).

## Sommaire

1. [Architecture](#1-architecture)
2. [Flux & garanties de non-blocage](#2-flux--garanties-de-non-blocage)
3. [Modules Rust](#3-modules-rust)
4. [Document indexé & mapping](#4-document-indexé--mapping)
5. [Déploiement (Docker + TLS + Dashboards)](#5-déploiement-docker--tls--dashboards)
6. [Le panneau Dashboards (debug)](#6-le-panneau-dashboards-debug)
7. [Sécurité & confidentialité](#7-sécurité--confidentialité)
8. [Tests](#8-tests)

---

## 1. Architecture

```
Requête HTTP
   │
   ▼
monitoring::layer   middleware Axum : mesure latence + capture statut/code/IP/UA
   │  record()  ── try_send NON bloquant (abandon si saturé)
   ▼
monitoring::shipper tâche de fond : tampon + envoi par lots (_bulk), best-effort
   │
   ▼
monitoring::client  OpenSearchClient : TLS≥1.2 / mTLS, auth (Basic|ApiKey), HTTP
   │
   ▼
OpenSearch  ◀── OpenSearch Dashboards (le « panneau » de debug, séparé)
```

Le middleware est inséré **après** `SetRequestIdLayer` (pour disposer du
correlation id) mais **autour** des couches métier (timeout, CORS, limite de
taille…) : il capture donc aussi les `408`, `413`, `500` générés par la pile,
pas seulement les réponses des handlers.

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
│   ├── event.rs     # ApiLogEvent + classification d'issue + index quotidien + mapping
│   ├── shipper.rs   # MonitoringHandle + tâche de fond (tampon, lots, abandon)
│   └── layer.rs     # middleware Axum from_fn capturant l'issue de chaque requête
├── config.rs        # MonitoringConfig (+ OpenSearchAuth) — fail-fast, https:// imposé
├── state.rs         # AppState.monitoring: Option<MonitoringHandle> (clone léger)
├── routes/mod.rs    # insertion du middleware de monitoring dans la pile
└── errors.rs        # ErrorCode attaché en extension de réponse (lu par le middleware)
```

## 4. Document indexé & mapping

Un appel produit un `ApiLogEvent` indexé dans un index **quotidien**
`api-logs-YYYY.MM.DD` (rotation ⇒ rétention/purge simple via une politique ISM).

```json
{
  "@timestamp": "2026-06-17T10:00:00Z",
  "request_id": "0b9c…",
  "method": "POST",
  "path": "/api/v1/auth/login",
  "status": 401,
  "outcome": "client_error",
  "latency_ms": 12,
  "error_code": "unauthorized",
  "client_ip": "203.0.113.7",
  "user_agent": "Mozilla/5.0 …"
}
```

`outcome` ∈ `success` (`< 400`) · `client_error` (`4xx`) · `server_error`
(`5xx`) : c'est le champ pivot du tableau de bord « erreurs vs succès ».

Le **mapping strict versionné** est appliqué automatiquement à tous les index
`api-logs-*` via un *index template* (`event::index_template`), créé au
démarrage (idempotent). `dynamic: "strict"` refuse tout champ non déclaré.

| Champ | Type | Note |
|---|---|---|
| `@timestamp` | date | horodatage de la requête |
| `request_id` | keyword | corrélation avec les logs applicatifs `tracing` |
| `method`, `path` | keyword | `path` **sans** query string |
| `status` | short | code HTTP |
| `outcome` | keyword | `success`/`client_error`/`server_error` |
| `latency_ms` | long | latence mesurée par le middleware |
| `error_code` | keyword | code applicatif stable (si erreur) |
| `client_ip`, `user_agent` | keyword | métadonnées d'audit (UA borné à 256) |

## 5. Déploiement (Docker + TLS + Dashboards)

Overlay fourni : [`docker-compose.observability.yml`](./docker-compose.observability.yml)
+ script de certificats [`docker/opensearch/generate-certs.sh`](./docker/opensearch/generate-certs.sh)
+ configs durcies [`opensearch.yml`](./docker/opensearch/opensearch.yml) et
[`opensearch_dashboards.yml`](./docker/opensearch/opensearch_dashboards.yml).

```bash
cd backend
# 1) PKI locale (CA + cert nœud/admin/client) — non committée.
#    Linux/macOS (openssl requis) :
./docker/opensearch/generate-certs.sh
#    Windows (PowerShell, AUCUN openssl requis — openssl tourne dans Docker) :
#    .\docker\opensearch\generate-certs.ps1
# 2) Stack complète : API + PostgreSQL + OpenSearch (TLS) + Dashboards.
docker compose -f docker-compose.yml -f docker-compose.observability.yml up -d --build
# 3) Générer du trafic puis ouvrir le panneau.
curl -s http://localhost:8080/health >/dev/null
#    Dashboards : http://localhost:5601  (admin / Dev_Strong_Passw0rd!)
```

> **Format des clés** : les scripts génèrent des clés **PKCS#8**
> (`BEGIN PRIVATE KEY`) via `openssl genpkey`. Le plugin de sécurité
> d'OpenSearch **n'accepte pas** le PKCS#1 (`BEGIN RSA PRIVATE KEY`) — une clé
> PKCS#1 fait échouer le démarrage du nœud (`exit 1`).
>
> **Linux** : si le conteneur `opensearch` sort en erreur avec
> `vm.max_map_count [65530] is too low`, exécuter
> `sudo sysctl -w vm.max_map_count=262144` (Docker Desktop :
> `wsl -d docker-desktop sysctl -w vm.max_map_count=262144`).

- OpenSearch **n'expose aucun port** sur l'hôte (réseau Docker interne) ; seul
  le backend (et Dashboards) le joignent, en TLS.
- Dashboards est exposé sur `127.0.0.1:5601` (opérateur uniquement).
- Le backend reçoit les `OPENSEARCH_*` et envoie ses logs automatiquement.

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

## 7. Sécurité & confidentialité

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

## 8. Tests

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
