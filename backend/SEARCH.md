# Recherche secondaire — OpenSearch (architecture & sécurité)

Intégration d'**OpenSearch** comme moteur de recherche **secondaire**. La base
**PostgreSQL reste la source de vérité** ; OpenSearch n'est qu'un index alimenté
par une pipeline d'indexation. **La sécurité prime sur la performance et la
simplicité** : tout accès passe par le backend Axum, jamais par le frontend.

> Fonctionnalité **opt-in** : sans `OPENSEARCH_URL`, la recherche est désactivée
> et `/api/v1/search` répond `503` proprement. Aucun impact sur le reste de l'API.

## Sommaire

1. [Architecture technique](#1-architecture-technique)
2. [Schéma des flux sécurisés](#2-schéma-des-flux-sécurisés)
3. [Structure des modules Rust](#3-structure-des-modules-rust)
4. [Mapping OpenSearch (exemple)](#4-mapping-opensearch-exemple)
5. [Endpoint Axum `/search`](#5-endpoint-axum-search)
6. [Stratégie d'indexation](#6-stratégie-dindexation)
7. [Checklist sécurité](#7-checklist-sécurité)
8. [Déploiement (Docker + TLS)](#8-déploiement-docker--tls)
9. [Tests](#9-tests)

---

## 1. Architecture technique

Quatre couches, chacune avec une responsabilité unique :

```
handlers::search       Axum : authN obligatoire, validation, rate limit, mapping erreurs
      │
      ▼
SearchService          Métier : RBAC champs, isolation tenant, audit + métriques,
      │                          pipeline d'indexation (événementiel + batch)
      ▼
OpenSearchClient       Bas niveau : TLS/mTLS, auth forte, timeouts, HTTP
      │
      ▼
OpenSearch cluster     JAMAIS exposé au frontend ni à Internet
```

Principes :

- **Confinement** : seul `OpenSearchClient` connaît le protocole HTTP du
  cluster ; les credentials et l'URL ne sortent jamais du backend.
- **Rejet par défaut** : toute entrée externe est désérialisée dans un type
  strict (`#[serde(deny_unknown_fields)]`) puis validée (`garde` + contrôles de
  config) avant d'atteindre la logique.
- **Pas de DSL brut** : le client ne fournit que `q`, `tags`, `sort`, `order`,
  `page`, `page_size`. Le Query DSL est **construit côté serveur** à partir de
  listes blanches. Le texte utilisateur n'alimente qu'un `multi_match` (donnée
  analysée), jamais un `query_string`/`simple_query_string` (mini-langage
  injectable).

## 2. Schéma des flux sécurisés

### Flux de recherche (lecture)

```
Navigateur ──TLS──> Next.js (BFF) ──TLS + Bearer JWT──> Axum /api/v1/search
                                                          │
                              authN (AuthUser, rôle relu en base)
                              validation (ValidatedQuery, deny_unknown_fields)
                              rate limit /search (anti-scraping)
                                                          │
                              SearchService.compile()  ── tenant + rôle DÉRIVÉS
                              (DSL sûr : multi_match + filtre tenant imposé)
                                                          │
                              OpenSearchClient ──HTTPS (TLS≥1.2) + Auth──> OpenSearch
                                                          │
                              audit log (sans donnée sensible) + métriques
                                                          ▼
                              résultats restreints (_source par rôle) ─> client
```

- Le **frontend n'atteint jamais OpenSearch** : `connect-src 'self'` (CSP) +
  appels uniquement vers le BFF ; le BFF appelle Axum ; Axum appelle le cluster.
- Le **tenant et le rôle ne viennent jamais du client** : ils sont dérivés du
  token authentifié → un utilisateur ne peut ni choisir le tenant interrogé, ni
  élargir les champs renvoyés.

### Flux d'indexation (écriture)

```
Mutation métier (PostgreSQL = vérité)
      │  (événement applicatif, ou batch contrôlé)
      ▼
SearchService.index_document() / reindex_batch()  ── tenant_id injecté serveur
      ▼
OpenSearchClient (PUT _doc / _bulk, refresh=wait_for) ──HTTPS──> OpenSearch
```

## 3. Structure des modules Rust

```
backend/src/
├── search/
│   ├── mod.rs        # doc d'architecture + ré-exports
│   ├── client.rs     # OpenSearchClient : TLS/mTLS, auth, timeouts, HTTP, SearchError
│   ├── service.rs    # SearchService : RBAC, tenant, audit/métriques, indexation
│   ├── query.rs      # SearchParams (validé) + compile() -> Query DSL sûr
│   └── index.rs      # mapping versionné, nommage d'index, listes blanches de champs
├── handlers/search.rs# handler Axum /search (authN, validation, 503)
├── config.rs         # SearchConfig (+ SearchAuth) chargé depuis l'env (fail-fast, TLS imposé)
├── state.rs          # AppState.search: Option<Arc<SearchService>>
├── routes/mod.rs     # route /api/v1/search + rate limiting dédié
└── errors.rs         # ApiError::ServiceUnavailable (503) pour indispo/désactivé
```

**Listes blanches** (dans `index.rs`, contrôle RBAC des champs) :

| Liste | Champs | Rôle |
|---|---|---|
| `QUERYABLE_FIELDS` | `title`, `body`, `tags` | cibles du `multi_match` |
| `SORTABLE_FIELDS` | `_score`, `created_at`, `title.raw` | tri autorisé |
| `CLIENT_FILTERABLE_FIELDS` | `tags` | filtres exacts ouverts au client |
| `returnable_fields(role)` | user: `title,tags,created_at` · admin: `+ body` | `_source` renvoyé |

`tenant_id` et `owner_id` sont des filtres **internes** imposés par le serveur,
jamais pilotés par le client (anti-IDOR / anti-énumération).

## 4. Mapping OpenSearch (exemple)

Index `documents`, **mapping strict versionné** (`documents-v1`) — voir
`index::index_definition()` :

```json
{
  "settings": {
    "index": { "number_of_shards": 1, "number_of_replicas": 1, "max_result_window": 10000 }
  },
  "mappings": {
    "dynamic": "strict",
    "properties": {
      "tenant_id":  { "type": "keyword" },
      "owner_id":   { "type": "keyword" },
      "title":      { "type": "text", "fields": { "raw": { "type": "keyword", "ignore_above": 256 } } },
      "body":       { "type": "text" },
      "tags":       { "type": "keyword" },
      "created_at": { "type": "date" }
    }
  }
}
```

- `dynamic: "strict"` : OpenSearch **refuse** tout champ non déclaré → pas de
  pollution de schéma / injection de champ à l'indexation.
- `title.raw` (`keyword`) permet le tri exact sans toucher au champ `text`.
- **Versionnement** : `MAPPING_VERSION` borne le nom (`…-v1`). Une évolution de
  schéma se fait par réindexation vers `…-v2` puis bascule d'alias (migration
  contrôlée, jamais de mapping muté en place).

## 5. Endpoint Axum `/search`

`GET /api/v1/search?q=…&page=&page_size=&sort=&order=&tags=` — **Bearer requis**.

```rust
pub async fn search(
    State(state): State<AppState>,
    auth: AuthUser,                                   // authN + rôle relu en base
    client_ctx: ClientContext,                        // IP/UA pour l'audit
    ValidatedQuery(params): ValidatedQuery<SearchParams>, // deny_unknown_fields + garde
) -> Result<Json<SearchResults>, ApiError> {
    let service = state.search.as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("search disabled".into()))?;
    let ctx = SearchContext { tenant: tenant_for(&auth), role: auth.role }; // dérivé serveur
    Ok(Json(service.search(&ctx, &params, &client_ctx).await?))
}
```

Exemple :

```bash
curl -s 'http://localhost:8080/api/v1/search?q=rapport+annuel&page=1&page_size=10&tags=finance,2026' \
  -H "authorization: Bearer <ACCESS_TOKEN>"
```

Réponse :

```json
{
  "items": [
    { "id": "doc-42", "score": 7.3, "title": "Rapport annuel", "tags": ["finance","2026"], "created_at": 1767225600 }
  ],
  "total": 1,
  "page": 1,
  "page_size": 10
}
```

Codes : `401` (non authentifié), `400` (param inconnu/malformé), `422`
(validation : `q` vide/trop long, `page_size`/pagination hors borne, tri/ filtre
invalides), `429` (rate limit), `503` (recherche désactivée/indisponible).

## 6. Stratégie d'indexation

PostgreSQL est la **source de vérité** ; OpenSearch est reconstructible.

- **Événementiel (unitaire)** : après une mutation métier réussie, appeler
  `SearchService::index_document()` (upsert, `refresh=wait_for` → visible
  immédiatement) ou `delete_document()` (propagation des suppressions). À
  brancher sur la couche métier ; idéalement via un *outbox* transactionnel
  pour garantir « commit DB ⇒ indexation » sans perte.
- **Batch contrôlé** : `reindex_batch()` (`_bulk`, lot **borné** à 1000 docs,
  échecs partiels détectés via `errors`) pour la réindexation initiale ou après
  un bump de `MAPPING_VERSION`.
- **Champs imposés** : `index_document`/`reindex_batch` ne sérialisent **que**
  les champs du mapping strict et **injectent `tenant_id` côté serveur** —
  l'appelant ne contrôle pas le tenant (contrôle des champs *indexables*).
- **Provisioning** : `ensure_index()` crée l'index (mapping versionné) de façon
  idempotente avant le premier batch / à la création d'un tenant.

## 7. Checklist sécurité

### Authentification & autorisation
- [x] Tout accès OpenSearch passe par le backend Axum (aucun chemin frontend).
- [x] `/search` exige un JWT valide (`AuthUser`) ; rôle **relu en base** à chaque requête.
- [x] TLS obligatoire backend ↔ cluster (`https_only`, TLS ≥ 1.2) ; refus de démarrage si `OPENSEARCH_URL` n'est pas `https://`.
- [x] Auth forte cluster : HTTP Basic **ou** ApiKey ; **mTLS** supporté (identité client PEM).
- [x] RBAC champs : *interrogeables*, *triables*, *filtrables*, *consultables* en listes blanches ; `_source` restreint par rôle.

### Protection des requêtes
- [x] Validation stricte des entrées (`deny_unknown_fields` + `garde` + contrôles config).
- [x] Anti-injection DSL : texte utilisateur uniquement en `multi_match` (donnée), jamais `query_string`/`simple_query_string` ; aucune requête brute acceptée.
- [x] Sanitization : rejet des caractères de contrôle ; bornes de longueur sur `q` et les tags.
- [x] Limites : taille de requête (`MAX_QUERY_CHARS`), taille de page (`MAX_PAGE_SIZE`), **profondeur de pagination** (`from+size ≤ MAX_RESULT_WINDOW`), **nombre de filtres** (`MAX_FILTERS`), `terminate_after` + `timeout` côté cluster.
- [x] Wildcards/regex dangereux neutralisés (le `multi_match` ne les interprète pas).
- [x] Rate limiting **dédié et renforcé** sur `/search` (anti-scraping, par IP).

### Isolation & données
- [x] Index dédié par tenant en mode multi-tenant (`{prefix}-{tenant}-vN`) ; noms validés `[a-z0-9_-]`, 1er caractère alphanumérique.
- [x] Filtre `tenant_id` **toujours** imposé par le serveur (défense en profondeur).
- [x] Tenant **dérivé du token**, jamais d'un paramètre client.
- [x] Chiffrement en transit (TLS) sur tous les liens.

### Observabilité
- [x] Logs structurés JSON, **sans donnée sensible** (le texte recherché n'est PAS loggé : seulement longueur, nb de filtres, tenant, rôle).
- [x] **Audit** de chaque recherche (`event = "search_query"`, `security.event = true`).
- [x] Métriques : latence (`search.latency_ms`), total, taux d'erreur (`event = "search_error"`).
- [x] Signaux d'anomalie : erreurs amont en `warn`, rate limit en `429` loggé → exploitable pour l'alerting (burst/scraping).

### Interdictions strictes (respectées)
- [x] Aucun accès direct frontend → OpenSearch.
- [x] Aucun endpoint OpenSearch exposé publiquement.
- [x] Aucune requête dynamique non validée.
- [x] Aucun credential OpenSearch côté client (tout reste serveur ; `Secret` caviardé en `Debug`).

## 8. Déploiement (Docker + TLS)

Un overlay Compose sécurisé est fourni : voir
[`docker-compose.search.yml`](./docker-compose.search.yml) et le script de
génération de certificats
[`docker/opensearch/generate-certs.sh`](./docker/opensearch/generate-certs.sh).

```bash
cd backend
# 1) Générer une CA locale + certs nœud/admin (non committés).
./docker/opensearch/generate-certs.sh
# 2) Lancer la stack avec OpenSearch sécurisé (TLS + security plugin).
docker compose -f docker-compose.yml -f docker-compose.search.yml up -d --build
```

L'overlay active le plugin de sécurité, TLS sur la couche REST, désactive la
config de démo, et injecte les variables `OPENSEARCH_*` dans l'API. Le cluster
n'est **pas** publié sur l'hôte (pas de `ports:`) : il n'est joignable que sur
le réseau Docker interne, par le backend.

## 9. Tests

- **Unitaires** (`cargo test --lib`) :
  - `search::query` : compilation du DSL, anti-injection (les chaînes hostiles
    restent des données du `multi_match`), rejet caractères de contrôle, bornes
    (longueur `q`, `page_size`, profondeur, nb de filtres), tri en liste
    blanche, RBAC `_source`, **fuzzing léger** (2000 entrées adverses :
    jamais de panique, jamais de `query_string`).
  - `search::index` : nommage d'index, rejet de tenants invalides, RBAC champs.
  - `search::service` : corps d'indexation limité aux champs mappés + tenant
    injecté, parsing des résultats, NDJSON du `_bulk`.
- **Intégration HTTP** (`tests/integration.rs`, CI avec PostgreSQL) :
  `/search` exige l'authentification (401), rejette les paramètres inconnus
  (400) et les requêtes vides (422), et répond 503 quand la recherche est
  désactivée — la chaîne authN → validation → dépendance est ainsi couverte
  sans cluster.
- **Bout-en-bout & charge (manuel, cluster requis)** : avec un OpenSearch TLS
  provisionné (cf. §8), exécuter des recherches réelles et un test de charge
  basique, p. ex. :
  ```bash
  # 50 req concurrentes x 200, mesure latence/erreurs (le rate limiting /search
  # doit renvoyer des 429 au-delà du quota — comportement attendu).
  ab -n 200 -c 50 -H "Authorization: Bearer <TOKEN>" \
     'http://localhost:8080/api/v1/search?q=test'
  ```
