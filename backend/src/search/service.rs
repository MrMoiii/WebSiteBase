//! Abstraction métier de la recherche.
//!
//! `SearchService` est la frontière entre les handlers Axum et OpenSearch :
//! - il compile les paramètres en Query DSL sûr (`query::compile`) ;
//! - il impose l'isolation par tenant (index dédié + filtre `tenant_id`) ;
//! - il restreint les champs renvoyés selon le rôle (`_source`) ;
//! - il journalise un AUDIT de chaque recherche (sans donnée sensible) et des
//!   métriques (latence, total, erreurs) ;
//! - il pilote l'indexation (événementielle unitaire + batch contrôlé).

use std::time::Instant;

use serde::Serialize;
use serde_json::{json, Map, Value};
use time::OffsetDateTime;

use crate::config::SearchConfig;
use crate::errors::ApiError;
use crate::middleware::client::ClientContext;

use super::client::{OpenSearchClient, SearchError};
use super::index::{index_definition, index_name, MAPPING_VERSION};
use super::query::{self, CompiledQuery, SearchContext, SearchParams};

/// Service de recherche prêt à l'emploi (client + politique de config).
#[derive(Clone)]
pub struct SearchService {
    client: OpenSearchClient,
    cfg: SearchConfig,
}

/// Un résultat de recherche : id + score + champs CONSULTABLES uniquement.
#[derive(Debug, Serialize)]
pub struct SearchHit {
    pub id: String,
    pub score: Option<f64>,
    /// Champs `_source` restreints par le rôle (jamais `tenant_id`/`owner_id`).
    #[serde(flatten)]
    pub fields: Map<String, Value>,
}

/// Enveloppe paginée renvoyée au handler.
#[derive(Debug, Serialize)]
pub struct SearchResults {
    pub items: Vec<SearchHit>,
    pub total: i64,
    pub page: i64,
    pub page_size: i64,
}

/// Document métier indexable (exemple : index `documents`). Seuls ces champs —
/// déclarés dans le mapping strict — sont envoyés à OpenSearch (contrôle des
/// champs INDEXABLES). `tenant_id` est ajouté par le service, pas par l'appelant.
#[derive(Debug, Clone)]
pub struct DocumentInput {
    pub id: String,
    pub title: String,
    pub body: String,
    pub tags: Vec<String>,
    pub owner_id: String,
    pub created_at: OffsetDateTime,
}

impl SearchService {
    /// Construit le service à partir de la configuration validée.
    pub fn from_config(cfg: &SearchConfig) -> Result<Self, SearchError> {
        Ok(Self {
            client: OpenSearchClient::from_config(cfg)?,
            cfg: cfg.clone(),
        })
    }

    /// Vérifie la disponibilité du cluster (readiness).
    pub async fn ping(&self) -> Result<(), SearchError> {
        self.client.ping().await
    }

    /// Nom d'index résolu pour un tenant, selon le mode mono/multi-tenant.
    fn resolve_index(&self, tenant: &str) -> Result<String, ApiError> {
        let tenant_arg = if self.cfg.multi_tenant {
            Some(tenant)
        } else {
            None
        };
        index_name(&self.cfg.index_prefix, tenant_arg, MAPPING_VERSION).ok_or_else(|| {
            // tenant invalide : ne devrait pas arriver (validé en amont).
            ApiError::Internal("invalid tenant for index resolution".into())
        })
    }

    /// Exécute une recherche validée et journalise l'audit + les métriques.
    pub async fn search(
        &self,
        ctx: &SearchContext,
        params: &SearchParams,
        client_ctx: &ClientContext,
    ) -> Result<SearchResults, ApiError> {
        let compiled = query::compile(params, &self.cfg, ctx)?;
        let index = self.resolve_index(&ctx.tenant)?;

        let started = Instant::now();
        let result = self.client.search(&index, &compiled.body).await;
        let latency_ms = started.elapsed().as_millis();

        match result {
            Ok(raw) => {
                let results = parse_results(&raw, &compiled)?;
                // AUDIT (exigence #11/12) : aucune donnée sensible. On NE logge
                // PAS le texte recherché (potentiellement personnel) — seulement
                // sa longueur, le nombre de filtres, le tenant, le rôle, la
                // latence et le total. Exploitable par un SIEM.
                tracing::info!(
                    security.event = true,
                    event = "search_query",
                    search.tenant = %ctx.tenant,
                    search.role = ?ctx.role,
                    search.q_chars = params.q.chars().count(),
                    search.filters = filter_count(params),
                    search.page = compiled.page,
                    search.page_size = compiled.page_size,
                    search.total = results.total,
                    search.latency_ms = latency_ms as u64,
                    client.ip = client_ctx.ip.as_deref().unwrap_or("unknown"),
                    "recherche exécutée"
                );
                Ok(results)
            }
            Err(err) => {
                // Métrique de taux d'erreur + signal d'anomalie (détail interne).
                tracing::warn!(
                    security.event = true,
                    event = "search_error",
                    search.tenant = %ctx.tenant,
                    search.latency_ms = latency_ms as u64,
                    error.detail = %err,
                    "échec de recherche"
                );
                Err(err.into())
            }
        }
    }

    /// S'assure que l'index d'un tenant existe (mapping versionné, strict).
    /// Idempotent : à appeler au provisioning d'un tenant ou avant un batch.
    pub async fn ensure_index(&self, tenant: &str) -> Result<(), ApiError> {
        let index = self.resolve_index(tenant)?;
        self.client
            .ensure_index(&index, &index_definition())
            .await?;
        Ok(())
    }

    /// Indexation ÉVÉNEMENTIELLE d'un document (à appeler après une mutation
    /// métier : création/màj). `tenant_id` est injecté par le service.
    pub async fn index_document(&self, tenant: &str, doc: &DocumentInput) -> Result<(), ApiError> {
        let index = self.resolve_index(tenant)?;
        let body = document_body(tenant, doc);
        self.client.index_document(&index, &doc.id, &body).await?;
        tracing::info!(
            event = "search_indexed",
            search.tenant = %tenant,
            "document indexé"
        );
        Ok(())
    }

    /// Supprime un document de l'index (suppression métier propagée).
    pub async fn delete_document(&self, tenant: &str, id: &str) -> Result<(), ApiError> {
        let index = self.resolve_index(tenant)?;
        self.client.delete_document(&index, id).await?;
        Ok(())
    }

    /// Réindexation BATCH contrôlée (`_bulk`). Borne la taille du lot pour
    /// éviter une requête géante. `tenant_id` est imposé pour chaque document.
    pub async fn reindex_batch(
        &self,
        tenant: &str,
        docs: &[DocumentInput],
    ) -> Result<(), ApiError> {
        const MAX_BATCH: usize = 1_000;
        if docs.len() > MAX_BATCH {
            return Err(ApiError::Validation(format!(
                "Batch too large (max {MAX_BATCH} documents)."
            )));
        }
        let index = self.resolve_index(tenant)?;
        let ndjson = build_bulk_ndjson(&index, tenant, docs);
        let resp = self.client.bulk(ndjson).await?;
        // `_bulk` renvoie 200 même en cas d'échecs partiels : on inspecte `errors`.
        if resp["errors"].as_bool() == Some(true) {
            tracing::error!(
                event = "search_bulk_partial_failure",
                search.tenant = %tenant,
                "échecs partiels lors de la réindexation"
            );
            return Err(ApiError::Internal("bulk indexing had errors".into()));
        }
        Ok(())
    }
}

/// Construit le corps JSON d'un document à indexer : UNIQUEMENT les champs du
/// mapping strict + `tenant_id` injecté côté serveur.
fn document_body(tenant: &str, doc: &DocumentInput) -> Value {
    json!({
        "tenant_id": tenant,
        "owner_id": doc.owner_id,
        "title": doc.title,
        "body": doc.body,
        "tags": doc.tags,
        "created_at": doc.created_at.unix_timestamp(),
    })
}

/// Sérialise un lot en NDJSON pour l'API `_bulk` (action + source par doc).
fn build_bulk_ndjson(index: &str, tenant: &str, docs: &[DocumentInput]) -> String {
    let mut out = String::new();
    for doc in docs {
        let action = json!({ "index": { "_index": index, "_id": doc.id } });
        let source = document_body(tenant, doc);
        out.push_str(&action.to_string());
        out.push('\n');
        out.push_str(&source.to_string());
        out.push('\n');
    }
    out
}

/// Nombre de filtres effectifs fournis par le client (pour l'audit).
fn filter_count(params: &SearchParams) -> usize {
    params
        .tags
        .as_deref()
        .map(|t| t.split(',').filter(|s| !s.trim().is_empty()).count())
        .unwrap_or(0)
}

/// Transforme la réponse brute d'OpenSearch en résultats typés et sûrs.
fn parse_results(raw: &Value, compiled: &CompiledQuery) -> Result<SearchResults, ApiError> {
    let hits = &raw["hits"];
    // `rest_total_hits_as_int=true` => total est un entier.
    let total = hits["total"].as_i64().unwrap_or(0);

    let items = hits["hits"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|h| SearchHit {
                    id: h["_id"].as_str().unwrap_or_default().to_string(),
                    score: h["_score"].as_f64(),
                    fields: h["_source"].as_object().cloned().unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(SearchResults {
        items,
        total,
        page: compiled.page,
        page_size: compiled.page_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn document_body_only_contains_mapped_fields() {
        let doc = DocumentInput {
            id: "1".into(),
            title: "t".into(),
            body: "b".into(),
            tags: vec!["x".into()],
            owner_id: "o".into(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        };
        let body = document_body("acme", &doc);
        let obj = body.as_object().unwrap();
        let mut keys: Vec<&String> = obj.keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "body",
                "created_at",
                "owner_id",
                "tags",
                "tenant_id",
                "title"
            ]
        );
        // tenant injecté par le serveur, jamais par l'appelant.
        assert_eq!(obj["tenant_id"], "acme");
    }

    #[test]
    fn parse_results_extracts_hits_and_total() {
        let raw = json!({
            "hits": {
                "total": 2,
                "hits": [
                    { "_id": "a", "_score": 1.5, "_source": { "title": "hello" } },
                    { "_id": "b", "_score": 0.5, "_source": { "title": "world" } }
                ]
            }
        });
        let compiled = CompiledQuery {
            page: 1,
            page_size: 20,
            from: 0,
            size: 20,
            body: json!({}),
        };
        let r = parse_results(&raw, &compiled).unwrap();
        assert_eq!(r.total, 2);
        assert_eq!(r.items.len(), 2);
        assert_eq!(r.items[0].id, "a");
        assert_eq!(r.items[0].fields["title"], "hello");
    }

    #[test]
    fn bulk_ndjson_is_well_formed() {
        let docs = vec![DocumentInput {
            id: "1".into(),
            title: "t".into(),
            body: "b".into(),
            tags: vec![],
            owner_id: "o".into(),
            created_at: OffsetDateTime::UNIX_EPOCH,
        }];
        let ndjson = build_bulk_ndjson("documents-v1", "public", &docs);
        let lines: Vec<&str> = ndjson.lines().collect();
        assert_eq!(lines.len(), 2); // une ligne d'action + une ligne source
        assert!(lines[0].contains("\"_index\":\"documents-v1\""));
        assert!(lines[1].contains("\"tenant_id\":\"public\""));
    }
}
