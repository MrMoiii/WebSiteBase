//! Validation stricte des paramètres de recherche et compilation en Query DSL
//! OpenSearch SÛR.
//!
//! Pierre angulaire anti-injection (exigence #2 du cahier des charges) :
//! - le texte utilisateur est injecté UNIQUEMENT dans un `multi_match`, où il
//!   est traité comme une DONNÉE analysée — jamais via `query_string` /
//!   `simple_query_string` (qui interprètent une mini-syntaxe et permettraient
//!   l'injection d'opérateurs, wildcards, regex…) ;
//! - aucune requête DSL brute venant du client n'est acceptée : le client ne
//!   fournit que `q`, des filtres `tags`, un tri et une pagination, tous validés ;
//! - les cibles de recherche, de tri et de filtre sont des LISTES BLANCHES ;
//! - les bornes (longueur de `q`, taille de page, profondeur de pagination,
//!   nombre de filtres) viennent de la configuration et sont imposées ici.

use garde::Validate;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::config::SearchConfig;
use crate::errors::ApiError;
use crate::models::user::UserRole;

use super::index::{
    returnable_fields, CLIENT_FILTERABLE_FIELDS, QUERYABLE_FIELDS, SORTABLE_FIELDS,
};

/// Paramètres de recherche reçus en query string (`/search?q=…`).
///
/// `deny_unknown_fields` : tout paramètre non prévu fait échouer la requête
/// (pas de canal caché pour injecter du DSL). Les bornes `garde` ici sont des
/// gardes-fous HAUTS ; les bornes fines (config) sont appliquées à la compilation.
#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct SearchParams {
    /// Requête plein-texte (donnée, pas du DSL).
    #[garde(length(chars, min = 1, max = 1024))]
    pub q: String,
    /// Page (1-based).
    #[garde(inner(range(min = 1, max = 100_000)))]
    pub page: Option<i64>,
    /// Taille de page.
    #[garde(inner(range(min = 1, max = 1000)))]
    pub page_size: Option<i64>,
    /// Champ de tri (doit appartenir à la liste blanche).
    #[garde(inner(length(chars, max = 32)))]
    pub sort: Option<String>,
    /// Sens du tri : `asc` ou `desc`.
    #[garde(inner(length(chars, max = 4)))]
    pub order: Option<String>,
    /// Filtres `tags` séparés par des virgules (ET logique).
    #[garde(inner(length(chars, max = 512)))]
    pub tags: Option<String>,
}

/// Contexte serveur de la recherche : valeurs DÉRIVÉES de l'utilisateur
/// authentifié, jamais fournies par le client.
#[derive(Debug, Clone)]
pub struct SearchContext {
    /// Tenant logique (isolation). Validé `[a-z0-9_-]` en amont.
    pub tenant: String,
    /// Rôle courant (pilote les champs consultables).
    pub role: UserRole,
}

/// Requête compilée : pagination effective + corps `_search` prêt à envoyer.
#[derive(Debug, Clone)]
pub struct CompiledQuery {
    pub page: i64,
    pub page_size: i64,
    pub from: i64,
    pub size: i64,
    /// Corps JSON du `POST {index}/_search`. Entièrement construit côté serveur.
    pub body: Value,
}

/// Taille de page par défaut si non précisée (bornée par la config).
const DEFAULT_PAGE_SIZE: i64 = 20;

/// Compile des paramètres validés en une requête OpenSearch sûre.
///
/// Effectue les contrôles dépendant de la configuration (longueur de `q`,
/// taille de page, profondeur de pagination, nombre/format des filtres, champ
/// de tri en liste blanche) et renvoie une [`ApiError`] explicite mais sûre en
/// cas de violation. AUCUNE valeur client n'est interpolée en tant que DSL.
pub fn compile(
    params: &SearchParams,
    cfg: &SearchConfig,
    ctx: &SearchContext,
) -> Result<CompiledQuery, ApiError> {
    // --- 1) Texte de recherche : sanitization + bornes de config ------------
    let q = params.q.trim();
    if q.is_empty() {
        return Err(ApiError::Validation(
            "Search query must not be empty.".into(),
        ));
    }
    if q.chars().count() > cfg.max_query_chars {
        return Err(ApiError::Validation(format!(
            "Search query too long (max {} characters).",
            cfg.max_query_chars
        )));
    }
    if contains_control_chars(q) {
        return Err(ApiError::Validation(
            "Search query contains forbidden control characters.".into(),
        ));
    }

    // --- 2) Pagination : bornes + profondeur --------------------------------
    let page = params.page.unwrap_or(1).max(1);
    let page_size = params
        .page_size
        .unwrap_or(DEFAULT_PAGE_SIZE.min(cfg.max_page_size))
        .clamp(1, i64::MAX);
    if page_size > cfg.max_page_size {
        return Err(ApiError::Validation(format!(
            "page_size too large (max {}).",
            cfg.max_page_size
        )));
    }
    let from = (page - 1).saturating_mul(page_size);
    // Borne la pagination profonde (anti-DoS, aligné `max_result_window`).
    if from.saturating_add(page_size) > cfg.max_result_window {
        return Err(ApiError::Validation(format!(
            "Pagination too deep (from + size must be <= {}).",
            cfg.max_result_window
        )));
    }

    // --- 3) Tri : champ + sens en liste blanche -----------------------------
    let sort = build_sort(params.sort.as_deref(), params.order.as_deref())?;

    // --- 4) Filtres client (tags) : format + nombre -------------------------
    let mut filters: Vec<Value> = Vec::new();
    // Isolation : filtre tenant TOUJOURS imposé par le serveur (défense en
    // profondeur, en plus de l'index dédié au tenant).
    filters.push(json!({ "term": { "tenant_id": ctx.tenant } }));

    if let Some(raw) = params.tags.as_deref() {
        let tags = parse_tags(raw, cfg.max_filters)?;
        if !tags.is_empty() {
            // `terms` = ensemble de valeurs exactes (donnée, pas du DSL). On
            // exige la présence d'AU MOINS un des tags (filtre, pas scoring).
            debug_assert!(CLIENT_FILTERABLE_FIELDS.contains(&"tags"));
            filters.push(json!({ "terms": { "tags": tags } }));
        }
    }

    // --- 5) Assemblage du corps `_search` -----------------------------------
    let source: Vec<&str> = returnable_fields(ctx.role).to_vec();

    let body = json!({
        "from": from,
        "size": page_size,
        // Ne renvoyer QUE les champs consultables (contrôle RBAC de sortie).
        "_source": source,
        // Borne le coût de comptage des hits (n'énumère pas au-delà).
        "track_total_hits": cfg.max_result_window,
        // Timeout côté cluster (complète le timeout réseau du client HTTP).
        "timeout": format!("{}s", cfg.request_timeout.as_secs().max(1)),
        // Borne le nombre de documents examinés par shard (anti-DoS).
        "terminate_after": cfg.max_result_window,
        "query": {
            "bool": {
                // Le texte utilisateur ne touche QUE multi_match (donnée analysée).
                "must": [{
                    "multi_match": {
                        "query": q,
                        "fields": boosted_fields(),
                        "type": "best_fields",
                        "operator": "and",
                        "zero_terms_query": "none"
                    }
                }],
                // Filtres exacts (n'influencent pas le score, cacheables).
                "filter": filters
            }
        },
        "sort": sort
    });

    Ok(CompiledQuery {
        page,
        page_size,
        from,
        size: page_size,
        body,
    })
}

/// Champs interrogeables avec pondération (boost). Dérivé de la liste blanche.
fn boosted_fields() -> Vec<String> {
    QUERYABLE_FIELDS
        .iter()
        .map(|f| match *f {
            "title" => "title^3".to_string(),
            "tags" => "tags^2".to_string(),
            other => other.to_string(),
        })
        .collect()
}

/// Construit la clause de tri à partir d'un champ + d'un sens validés.
fn build_sort(sort: Option<&str>, order: Option<&str>) -> Result<Value, ApiError> {
    let field = match sort {
        None => return Ok(json!([{ "_score": { "order": "desc" } }])),
        Some(s) => s,
    };
    if !SORTABLE_FIELDS.contains(&field) {
        return Err(ApiError::Validation(format!(
            "Unsupported sort field. Allowed: {}.",
            SORTABLE_FIELDS.join(", ")
        )));
    }
    let order = match order.unwrap_or("desc") {
        "asc" => "asc",
        "desc" => "desc",
        _ => {
            return Err(ApiError::Validation(
                "Sort order must be 'asc' or 'desc'.".into(),
            ))
        }
    };
    Ok(json!([{ field: { "order": order } }]))
}

/// Découpe et valide une liste de tags séparés par des virgules.
///
/// Refuse : caractères de contrôle, tags trop longs, et dépassement du nombre
/// maximal de filtres (borne la « profondeur » des filtres — exigence).
fn parse_tags(raw: &str, max_filters: usize) -> Result<Vec<String>, ApiError> {
    let tags: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect();

    if tags.len() > max_filters {
        return Err(ApiError::Validation(format!(
            "Too many tag filters (max {max_filters})."
        )));
    }
    for tag in &tags {
        if tag.chars().count() > 64 {
            return Err(ApiError::Validation(
                "A tag filter is too long (max 64 characters).".into(),
            ));
        }
        if contains_control_chars(tag) {
            return Err(ApiError::Validation(
                "A tag filter contains forbidden control characters.".into(),
            ));
        }
    }
    Ok(tags)
}

/// Détecte la présence d'un caractère de contrôle (C0/C1 hors espaces usuels).
fn contains_control_chars(s: &str) -> bool {
    s.chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SearchConfig {
        use crate::config::{SearchAuth, Secret};
        use std::time::Duration;
        SearchConfig {
            base_url: "https://opensearch:9200".into(),
            auth: SearchAuth::ApiKey(Secret::new("k")),
            ca_cert_path: None,
            client_identity_path: None,
            index_prefix: "documents".into(),
            multi_tenant: false,
            request_timeout: Duration::from_secs(5),
            max_query_chars: 256,
            max_page_size: 50,
            max_result_window: 10_000,
            max_filters: 8,
        }
    }

    fn ctx() -> SearchContext {
        SearchContext {
            tenant: "public".into(),
            role: UserRole::User,
        }
    }

    fn params(q: &str) -> SearchParams {
        SearchParams {
            q: q.into(),
            page: None,
            page_size: None,
            sort: None,
            order: None,
            tags: None,
        }
    }

    #[test]
    fn compiles_a_basic_query_into_multi_match() {
        let c = compile(&params("hello world"), &cfg(), &ctx()).unwrap();
        let must = &c.body["query"]["bool"]["must"][0];
        // Le texte va dans multi_match, JAMAIS dans query_string.
        assert!(must.get("multi_match").is_some());
        assert!(must.get("query_string").is_none());
        assert_eq!(must["multi_match"]["query"], "hello world");
        assert_eq!(must["multi_match"]["operator"], "and");
    }

    #[test]
    fn always_injects_tenant_filter() {
        let c = compile(&params("x"), &cfg(), &ctx()).unwrap();
        let filters = c.body["query"]["bool"]["filter"].as_array().unwrap();
        assert!(filters.iter().any(|f| f["term"]["tenant_id"] == "public"));
    }

    #[test]
    fn injection_attempts_are_treated_as_plain_text() {
        // Ces chaînes seraient dangereuses dans query_string : ici ce sont de
        // simples données passées à multi_match (aucune interprétation DSL).
        for evil in [
            "*",
            "title:admin OR _exists_:password",
            ") OR (1=1",
            "a\\b~2 /etc/passwd/",
        ] {
            let c = compile(&params(evil), &cfg(), &ctx()).unwrap();
            assert_eq!(
                c.body["query"]["bool"]["must"][0]["multi_match"]["query"],
                evil
            );
        }
    }

    #[test]
    fn rejects_control_characters() {
        let p = params("bad\u{0000}query");
        assert!(matches!(
            compile(&p, &cfg(), &ctx()),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn rejects_query_longer_than_config() {
        let long = "a".repeat(300);
        assert!(matches!(
            compile(&params(&long), &cfg(), &ctx()),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn rejects_page_size_over_limit() {
        let mut p = params("x");
        p.page_size = Some(51);
        assert!(matches!(
            compile(&p, &cfg(), &ctx()),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn rejects_deep_pagination() {
        let mut p = params("x");
        p.page = Some(1_000);
        p.page_size = Some(50); // from = 49_950 > 10_000
        assert!(matches!(
            compile(&p, &cfg(), &ctx()),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn rejects_unknown_sort_field() {
        let mut p = params("x");
        p.sort = Some("password".into());
        assert!(matches!(
            compile(&p, &cfg(), &ctx()),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn accepts_whitelisted_sort_field() {
        let mut p = params("x");
        p.sort = Some("created_at".into());
        p.order = Some("asc".into());
        let c = compile(&p, &cfg(), &ctx()).unwrap();
        assert_eq!(c.body["sort"][0]["created_at"]["order"], "asc");
    }

    #[test]
    fn rejects_too_many_tag_filters() {
        let mut p = params("x");
        p.tags = Some(
            (0..20)
                .map(|i| format!("t{i}"))
                .collect::<Vec<_>>()
                .join(","),
        );
        assert!(matches!(
            compile(&p, &cfg(), &ctx()),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn admin_source_includes_body_user_does_not() {
        let admin_ctx = SearchContext {
            tenant: "public".into(),
            role: UserRole::Admin,
        };
        let user = compile(&params("x"), &cfg(), &ctx()).unwrap();
        let admin = compile(&params("x"), &cfg(), &admin_ctx).unwrap();
        let user_src = user.body["_source"].as_array().unwrap();
        let admin_src = admin.body["_source"].as_array().unwrap();
        assert!(!user_src.iter().any(|v| v == "body"));
        assert!(admin_src.iter().any(|v| v == "body"));
    }

    #[test]
    fn fuzz_compile_never_panics_and_never_emits_query_string() {
        // Fuzzing léger sans dépendance : un PRNG (LCG) déterministe génère des
        // chaînes adverses. Invariants : (1) `compile` ne panique jamais ;
        // (2) en cas de succès, le texte n'atteint QUE `multi_match` — jamais
        // `query_string`/`simple_query_string` (pas d'injection d'opérateurs).
        let mut seed: u64 = 0x9E3779B97F4A7C15;
        let alphabet: &[u8] = b"abc 09*?~:/\\(){}[]\"'^!+-_=<>|&.";
        for _ in 0..2_000 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let len = (seed >> 33) as usize % 300;
            let s: String = (0..len)
                .map(|i| {
                    let r = (seed.rotate_left(i as u32 % 63)) as usize;
                    alphabet[r % alphabet.len()] as char
                })
                .collect();

            if let Ok(c) = compile(&params(&s), &cfg(), &ctx()) {
                let must = &c.body["query"]["bool"]["must"][0];
                assert!(must.get("multi_match").is_some());
                assert!(must.get("query_string").is_none());
                assert!(must.get("simple_query_string").is_none());
                // Le tenant reste toujours imposé, quel que soit l'input.
                let filters = c.body["query"]["bool"]["filter"].as_array().unwrap();
                assert!(filters.iter().any(|f| f["term"]["tenant_id"] == "public"));
            }
        }
    }

    #[test]
    fn pagination_fields_are_consistent() {
        let mut p = params("x");
        p.page = Some(3);
        p.page_size = Some(10);
        let c = compile(&p, &cfg(), &ctx()).unwrap();
        assert_eq!(c.from, 20);
        assert_eq!(c.size, 10);
        assert_eq!(c.body["from"], 20);
        assert_eq!(c.body["size"], 10);
    }
}
