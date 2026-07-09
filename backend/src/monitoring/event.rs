//! Documents de log envoyés à OpenSearch (observabilité des appels d'API).
//!
//! Deux familles de documents, dans le MÊME index quotidien, corrélables par
//! `request_id` :
//! - `kind = "access"` : une synthèse par requête HTTP (méthode, chemin, statut,
//!   latence, code d'erreur) — produite par le middleware `layer` ;
//! - `kind = "event"`  : chaque événement `tracing` applicatif (raise d'erreur,
//!   événement de sécurité/métier…) — produit par la couche `log_layer`.
//!
//! Confidentialité (cohérente avec `telemetry`/`errors`) : on n'indexe aucune
//! donnée sensible (ni corps, ni en-tête d'auth, ni query string).

use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Catégorie d'issue d'un appel, dérivée du code HTTP (filtrage « erreurs vs
/// succès » dans le tableau de bord).
pub fn outcome_for(status: u16) -> &'static str {
    match status {
        500..=599 => "server_error",
        400..=499 => "client_error",
        _ => "success",
    }
}

/// Document prêt à indexer : horodatage (pour le routage par index quotidien)
/// + corps JSON (qui contient lui-même `@timestamp`).
#[derive(Debug, Clone)]
pub struct LogDoc {
    pub timestamp: OffsetDateTime,
    pub body: Map<String, Value>,
}

/// Formate un horodatage en RFC3339 (champ `@timestamp`).
fn rfc3339(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339)
        .unwrap_or_else(|_| ts.unix_timestamp().to_string())
}

/// Squelette commun d'un document : `@timestamp`, `kind`, `level`.
pub fn base_doc(ts: OffsetDateTime, kind: &str, level: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("@timestamp".into(), json!(rfc3339(ts)));
    m.insert("kind".into(), json!(kind));
    m.insert("level".into(), json!(level));
    m
}

/// Construit le document de synthèse d'une requête HTTP (`kind = "access"`).
#[allow(clippy::too_many_arguments)]
pub fn access_log(
    ts: OffsetDateTime,
    request_id: String,
    method: String,
    path: String,
    status: u16,
    latency_ms: u64,
    error_code: Option<String>,
    client_ip: Option<String>,
    user_agent: Option<String>,
) -> LogDoc {
    let mut m = base_doc(ts, "access", "info");
    m.insert("request_id".into(), json!(request_id));
    m.insert("method".into(), json!(method));
    m.insert("path".into(), json!(path));
    m.insert("status".into(), json!(status));
    m.insert("outcome".into(), json!(outcome_for(status)));
    m.insert("latency_ms".into(), json!(latency_ms));
    if let Some(ec) = error_code {
        m.insert("error_code".into(), json!(ec));
    }
    if let Some(ip) = client_ip {
        m.insert("client_ip".into(), json!(ip));
    }
    if let Some(ua) = user_agent {
        m.insert("user_agent".into(), json!(ua));
    }
    LogDoc {
        timestamp: ts,
        body: m,
    }
}

/// Nom de l'index template (et préfixe des patterns `*`).
pub const TEMPLATE_NAME: &str = "api-logs";

/// Nom de l'index quotidien cible : `{prefix}-YYYY.MM.DD` (rotation par jour ⇒
/// rétention/purge simple via une politique ISM côté cluster).
pub fn index_name_for(prefix: &str, ts: OffsetDateTime) -> String {
    let d = ts.date();
    format!(
        "{prefix}-{:04}.{:02}.{:02}",
        d.year(),
        u8::from(d.month()),
        d.day()
    )
}

/// Définition de l'index template appliquée à tous les index `{prefix}-*`.
///
/// `dynamic: true` : un index de LOGS doit accepter les champs structurés
/// variables des événements (`event`, `user.id`, `error.detail`…). Les champs
/// usuels sont typés explicitement pour des agrégations correctes.
pub fn index_template(prefix: &str) -> Value {
    json!({
        "index_patterns": [format!("{prefix}-*")],
        "template": {
            "settings": { "number_of_shards": 1, "number_of_replicas": 1 },
            "mappings": {
                "dynamic": true,
                "properties": {
                    "@timestamp":  { "type": "date" },
                    "kind":        { "type": "keyword" },
                    "level":       { "type": "keyword" },
                    "target":      { "type": "keyword" },
                    "message":     { "type": "text" },
                    "request_id":  { "type": "keyword" },
                    "method":      { "type": "keyword" },
                    "path":        { "type": "keyword" },
                    "status":      { "type": "short" },
                    "outcome":     { "type": "keyword" },
                    "latency_ms":  { "type": "long" },
                    "error_code":  { "type": "keyword" },
                    "client_ip":   { "type": "keyword" },
                    "user_agent":  { "type": "keyword" }
                }
            }
        }
    })
}

/// Sérialise un lot de documents en NDJSON pour l'API `_bulk`, en routant
/// chaque document vers son index quotidien (action `create`).
pub fn to_bulk_ndjson(docs: &[LogDoc], prefix: &str) -> String {
    let mut out = String::with_capacity(docs.len() * 256);
    for doc in docs {
        let action = json!({ "create": { "_index": index_name_for(prefix, doc.timestamp) } });
        out.push_str(&action.to_string());
        out.push('\n');
        out.push_str(&serde_json::to_string(&doc.body).unwrap_or_else(|_| "{}".to_string()));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_767_225_600).unwrap() // 2026-01-01
    }

    #[test]
    fn outcome_classification() {
        assert_eq!(outcome_for(200), "success");
        assert_eq!(outcome_for(302), "success");
        assert_eq!(outcome_for(404), "client_error");
        assert_eq!(outcome_for(503), "server_error");
    }

    #[test]
    fn index_name_is_daily() {
        assert_eq!(index_name_for("api-logs", ts()), "api-logs-2026.01.01");
    }

    #[test]
    fn access_log_has_correlation_and_no_sensitive_fields() {
        let d = access_log(
            ts(),
            "rid-1".into(),
            "POST".into(),
            "/api/v1/auth/login".into(),
            401,
            12,
            Some("unauthorized".into()),
            Some("203.0.113.7".into()),
            Some("curl/8".into()),
        );
        assert_eq!(d.body["kind"], "access");
        assert_eq!(d.body["request_id"], "rid-1");
        assert_eq!(d.body["outcome"], "client_error");
        assert_eq!(d.body["error_code"], "unauthorized");
        assert!(d.body.get("@timestamp").is_some());
        // Jamais de corps/secret indexé.
        assert!(d.body.get("authorization").is_none());
        assert!(d.body.get("body").is_none());
    }

    #[test]
    fn outcome_for_class_boundaries() {
        // Frontières exactes des classes HTTP.
        assert_eq!(outcome_for(0), "success");
        assert_eq!(outcome_for(199), "success");
        assert_eq!(outcome_for(399), "success");
        assert_eq!(outcome_for(400), "client_error");
        assert_eq!(outcome_for(499), "client_error");
        assert_eq!(outcome_for(500), "server_error");
        assert_eq!(outcome_for(599), "server_error");
        // Au-delà de 599 (codes non standard) : traité comme succès (défaut).
        assert_eq!(outcome_for(600), "success");
    }

    #[test]
    fn index_name_zero_pads_month_and_day() {
        // 2026-03-07 : mois et jour à un chiffre doivent être zéro-paddés.
        let ts = OffsetDateTime::from_unix_timestamp(1_772_841_600).unwrap();
        assert_eq!(index_name_for("logs", ts), "logs-2026.03.07");
    }

    #[test]
    fn base_doc_carries_kind_and_level() {
        let d = base_doc(ts(), "event", "warn");
        assert_eq!(d["kind"], "event");
        assert_eq!(d["level"], "warn");
        assert!(d.get("@timestamp").is_some());
    }

    #[test]
    fn access_log_omits_absent_optional_fields() {
        let d = access_log(
            ts(),
            "r".into(),
            "GET".into(),
            "/x".into(),
            200,
            1,
            None,
            None,
            None,
        );
        assert!(d.body.get("error_code").is_none());
        assert!(d.body.get("client_ip").is_none());
        assert!(d.body.get("user_agent").is_none());
        // Les champs obligatoires restent présents.
        assert_eq!(d.body["outcome"], "success");
        assert_eq!(d.body["status"], 200);
    }

    #[test]
    fn empty_docs_produce_empty_ndjson() {
        assert_eq!(to_bulk_ndjson(&[], "api-logs"), "");
    }

    #[test]
    fn index_template_targets_prefix_pattern() {
        let tpl = index_template("api-logs");
        assert_eq!(tpl["index_patterns"][0], "api-logs-*");
        assert_eq!(tpl["template"]["mappings"]["dynamic"], true);
        assert_eq!(
            tpl["template"]["mappings"]["properties"]["request_id"]["type"],
            "keyword"
        );
    }

    #[test]
    fn bulk_ndjson_pairs_action_and_source() {
        let docs = vec![
            access_log(
                ts(),
                "a".into(),
                "GET".into(),
                "/x".into(),
                200,
                1,
                None,
                None,
                None,
            ),
            access_log(
                ts(),
                "b".into(),
                "GET".into(),
                "/y".into(),
                500,
                2,
                None,
                None,
                None,
            ),
        ];
        let ndjson = to_bulk_ndjson(&docs, "api-logs");
        let lines: Vec<&str> = ndjson.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].contains("\"_index\":\"api-logs-2026.01.01\""));
        assert!(lines[1].contains("\"request_id\":\"a\""));
        assert!(lines[3].contains("\"status\":500"));
    }
}
