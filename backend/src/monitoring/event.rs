//! Événement de monitoring d'API : ce qui est indexé dans OpenSearch pour
//! observer les succès et erreurs des appels (debugging).
//!
//! Règle de confidentialité (cohérente avec `telemetry`/`errors`) : on n'indexe
//! AUCUNE donnée sensible. Pas de corps de requête/réponse, pas d'en-tête
//! d'autorisation, pas de query string (qui pourrait contenir des termes
//! personnels) — uniquement des métadonnées techniques utiles au debug.

use serde::Serialize;
use serde_json::{json, Value};
use time::OffsetDateTime;

/// Catégorie d'issue d'un appel, dérivée du code HTTP (facilite le filtrage
/// « erreurs vs succès » dans le tableau de bord).
pub fn outcome_for(status: u16) -> &'static str {
    match status {
        500..=599 => "server_error",
        400..=499 => "client_error",
        _ => "success",
    }
}

/// Document indexé pour un appel d'API. Champs alignés sur le mapping strict.
#[derive(Debug, Clone, Serialize)]
pub struct ApiLogEvent {
    /// Horodatage de la requête (sérialisé en RFC3339 → champ `@timestamp`).
    #[serde(rename = "@timestamp", with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    /// Correlation id (croise les logs applicatifs `tracing`).
    pub request_id: String,
    pub method: String,
    /// Chemin de la requête SANS query string (anti-fuite de données).
    pub path: String,
    pub status: u16,
    /// `success` | `client_error` | `server_error`.
    pub outcome: &'static str,
    pub latency_ms: u64,
    /// Code d'erreur applicatif stable, si la réponse en portait un.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

impl ApiLogEvent {
    /// Nom de l'index quotidien cible : `{prefix}-YYYY.MM.DD` (rotation par
    /// jour ⇒ purge/rétention simple via une politique ISM côté cluster).
    pub fn index_name(&self, prefix: &str) -> String {
        let d = self.timestamp.date();
        format!(
            "{prefix}-{:04}.{:02}.{:02}",
            d.year(),
            u8::from(d.month()),
            d.day()
        )
    }
}

/// Nom de l'index template (et préfixe des patterns `*`).
pub const TEMPLATE_NAME: &str = "api-logs";

/// Définition de l'index template : mapping STRICT versionné appliqué à tous
/// les index `{prefix}-*`. `dynamic: strict` refuse tout champ non déclaré.
pub fn index_template(prefix: &str) -> Value {
    json!({
        "index_patterns": [format!("{prefix}-*")],
        "template": {
            "settings": { "number_of_shards": 1, "number_of_replicas": 1 },
            "mappings": {
                "dynamic": "strict",
                "properties": {
                    "@timestamp":  { "type": "date" },
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

/// Sérialise un lot d'événements en NDJSON pour l'API `_bulk`, en routant
/// chaque document vers son index quotidien (action `create`).
pub fn to_bulk_ndjson(events: &[ApiLogEvent], prefix: &str) -> String {
    let mut out = String::with_capacity(events.len() * 256);
    for ev in events {
        let action = json!({ "create": { "_index": ev.index_name(prefix) } });
        out.push_str(&action.to_string());
        out.push('\n');
        // `ApiLogEvent` ne contient que des champs sûrs : sérialisation directe.
        out.push_str(&serde_json::to_string(ev).unwrap_or_else(|_| "{}".to_string()));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(status: u16) -> ApiLogEvent {
        ApiLogEvent {
            timestamp: OffsetDateTime::from_unix_timestamp(1_767_225_600).unwrap(), // 2026-01-01
            request_id: "rid-1".into(),
            method: "GET".into(),
            path: "/api/v1/users/me".into(),
            status,
            outcome: outcome_for(status),
            latency_ms: 12,
            error_code: None,
            client_ip: Some("203.0.113.7".into()),
            user_agent: Some("curl/8".into()),
        }
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
        assert_eq!(sample(200).index_name("api-logs"), "api-logs-2026.01.01");
    }

    #[test]
    fn serialization_excludes_query_and_uses_timestamp_field() {
        let v = serde_json::to_value(sample(200)).unwrap();
        assert!(v.get("@timestamp").is_some());
        assert_eq!(v["path"], "/api/v1/users/me");
        // Aucun champ de corps/secret ne doit apparaître.
        assert!(v.get("authorization").is_none());
        assert!(v.get("body").is_none());
        // error_code absent => non sérialisé.
        assert!(v.get("error_code").is_none());
    }

    #[test]
    fn bulk_ndjson_pairs_action_and_source() {
        let events = vec![sample(200), sample(500)];
        let ndjson = to_bulk_ndjson(&events, "api-logs");
        let lines: Vec<&str> = ndjson.lines().collect();
        assert_eq!(lines.len(), 4); // 2 events => 4 lignes
        assert!(lines[0].contains("\"_index\":\"api-logs-2026.01.01\""));
        assert!(lines[0].contains("\"create\""));
        assert!(lines[1].contains("\"outcome\":\"success\""));
        assert!(lines[3].contains("\"outcome\":\"server_error\""));
    }
}
