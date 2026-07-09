//! Vues de sortie pour la gestion des sessions actives.

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::session::SessionSummary;

/// Représentation publique d'une session active de l'utilisateur courant.
#[derive(Debug, Serialize)]
pub struct SessionView {
    /// Identifiant de session (`sid`).
    pub id: Uuid,
    /// Horodatages RFC3339 (comme le reste de l'API).
    pub created_at: String,
    pub last_seen: String,
    pub user_agent: Option<String>,
    pub ip: Option<String>,
    /// `true` s'il s'agit de la session ayant émis la requête courante.
    pub current: bool,
}

impl SessionView {
    /// Construit la vue à partir du résumé stocké, en marquant la session
    /// courante (`current_sid`).
    pub fn from_summary(s: SessionSummary, current_sid: Uuid) -> Self {
        SessionView {
            current: s.sid == current_sid,
            id: s.sid,
            created_at: unix_to_rfc3339(s.created_at),
            last_seen: unix_to_rfc3339(s.last_seen),
            user_agent: s.user_agent,
            ip: s.ip,
        }
    }
}

/// Enveloppe de la liste des sessions.
#[derive(Debug, Serialize)]
pub struct SessionList {
    pub items: Vec<SessionView>,
}

/// Réponse d'une révocation de masse.
#[derive(Debug, Serialize)]
pub struct RevokeResult {
    pub revoked_sessions: u64,
}

/// Convertit un timestamp Unix (secondes) en RFC3339 ; repli sur epoch si invalide.
fn unix_to_rfc3339(secs: i64) -> String {
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|d| d.format(&Rfc3339).ok())
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(sid: Uuid) -> SessionSummary {
        SessionSummary {
            sid,
            created_at: 1_767_225_600, // 2026-01-01T00:00:00Z
            last_seen: 1_767_229_200,  // 2026-01-01T01:00:00Z
            user_agent: Some("curl/8".into()),
            ip: Some("203.0.113.7".into()),
        }
    }

    #[test]
    fn from_summary_marks_current_session() {
        let sid = Uuid::new_v4();
        let view = SessionView::from_summary(summary(sid), sid);
        assert!(view.current);
        assert_eq!(view.id, sid);
        assert_eq!(view.created_at, "2026-01-01T00:00:00Z");
        assert_eq!(view.last_seen, "2026-01-01T01:00:00Z");
        assert_eq!(view.user_agent.as_deref(), Some("curl/8"));
        assert_eq!(view.ip.as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn from_summary_non_current_is_false() {
        let view = SessionView::from_summary(summary(Uuid::new_v4()), Uuid::new_v4());
        assert!(!view.current);
    }

    #[test]
    fn unix_to_rfc3339_known_and_epoch() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_rfc3339(1_767_225_600), "2026-01-01T00:00:00Z");
    }

    #[test]
    fn unix_to_rfc3339_negative_is_pre_epoch() {
        // Un timestamp négatif est valide (avant 1970) et doit se formater, pas
        // retomber sur le repli.
        assert_eq!(unix_to_rfc3339(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn unix_to_rfc3339_out_of_range_falls_back_to_epoch() {
        // i64::MAX dépasse la plage représentable -> repli déterministe.
        assert_eq!(unix_to_rfc3339(i64::MAX), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_rfc3339(i64::MIN), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn revoke_result_serializes_count() {
        let json = serde_json::to_string(&RevokeResult {
            revoked_sessions: 3,
        })
        .unwrap();
        assert_eq!(json, r#"{"revoked_sessions":3}"#);
    }
}
