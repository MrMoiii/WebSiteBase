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
