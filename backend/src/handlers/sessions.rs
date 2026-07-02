//! Gestion des sessions actives de l'utilisateur courant.
//!
//! Toutes les opérations sont dérivées de `AuthUser` (identité + session
//! courante issues du token, jamais d'un paramètre client) — pas d'IDOR
//! possible : on ne peut lister/révoquer que SES propres sessions.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use uuid::Uuid;

use crate::errors::ApiError;
use crate::middleware::auth::AuthUser;
use crate::models::session::{RevokeResult, SessionList, SessionView};
use crate::state::AppState;

/// GET /api/v1/users/me/sessions — liste les sessions actives.
pub async fn list_sessions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SessionList>, ApiError> {
    let summaries = state.session.list(&auth.id).await?;
    let items = summaries
        .into_iter()
        .map(|s| SessionView::from_summary(s, auth.sid))
        .collect();
    Ok(Json(SessionList { items }))
}

/// DELETE /api/v1/users/me/sessions/{sid} — révoque UNE session (la sienne).
///
/// 204 si révoquée, 404 si elle n'existe pas / n'appartient pas à l'utilisateur
/// (message générique : on ne révèle pas l'existence d'une session tierce).
pub async fn revoke_session(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(sid): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    if state.session.revoke(&auth.id, &sid).await? {
        tracing::info!(
            security.event = true,
            event = "session_revoked",
            user.id = %auth.id,
            "session révoquée par l'utilisateur"
        );
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::NotFound)
    }
}

/// POST /api/v1/users/me/sessions/logout-others — révoque toutes les sessions
/// SAUF la session courante (« se déconnecter des autres appareils »).
pub async fn logout_others(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<RevokeResult>, ApiError> {
    let revoked = state.session.revoke_others(&auth.id, &auth.sid).await?;
    tracing::info!(
        security.event = true,
        event = "sessions_logout_others",
        user.id = %auth.id,
        count = revoked,
        "déconnexion des autres sessions"
    );
    Ok(Json(RevokeResult {
        revoked_sessions: revoked,
    }))
}
