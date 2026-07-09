//! Endpoints de santé (liveness / readiness) pour l'orchestrateur et le
//! healthcheck Docker. Non authentifiés et sans donnée sensible.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::json;

use crate::state::AppState;

/// GET /health — liveness simple (le process répond).
pub async fn liveness() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// GET /health/ready — readiness : vérifie l'accès à la base de données.
pub async fn readiness(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    match sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pool)
        .await
    {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ready" }))),
        Err(e) => {
            // Détail loggé côté serveur, jamais renvoyé au client.
            tracing::error!(error.detail = %e, "readiness: base de données injoignable");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "unavailable" })),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn liveness_reports_ok_without_side_effects() {
        let Json(body) = liveness().await;
        assert_eq!(body, json!({ "status": "ok" }));
    }
}
