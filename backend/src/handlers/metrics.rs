//! Endpoint d'exposition des métriques Prometheus (`GET /metrics`).
//!
//! Non authentifié et sans donnée sensible : uniquement des agrégats numériques
//! (compteurs/histogrammes). Destiné au *scrape* par Prometheus sur le réseau
//! interne — à restreindre au niveau réseau/reverse proxy en production (ne pas
//! exposer publiquement).

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;

use crate::state::AppState;

/// GET /metrics — exposition au format texte Prometheus (version 0.0.4).
pub async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let body = state.metrics.render();
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}
