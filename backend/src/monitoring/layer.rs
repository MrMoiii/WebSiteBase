//! Middleware Axum capturant l'issue de CHAQUE requête (succès/erreur) pour
//! l'envoyer au monitoring OpenSearch.
//!
//! Placement (cf. `routes`) : à l'intérieur du `SetRequestIdLayer` (pour lire
//! le correlation id) mais à l'extérieur des couches métier (timeout, CORS,
//! limites…), afin de capturer aussi les 408/413/500 générés par la pile.
//!
//! Strictement NON BLOQUANT : on n'émet qu'un `record()` best-effort après la
//! réponse ; aucune attente réseau sur le chemin de la requête.

use std::time::Instant;

use axum::extract::{Request, State};
use axum::http::header::USER_AGENT;
use axum::middleware::Next;
use axum::response::Response;
use time::OffsetDateTime;

use crate::errors::ErrorCode;
use crate::middleware::client::{client_ip, peer_ip};
use crate::state::AppState;

use super::event::{outcome_for, ApiLogEvent};

/// Correlation id par défaut si l'en-tête est absent (ne devrait pas arriver).
const UNKNOWN: &str = "unknown";

/// Middleware `from_fn_with_state` : enregistre un `ApiLogEvent` par requête.
pub async fn record_requests(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    // Monitoring désactivé : on ne fait rien (zéro surcoût).
    let Some(handle) = state.monitoring.clone() else {
        return next.run(request).await;
    };

    // Métadonnées extraites AVANT de céder la requête (pas de query string).
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(UNKNOWN)
        .to_owned();
    let user_agent = request
        .headers()
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        // Borne la longueur (évite un UA géant dans l'index).
        .map(|s| s.chars().take(256).collect::<String>());
    // IP cliente de CONFIANCE (résistante à l'usurpation XFF), via l'API
    // partagée avec le rate limiting (cf. middleware::client).
    let peer = peer_ip(request.extensions());
    let client_ip = client_ip(request.headers(), peer, state.config.trusted_proxy_hops)
        .map(|ip| ip.to_string());

    let started = Instant::now();
    let response = next.run(request).await;
    let latency_ms = started.elapsed().as_millis() as u64;

    let status = response.status().as_u16();
    // Code d'erreur applicatif stable, attaché par `ApiError` en extension.
    let error_code = response
        .extensions()
        .get::<ErrorCode>()
        .map(|c| c.0.to_owned());

    handle.record(ApiLogEvent {
        timestamp: OffsetDateTime::now_utc(),
        request_id,
        method,
        path,
        status,
        outcome: outcome_for(status),
        latency_ms,
        error_code,
        client_ip,
        user_agent,
    });

    response
}
