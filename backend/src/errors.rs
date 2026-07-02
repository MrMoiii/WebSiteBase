//! Type d'erreur central de l'API (exigence sécurité #7).
//!
//! Principe : le détail technique (message SQL, panique, contexte interne) est
//! LOGGÉ côté serveur dans le span de requête (donc avec le correlation id),
//! mais le client ne reçoit qu'une réponse générique. On ne renvoie jamais de
//! stack trace, de message d'ORM ou de détail d'implémentation.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use thiserror::Error;

/// Erreur applicative unifiée. Chaque variante porte éventuellement un détail
/// interne destiné UNIQUEMENT aux logs serveur.
#[derive(Debug, Error)]
pub enum ApiError {
    /// Validation d'entrée échouée. Le message est sûr à exposer (pas de
    /// donnée interne) et aide le client à corriger sa requête.
    #[error("validation error: {0}")]
    Validation(String),

    /// Authentification absente ou invalide.
    #[error("unauthorized")]
    Unauthorized,

    /// Authentifié mais non autorisé (autorisation refusée).
    #[error("forbidden")]
    Forbidden,

    /// Ressource introuvable.
    #[error("not found")]
    NotFound,

    /// Conflit métier (ex. email déjà utilisé). Message court et générique.
    #[error("conflict: {0}")]
    Conflict(&'static str),

    /// Trop de requêtes (rate limiting / lockout).
    #[error("too many requests")]
    TooManyRequests,

    /// Corps de requête trop volumineux.
    #[error("payload too large")]
    PayloadTooLarge,

    /// Requête malformée (JSON invalide, type incorrect…).
    #[error("bad request: {0}")]
    BadRequest(String),

    /// Dépendance indispensable indisponible (ex. store de sessions Redis
    /// injoignable). Le détail est loggé, jamais renvoyé. 503 => le client peut
    /// réessayer.
    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Erreur interne. Le détail (`String`) est loggé, jamais renvoyé.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Code d'erreur applicatif stable, attaché aux réponses d'erreur en extension.
///
/// Permet à des couches en aval (ex. middleware de monitoring) de connaître le
/// code sans re-parser le corps JSON. Sûr à indexer (pas de donnée sensible).
#[derive(Debug, Clone, Copy)]
pub struct ErrorCode(pub &'static str);

impl ApiError {
    /// Status HTTP associé.
    fn status(&self) -> StatusCode {
        match self {
            ApiError::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Forbidden => StatusCode::FORBIDDEN,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            ApiError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Code machine stable, sûr à exposer au client.
    fn code(&self) -> &'static str {
        match self {
            ApiError::Validation(_) => "validation_error",
            ApiError::Unauthorized => "unauthorized",
            ApiError::Forbidden => "forbidden",
            ApiError::NotFound => "not_found",
            ApiError::Conflict(_) => "conflict",
            ApiError::TooManyRequests => "too_many_requests",
            ApiError::PayloadTooLarge => "payload_too_large",
            ApiError::BadRequest(_) => "bad_request",
            ApiError::ServiceUnavailable(_) => "service_unavailable",
            ApiError::Internal(_) => "internal_error",
        }
    }

    /// Message public, volontairement générique pour les erreurs internes.
    fn public_message(&self) -> String {
        match self {
            ApiError::Validation(m) => m.clone(),
            ApiError::Unauthorized => "Authentication required or invalid.".to_string(),
            ApiError::Forbidden => "You do not have permission to perform this action.".to_string(),
            ApiError::NotFound => "Resource not found.".to_string(),
            ApiError::Conflict(m) => (*m).to_string(),
            ApiError::TooManyRequests => "Too many requests. Please retry later.".to_string(),
            ApiError::PayloadTooLarge => "Request body too large.".to_string(),
            ApiError::BadRequest(m) => m.clone(),
            ApiError::ServiceUnavailable(_) => {
                "Service temporarily unavailable. Please retry later.".to_string()
            }
            // Aucune fuite : message générique côté client.
            ApiError::Internal(_) => "An internal error occurred.".to_string(),
        }
    }
}

/// Corps JSON d'erreur renvoyé au client.
#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();

        // Journalisation côté serveur : on émet l'événement DANS le span de la
        // requête courante (donc avec le correlation id / request id). Les 5xx
        // sont des erreurs, les 401/403/429 sont des événements SOC en warn.
        match &self {
            ApiError::Internal(detail) | ApiError::ServiceUnavailable(detail) => {
                tracing::error!(
                    error.kind = self.code(),
                    error.detail = %detail,
                    http.status = status.as_u16(),
                    "requête échouée (erreur interne / dépendance indisponible)"
                );
            }
            ApiError::Unauthorized | ApiError::Forbidden | ApiError::TooManyRequests => {
                // Événements d'intérêt sécurité (exigence #11).
                tracing::warn!(
                    error.kind = self.code(),
                    http.status = status.as_u16(),
                    security.event = true,
                    "accès refusé / limité"
                );
            }
            other => {
                tracing::info!(
                    error.kind = other.code(),
                    http.status = status.as_u16(),
                    "requête rejetée"
                );
            }
        }

        let code = self.code();
        let body = ErrorBody {
            error: ErrorDetail {
                code,
                message: self.public_message(),
            },
        };

        let mut response = (status, Json(body)).into_response();
        // Expose le code aux couches en aval (monitoring) sans re-parser le corps.
        response.extensions_mut().insert(ErrorCode(code));
        response
    }
}

// --- Conversions depuis les erreurs des dépendances ---------------------------

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        // On distingue le cas "ligne absente" (404) du reste (500), sans jamais
        // exposer le message SQL d'origine au client.
        match e {
            sqlx::Error::RowNotFound => ApiError::NotFound,
            other => ApiError::Internal(format!("database error: {other}")),
        }
    }
}

impl From<garde::Report> for ApiError {
    fn from(report: garde::Report) -> Self {
        ApiError::Validation(summarize_validation(&report))
    }
}

impl From<crate::session::SessionError> for ApiError {
    fn from(e: crate::session::SessionError) -> Self {
        // Le store de sessions (Redis) est indispensable à l'auth : s'il est
        // injoignable, on renvoie 503 (le client peut réessayer), détail loggé.
        ApiError::ServiceUnavailable(e.to_string())
    }
}

/// Résume les erreurs de validation en un message court et sûr à exposer.
/// On expose le chemin des champs en faute mais JAMAIS la valeur reçue.
fn summarize_validation(report: &garde::Report) -> String {
    let mut fields: Vec<String> = report
        .iter()
        .map(|(path, _)| path.to_string())
        .filter(|p| !p.is_empty())
        .collect();
    fields.sort();
    fields.dedup();
    if fields.is_empty() {
        "Invalid input.".to_string()
    } else {
        format!("Invalid input for field(s): {}.", fields.join(", "))
    }
}
