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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use garde::Validate;

    /// Toutes les variantes, avec un détail non vide là où c'est pertinent (pour
    /// vérifier qu'il ne fuite jamais au client).
    fn all_variants() -> Vec<ApiError> {
        vec![
            ApiError::Validation("field x".into()),
            ApiError::Unauthorized,
            ApiError::Forbidden,
            ApiError::NotFound,
            ApiError::Conflict("Email already registered."),
            ApiError::TooManyRequests,
            ApiError::PayloadTooLarge,
            ApiError::BadRequest("bad json".into()),
            ApiError::ServiceUnavailable("redis down: connection refused".into()),
            ApiError::Internal("SELECT boom FROM secret_table".into()),
        ]
    }

    #[test]
    fn status_codes_match_variants() {
        use StatusCode as S;
        let cases = [
            (ApiError::Validation("x".into()), S::UNPROCESSABLE_ENTITY),
            (ApiError::Unauthorized, S::UNAUTHORIZED),
            (ApiError::Forbidden, S::FORBIDDEN),
            (ApiError::NotFound, S::NOT_FOUND),
            (ApiError::Conflict("x"), S::CONFLICT),
            (ApiError::TooManyRequests, S::TOO_MANY_REQUESTS),
            (ApiError::PayloadTooLarge, S::PAYLOAD_TOO_LARGE),
            (ApiError::BadRequest("x".into()), S::BAD_REQUEST),
            (
                ApiError::ServiceUnavailable("x".into()),
                S::SERVICE_UNAVAILABLE,
            ),
            (ApiError::Internal("x".into()), S::INTERNAL_SERVER_ERROR),
        ];
        for (err, expected) in cases {
            assert_eq!(err.status(), expected, "statut pour {err:?}");
        }
    }

    #[test]
    fn codes_are_stable_machine_strings() {
        let expected = [
            "validation_error",
            "unauthorized",
            "forbidden",
            "not_found",
            "conflict",
            "too_many_requests",
            "payload_too_large",
            "bad_request",
            "service_unavailable",
            "internal_error",
        ];
        for (err, code) in all_variants().iter().zip(expected) {
            assert_eq!(err.code(), code);
        }
    }

    #[test]
    fn internal_and_service_unavailable_never_leak_detail() {
        let internal = ApiError::Internal("SELECT boom FROM secret_table".into());
        assert_eq!(internal.public_message(), "An internal error occurred.");
        assert!(!internal.public_message().contains("secret_table"));

        let unavailable = ApiError::ServiceUnavailable("redis down: 10.0.0.5:6379".into());
        assert!(!unavailable.public_message().contains("10.0.0.5"));
        assert!(unavailable
            .public_message()
            .contains("temporarily unavailable"));
    }

    #[test]
    fn safe_messages_are_passed_through() {
        // Les messages destinés au client (Validation/BadRequest/Conflict) sont
        // exposés tels quels — ils ne contiennent pas de donnée interne.
        assert_eq!(
            ApiError::Validation("Invalid input for field(s): email.".into()).public_message(),
            "Invalid input for field(s): email."
        );
        assert_eq!(
            ApiError::BadRequest("Invalid or malformed JSON body.".into()).public_message(),
            "Invalid or malformed JSON body."
        );
        assert_eq!(
            ApiError::Conflict("Email already registered.").public_message(),
            "Email already registered."
        );
    }

    #[tokio::test]
    async fn into_response_sets_status_body_and_error_code_extension() {
        for err in all_variants() {
            let expected_status = err.status();
            let expected_code = err.code();
            let response = err.into_response();
            assert_eq!(response.status(), expected_status);
            // Le code stable est exposé en extension pour les couches en aval.
            let ext = response
                .extensions()
                .get::<ErrorCode>()
                .expect("ErrorCode en extension");
            assert_eq!(ext.0, expected_code);

            let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json["error"]["code"], expected_code);
            assert!(json["error"]["message"].is_string());
        }
    }

    #[tokio::test]
    async fn into_response_internal_body_is_generic() {
        let response = ApiError::Internal("db password = hunter2".into()).into_response();
        let bytes = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(text.contains("An internal error occurred."));
        assert!(!text.contains("hunter2"));
    }

    #[test]
    fn from_sqlx_row_not_found_is_404_else_internal() {
        assert!(matches!(
            ApiError::from(sqlx::Error::RowNotFound),
            ApiError::NotFound
        ));
        let other = ApiError::from(sqlx::Error::Protocol("boom".into()));
        match other {
            ApiError::Internal(detail) => assert!(detail.contains("database error")),
            _ => panic!("attendu Internal"),
        }
    }

    #[test]
    fn from_session_error_is_service_unavailable() {
        let err = ApiError::from(crate::session::SessionError::Backend("nope".into()));
        assert!(matches!(err, ApiError::ServiceUnavailable(_)));
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn from_garde_report_lists_offending_fields_without_values() {
        // Un DTO invalide (email + mot de passe) produit un rapport ; le résumé
        // cite les champs mais jamais les valeurs reçues.
        let bad = crate::models::auth::RegisterRequest {
            email: "not-an-email".to_string(),
            password: "short".to_string(),
            display_name: None,
        };
        let report = bad.validate().unwrap_err();
        let err = ApiError::from(report);
        match err {
            ApiError::Validation(msg) => {
                assert!(msg.contains("email"));
                assert!(msg.contains("password"));
                assert!(!msg.contains("not-an-email"));
                assert!(!msg.contains("short"));
            }
            _ => panic!("attendu Validation"),
        }
    }

    #[test]
    fn summarize_validation_empty_report_is_generic() {
        let empty = garde::Report::new();
        assert_eq!(summarize_validation(&empty), "Invalid input.");
    }
}
