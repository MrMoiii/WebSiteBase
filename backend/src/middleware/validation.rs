//! Extracteurs validés : toute entrée externe (body JSON, query string) est
//! d'abord désérialisée dans un type strict (`#[serde(deny_unknown_fields)]`)
//! PUIS validée par `garde` avant d'atteindre la logique métier
//! (exigence sécurité #2 : rejeter par défaut).

use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{FromRequest, FromRequestParts, Json, Query, Request};
use axum::http::request::Parts;
use axum::http::StatusCode;
use garde::Validate;
use serde::de::DeserializeOwned;

use crate::errors::ApiError;
use crate::state::AppState;

/// Body JSON désérialisé et validé.
pub struct ValidatedJson<T>(pub T);

impl<T> FromRequest<AppState> for ValidatedJson<T>
where
    T: DeserializeOwned + Validate,
    // Les DTO utilisent le contexte par défaut `()` ; `validate()` l'exige.
    T::Context: Default,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(map_json_rejection)?;
        // `validate()` renvoie un `garde::Report` -> 422 via `From`.
        value.validate()?;
        Ok(ValidatedJson(value))
    }
}

/// Query string désérialisée et validée.
pub struct ValidatedQuery<T>(pub T);

impl<T> FromRequestParts<AppState> for ValidatedQuery<T>
where
    T: DeserializeOwned + Validate,
    T::Context: Default,
{
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let Query(value) = Query::<T>::from_request_parts(parts, state)
            .await
            .map_err(map_query_rejection)?;
        value.validate()?;
        Ok(ValidatedQuery(value))
    }
}

/// Traduit un rejet JSON en erreur générique. Le détail est loggé côté serveur
/// mais on ne renvoie pas le contenu brut au client.
fn map_json_rejection(rej: JsonRejection) -> ApiError {
    tracing::debug!(rejection = %rej, "rejet du body JSON");
    // Un corps dépassant la limite (DefaultBodyLimit) remonte ici en 413.
    if rej.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return ApiError::PayloadTooLarge;
    }
    match rej {
        JsonRejection::JsonDataError(_) | JsonRejection::JsonSyntaxError(_) => {
            ApiError::BadRequest("Invalid or malformed JSON body.".to_string())
        }
        JsonRejection::MissingJsonContentType(_) => {
            ApiError::BadRequest("Expected Content-Type: application/json.".to_string())
        }
        _ => ApiError::BadRequest("Invalid request body.".to_string()),
    }
}

/// Traduit un rejet de query string en erreur générique.
fn map_query_rejection(rej: QueryRejection) -> ApiError {
    tracing::debug!(rejection = %rej, "rejet de la query string");
    ApiError::BadRequest("Invalid query parameters.".to_string())
}
