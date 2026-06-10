//! Handlers de profil utilisateur (lecture / mise à jour de SON profil).
//!
//! Protection IDOR : l'identifiant de l'utilisateur provient TOUJOURS du token
//! authentifié (`AuthUser`), jamais d'un paramètre fourni par le client. Un
//! utilisateur ne peut donc pas lire/modifier le profil d'un autre via cet
//! endpoint.

use axum::extract::State;
use axum::Json;

use crate::db;
use crate::errors::ApiError;
use crate::middleware::auth::AuthUser;
use crate::middleware::validation::ValidatedJson;
use crate::models::user::{UpdateProfileRequest, UserProfile};
use crate::state::AppState;

/// GET /api/v1/users/me
pub async fn get_me(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<UserProfile>, ApiError> {
    let user = db::find_user_by_id(&state.pool, auth.id)
        .await?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(UserProfile::from(user)))
}

/// PATCH /api/v1/users/me
pub async fn update_me(
    State(state): State<AppState>,
    auth: AuthUser,
    ValidatedJson(body): ValidatedJson<UpdateProfileRequest>,
) -> Result<Json<UserProfile>, ApiError> {
    let updated =
        db::update_display_name(&state.pool, auth.id, body.display_name.as_deref()).await?;
    tracing::info!(user.id = %auth.id, "profil mis à jour");
    Ok(Json(UserProfile::from(updated)))
}
