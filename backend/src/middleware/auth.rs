//! Extracteurs d'authentification et d'autorisation.
//!
//! `AuthUser` valide le JWT d'accès, vérifie que sa SESSION est toujours active
//! dans Redis (révocation immédiate : un logout/ban prend effet sans attendre
//! l'expiration du token), PUIS recharge l'utilisateur en base pour obtenir le
//! rôle COURANT. `AdminUser` impose en plus le rôle admin. L'autorisation est
//! ainsi vérifiée au niveau de chaque handler qui exige ces extracteurs
//! (exigence #9), et pas seulement au routage.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use uuid::Uuid;

use crate::db;
use crate::errors::ApiError;
use crate::models::user::UserRole;
use crate::state::AppState;

/// Utilisateur authentifié, tel que connu en base au moment de la requête.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub id: Uuid,
    pub email: String,
    pub role: UserRole,
    /// Session courante (permet de marquer « cette session » dans la liste et
    /// de préserver la session active lors d'une déconnexion des autres).
    pub sid: Uuid,
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 1. Extraire le bearer token de l'en-tête Authorization.
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or(ApiError::Unauthorized)?;

        // 2. Vérifier signature, expiration, émetteur et type du token.
        let claims = crate::auth::jwt::verify_access_token(&state.config, token)?;

        // 3. La session doit être ACTIVE dans Redis ET appartenir au sujet du
        //    token. Une session révoquée (logout, « déconnexion partout », ban)
        //    invalide le JWT immédiatement, avant son expiration.
        match state.session.owner_if_active(&claims.sid).await? {
            Some(owner) if owner == claims.sub => {}
            _ => return Err(ApiError::Unauthorized),
        }

        // 4. Recharger l'utilisateur pour obtenir l'état/rôle COURANT.
        let user = db::find_user_by_id(&state.pool, claims.sub)
            .await?
            .ok_or(ApiError::Unauthorized)?;

        Ok(AuthUser {
            id: user.id,
            email: user.email,
            role: user.role,
            sid: claims.sid,
        })
    }
}

/// Utilisateur authentifié ET ayant le rôle admin. Toute autre situation
/// produit une 403 (et un événement de sécurité loggé).
#[derive(Debug, Clone)]
pub struct AdminUser(pub AuthUser);

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = AuthUser::from_request_parts(parts, state).await?;
        if !user.role.is_admin() {
            tracing::warn!(
                security.event = true,
                user.id = %user.id,
                "tentative d'accès admin par un compte non autorisé"
            );
            return Err(ApiError::Forbidden);
        }
        Ok(AdminUser(user))
    }
}
