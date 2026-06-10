//! Handlers réservés aux administrateurs.
//!
//! L'extracteur `AdminUser` garantit l'autorisation au niveau du handler
//! (rôle admin vérifié contre l'état COURANT en base), pas uniquement au
//! routage (exigence #9).

use axum::extract::State;
use axum::Json;

use crate::db;
use crate::errors::ApiError;
use crate::middleware::auth::AdminUser;
use crate::middleware::validation::ValidatedQuery;
use crate::models::pagination::{Paginated, PaginationQuery};
use crate::models::user::UserProfile;
use crate::state::AppState;

/// GET /api/v1/admin/users?page=&page_size=
pub async fn list_users(
    State(state): State<AppState>,
    admin: AdminUser,
    ValidatedQuery(pagination): ValidatedQuery<PaginationQuery>,
) -> Result<Json<Paginated<UserProfile>>, ApiError> {
    let items = db::list_users(&state.pool, pagination.page_size(), pagination.offset()).await?;
    let total = db::count_users(&state.pool).await?;

    tracing::info!(
        admin.id = %admin.0.id,
        page = pagination.page(),
        page_size = pagination.page_size(),
        "listing des utilisateurs (admin)"
    );

    Ok(Json(Paginated {
        items,
        page: pagination.page(),
        page_size: pagination.page_size(),
        total,
    }))
}
