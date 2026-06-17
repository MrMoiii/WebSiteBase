//! Handler de l'endpoint de recherche `/api/v1/search`.
//!
//! Garanties de sécurité au niveau du handler :
//! - accès AUTHENTIFIÉ obligatoire (`AuthUser`) — pas de recherche anonyme ;
//! - paramètres VALIDÉS (`ValidatedQuery<SearchParams>`, `deny_unknown_fields`)
//!   avant d'atteindre la logique : aucune requête DSL brute n'est acceptée ;
//! - le `SearchContext` (tenant + rôle) est DÉRIVÉ du token, jamais du client :
//!   un utilisateur ne peut pas choisir le tenant qu'il interroge (isolation) ;
//! - si la recherche est désactivée/indisponible, réponse 503 générique.
//!
//! Le rate limiting et le timeout sont appliqués par la pile de middlewares
//! (cf. `routes::mod`), spécifiquement renforcés pour cet endpoint.

use axum::extract::State;
use axum::Json;

use crate::errors::ApiError;
use crate::middleware::auth::AuthUser;
use crate::middleware::client::ClientContext;
use crate::middleware::validation::ValidatedQuery;
use crate::search::query::{SearchContext, SearchParams};
use crate::search::SearchResults;
use crate::state::AppState;

/// GET /api/v1/search?q=…&page=&page_size=&sort=&order=&tags=
pub async fn search(
    State(state): State<AppState>,
    auth: AuthUser,
    client_ctx: ClientContext,
    ValidatedQuery(params): ValidatedQuery<SearchParams>,
) -> Result<Json<SearchResults>, ApiError> {
    // Recherche non configurée => dépendance indisponible (503), proprement géré
    // par le frontend. On ne révèle pas la cause exacte.
    let service = state
        .search
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("search disabled".into()))?;

    // Le tenant est dérivé du contexte serveur (jamais d'un paramètre client) :
    // c'est le point d'intégration de l'isolation multi-tenant. Dans cette base
    // mono-domaine, tous les comptes partagent le tenant logique « public » ;
    // un déploiement multi-tenant le déduirait d'un claim d'organisation.
    let ctx = SearchContext {
        tenant: tenant_for(&auth),
        role: auth.role,
    };

    let results = service.search(&ctx, &params, &client_ctx).await?;
    Ok(Json(results))
}

/// Résout le tenant logique d'un utilisateur. Centralisé ici pour rester le
/// SEUL endroit où le tenant est déterminé (toujours côté serveur).
fn tenant_for(_auth: &AuthUser) -> String {
    "public".to_string()
}
