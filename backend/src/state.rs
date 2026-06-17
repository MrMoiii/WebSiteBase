//! État applicatif partagé injecté dans tous les handlers via l'extracteur
//! `State` d'Axum.

use std::sync::Arc;

use sqlx::PgPool;

use crate::config::Config;
use crate::search::SearchService;

/// État cloné à chaque requête. `PgPool` est un `Arc` interne (clone bon marché)
/// et `Config` est encapsulée dans un `Arc` pour partager la config immuable.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pool: PgPool,
    /// Service de recherche secondaire. `None` si OpenSearch n'est pas
    /// configuré : l'endpoint `/search` répond alors 503. `Arc` car
    /// `SearchService` détient un client HTTP réutilisable.
    pub search: Option<Arc<SearchService>>,
}

impl AppState {
    pub fn new(config: Config, pool: PgPool) -> Self {
        Self {
            config: Arc::new(config),
            pool,
            search: None,
        }
    }

    /// Attache (ou non) un service de recherche. Chaînable depuis le bootstrap.
    pub fn with_search(mut self, search: Option<Arc<SearchService>>) -> Self {
        self.search = search;
        self
    }
}
