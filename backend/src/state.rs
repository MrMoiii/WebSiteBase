//! État applicatif partagé injecté dans tous les handlers via l'extracteur
//! `State` d'Axum.

use std::sync::Arc;

use sqlx::PgPool;

use crate::config::Config;

/// État cloné à chaque requête. `PgPool` est un `Arc` interne (clone bon marché)
/// et `Config` est encapsulée dans un `Arc` pour partager la config immuable.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pool: PgPool,
}

impl AppState {
    pub fn new(config: Config, pool: PgPool) -> Self {
        Self {
            config: Arc::new(config),
            pool,
        }
    }
}
