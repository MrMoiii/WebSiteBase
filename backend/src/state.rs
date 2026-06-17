//! État applicatif partagé injecté dans tous les handlers via l'extracteur
//! `State` d'Axum.

use std::sync::Arc;

use sqlx::PgPool;

use crate::config::Config;
use crate::monitoring::MonitoringHandle;

/// État cloné à chaque requête. `PgPool` est un `Arc` interne (clone bon marché)
/// et `Config` est encapsulée dans un `Arc` pour partager la config immuable.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub pool: PgPool,
    /// Poignée de monitoring (clone léger : un `Sender` mpsc). `None` si le
    /// monitoring OpenSearch n'est pas configuré.
    pub monitoring: Option<MonitoringHandle>,
}

impl AppState {
    pub fn new(config: Config, pool: PgPool) -> Self {
        Self {
            config: Arc::new(config),
            pool,
            monitoring: None,
        }
    }

    /// Attache (ou non) une poignée de monitoring. Chaînable depuis le bootstrap.
    pub fn with_monitoring(mut self, monitoring: Option<MonitoringHandle>) -> Self {
        self.monitoring = monitoring;
        self
    }
}
