//! Monitoring d'API via OpenSearch : observabilité des appels (succès/erreurs)
//! pour le debugging, visualisée dans OpenSearch Dashboards.
//!
//! Chaîne (de haut en bas) :
//!
//! ```text
//!   monitoring::layer   (middleware Axum : capture l'issue de chaque requête)
//!        │  record() best-effort, NON bloquant
//!        ▼
//!   monitoring::shipper (tâche de fond : tampon + envoi par lots _bulk)
//!        │
//!        ▼
//!   monitoring::client  (OpenSearchClient : TLS/mTLS, auth, HTTP)
//!        │
//!        ▼
//!   OpenSearch  ◀── OpenSearch Dashboards (le « panneau » de debug)
//! ```
//!
//! Fonctionnalité **opt-in** : sans `OPENSEARCH_URL`, le monitoring est
//! désactivé et l'application fonctionne normalement (aucun envoi).

pub mod client;
pub mod event;
pub mod layer;
pub mod log_layer;
pub mod metrics;
pub mod shipper;

pub use client::{OpenSearchClient, OpenSearchError};
pub use metrics::Metrics;
pub use shipper::{spawn, MonitoringHandle};

use std::sync::OnceLock;

/// Poignée globale utilisée par la couche `tracing` (`log_layer`), qui ne
/// dispose pas de l'`AppState`. Renseignée une fois au démarrage si le
/// monitoring est activé ; sinon la couche n'expédie rien.
static GLOBAL_HANDLE: OnceLock<MonitoringHandle> = OnceLock::new();

/// Renseigne la poignée globale (idempotent : seul le premier appel compte).
pub fn set_global_handle(handle: MonitoringHandle) {
    let _ = GLOBAL_HANDLE.set(handle);
}

/// Accès à la poignée globale (None si monitoring désactivé).
pub fn global_handle() -> Option<&'static MonitoringHandle> {
    GLOBAL_HANDLE.get()
}
