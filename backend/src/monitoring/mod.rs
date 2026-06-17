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
pub mod shipper;

pub use client::{OpenSearchClient, OpenSearchError};
pub use event::ApiLogEvent;
pub use shipper::{spawn, MonitoringHandle};
