//! Module de recherche secondaire (OpenSearch), isolé du reste de l'API.
//!
//! Architecture en couches (de bas en haut) :
//!
//! ```text
//!   handlers::search        (Axum : auth, validation, rate limit, audit HTTP)
//!        │
//!        ▼
//!   search::service::SearchService   (abstraction métier : RBAC, tenant, audit)
//!        │
//!        ▼
//!   search::client::OpenSearchClient (wrapper bas niveau : TLS, auth, HTTP)
//!        │
//!        ▼
//!   OpenSearch cluster (jamais exposé au frontend)
//! ```
//!
//! Le frontend n'atteint JAMAIS OpenSearch : tout passe par `/api/v1/search`.
//! La base de données principale (PostgreSQL) reste la source de vérité ;
//! OpenSearch n'est qu'un index secondaire alimenté par la pipeline
//! d'indexation (`SearchService::index_document` / `reindex_batch`).

pub mod client;
pub mod index;
pub mod query;
pub mod service;

pub use client::{OpenSearchClient, SearchError};
pub use query::{SearchContext, SearchParams};
pub use service::{DocumentInput, SearchHit, SearchResults, SearchService};
