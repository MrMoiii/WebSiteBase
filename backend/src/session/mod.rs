//! Sessions utilisateur stockées dans Redis (source de vérité).
//!
//! Redis remplace la table `refresh_tokens` de Postgres comme store de sessions :
//! rotation atomique des refresh tokens, TTL natif (idle glissant + plafond
//! absolu), révocation immédiate des access tokens (liés à un `sid`), gestion
//! des sessions actives, et verrouillage/rate-limiting distribués.
//!
//! ```text
//!   handlers::auth / middleware::auth / handlers::sessions
//!        │
//!        ▼
//!   session::SessionStore  (abstraction : create/rotate/logout/list/revoke, lockout, rate limit)
//!        │
//!        ▼
//!   Redis  (jamais exposé au frontend)
//! ```

pub mod store;

pub use store::{Rotated, SessionError, SessionStore, SessionSummary};
