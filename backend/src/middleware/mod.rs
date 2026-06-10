//! Middlewares et extracteurs transverses : sécurité des en-têtes,
//! authentification/autorisation, contexte client et validation d'entrée.

pub mod auth;
pub mod client;
pub mod security_headers;
pub mod validation;
