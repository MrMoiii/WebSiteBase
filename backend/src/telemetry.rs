//! Initialisation du logging structuré JSON (exploitable par un SIEM).
//!
//! Tous les logs sont émis en JSON sur stdout, avec niveau, cible, timestamp
//! et champs structurés (dont le `correlation_id` ajouté par le middleware de
//! trace). On ne logge JAMAIS de secret, token ou mot de passe.

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Installe le subscriber global. À appeler une seule fois au démarrage.
pub fn init(log_filter: &str) {
    // Le filtre suit la syntaxe RUST_LOG (ex. "info,websitebase_backend=debug").
    let env_filter = EnvFilter::try_new(log_filter).unwrap_or_else(|_| EnvFilter::new("info"));

    let json_layer = fmt::layer()
        .json()
        .flatten_event(true)
        .with_current_span(true)
        .with_span_list(false)
        .with_target(true)
        // Pas de chemins de fichiers source en prod (réduit les fuites d'info).
        .with_file(false)
        .with_line_number(false);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(json_layer)
        // Expédie les événements applicatifs vers OpenSearch (si le monitoring
        // est activé). No-op tant que la poignée globale n'est pas renseignée.
        .with(crate::monitoring::log_layer::OpenSearchLogLayer)
        .init();
}
