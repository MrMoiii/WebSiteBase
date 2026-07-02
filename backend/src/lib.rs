//! Backend d'API REST sécurisé du projet WebSiteBase.
//!
//! Exposé en bibliothèque afin que les tests d'intégration puissent monter le
//! routeur complet. Le binaire (`main.rs`) se contente d'appeler [`run`].

// Exigence sécurité #1 : aucun `unsafe` dans le code applicatif.
#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod db;
pub mod errors;
pub mod handlers;
pub mod middleware;
pub mod models;
pub mod monitoring;
pub mod routes;
pub mod state;
pub mod telemetry;

use std::net::SocketAddr;

use anyhow_lite::Context as _;

use crate::config::Config;
use crate::state::AppState;

/// Point d'entrée applicatif : charge la config, initialise les logs, ouvre le
/// pool, construit le routeur et sert jusqu'à réception d'un signal d'arrêt.
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // En développement uniquement : charge un éventuel `.env`. En production,
    // les variables proviennent de l'orchestrateur (le fichier est absent).
    let _ = dotenvy::dotenv();

    // 1) Configuration (échoue immédiatement si un secret obligatoire manque).
    let config = Config::from_env().context("chargement de la configuration")?;

    // 2) Logs structurés JSON.
    telemetry::init(&config.log_filter);
    tracing::info!(
        bind_addr = %config.bind_addr,
        "démarrage du backend WebSiteBase"
    );

    // 3) Pool PostgreSQL (le runtime utilise le rôle applicatif DML uniquement).
    let pool = db::create_pool(&config)
        .await
        .context("connexion à la base de données")?;

    // NB : les migrations ne sont PAS exécutées par l'application (le rôle
    // applicatif n'a pas de droits DDL). Elles sont jouées séparément avec le
    // rôle propriétaire (cf. README).

    // 3bis) Monitoring d'API via OpenSearch (optionnel). Construit le client TLS
    // (charge les certificats), provisionne l'index template, puis démarre la
    // tâche de fond d'envoi. Si la config est absente, le monitoring est
    // simplement désactivé (aucun envoi, aucun impact).
    let monitoring = match &config.monitoring {
        Some(mon_cfg) => {
            let client = monitoring::OpenSearchClient::from_config(mon_cfg)
                .context("initialisation du client OpenSearch (monitoring)")?;
            // Provisionne le mapping strict des index de logs (idempotent). Un
            // échec ici n'est pas fatal : on logge et on continue (best-effort).
            if let Err(err) = client
                .ensure_index_template(
                    monitoring::event::TEMPLATE_NAME,
                    &monitoring::event::index_template(&mon_cfg.index_prefix),
                )
                .await
            {
                tracing::warn!(error.detail = %err, "échec de création de l'index template de monitoring");
            }
            let handle = monitoring::spawn(client, mon_cfg.clone());
            // Renseigne la poignée globale pour la couche `tracing` (log_layer),
            // afin que TOUS les événements applicatifs partent vers OpenSearch,
            // corrélés par request_id.
            monitoring::set_global_handle(handle.clone());
            tracing::info!("monitoring OpenSearch initialisé");
            Some(handle)
        }
        None => {
            tracing::info!("monitoring désactivé (OPENSEARCH_URL absent)");
            None
        }
    };

    let bind_addr = config.bind_addr;
    let state = AppState::new(config, pool).with_monitoring(monitoring);
    let app = routes::build_router(state);

    // 4) Écoute sur un port non privilégié, derrière un reverse proxy TLS.
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("bind sur {bind_addr}"))?;
    tracing::info!(bind_addr = %bind_addr, "serveur à l'écoute");

    // `ConnectInfo` fournit l'IP de pair pour le rate limiting et l'audit.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await
    .context("erreur du serveur HTTP")?;

    tracing::info!("arrêt propre du serveur");
    Ok(())
}

/// Attend Ctrl-C ou SIGTERM pour un arrêt gracieux (drainage des requêtes).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("signal d'arrêt reçu");
}

/// Mini-utilitaire de contexte d'erreur sans dépendre d'`anyhow` (chaîne
/// d'approvisionnement minimale). Ajoute un message à toute erreur.
mod anyhow_lite {
    use std::fmt::Display;

    /// Erreur enrichie d'un message de contexte.
    #[derive(Debug)]
    pub struct ContextError {
        message: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    }

    impl Display for ContextError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}: {}", self.message, self.source)
        }
    }

    impl std::error::Error for ContextError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self.source.as_ref())
        }
    }

    /// Trait d'extension pour ajouter du contexte à un `Result`.
    pub trait Context<T> {
        fn context<C: Display>(self, msg: C) -> Result<T, Box<dyn std::error::Error>>;
        fn with_context<C: Display, F: FnOnce() -> C>(
            self,
            f: F,
        ) -> Result<T, Box<dyn std::error::Error>>;
    }

    impl<T, E> Context<T> for Result<T, E>
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        fn context<C: Display>(self, msg: C) -> Result<T, Box<dyn std::error::Error>> {
            self.map_err(|e| {
                Box::new(ContextError {
                    message: msg.to_string(),
                    source: Box::new(e),
                }) as Box<dyn std::error::Error>
            })
        }

        fn with_context<C: Display, F: FnOnce() -> C>(
            self,
            f: F,
        ) -> Result<T, Box<dyn std::error::Error>> {
            self.map_err(|e| {
                Box::new(ContextError {
                    message: f().to_string(),
                    source: Box::new(e),
                }) as Box<dyn std::error::Error>
            })
        }
    }
}
