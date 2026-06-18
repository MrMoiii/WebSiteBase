//! Wrapper bas niveau autour du cluster OpenSearch (couche transport).
//!
//! Seul ce module parle le protocole HTTP d'OpenSearch. Il est utilisé par le
//! *shipper* de monitoring pour pousser les logs d'API. Il N'EXPOSE PAS le
//! cluster : aucun chemin direct depuis le frontend.
//!
//! Sécurité transport (exigences CRITIQUES) :
//! - TLS imposé (`https_only`) + version minimale TLS 1.2 ;
//! - CA privée optionnelle (cluster interne à certificat auto-signé) ;
//! - identité client optionnelle (mTLS) ;
//! - authentification forte par requête (Basic ou ApiKey), jamais loggée ;
//! - timeout réseau strict (anti-blocage).

use std::time::Duration;

use reqwest::{Client, RequestBuilder};
use serde_json::Value;
use thiserror::Error;

use crate::config::{MonitoringConfig, OpenSearchAuth};

/// Erreurs du client OpenSearch. Le détail reste interne (loggé), jamais exposé.
#[derive(Debug, Error)]
pub enum OpenSearchError {
    /// Erreur de configuration / construction du client (ex. certificat illisible).
    #[error("opensearch client build error: {0}")]
    Build(String),
    /// Cluster injoignable, en timeout, ou erreur réseau.
    #[error("opensearch unavailable: {0}")]
    Unavailable(String),
    /// Le cluster a répondu par un statut d'erreur.
    #[error("opensearch returned status {0}")]
    Upstream(u16),
    /// Réponse illisible / hors contrat.
    #[error("invalid opensearch response: {0}")]
    Decode(String),
}

/// Client HTTP réutilisable vers un cluster OpenSearch.
#[derive(Clone)]
pub struct OpenSearchClient {
    http: Client,
    base_url: String,
    auth: OpenSearchAuth,
}

impl OpenSearchClient {
    /// Construit le client à partir de la configuration validée.
    ///
    /// Charge les éventuels certificats (CA privée, identité mTLS) depuis le
    /// disque. Échoue si un fichier est illisible ou mal formé (fail-fast).
    pub fn from_config(cfg: &MonitoringConfig) -> Result<Self, OpenSearchError> {
        let is_https = cfg.base_url.starts_with("https://");

        let mut builder = Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(cfg.request_timeout)
            // Pas de redirection : un cluster ne redirige pas, c'est suspect.
            .redirect(reqwest::redirect::Policy::none());

        if is_https {
            // TLS obligatoire pour un endpoint https : aucune dégradation en clair.
            builder = builder
                .https_only(true)
                .min_tls_version(reqwest::tls::Version::TLS_1_2)
                .use_rustls_tls();

            // CA privée : ajoute la racine de confiance sans désactiver la
            // vérification (on n'expose JAMAIS d'option `accept_invalid_certs`).
            if let Some(path) = &cfg.ca_cert_path {
                let pem = std::fs::read(path)
                    .map_err(|e| OpenSearchError::Build(format!("read CA cert {path}: {e}")))?;
                let cert = reqwest::Certificate::from_pem(&pem)
                    .map_err(|e| OpenSearchError::Build(format!("parse CA cert: {e}")))?;
                builder = builder.add_root_certificate(cert);
            }

            // Identité client (mTLS) : PEM concaténant le certificat et la clé.
            if let Some(path) = &cfg.client_identity_path {
                let pem = std::fs::read(path).map_err(|e| {
                    OpenSearchError::Build(format!("read client identity {path}: {e}"))
                })?;
                let identity = reqwest::Identity::from_pem(&pem)
                    .map_err(|e| OpenSearchError::Build(format!("parse client identity: {e}")))?;
                builder = builder.identity(identity);
            }
        }
        // NB : si l'URL est en http:// (dev, OPENSEARCH_ALLOW_INSECURE=true validé
        // par la config), on n'applique aucune contrainte TLS — le cluster de dev
        // n'est joignable que sur le réseau Docker interne, jamais exposé.

        let http = builder
            .build()
            .map_err(|e| OpenSearchError::Build(e.to_string()))?;

        Ok(Self {
            http,
            base_url: cfg.base_url.clone(),
            auth: cfg.auth.clone(),
        })
    }

    /// Ajoute l'authentification forte à une requête. Les secrets ne transitent
    /// que dans cet en-tête, jamais dans une URL ni dans un log.
    fn authed(&self, rb: RequestBuilder) -> RequestBuilder {
        match &self.auth {
            OpenSearchAuth::Basic { username, password } => {
                rb.basic_auth(username, Some(password.expose()))
            }
            OpenSearchAuth::ApiKey(key) => rb.header(
                reqwest::header::AUTHORIZATION,
                format!("ApiKey {}", key.expose()),
            ),
        }
    }

    /// Crée/maj un *index template* (idempotent) : les index quotidiens
    /// `api-logs-*` héritent ainsi du mapping strict sans création manuelle.
    pub async fn ensure_index_template(
        &self,
        name: &str,
        body: &Value,
    ) -> Result<(), OpenSearchError> {
        let url = format!("{}/_index_template/{}", self.base_url, name);
        let resp = self
            .authed(self.http.put(&url))
            .json(body)
            .send()
            .await
            .map_err(|e| OpenSearchError::Unavailable(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(OpenSearchError::Upstream(resp.status().as_u16()))
        }
    }

    /// Indexation par lot (`_bulk`) à partir d'un corps NDJSON déjà sérialisé.
    /// Pas de `refresh` forcé : les logs n'ont pas besoin d'être visibles
    /// instantanément (meilleur débit). Retourne la réponse brute du cluster.
    pub async fn bulk(&self, ndjson: String) -> Result<Value, OpenSearchError> {
        let url = format!("{}/_bulk", self.base_url);
        let resp = self
            .authed(self.http.post(&url))
            .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
            .body(ndjson)
            .send()
            .await
            .map_err(|e| OpenSearchError::Unavailable(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(OpenSearchError::Upstream(status.as_u16()));
        }
        resp.json::<Value>()
            .await
            .map_err(|e| OpenSearchError::Decode(e.to_string()))
    }

    /// Vérifie la disponibilité du cluster (santé) — utile au démarrage.
    pub async fn ping(&self) -> Result<(), OpenSearchError> {
        let url = format!("{}/_cluster/health", self.base_url);
        let resp = self
            .authed(self.http.get(&url))
            .send()
            .await
            .map_err(|e| OpenSearchError::Unavailable(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(OpenSearchError::Upstream(resp.status().as_u16()))
        }
    }
}
