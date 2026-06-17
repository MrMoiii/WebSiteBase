//! Wrapper bas niveau autour du cluster OpenSearch.
//!
//! Seul ce module parle le protocole HTTP d'OpenSearch. Il N'EXPOSE PAS le
//! cluster : il est appelé exclusivement par [`super::service::SearchService`],
//! lui-même appelé par les handlers Axum. Le frontend n'a aucun chemin direct.
//!
//! Sécurité transport (exigences CRITIQUES) :
//! - TLS imposé (`https_only`) + version minimale TLS 1.2 ;
//! - CA privée optionnelle (cluster interne à certificat auto-signé) ;
//! - identité client optionnelle (mTLS) ;
//! - authentification forte par requête (Basic ou ApiKey), jamais loggée ;
//! - timeout réseau strict (anti-blocage / anti-DoS).

use std::time::Duration;

use reqwest::{Client, RequestBuilder, StatusCode};
use serde_json::Value;
use thiserror::Error;

use crate::config::{SearchAuth, SearchConfig};
use crate::errors::ApiError;

/// Erreurs du client OpenSearch. Le détail reste interne (loggé), jamais
/// renvoyé tel quel au client HTTP de l'API.
#[derive(Debug, Error)]
pub enum SearchError {
    /// Erreur de configuration / construction du client (ex. certificat illisible).
    #[error("search client build error: {0}")]
    Build(String),
    /// Cluster injoignable, en timeout, ou erreur réseau.
    #[error("search backend unavailable: {0}")]
    Unavailable(String),
    /// Le cluster a répondu par un statut d'erreur.
    #[error("search backend returned status {0}")]
    Upstream(u16),
    /// Réponse illisible / hors contrat.
    #[error("invalid search backend response: {0}")]
    Decode(String),
}

impl From<SearchError> for ApiError {
    fn from(e: SearchError) -> Self {
        match e {
            // Indispo / build / 5xx amont => 503 générique côté client.
            SearchError::Unavailable(d) | SearchError::Build(d) => ApiError::ServiceUnavailable(d),
            SearchError::Upstream(code) if (500..=599).contains(&code) => {
                ApiError::ServiceUnavailable(format!("upstream status {code}"))
            }
            // 4xx amont = erreur de construction de requête de notre côté : 500
            // (ne devrait pas arriver car on ne génère que du DSL contrôlé).
            SearchError::Upstream(code) => ApiError::Internal(format!("upstream status {code}")),
            SearchError::Decode(d) => ApiError::Internal(format!("search decode: {d}")),
        }
    }
}

/// Client HTTP réutilisable vers un cluster OpenSearch.
#[derive(Clone)]
pub struct OpenSearchClient {
    http: Client,
    base_url: String,
    auth: SearchAuth,
}

impl OpenSearchClient {
    /// Construit le client à partir de la configuration validée.
    ///
    /// Charge les éventuels certificats (CA privée, identité mTLS) depuis le
    /// disque. Échoue si un fichier est illisible ou mal formé (fail-fast).
    pub fn from_config(cfg: &SearchConfig) -> Result<Self, SearchError> {
        let mut builder = Client::builder()
            // TLS obligatoire : aucune requête en clair n'est émise.
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .use_rustls_tls()
            .connect_timeout(Duration::from_secs(3))
            .timeout(cfg.request_timeout)
            // Pas de redirection : un cluster ne redirige pas, c'est suspect.
            .redirect(reqwest::redirect::Policy::none());

        // CA privée : ajoute la racine de confiance sans désactiver la
        // vérification (on n'expose JAMAIS d'option `accept_invalid_certs`).
        if let Some(path) = &cfg.ca_cert_path {
            let pem = std::fs::read(path)
                .map_err(|e| SearchError::Build(format!("read CA cert {path}: {e}")))?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .map_err(|e| SearchError::Build(format!("parse CA cert: {e}")))?;
            builder = builder.add_root_certificate(cert);
        }

        // Identité client (mTLS) : PEM concaténant le certificat et la clé.
        if let Some(path) = &cfg.client_identity_path {
            let pem = std::fs::read(path)
                .map_err(|e| SearchError::Build(format!("read client identity {path}: {e}")))?;
            let identity = reqwest::Identity::from_pem(&pem)
                .map_err(|e| SearchError::Build(format!("parse client identity: {e}")))?;
            builder = builder.identity(identity);
        }

        let http = builder
            .build()
            .map_err(|e| SearchError::Build(e.to_string()))?;

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
            SearchAuth::Basic { username, password } => {
                rb.basic_auth(username, Some(password.expose()))
            }
            SearchAuth::ApiKey(key) => rb.header(
                reqwest::header::AUTHORIZATION,
                format!("ApiKey {}", key.expose()),
            ),
        }
    }

    /// Exécute une recherche sur `index` avec un corps DSL déjà compilé et
    /// validé par le service. Retourne la réponse brute du cluster.
    pub async fn search(&self, index: &str, body: &Value) -> Result<Value, SearchError> {
        // `rest_total_hits_as_int` : total renvoyé en entier (contrat stable).
        let url = format!(
            "{}/{}/_search?rest_total_hits_as_int=true",
            self.base_url, index
        );
        let resp = self
            .authed(self.http.post(&url))
            .json(body)
            .send()
            .await
            .map_err(|e| SearchError::Unavailable(e.to_string()))?;
        Self::json_or_error(resp).await
    }

    /// Crée l'index s'il n'existe pas (idempotent : un 400 `resource_already_
    /// exists_exception` est toléré). Utilisé par la stratégie d'indexation.
    pub async fn ensure_index(&self, index: &str, definition: &Value) -> Result<(), SearchError> {
        let url = format!("{}/{}", self.base_url, index);
        let resp = self
            .authed(self.http.put(&url))
            .json(definition)
            .send()
            .await
            .map_err(|e| SearchError::Unavailable(e.to_string()))?;

        let status = resp.status();
        if status.is_success() || status == StatusCode::BAD_REQUEST {
            // 400 possible si l'index existe déjà : on considère idempotent.
            return Ok(());
        }
        Err(SearchError::Upstream(status.as_u16()))
    }

    /// Indexe (upsert) un document avec un id explicite. `refresh=wait_for`
    /// rend le document visible à la recherche dès le retour (cohérence pour
    /// l'indexation événementielle).
    pub async fn index_document(
        &self,
        index: &str,
        id: &str,
        document: &Value,
    ) -> Result<(), SearchError> {
        let url = format!("{}/{}/_doc/{}?refresh=wait_for", self.base_url, index, id);
        let resp = self
            .authed(self.http.put(&url))
            .json(document)
            .send()
            .await
            .map_err(|e| SearchError::Unavailable(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(SearchError::Upstream(status.as_u16()))
        }
    }

    /// Supprime un document par id (idempotent : 404 toléré).
    pub async fn delete_document(&self, index: &str, id: &str) -> Result<(), SearchError> {
        let url = format!("{}/{}/_doc/{}?refresh=wait_for", self.base_url, index, id);
        let resp = self
            .authed(self.http.delete(&url))
            .send()
            .await
            .map_err(|e| SearchError::Unavailable(e.to_string()))?;
        let status = resp.status();
        if status.is_success() || status == StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(SearchError::Upstream(status.as_u16()))
        }
    }

    /// Indexation par lot (`_bulk`) à partir d'un corps NDJSON déjà sérialisé.
    /// Utilisé par la réindexation batch contrôlée.
    pub async fn bulk(&self, ndjson: String) -> Result<Value, SearchError> {
        let url = format!("{}/_bulk?refresh=wait_for", self.base_url);
        let resp = self
            .authed(self.http.post(&url))
            .header(reqwest::header::CONTENT_TYPE, "application/x-ndjson")
            .body(ndjson)
            .send()
            .await
            .map_err(|e| SearchError::Unavailable(e.to_string()))?;
        Self::json_or_error(resp).await
    }

    /// Vérifie la disponibilité du cluster (utilisé par la readiness).
    pub async fn ping(&self) -> Result<(), SearchError> {
        let url = format!("{}/_cluster/health", self.base_url);
        let resp = self
            .authed(self.http.get(&url))
            .send()
            .await
            .map_err(|e| SearchError::Unavailable(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(SearchError::Upstream(resp.status().as_u16()))
        }
    }

    /// Lit le corps JSON d'une réponse 2xx, sinon mappe le statut en erreur.
    async fn json_or_error(resp: reqwest::Response) -> Result<Value, SearchError> {
        let status = resp.status();
        if !status.is_success() {
            // On NE relaie PAS le corps d'erreur du cluster (peut contenir des
            // détails internes) ; seul le statut est conservé pour le log.
            return Err(SearchError::Upstream(status.as_u16()));
        }
        resp.json::<Value>()
            .await
            .map_err(|e| SearchError::Decode(e.to_string()))
    }
}
