//! Chargement et validation de la configuration au démarrage.
//!
//! Tous les secrets proviennent EXCLUSIVEMENT de variables d'environnement
//! (exigence sécurité #8). Le démarrage échoue immédiatement si une variable
//! obligatoire manque ou est invalide : on préfère un crash explicite à un
//! service qui tourne dans un état non sécurisé.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use thiserror::Error;

/// Enveloppe pour une valeur sensible (secret de signature JWT, etc.).
///
/// Son implémentation de `Debug` est volontairement caviardée afin qu'un secret
/// ne puisse jamais fuiter dans un log, un message d'erreur ou un dump.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***redacted***)")
    }
}

/// Erreurs de configuration au démarrage.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("variable d'environnement obligatoire manquante : {0}")]
    Missing(&'static str),
    #[error("variable d'environnement invalide {name} : {reason}")]
    Invalid { name: &'static str, reason: String },
}

/// Configuration applicative validée et immuable.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    /// Nombre de proxys de confiance en frontal (pour extraire l'IP cliente).
    pub trusted_proxy_hops: usize,

    pub database_url: Secret,
    pub database_max_connections: u32,

    pub jwt_secret: Secret,
    pub jwt_issuer: String,
    pub jwt_access_ttl: Duration,
    pub refresh_ttl: Duration,

    pub cors_allowed_origins: Vec<String>,
    pub cookie_secure: bool,

    pub max_body_bytes: usize,
    pub request_timeout: Duration,

    pub login_max_failed_attempts: i32,
    pub login_lockout: Duration,

    pub log_filter: String,

    /// Configuration du moteur de recherche secondaire (OpenSearch).
    ///
    /// `None` = recherche désactivée : l'endpoint `/search` répond alors 503
    /// proprement. La fonctionnalité est ainsi *opt-in* et n'impacte pas le
    /// reste de l'application si le cluster n'est pas provisionné.
    pub search: Option<SearchConfig>,
}

/// Mode d'authentification du backend AUPRÈS d'OpenSearch.
///
/// Aucun de ces secrets n'atteint jamais le frontend (exigence : le client ne
/// stocke aucun credential OpenSearch). Ils restent côté serveur.
#[derive(Clone)]
pub enum SearchAuth {
    /// HTTP Basic (`user` + mot de passe). Le mot de passe est un [`Secret`].
    Basic { username: String, password: Secret },
    /// En-tête `Authorization: ApiKey <base64>` (clé d'API OpenSearch).
    ApiKey(Secret),
}

impl fmt::Debug for SearchAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ne jamais divulguer le secret, même via Debug.
        match self {
            SearchAuth::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"***redacted***")
                .finish(),
            SearchAuth::ApiKey(_) => f.write_str("ApiKey(***redacted***)"),
        }
    }
}

/// Configuration validée du sous-système de recherche.
#[derive(Debug, Clone)]
pub struct SearchConfig {
    /// URL de base du cluster (DOIT être en `https://` : TLS obligatoire).
    pub base_url: String,
    /// Authentification backend ↔ OpenSearch.
    pub auth: SearchAuth,
    /// Certificat CA (PEM) de confiance pour un cluster à CA privée (mTLS/TLS
    /// interne). Si absent, on s'appuie sur le magasin de racines système.
    pub ca_cert_path: Option<String>,
    /// Identité client (PEM concaténé cert+clé) pour le mTLS. Optionnelle.
    pub client_identity_path: Option<String>,
    /// Préfixe/alias logique des index métier (ex. `documents`).
    pub index_prefix: String,
    /// Active l'isolation par index dédié et le filtre tenant systématique.
    pub multi_tenant: bool,
    /// Timeout des appels sortants vers OpenSearch.
    pub request_timeout: Duration,
    /// Longueur maximale (en caractères) de la requête plein-texte `q`.
    pub max_query_chars: usize,
    /// Taille de page maximale autorisée.
    pub max_page_size: i64,
    /// Fenêtre de résultats maximale (`from + size`) — borne la pagination
    /// profonde (anti-DoS, aligné sur `index.max_result_window`).
    pub max_result_window: i64,
    /// Nombre maximal de filtres acceptés dans une requête (borne la profondeur).
    pub max_filters: usize,
}

impl SearchConfig {
    /// Construit la config de recherche depuis l'environnement.
    ///
    /// Désactivée (`Ok(None)`) si `OPENSEARCH_URL` est absent. Si présente,
    /// l'URL DOIT être en HTTPS et une méthode d'auth doit être fournie, sinon
    /// le démarrage échoue (fail-fast : jamais de recherche non sécurisée).
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        let base_url = match std::env::var("OPENSEARCH_URL") {
            Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
            _ => return Ok(None),
        };

        // TLS obligatoire : on refuse explicitement tout endpoint en clair.
        if !base_url.starts_with("https://") {
            return Err(ConfigError::Invalid {
                name: "OPENSEARCH_URL",
                reason: "doit utiliser https:// (TLS obligatoire)".to_string(),
            });
        }
        let base_url = base_url.trim_end_matches('/').to_string();

        // Auth : ApiKey prioritaire si fournie, sinon Basic (user + password).
        let auth = if let Ok(key) = std::env::var("OPENSEARCH_API_KEY") {
            if key.trim().is_empty() {
                return Err(ConfigError::Invalid {
                    name: "OPENSEARCH_API_KEY",
                    reason: "valeur vide".to_string(),
                });
            }
            SearchAuth::ApiKey(Secret(key))
        } else {
            let username = require("OPENSEARCH_USERNAME")?;
            let password = Secret(require("OPENSEARCH_PASSWORD")?);
            SearchAuth::Basic { username, password }
        };

        let ca_cert_path = opt_string("OPENSEARCH_CA_CERT_PATH");
        let client_identity_path = opt_string("OPENSEARCH_CLIENT_IDENTITY_PATH");

        let index_prefix = std::env::var("OPENSEARCH_INDEX_PREFIX")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "documents".to_string());
        // Le préfixe sert à nommer des index : on le contraint strictement.
        if !is_valid_index_token(&index_prefix) {
            return Err(ConfigError::Invalid {
                name: "OPENSEARCH_INDEX_PREFIX",
                reason: "caractères autorisés : [a-z0-9_-], 1..=64".to_string(),
            });
        }

        let multi_tenant = opt_parse::<bool>("OPENSEARCH_MULTI_TENANT", false)?;
        let request_timeout =
            Duration::from_secs(opt_parse::<u64>("OPENSEARCH_TIMEOUT_SECONDS", 5)?);
        let max_query_chars = opt_parse::<usize>("OPENSEARCH_MAX_QUERY_CHARS", 256)?;
        let max_page_size = opt_parse::<i64>("OPENSEARCH_MAX_PAGE_SIZE", 50)?;
        let max_result_window = opt_parse::<i64>("OPENSEARCH_MAX_RESULT_WINDOW", 10_000)?;
        let max_filters = opt_parse::<usize>("OPENSEARCH_MAX_FILTERS", 8)?;

        Ok(Some(SearchConfig {
            base_url,
            auth,
            ca_cert_path,
            client_identity_path,
            index_prefix,
            multi_tenant,
            request_timeout,
            max_query_chars,
            max_page_size,
            max_result_window,
            max_filters,
        }))
    }
}

/// Valide un jeton d'index OpenSearch : minuscules, chiffres, `_` et `-`,
/// longueur 1..=64. Le premier caractère DOIT être alphanumérique : OpenSearch
/// interdit les noms d'index commençant par `_`, `-` ou `+` (collision avec les
/// index/API internes). Empêche l'injection de caractères spéciaux dans un nom
/// d'index dérivé de la configuration ou d'un tenant.
pub fn is_valid_index_token(s: &str) -> bool {
    if s.is_empty() || s.len() > 64 {
        return false;
    }
    let mut bytes = s.bytes();
    let first = bytes.next().expect("non-empty checked above");
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return false;
    }
    bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

impl Config {
    /// Construit la configuration depuis l'environnement courant.
    ///
    /// En développement, `main` charge d'abord un éventuel fichier `.env` via
    /// `dotenvy` ; en production, les variables proviennent de l'orchestrateur.
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind_addr = req_parse::<SocketAddr>("APP_BIND_ADDR")?;
        let trusted_proxy_hops = opt_parse::<usize>("APP_TRUSTED_PROXY_HOPS", 1)?;

        let database_url = Secret(require("DATABASE_URL")?);
        let database_max_connections = opt_parse::<u32>("DATABASE_MAX_CONNECTIONS", 10)?;

        let jwt_secret_raw = require("JWT_SECRET")?;
        // Un secret HS256 trop court réduit la sécurité de la signature.
        if jwt_secret_raw.len() < 32 {
            return Err(ConfigError::Invalid {
                name: "JWT_SECRET",
                reason: "doit faire au moins 32 octets".to_string(),
            });
        }
        let jwt_secret = Secret(jwt_secret_raw);
        let jwt_issuer = require("JWT_ISSUER")?;
        let jwt_access_ttl = Duration::from_secs(opt_parse::<u64>("JWT_ACCESS_TTL_SECONDS", 900)?);
        let refresh_ttl = Duration::from_secs(opt_parse::<u64>("REFRESH_TTL_SECONDS", 1_209_600)?);

        let cors_allowed_origins = require("CORS_ALLOWED_ORIGINS")?
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        if cors_allowed_origins.is_empty() {
            return Err(ConfigError::Invalid {
                name: "CORS_ALLOWED_ORIGINS",
                reason: "au moins une origine doit être autorisée".to_string(),
            });
        }

        let cookie_secure = opt_parse::<bool>("COOKIE_SECURE", true)?;
        let max_body_bytes = opt_parse::<usize>("MAX_BODY_BYTES", 1_048_576)?;
        let request_timeout = Duration::from_secs(opt_parse::<u64>("REQUEST_TIMEOUT_SECONDS", 15)?);

        let login_max_failed_attempts = opt_parse::<i32>("LOGIN_MAX_FAILED_ATTEMPTS", 5)?;
        let login_lockout = Duration::from_secs(opt_parse::<u64>("LOGIN_LOCKOUT_SECONDS", 900)?);

        let log_filter = std::env::var("LOG_FILTER").unwrap_or_else(|_| "info".to_string());

        let search = SearchConfig::from_env()?;

        Ok(Self {
            bind_addr,
            trusted_proxy_hops,
            database_url,
            database_max_connections,
            jwt_secret,
            jwt_issuer,
            jwt_access_ttl,
            refresh_ttl,
            cors_allowed_origins,
            cookie_secure,
            max_body_bytes,
            request_timeout,
            login_max_failed_attempts,
            login_lockout,
            log_filter,
            search,
        })
    }
}

impl Config {
    /// Constructeur destiné aux tests : configuration minimale et déterministe
    /// pointant vers une base de données fournie. Non utilisé en production.
    #[doc(hidden)]
    pub fn for_tests(database_url: impl Into<String>) -> Self {
        Self {
            bind_addr: "127.0.0.1:0".parse().expect("adresse de test valide"),
            trusted_proxy_hops: 0,
            database_url: Secret::new(database_url),
            database_max_connections: 5,
            jwt_secret: Secret::new("test_secret_at_least_32_bytes_long_value_0001"),
            jwt_issuer: "websitebase-test".to_string(),
            jwt_access_ttl: Duration::from_secs(900),
            refresh_ttl: Duration::from_secs(1_209_600),
            cors_allowed_origins: vec!["http://localhost:5173".to_string()],
            cookie_secure: false,
            max_body_bytes: 1_048_576,
            request_timeout: Duration::from_secs(15),
            login_max_failed_attempts: 5,
            login_lockout: Duration::from_secs(900),
            log_filter: "warn".to_string(),
            // Recherche désactivée par défaut en test : `/search` répond 503.
            search: None,
        }
    }
}

/// Récupère une variable obligatoire (chaîne brute).
fn require(name: &'static str) -> Result<String, ConfigError> {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => Ok(v),
        _ => Err(ConfigError::Missing(name)),
    }
}

/// Récupère une variable optionnelle non vide (chaîne brute), ou `None`.
fn opt_string(name: &'static str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Récupère et parse une variable obligatoire.
fn req_parse<T>(name: &'static str) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    let raw = require(name)?;
    raw.parse::<T>().map_err(|e| ConfigError::Invalid {
        name,
        reason: e.to_string(),
    })
}

/// Récupère et parse une variable optionnelle avec valeur par défaut.
fn opt_parse<T>(name: &'static str, default: T) -> Result<T, ConfigError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    match std::env::var(name) {
        Err(_) => Ok(default),
        Ok(raw) if raw.trim().is_empty() => Ok(default),
        Ok(raw) => raw.trim().parse::<T>().map_err(|e| ConfigError::Invalid {
            name,
            reason: e.to_string(),
        }),
    }
}
