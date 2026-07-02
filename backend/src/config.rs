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

    /// Store de sessions Redis (source de vérité des sessions/refresh tokens).
    /// OBLIGATOIRE : l'authentification en dépend (fail-fast au démarrage).
    pub redis: RedisConfig,

    /// Configuration du monitoring d'API via OpenSearch (observabilité).
    ///
    /// `None` = monitoring désactivé : l'application fonctionne normalement,
    /// aucun log n'est envoyé. *Opt-in* : sans `OPENSEARCH_URL`, rien n'est
    /// monté (pas d'impact si le cluster n'est pas provisionné).
    pub monitoring: Option<MonitoringConfig>,
}

/// Configuration du store de sessions Redis.
///
/// Redis est la **source de vérité** des sessions : refresh tokens (rotation +
/// TTL natif), liaison des access tokens à un `sid` (révocation immédiate),
/// verrouillage anti-bruteforce et rate limiting distribués.
#[derive(Debug, Clone)]
pub struct RedisConfig {
    /// URL de connexion (`redis://` ou `rediss://` pour TLS). Secret (peut
    /// contenir un mot de passe) : caviardé en `Debug`.
    pub url: Secret,
    /// Durée de vie ABSOLUE d'une session (plafond dur, non prolongeable). Au
    /// delà, une nouvelle authentification est exigée même si la session est
    /// restée active. Le TTL glissant (idle) réutilise `refresh_ttl`.
    pub session_absolute_ttl: Duration,
    /// Nombre maximal de requêtes d'auth par fenêtre et par IP (rate limiting
    /// distribué, complémentaire du `tower_governor` en mémoire).
    pub auth_rate_limit_max: u32,
    /// Fenêtre du rate limiting d'auth.
    pub auth_rate_limit_window: Duration,
}

impl RedisConfig {
    /// Charge la configuration Redis depuis l'environnement (fail-fast).
    pub fn from_env() -> Result<Self, ConfigError> {
        let url = Secret(require("REDIS_URL")?);
        let raw = url.expose();
        if !(raw.starts_with("redis://") || raw.starts_with("rediss://")) {
            return Err(ConfigError::Invalid {
                name: "REDIS_URL",
                reason: "doit commencer par redis:// ou rediss:// (TLS)".to_string(),
            });
        }
        let session_absolute_ttl =
            Duration::from_secs(opt_parse::<u64>("SESSION_ABSOLUTE_TTL_SECONDS", 2_592_000)?);
        let auth_rate_limit_max = opt_parse::<u32>("AUTH_RATE_LIMIT_MAX", 30)?.max(1);
        let auth_rate_limit_window =
            Duration::from_secs(opt_parse::<u64>("AUTH_RATE_LIMIT_WINDOW_SECONDS", 60)?.max(1));
        Ok(Self {
            url,
            session_absolute_ttl,
            auth_rate_limit_max,
            auth_rate_limit_window,
        })
    }
}

/// Mode d'authentification du backend AUPRÈS d'OpenSearch.
///
/// Aucun de ces secrets n'atteint jamais le frontend (le navigateur ne connaît
/// ni l'URL ni les credentials du cluster). Ils restent côté serveur.
#[derive(Clone)]
pub enum OpenSearchAuth {
    /// HTTP Basic (`user` + mot de passe). Le mot de passe est un [`Secret`].
    Basic { username: String, password: Secret },
    /// En-tête `Authorization: ApiKey <base64>` (clé d'API OpenSearch).
    ApiKey(Secret),
}

impl fmt::Debug for OpenSearchAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ne jamais divulguer le secret, même via Debug.
        match self {
            OpenSearchAuth::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"***redacted***")
                .finish(),
            OpenSearchAuth::ApiKey(_) => f.write_str("ApiKey(***redacted***)"),
        }
    }
}

/// Configuration validée du monitoring d'API.
#[derive(Debug, Clone)]
pub struct MonitoringConfig {
    /// URL de base du cluster (DOIT être en `https://` : TLS obligatoire).
    pub base_url: String,
    /// Authentification backend ↔ OpenSearch.
    pub auth: OpenSearchAuth,
    /// Certificat CA (PEM) de confiance pour un cluster à CA privée (TLS
    /// interne). Si absent, on s'appuie sur le magasin de racines système.
    pub ca_cert_path: Option<String>,
    /// Identité client (PEM concaténé cert+clé) pour le mTLS. Optionnelle.
    pub client_identity_path: Option<String>,
    /// Préfixe des index quotidiens de logs (ex. `api-logs` → `api-logs-YYYY.MM.DD`).
    pub index_prefix: String,
    /// Timeout des appels sortants vers OpenSearch.
    pub request_timeout: Duration,
    /// Taille de lot maximale avant envoi `_bulk`.
    pub batch_size: usize,
    /// Intervalle de vidange périodique du tampon.
    pub flush_interval: Duration,
    /// Capacité du canal interne (au-delà, les events sont abandonnés, jamais
    /// de contre-pression sur le chemin de requête).
    pub channel_capacity: usize,
}

impl MonitoringConfig {
    /// Construit la config de monitoring depuis l'environnement.
    ///
    /// Désactivé (`Ok(None)`) si `OPENSEARCH_URL` est absent. Si présent,
    /// l'URL DOIT être en HTTPS et une méthode d'auth doit être fournie, sinon
    /// le démarrage échoue (fail-fast : jamais d'envoi non sécurisé).
    pub fn from_env() -> Result<Option<Self>, ConfigError> {
        let base_url = match std::env::var("OPENSEARCH_URL") {
            Ok(v) if !v.trim().is_empty() => v.trim().to_string(),
            _ => return Ok(None),
        };

        let base_url = base_url.trim_end_matches('/').to_string();

        // TLS obligatoire par défaut. Le `http://` n'est toléré qu'en DEV
        // explicite (`OPENSEARCH_ALLOW_INSECURE=true`), pour un cluster sur
        // réseau interne non exposé. En production, toute URL non-https est
        // refusée au démarrage (fail-fast).
        let allow_insecure = opt_parse::<bool>("OPENSEARCH_ALLOW_INSECURE", false)?;
        let scheme_ok =
            base_url.starts_with("https://") || (base_url.starts_with("http://") && allow_insecure);
        if !scheme_ok {
            return Err(ConfigError::Invalid {
                name: "OPENSEARCH_URL",
                reason: "doit utiliser https:// (TLS obligatoire) ; pour du http \
                         en dev sur réseau interne, poser OPENSEARCH_ALLOW_INSECURE=true"
                    .to_string(),
            });
        }

        // Auth : ApiKey prioritaire si fournie, sinon Basic (user + password).
        let auth = if let Ok(key) = std::env::var("OPENSEARCH_API_KEY") {
            if key.trim().is_empty() {
                return Err(ConfigError::Invalid {
                    name: "OPENSEARCH_API_KEY",
                    reason: "valeur vide".to_string(),
                });
            }
            OpenSearchAuth::ApiKey(Secret(key))
        } else {
            let username = require("OPENSEARCH_USERNAME")?;
            let password = Secret(require("OPENSEARCH_PASSWORD")?);
            OpenSearchAuth::Basic { username, password }
        };

        let ca_cert_path = opt_string("OPENSEARCH_CA_CERT_PATH");
        let client_identity_path = opt_string("OPENSEARCH_CLIENT_IDENTITY_PATH");

        let index_prefix = std::env::var("OPENSEARCH_INDEX_PREFIX")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "api-logs".to_string());
        // Le préfixe sert à nommer des index : on le contraint strictement.
        if !is_valid_index_token(&index_prefix) {
            return Err(ConfigError::Invalid {
                name: "OPENSEARCH_INDEX_PREFIX",
                reason: "caractères autorisés : [a-z0-9_-], 1..=64".to_string(),
            });
        }

        let request_timeout =
            Duration::from_secs(opt_parse::<u64>("OPENSEARCH_TIMEOUT_SECONDS", 5)?);
        let batch_size = opt_parse::<usize>("OPENSEARCH_BATCH_SIZE", 500)?.max(1);
        let flush_interval =
            Duration::from_secs(opt_parse::<u64>("OPENSEARCH_FLUSH_INTERVAL_SECONDS", 2)?.max(1));
        let channel_capacity = opt_parse::<usize>("OPENSEARCH_CHANNEL_CAPACITY", 10_000)?.max(1);

        Ok(Some(MonitoringConfig {
            base_url,
            auth,
            ca_cert_path,
            client_identity_path,
            index_prefix,
            request_timeout,
            batch_size,
            flush_interval,
            channel_capacity,
        }))
    }
}

/// Valide un jeton d'index OpenSearch : minuscules, chiffres, `_` et `-`,
/// longueur 1..=64. Le premier caractère DOIT être alphanumérique : OpenSearch
/// interdit les noms d'index commençant par `_`, `-` ou `+` (collision avec les
/// index/API internes). Empêche l'injection de caractères spéciaux dans un nom
/// d'index dérivé de la configuration.
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

        let redis = RedisConfig::from_env()?;
        let monitoring = MonitoringConfig::from_env()?;

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
            redis,
            monitoring,
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
            redis: RedisConfig {
                // Les tests d'intégration fournissent un Redis via REDIS_URL
                // (défaut : instance locale). Non contacté par les tests unitaires.
                url: Secret::new(
                    std::env::var("REDIS_URL")
                        .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
                ),
                session_absolute_ttl: Duration::from_secs(2_592_000),
                auth_rate_limit_max: 1000,
                auth_rate_limit_window: Duration::from_secs(60),
            },
            // Monitoring désactivé par défaut en test (aucun envoi).
            monitoring: None,
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
