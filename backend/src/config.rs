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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // --- Secret : jamais de fuite via Debug -------------------------------

    #[test]
    fn secret_exposes_value_but_debug_is_redacted() {
        let s = Secret::new("super-sensitive-value");
        assert_eq!(s.expose(), "super-sensitive-value");
        let dbg = format!("{s:?}");
        assert_eq!(dbg, "Secret(***redacted***)");
        assert!(!dbg.contains("super-sensitive-value"));
    }

    #[test]
    fn secret_clone_preserves_value() {
        let s = Secret::new(String::from("v"));
        assert_eq!(s.clone().expose(), "v");
    }

    #[test]
    fn opensearch_auth_debug_never_leaks_secret() {
        let basic = OpenSearchAuth::Basic {
            username: "admin".into(),
            password: Secret::new("hunter2"),
        };
        let d = format!("{basic:?}");
        assert!(d.contains("admin"));
        assert!(d.contains("***redacted***"));
        assert!(!d.contains("hunter2"));

        let key = OpenSearchAuth::ApiKey(Secret::new("api-key-material"));
        let d = format!("{key:?}");
        assert!(d.contains("***redacted***"));
        assert!(!d.contains("api-key-material"));
    }

    #[test]
    fn config_error_display_messages() {
        assert_eq!(
            ConfigError::Missing("X").to_string(),
            "variable d'environnement obligatoire manquante : X"
        );
        assert_eq!(
            ConfigError::Invalid {
                name: "Y",
                reason: "bad".into(),
            }
            .to_string(),
            "variable d'environnement invalide Y : bad"
        );
    }

    // --- is_valid_index_token : bornes et jeu de caractères ---------------

    #[test]
    fn index_token_accepts_valid_tokens() {
        assert!(is_valid_index_token("api-logs"));
        assert!(is_valid_index_token("a")); // 1 caractère
        assert!(is_valid_index_token("0")); // chiffre en tête autorisé
        assert!(is_valid_index_token("a_b-c9"));
        assert!(is_valid_index_token(&"a".repeat(64))); // borne haute incluse
    }

    #[test]
    fn index_token_rejects_out_of_bounds_length() {
        assert!(!is_valid_index_token("")); // vide
        assert!(!is_valid_index_token(&"a".repeat(65))); // > 64
    }

    #[test]
    fn index_token_rejects_bad_first_char() {
        assert!(!is_valid_index_token("_leading")); // OpenSearch interdit `_`
        assert!(!is_valid_index_token("-leading"));
        assert!(!is_valid_index_token("+leading"));
        assert!(!is_valid_index_token("Abc")); // majuscule interdite partout
    }

    #[test]
    fn index_token_rejects_bad_inner_chars() {
        assert!(!is_valid_index_token("api.logs")); // point
        assert!(!is_valid_index_token("api/logs")); // slash
        assert!(!is_valid_index_token("api logs")); // espace
        assert!(!is_valid_index_token("apiLogs")); // majuscule
        assert!(!is_valid_index_token("api:logs")); // deux-points
        assert!(!is_valid_index_token("logsé")); // non-ASCII
    }

    // --- from_env : accès sérialisé à l'environnement du process ----------
    //
    // `std::env` est un état global partagé : on sérialise TOUS les tests qui
    // le touchent derrière un même verrou, et on restaure l'environnement
    // après chaque cas (isolation contre les autres tests du binaire).

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Toutes les variables lues par la config (remises à zéro avant chaque cas).
    const ALL_KEYS: &[&str] = &[
        "APP_BIND_ADDR",
        "APP_TRUSTED_PROXY_HOPS",
        "DATABASE_URL",
        "DATABASE_MAX_CONNECTIONS",
        "JWT_SECRET",
        "JWT_ISSUER",
        "JWT_ACCESS_TTL_SECONDS",
        "REFRESH_TTL_SECONDS",
        "CORS_ALLOWED_ORIGINS",
        "COOKIE_SECURE",
        "MAX_BODY_BYTES",
        "REQUEST_TIMEOUT_SECONDS",
        "LOGIN_MAX_FAILED_ATTEMPTS",
        "LOGIN_LOCKOUT_SECONDS",
        "LOG_FILTER",
        "REDIS_URL",
        "SESSION_ABSOLUTE_TTL_SECONDS",
        "AUTH_RATE_LIMIT_MAX",
        "AUTH_RATE_LIMIT_WINDOW_SECONDS",
        "OPENSEARCH_URL",
        "OPENSEARCH_ALLOW_INSECURE",
        "OPENSEARCH_API_KEY",
        "OPENSEARCH_USERNAME",
        "OPENSEARCH_PASSWORD",
        "OPENSEARCH_CA_CERT_PATH",
        "OPENSEARCH_CLIENT_IDENTITY_PATH",
        "OPENSEARCH_INDEX_PREFIX",
        "OPENSEARCH_TIMEOUT_SECONDS",
        "OPENSEARCH_BATCH_SIZE",
        "OPENSEARCH_FLUSH_INTERVAL_SECONDS",
        "OPENSEARCH_CHANNEL_CAPACITY",
    ];

    /// Verrouille l'environnement, le nettoie, applique `vars`, exécute `f`,
    /// puis restaure l'état initial. `None` = variable retirée.
    fn with_env<T>(vars: &[(&str, Option<&str>)], f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved: Vec<(&str, Option<String>)> = ALL_KEYS
            .iter()
            .map(|k| (*k, std::env::var(k).ok()))
            .collect();
        for k in ALL_KEYS {
            std::env::remove_var(k);
        }
        for (k, v) in vars {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        let out = f();
        for (k, v) in saved {
            match v {
                Some(v) => std::env::set_var(k, v),
                None => std::env::remove_var(k),
            }
        }
        out
    }

    /// Jeu minimal de variables OBLIGATOIRES et valides pour `Config::from_env`.
    fn valid_required() -> Vec<(&'static str, Option<&'static str>)> {
        vec![
            ("APP_BIND_ADDR", Some("127.0.0.1:8080")),
            ("DATABASE_URL", Some("postgres://u:p@localhost/db")),
            (
                "JWT_SECRET",
                Some("a_secret_that_is_at_least_32_bytes_long!!"),
            ),
            ("JWT_ISSUER", Some("websitebase")),
            ("CORS_ALLOWED_ORIGINS", Some("https://example.com")),
            ("REDIS_URL", Some("redis://localhost:6379")),
        ]
    }

    fn merged(
        extra: &[(&'static str, Option<&'static str>)],
    ) -> Vec<(&'static str, Option<&'static str>)> {
        let mut v = valid_required();
        v.extend_from_slice(extra);
        v
    }

    // -- helpers privés --

    #[test]
    fn require_rejects_missing_and_blank() {
        with_env(&[("APP_BIND_ADDR", None)], || {
            assert!(matches!(
                require("APP_BIND_ADDR"),
                Err(ConfigError::Missing(_))
            ));
        });
        with_env(&[("APP_BIND_ADDR", Some("   "))], || {
            assert!(matches!(
                require("APP_BIND_ADDR"),
                Err(ConfigError::Missing(_))
            ));
        });
        with_env(&[("APP_BIND_ADDR", Some("value"))], || {
            assert_eq!(require("APP_BIND_ADDR").unwrap(), "value");
        });
    }

    #[test]
    fn opt_string_trims_and_filters_empty() {
        with_env(&[("LOG_FILTER", Some("  hello  "))], || {
            assert_eq!(opt_string("LOG_FILTER"), Some("hello".to_string()));
        });
        with_env(&[("LOG_FILTER", Some("   "))], || {
            assert_eq!(opt_string("LOG_FILTER"), None);
        });
        with_env(&[("LOG_FILTER", None)], || {
            assert_eq!(opt_string("LOG_FILTER"), None);
        });
    }

    #[test]
    fn opt_parse_uses_default_and_reports_invalid() {
        with_env(&[("MAX_BODY_BYTES", None)], || {
            assert_eq!(opt_parse::<usize>("MAX_BODY_BYTES", 42).unwrap(), 42);
        });
        with_env(&[("MAX_BODY_BYTES", Some("  "))], || {
            assert_eq!(opt_parse::<usize>("MAX_BODY_BYTES", 42).unwrap(), 42);
        });
        with_env(&[("MAX_BODY_BYTES", Some(" 100 "))], || {
            assert_eq!(opt_parse::<usize>("MAX_BODY_BYTES", 42).unwrap(), 100);
        });
        with_env(&[("MAX_BODY_BYTES", Some("not-a-number"))], || {
            assert!(matches!(
                opt_parse::<usize>("MAX_BODY_BYTES", 42),
                Err(ConfigError::Invalid { .. })
            ));
        });
    }

    #[test]
    fn req_parse_reports_invalid_type() {
        with_env(&[("APP_TRUSTED_PROXY_HOPS", Some("abc"))], || {
            assert!(matches!(
                req_parse::<usize>("APP_TRUSTED_PROXY_HOPS"),
                Err(ConfigError::Invalid { .. })
            ));
        });
    }

    // -- Config::from_env --

    #[test]
    fn config_from_env_minimal_ok_with_defaults() {
        let cfg = with_env(&valid_required(), Config::from_env).unwrap();
        assert_eq!(cfg.bind_addr.port(), 8080);
        assert_eq!(cfg.trusted_proxy_hops, 1); // défaut
        assert_eq!(cfg.database_max_connections, 10); // défaut
        assert_eq!(cfg.jwt_access_ttl, Duration::from_secs(900));
        assert_eq!(cfg.cors_allowed_origins, vec!["https://example.com"]);
        assert!(cfg.cookie_secure); // défaut true
        assert_eq!(cfg.max_body_bytes, 1_048_576);
        assert_eq!(cfg.login_max_failed_attempts, 5);
        assert_eq!(cfg.log_filter, "info");
        assert!(cfg.monitoring.is_none());
    }

    #[test]
    fn config_from_env_rejects_short_jwt_secret() {
        let vars = merged(&[("JWT_SECRET", Some("too-short"))]);
        let err = with_env(&vars, Config::from_env).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                name: "JWT_SECRET",
                ..
            }
        ));
    }

    #[test]
    fn config_from_env_accepts_jwt_secret_exactly_32_bytes() {
        let vars = merged(&[("JWT_SECRET", Some("0123456789abcdef0123456789abcdef"))]); // 32
        assert!(with_env(&vars, Config::from_env).is_ok());
    }

    #[test]
    fn config_from_env_missing_required_fields() {
        for key in [
            "APP_BIND_ADDR",
            "DATABASE_URL",
            "JWT_SECRET",
            "JWT_ISSUER",
            "CORS_ALLOWED_ORIGINS",
            "REDIS_URL",
        ] {
            let vars = merged(&[(key, None)]);
            let err = with_env(&vars, Config::from_env).unwrap_err();
            assert!(
                matches!(err, ConfigError::Missing(_) | ConfigError::Invalid { .. }),
                "clé manquante {key} devrait échouer, obtenu {err:?}"
            );
        }
    }

    #[test]
    fn config_from_env_rejects_bad_bind_addr() {
        let vars = merged(&[("APP_BIND_ADDR", Some("not-an-address"))]);
        let err = with_env(&vars, Config::from_env).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                name: "APP_BIND_ADDR",
                ..
            }
        ));
    }

    #[test]
    fn config_from_env_rejects_empty_cors_list() {
        // Une liste faite uniquement de séparateurs/espaces se réduit à vide.
        let vars = merged(&[("CORS_ALLOWED_ORIGINS", Some("  ,  , "))]);
        let err = with_env(&vars, Config::from_env).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::Invalid {
                name: "CORS_ALLOWED_ORIGINS",
                ..
            }
        ));
    }

    #[test]
    fn config_from_env_parses_multiple_cors_origins() {
        let vars = merged(&[(
            "CORS_ALLOWED_ORIGINS",
            Some("https://a.com, https://b.com ,https://c.com"),
        )]);
        let cfg = with_env(&vars, Config::from_env).unwrap();
        assert_eq!(
            cfg.cors_allowed_origins,
            vec!["https://a.com", "https://b.com", "https://c.com"]
        );
    }

    // -- RedisConfig::from_env --

    #[test]
    fn redis_config_requires_url() {
        with_env(&[("REDIS_URL", None)], || {
            assert!(matches!(
                RedisConfig::from_env(),
                Err(ConfigError::Missing(_))
            ));
        });
    }

    #[test]
    fn redis_config_rejects_bad_scheme() {
        with_env(&[("REDIS_URL", Some("http://localhost:6379"))], || {
            assert!(matches!(
                RedisConfig::from_env(),
                Err(ConfigError::Invalid {
                    name: "REDIS_URL",
                    ..
                })
            ));
        });
    }

    #[test]
    fn redis_config_accepts_both_schemes_and_defaults() {
        for url in ["redis://localhost:6379", "rediss://secure:6380"] {
            let cfg = with_env(&[("REDIS_URL", Some(url))], RedisConfig::from_env).unwrap();
            assert_eq!(cfg.url.expose(), url);
            assert_eq!(cfg.session_absolute_ttl, Duration::from_secs(2_592_000));
            assert_eq!(cfg.auth_rate_limit_max, 30);
            assert_eq!(cfg.auth_rate_limit_window, Duration::from_secs(60));
        }
    }

    #[test]
    fn redis_config_clamps_rate_limit_floor_to_one() {
        let vars = [
            ("REDIS_URL", Some("redis://localhost:6379")),
            ("AUTH_RATE_LIMIT_MAX", Some("0")),
            ("AUTH_RATE_LIMIT_WINDOW_SECONDS", Some("0")),
        ];
        let cfg = with_env(&vars, RedisConfig::from_env).unwrap();
        assert_eq!(cfg.auth_rate_limit_max, 1); // .max(1)
        assert_eq!(cfg.auth_rate_limit_window, Duration::from_secs(1)); // .max(1)
    }

    #[test]
    fn redis_config_rejects_non_numeric_ttl() {
        let vars = [
            ("REDIS_URL", Some("redis://localhost:6379")),
            ("SESSION_ABSOLUTE_TTL_SECONDS", Some("forever")),
        ];
        assert!(matches!(
            with_env(&vars, RedisConfig::from_env),
            Err(ConfigError::Invalid { .. })
        ));
    }

    // -- MonitoringConfig::from_env --

    #[test]
    fn monitoring_disabled_when_url_absent_or_blank() {
        with_env(&[("OPENSEARCH_URL", None)], || {
            assert!(MonitoringConfig::from_env().unwrap().is_none());
        });
        with_env(&[("OPENSEARCH_URL", Some("   "))], || {
            assert!(MonitoringConfig::from_env().unwrap().is_none());
        });
    }

    #[test]
    fn monitoring_rejects_plain_http_without_optin() {
        let vars = [
            ("OPENSEARCH_URL", Some("http://opensearch:9200")),
            ("OPENSEARCH_USERNAME", Some("admin")),
            ("OPENSEARCH_PASSWORD", Some("admin")),
        ];
        assert!(matches!(
            with_env(&vars, MonitoringConfig::from_env),
            Err(ConfigError::Invalid {
                name: "OPENSEARCH_URL",
                ..
            })
        ));
    }

    #[test]
    fn monitoring_allows_http_with_insecure_optin() {
        let vars = [
            ("OPENSEARCH_URL", Some("http://opensearch:9200/")),
            ("OPENSEARCH_ALLOW_INSECURE", Some("true")),
            ("OPENSEARCH_API_KEY", Some("k")),
        ];
        let cfg = with_env(&vars, MonitoringConfig::from_env)
            .unwrap()
            .unwrap();
        assert_eq!(cfg.base_url, "http://opensearch:9200"); // slash final retiré
        assert!(matches!(cfg.auth, OpenSearchAuth::ApiKey(_)));
    }

    #[test]
    fn monitoring_https_with_basic_auth_and_defaults() {
        let vars = [
            ("OPENSEARCH_URL", Some("https://opensearch:9200")),
            ("OPENSEARCH_USERNAME", Some("admin")),
            ("OPENSEARCH_PASSWORD", Some("s3cret")),
        ];
        let cfg = with_env(&vars, MonitoringConfig::from_env)
            .unwrap()
            .unwrap();
        match cfg.auth {
            OpenSearchAuth::Basic { username, .. } => assert_eq!(username, "admin"),
            _ => panic!("attendu Basic"),
        }
        assert_eq!(cfg.index_prefix, "api-logs"); // défaut
        assert_eq!(cfg.batch_size, 500);
        assert_eq!(cfg.channel_capacity, 10_000);
    }

    #[test]
    fn monitoring_api_key_takes_priority_over_basic() {
        let vars = [
            ("OPENSEARCH_URL", Some("https://os:9200")),
            ("OPENSEARCH_API_KEY", Some("the-key")),
            ("OPENSEARCH_USERNAME", Some("admin")),
            ("OPENSEARCH_PASSWORD", Some("admin")),
        ];
        let cfg = with_env(&vars, MonitoringConfig::from_env)
            .unwrap()
            .unwrap();
        assert!(matches!(cfg.auth, OpenSearchAuth::ApiKey(_)));
    }

    #[test]
    fn monitoring_rejects_empty_api_key() {
        let vars = [
            ("OPENSEARCH_URL", Some("https://os:9200")),
            ("OPENSEARCH_API_KEY", Some("   ")),
        ];
        assert!(matches!(
            with_env(&vars, MonitoringConfig::from_env),
            Err(ConfigError::Invalid {
                name: "OPENSEARCH_API_KEY",
                ..
            })
        ));
    }

    #[test]
    fn monitoring_https_requires_some_auth() {
        // https valide mais AUCUNE auth fournie -> username obligatoire manquant.
        let vars = [("OPENSEARCH_URL", Some("https://os:9200"))];
        assert!(matches!(
            with_env(&vars, MonitoringConfig::from_env),
            Err(ConfigError::Missing("OPENSEARCH_USERNAME"))
        ));
    }

    #[test]
    fn monitoring_rejects_invalid_index_prefix() {
        let vars = [
            ("OPENSEARCH_URL", Some("https://os:9200")),
            ("OPENSEARCH_API_KEY", Some("k")),
            ("OPENSEARCH_INDEX_PREFIX", Some("Bad/Prefix")),
        ];
        assert!(matches!(
            with_env(&vars, MonitoringConfig::from_env),
            Err(ConfigError::Invalid {
                name: "OPENSEARCH_INDEX_PREFIX",
                ..
            })
        ));
    }

    #[test]
    fn monitoring_clamps_numeric_floors() {
        let vars = [
            ("OPENSEARCH_URL", Some("https://os:9200")),
            ("OPENSEARCH_API_KEY", Some("k")),
            ("OPENSEARCH_BATCH_SIZE", Some("0")),
            ("OPENSEARCH_FLUSH_INTERVAL_SECONDS", Some("0")),
            ("OPENSEARCH_CHANNEL_CAPACITY", Some("0")),
        ];
        let cfg = with_env(&vars, MonitoringConfig::from_env)
            .unwrap()
            .unwrap();
        assert_eq!(cfg.batch_size, 1);
        assert_eq!(cfg.flush_interval, Duration::from_secs(1));
        assert_eq!(cfg.channel_capacity, 1);
    }
}
