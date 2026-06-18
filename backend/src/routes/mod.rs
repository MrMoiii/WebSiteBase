//! Construction du routeur et application de la pile de middlewares de sécurité.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use tower::ServiceBuilder;
use tower_governor::governor::GovernorConfigBuilder;
use tower_governor::GovernorLayer;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::CorsLayer;
use tower_http::request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::handlers::{admin, auth, health, metrics, users};
use crate::middleware::client::RateLimitKeyExtractor;
use crate::middleware::security_headers::SECURITY_HEADERS;
use crate::monitoring::layer::record_requests;
use crate::state::AppState;

/// En-tête portant le correlation id propagé dans les logs et les réponses.
const REQUEST_ID_HEADER: &str = "x-request-id";

/// Assemble le routeur complet à partir de l'état applicatif.
pub fn build_router(state: AppState) -> Router {
    let config = state.config.clone();
    // Clone destiné au middleware de monitoring (l'original est consommé par
    // `with_state`). Clone bon marché : Arc<Config> + Sender mpsc + PgPool.
    let state_for_monitoring = state.clone();

    // --- Rate limiting des endpoints sensibles (login/register) -------------
    // Clé = IP cliente de CONFIANCE (cf. RateLimitKeyExtractor), déterminée en
    // respectant `trusted_proxy_hops` : on N'utilise PAS `SmartIpKeyExtractor`,
    // qui retient l'IP la plus à gauche de X-Forwarded-For — valeur usurpable
    // permettant de contourner le quota en faisant tourner l'en-tête. Quota :
    // rafale de 10 requêtes, réapprovisionnée d'1 jeton toutes les 2 secondes.
    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(2)
            .burst_size(10)
            .key_extractor(RateLimitKeyExtractor::new(config.trusted_proxy_hops))
            .finish()
            .expect("configuration governor valide"),
    );
    let rate_limit = GovernorLayer {
        config: governor_conf,
    };

    // Routes d'authentification non protégées par JWT mais soumises au rate
    // limiting (surface d'attaque bruteforce / énumération).
    let auth_routes = Router::new()
        .route("/register", post(auth::register))
        .route("/login", post(auth::login))
        .route("/refresh", post(auth::refresh))
        .route("/logout", post(auth::logout))
        .layer(rate_limit);

    // Routes métier (l'autorisation est imposée par les extracteurs des handlers).
    let api_routes = Router::new()
        .nest("/auth", auth_routes)
        .route("/users/me", get(users::get_me).patch(users::update_me))
        .route("/admin/users", get(admin::list_users));

    let mut app = Router::new()
        .route("/health", get(health::liveness))
        .route("/health/ready", get(health::readiness))
        // Exposition Prometheus (scrape interne). Pas d'auth, agrégats seulement.
        .route("/metrics", get(metrics::metrics))
        .nest("/api/v1", api_routes)
        // Toute route inconnue => 404 JSON générique (pas de fuite de structure).
        .fallback(handler_404)
        .with_state(state);

    // En-têtes de sécurité ajoutés à TOUTES les réponses (y compris erreurs).
    for (name, value) in SECURITY_HEADERS {
        app = app.layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        ));
    }

    // --- Pile de middlewares globaux ----------------------------------------
    // ServiceBuilder applique du plus EXTERNE (haut) au plus INTERNE (bas).
    app.layer(
        ServiceBuilder::new()
            // 1. Masque Authorization/Cookie pour qu'ils ne soient jamais loggés.
            .layer(SetSensitiveRequestHeadersLayer::new([
                header::AUTHORIZATION,
                header::COOKIE,
            ]))
            // 2. Génère un correlation id par requête.
            .layer(SetRequestIdLayer::new(
                header::HeaderName::from_static(REQUEST_ID_HEADER),
                MakeRequestUuid,
            ))
            // 2bis. Monitoring : capture l'issue de chaque requête (succès/erreur)
            //       et l'envoie à OpenSearch (non bloquant). Placé ici pour voir
            //       le correlation id (posé ci-dessus) ET les statuts générés par
            //       les couches métier en aval (timeout 408, limite 413, 500…).
            .layer(axum::middleware::from_fn_with_state(
                state_for_monitoring,
                record_requests,
            ))
            // 3. Trace chaque requête dans un span incluant le correlation id.
            .layer(
                TraceLayer::new_for_http().make_span_with(|req: &Request<axum::body::Body>| {
                    let request_id = req
                        .headers()
                        .get(REQUEST_ID_HEADER)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("unknown")
                        .to_string();
                    tracing::info_span!(
                        "http_request",
                        method = %req.method(),
                        path = %req.uri().path(),
                        correlation_id = %request_id,
                    )
                }),
            )
            // 4. Recopie le correlation id dans la réponse (traçabilité client).
            .layer(PropagateRequestIdLayer::new(
                header::HeaderName::from_static(REQUEST_ID_HEADER),
            ))
            // 5. Convertit toute panique en 500 générique (pas de fuite).
            .layer(CatchPanicLayer::new())
            // 6. CORS : liste blanche stricte.
            .layer(build_cors(&config.cors_allowed_origins))
            // 7. Timeout global par requête (408 si dépassé).
            .layer(TimeoutLayer::with_status_code(
                StatusCode::REQUEST_TIMEOUT,
                config.request_timeout,
            ))
            // 8. Limite de taille du corps de requête (413 si dépassée). Ne
            //    modifie pas le type du corps de réponse (contrairement à
            //    RequestBodyLimitLayer), ce qui préserve la compatibilité avec
            //    CatchPanic/Trace en amont.
            .layer(DefaultBodyLimit::max(config.max_body_bytes)),
    )
}

/// Construit la couche CORS à partir de la liste blanche d'origines.
fn build_cors(origins: &[String]) -> CorsLayer {
    let parsed: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();

    CorsLayer::new()
        // Jamais de wildcard : uniquement les origines explicitement autorisées.
        .allow_origin(parsed)
        .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::OPTIONS])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
        // Autorise l'envoi du cookie de refresh depuis les origines de confiance.
        .allow_credentials(true)
        .max_age(Duration::from_secs(600))
}

/// 404 générique au format JSON de l'API.
async fn handler_404() -> crate::errors::ApiError {
    crate::errors::ApiError::NotFound
}
