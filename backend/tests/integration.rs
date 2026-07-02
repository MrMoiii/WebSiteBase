//! Tests d'intégration de bout en bout des endpoints HTTP.
//!
//! Couvre les cas nominaux ET des cas d'attaque : payloads malformés,
//! dépassement de limites de taille, accès non autorisé, élévation de
//! privilège (admin) et tentative d'IDOR.
//!
//! Pré-requis : une base PostgreSQL accessible via `DATABASE_URL` (le rôle
//! applicatif suffit). Voir le README pour la préparation de la base de test.

use std::net::SocketAddr;

use reqwest::StatusCode;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use websitebase_backend::config::Config;
use websitebase_backend::session::SessionStore;
use websitebase_backend::state::AppState;
use websitebase_backend::{db, routes};

/// Application de test démarrée sur un port éphémère.
struct TestApp {
    base_url: String,
    pool: PgPool,
}

impl TestApp {
    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

/// Démarre une instance de l'API sur 127.0.0.1:<port libre>.
async fn spawn_app() -> TestApp {
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://app_user:app_dev_pw@localhost:5432/websitebase".to_string()
    });

    let config = Config::for_tests(database_url);
    let pool = db::create_pool(&config)
        .await
        .expect("connexion à la base de test");
    // Store de sessions Redis (source de vérité) — requis pour l'auth. Les tests
    // d'intégration nécessitent donc un Redis accessible via REDIS_URL (fourni
    // par la CI ; défaut localhost:6379).
    let session = SessionStore::connect(&config.redis, config.refresh_ttl)
        .await
        .expect("connexion au Redis de test");
    let state = AppState::new(config, pool.clone(), session);
    let app = routes::build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind port éphémère");
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .expect("serveur de test");
    });

    TestApp {
        base_url: format!("http://{addr}"),
        pool,
    }
}

/// Génère un email unique pour isoler les données de chaque test.
fn unique_email() -> String {
    format!("user-{}@example.com", Uuid::new_v4())
}

/// Client HTTP avec gestion des cookies (pour les flux refresh/logout).
fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .build()
        .unwrap()
}

/// Inscrit un utilisateur et renvoie (client, email, access_token).
async fn register_user(app: &TestApp) -> (reqwest::Client, String, String) {
    let c = client();
    let email = unique_email();
    let resp = c
        .post(app.url("/api/v1/auth/register"))
        .json(&json!({ "email": email, "password": "a-strong-password-123" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "register doit réussir");
    let body: Value = resp.json().await.unwrap();
    let token = body["access_token"].as_str().unwrap().to_string();
    (c, email, token)
}

// --- Cas nominaux -----------------------------------------------------------

#[tokio::test]
async fn register_then_read_own_profile() {
    let app = spawn_app().await;
    let (c, email, token) = register_user(&app).await;

    let resp = c
        .get(app.url("/api/v1/users/me"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["email"], email);
    assert_eq!(body["role"], "user");
    // Le hash de mot de passe ne doit JAMAIS être exposé.
    assert!(body.get("password_hash").is_none());
}

#[tokio::test]
async fn login_succeeds_and_updates_profile() {
    let app = spawn_app().await;
    let (c, email, _) = register_user(&app).await;

    let resp = c
        .post(app.url("/api/v1/auth/login"))
        .json(&json!({ "email": email, "password": "a-strong-password-123" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let token = resp.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = c
        .patch(app.url("/api/v1/users/me"))
        .bearer_auth(&token)
        .json(&json!({ "display_name": "Renamed" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["display_name"],
        "Renamed"
    );
}

#[tokio::test]
async fn refresh_rotates_and_logout_revokes() {
    let app = spawn_app().await;
    let (c, _, _) = register_user(&app).await; // cookie de refresh stocké par le client

    // Le refresh fonctionne tant que le token est valide.
    let resp = c
        .post(app.url("/api/v1/auth/refresh"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Logout révoque le token courant.
    let resp = c.post(app.url("/api/v1/auth/logout")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Après logout, le refresh doit échouer (token révoqué + cookie effacé).
    let resp = c
        .post(app.url("/api/v1/auth/refresh"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- Cas d'attaque / sécurité ----------------------------------------------

#[tokio::test]
async fn duplicate_registration_is_conflict() {
    let app = spawn_app().await;
    let c = client();
    let email = unique_email();
    let payload = json!({ "email": email, "password": "a-strong-password-123" });

    let first = c
        .post(app.url("/api/v1/auth/register"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = c
        .post(app.url("/api/v1/auth/register"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn weak_password_is_unprocessable() {
    let app = spawn_app().await;
    let resp = client()
        .post(app.url("/api/v1/auth/register"))
        .json(&json!({ "email": unique_email(), "password": "short" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn unknown_fields_are_rejected() {
    let app = spawn_app().await;
    // Tentative d'injecter `role: admin` via un champ non prévu (deny_unknown_fields).
    let resp = client()
        .post(app.url("/api/v1/auth/register"))
        .json(&json!({
            "email": unique_email(),
            "password": "a-strong-password-123",
            "role": "admin"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn malformed_json_is_bad_request() {
    let app = spawn_app().await;
    let resp = client()
        .post(app.url("/api/v1/auth/register"))
        .header("content-type", "application/json")
        .body("{not valid json")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oversized_body_is_rejected() {
    let app = spawn_app().await;
    // Corps > 1 Mo : doit être rejeté par la limite de taille (413).
    let big = "x".repeat(2 * 1024 * 1024);
    let resp = client()
        .post(app.url("/api/v1/auth/register"))
        .header("content-type", "application/json")
        .body(format!("{{\"email\":\"a@b.com\",\"password\":\"{big}\"}}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn login_with_wrong_password_is_unauthorized() {
    let app = spawn_app().await;
    let (_, email, _) = register_user(&app).await;
    let resp = client()
        .post(app.url("/api/v1/auth/login"))
        .json(&json!({ "email": email, "password": "wrong-password-xxx" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_for_unknown_user_is_unauthorized() {
    let app = spawn_app().await;
    // Anti-énumération : même réponse générique qu'un mauvais mot de passe.
    let resp = client()
        .post(app.url("/api/v1/auth/login"))
        .json(&json!({ "email": unique_email(), "password": "a-strong-password-123" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn profile_requires_authentication() {
    let app = spawn_app().await;
    let resp = client()
        .get(app.url("/api/v1/users/me"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invalid_bearer_token_is_unauthorized() {
    let app = spawn_app().await;
    let resp = client()
        .get(app.url("/api/v1/users/me"))
        .bearer_auth("not-a-real-jwt")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_endpoint_forbidden_for_regular_user() {
    let app = spawn_app().await;
    let (c, _, token) = register_user(&app).await;
    let resp = c
        .get(app.url("/api/v1/admin/users"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn admin_endpoint_allows_admin() {
    let app = spawn_app().await;
    let (c, email, token) = register_user(&app).await;

    // Élève le compte au rôle admin (simulant une action d'administration).
    sqlx::query("UPDATE users SET role = 'admin' WHERE lower(email) = lower($1)")
        .bind(&email)
        .execute(&app.pool)
        .await
        .unwrap();

    // L'autorisation est revérifiée en base à chaque requête : le token existant
    // donne désormais accès (le rôle courant est admin).
    let resp = c
        .get(app.url("/api/v1/admin/users?page=1&page_size=10"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert!(body["total"].as_i64().unwrap() >= 1);
    assert!(body["items"].is_array());
}

#[tokio::test]
async fn pagination_rejects_out_of_range() {
    let app = spawn_app().await;
    let (c, email, token) = register_user(&app).await;
    sqlx::query("UPDATE users SET role = 'admin' WHERE lower(email) = lower($1)")
        .bind(&email)
        .execute(&app.pool)
        .await
        .unwrap();

    // page_size au-delà de la borne max (100) doit être rejeté (422).
    let resp = c
        .get(app.url("/api/v1/admin/users?page=1&page_size=10000"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// --- Sessions Redis (source de vérité) --------------------------------------
// NB : ces tests nécessitent Redis ET PostgreSQL (fournis par la CI).

#[tokio::test]
async fn logout_revokes_access_token_immediately() {
    let app = spawn_app().await;
    let (c, _, token) = register_user(&app).await;

    // Le token d'accès fonctionne tant que la session existe.
    let resp = c
        .get(app.url("/api/v1/users/me"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Logout : la session (sid) est supprimée de Redis.
    let resp = c.post(app.url("/api/v1/auth/logout")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Le MÊME token d'accès (non expiré) est désormais rejeté : révocation
    // immédiate via la vérification de session dans Redis.
    let resp = c
        .get(app.url("/api/v1/users/me"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sessions_list_shows_current() {
    let app = spawn_app().await;
    let (c, _, token) = register_user(&app).await;

    let resp = c
        .get(app.url("/api/v1/users/me/sessions"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["current"], true);
}

#[tokio::test]
async fn revoke_unknown_session_is_not_found() {
    let app = spawn_app().await;
    let (c, _, token) = register_user(&app).await;
    let unknown = Uuid::new_v4();
    let resp = c
        .delete(app.url(&format!("/api/v1/users/me/sessions/{unknown}")))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn logout_others_keeps_current_and_revokes_the_rest() {
    let app = spawn_app().await;
    // Session 1 (client c1) + un compte.
    let (c1, email, token1) = register_user(&app).await;

    // Session 2 (client c2) pour le MÊME utilisateur.
    let c2 = client();
    let resp = c2
        .post(app.url("/api/v1/auth/login"))
        .json(&json!({ "email": email, "password": "a-strong-password-123" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let token2 = resp.json::<Value>().await.unwrap()["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Depuis la session 1 : déconnexion des AUTRES sessions.
    let resp = c1
        .post(app.url("/api/v1/users/me/sessions/logout-others"))
        .bearer_auth(&token1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        resp.json::<Value>().await.unwrap()["revoked_sessions"]
            .as_u64()
            .unwrap()
            >= 1
    );

    // La session courante (1) reste valide…
    let resp = c1
        .get(app.url("/api/v1/users/me"))
        .bearer_auth(&token1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // …tandis que la session 2 est révoquée immédiatement.
    let resp = c2
        .get(app.url("/api/v1/users/me"))
        .bearer_auth(&token2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn metrics_endpoint_exposes_prometheus_text() {
    let app = spawn_app().await;
    // Génère du trafic mesurable avant de scraper.
    let _ = client().get(app.url("/health")).send().await.unwrap();

    let resp = client().get(app.url("/metrics")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.contains("text/plain"),
        "format Prometheus texte"
    );

    let body = resp.text().await.unwrap();
    assert!(body.contains("# TYPE http_requests_total counter"));
    assert!(body.contains("http_request_duration_seconds_bucket"));
    // Aucune donnée à haute cardinalité (corrélation = rôle des logs, pas des métriques).
    assert!(!body.contains("request_id"));
}

#[tokio::test]
async fn unknown_route_is_not_found() {
    let app = spawn_app().await;
    let resp = client()
        .get(app.url("/api/v1/does-not-exist"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn security_headers_are_present() {
    let app = spawn_app().await;
    let resp = client().get(app.url("/health")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let headers = resp.headers();
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["x-frame-options"], "DENY");
    assert!(headers.contains_key("content-security-policy"));
    assert!(headers.contains_key("strict-transport-security"));
    // Un correlation id est propagé dans la réponse.
    assert!(headers.contains_key("x-request-id"));
}
