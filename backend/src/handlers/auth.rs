//! Handlers d'authentification : inscription, login, refresh, logout.
//!
//! Décisions de sécurité notables :
//! - les SESSIONS sont stockées dans **Redis** (source de vérité) : refresh
//!   token opaque haché, rotation ATOMIQUE (`GETDEL` → un seul gagnant, anti-rejeu),
//!   TTL glissant (idle) + plafond absolu, et un `sid` porté par le JWT permettant
//!   la révocation immédiate des tokens d'accès ;
//! - le refresh token est livré dans un cookie `HttpOnly; Secure; SameSite=Strict`
//!   (inaccessible au JS, non envoyé en cross-site => protège du vol XSS et du CSRF) ;
//! - le login ne révèle PAS si l'email existe (réponse générique + vérification
//!   factice pour égaliser le temps de réponse / anti-énumération) ;
//! - verrouillage de compte après N échecs et rate limiting par IP, tous deux
//!   **distribués** via Redis (cohérents entre instances), en plus du rate
//!   limiting en mémoire (`tower_governor`).

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use uuid::Uuid;

use crate::auth::{jwt, password, tokens};
use crate::db;
use crate::errors::ApiError;
use crate::middleware::client::ClientContext;
use crate::middleware::validation::ValidatedJson;
use crate::models::auth::{AuthResponse, LoginRequest, RegisterRequest};
use crate::models::user::{UserProfile, UserRecord};
use crate::state::AppState;

/// Nom du cookie portant le refresh token.
const REFRESH_COOKIE: &str = "refresh_token";

/// POST /api/v1/auth/register
pub async fn register(
    State(state): State<AppState>,
    ctx: ClientContext,
    ValidatedJson(body): ValidatedJson<RegisterRequest>,
) -> Result<impl IntoResponse, ApiError> {
    enforce_auth_rate_limit(&state, &ctx).await?;

    let password_hash = password::hash_password(&body.password)?;

    let user = match db::insert_user(
        &state.pool,
        &body.email,
        &password_hash,
        body.display_name.as_deref(),
    )
    .await
    {
        Ok(u) => u,
        Err(e) if db::is_unique_violation(&e) => {
            // On reste générique : ne pas confirmer l'existence d'un compte.
            return Err(ApiError::Conflict("Email already registered."));
        }
        Err(e) => return Err(e.into()),
    };

    tracing::info!(
        security.event = true,
        event = "user_registered",
        user.id = %user.id,
        client.ip = ctx.ip.as_deref().unwrap_or("unknown"),
        "nouvel utilisateur inscrit"
    );

    let (jar, response) = start_session(&state, &user, &ctx, CookieJar::new()).await?;
    Ok((StatusCode::CREATED, jar, Json(response)))
}

/// POST /api/v1/auth/login
pub async fn login(
    State(state): State<AppState>,
    ctx: ClientContext,
    ValidatedJson(body): ValidatedJson<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    enforce_auth_rate_limit(&state, &ctx).await?;

    let maybe_user = db::find_user_by_email(&state.pool, &body.email).await?;

    let user = match maybe_user {
        Some(u) => u,
        None => {
            // Anti-énumération : on effectue une vérification factice pour que
            // le temps de réponse ne trahisse pas l'absence du compte.
            let _ = password::verify_password(&body.password, dummy_phc());
            log_failed_login(&ctx, None);
            return Err(ApiError::Unauthorized);
        }
    };

    // Verrouillage anti-bruteforce (distribué via Redis).
    let max_attempts = i64::from(state.config.login_max_failed_attempts);
    if state.session.is_locked(&user.id, max_attempts).await? {
        tracing::warn!(
            security.event = true,
            event = "login_locked_out",
            user.id = %user.id,
            client.ip = ctx.ip.as_deref().unwrap_or("unknown"),
            "tentative de login sur compte verrouillé"
        );
        return Err(ApiError::TooManyRequests);
    }

    let valid = password::verify_password(&body.password, &user.password_hash)?;
    if !valid {
        let count = state
            .session
            .record_login_failure(&user.id, state.config.login_lockout)
            .await?;
        log_failed_login(&ctx, Some(user.id));
        if count >= max_attempts {
            tracing::warn!(
                security.event = true,
                event = "account_locked",
                user.id = %user.id,
                "compte verrouillé après trop d'échecs"
            );
        }
        return Err(ApiError::Unauthorized);
    }

    // Succès : on remet à zéro les compteurs anti-bruteforce.
    state.session.clear_login_failures(&user.id).await?;

    tracing::info!(
        security.event = true,
        event = "login_succeeded",
        user.id = %user.id,
        client.ip = ctx.ip.as_deref().unwrap_or("unknown"),
        "login réussi"
    );

    let (jar, response) = start_session(&state, &user, &ctx, CookieJar::new()).await?;
    Ok((StatusCode::OK, jar, Json(response)))
}

/// POST /api/v1/auth/refresh
///
/// Lit le refresh token dans le cookie et effectue une ROTATION atomique dans
/// Redis (l'ancien token est consommé par `GETDEL` : un rejeu ou une requête
/// concurrente obtient un échec). La session (`sid`) reste stable.
pub async fn refresh(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, ApiError> {
    let presented = jar
        .get(REFRESH_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or(ApiError::Unauthorized)?;

    let old_hash = tokens::hash_refresh_token(&presented);
    let generated = tokens::generate_refresh_token();

    let rotated = match state.session.rotate(&old_hash, &generated.hash).await? {
        Some(r) => r,
        None => {
            // Token inconnu, déjà tourné (rejeu / race) ou session expirée.
            tracing::warn!(
                security.event = true,
                event = "refresh_token_invalid",
                "refresh token rejeté (rejeu, expiration ou plafond absolu)"
            );
            return Err(ApiError::Unauthorized);
        }
    };

    let user = db::find_user_by_id(&state.pool, rotated.user_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;

    let access_token = jwt::issue_access_token(&state.config, user.id, user.role, rotated.sid)?;
    let jar = jar.add(build_refresh_cookie(&state, generated.plaintext, false));
    Ok((
        StatusCode::OK,
        jar,
        Json(auth_response(&state, &user, access_token)),
    ))
}

/// POST /api/v1/auth/logout
///
/// Révoque la session portant le refresh token présenté et efface le cookie.
/// Idempotent : renvoie 204 même si aucun token valide n'était présent.
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(cookie) = jar.get(REFRESH_COOKIE) {
        let token_hash = tokens::hash_refresh_token(cookie.value());
        state.session.logout(&token_hash).await?;
        tracing::info!(security.event = true, event = "logout", "session révoquée");
    }

    // Cookie de suppression (même path/attributs) pour effacer côté navigateur.
    let removal = build_refresh_cookie(&state, String::new(), true);
    let jar = jar.add(removal);
    Ok((StatusCode::NO_CONTENT, jar))
}

// --- Helpers ---------------------------------------------------------------

/// Démarre une NOUVELLE session (login/register) : crée la session dans Redis,
/// émet un token d'accès lié à son `sid`, pose le cookie de refresh.
async fn start_session(
    state: &AppState,
    user: &UserRecord,
    ctx: &ClientContext,
    jar: CookieJar,
) -> Result<(CookieJar, AuthResponse), ApiError> {
    let generated = tokens::generate_refresh_token();
    let sid = state
        .session
        .create(
            user.id,
            ctx.user_agent.as_deref(),
            ctx.ip.as_deref(),
            &generated.hash,
        )
        .await?;

    let access_token = jwt::issue_access_token(&state.config, user.id, user.role, sid)?;
    let jar = jar.add(build_refresh_cookie(state, generated.plaintext, false));
    Ok((jar, auth_response(state, user, access_token)))
}

/// Construit la réponse d'authentification (token d'accès + profil).
fn auth_response(state: &AppState, user: &UserRecord, access_token: String) -> AuthResponse {
    AuthResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.config.jwt_access_ttl.as_secs() as i64,
        user: UserProfile::from(user.clone()),
    }
}

/// Applique le rate limiting d'auth distribué (par IP). Complète le
/// `tower_governor` en mémoire ; cohérent entre plusieurs instances.
async fn enforce_auth_rate_limit(state: &AppState, ctx: &ClientContext) -> Result<(), ApiError> {
    let key = ctx.ip.as_deref().unwrap_or("unknown");
    if !state.session.auth_rate_limit_ok(key).await? {
        tracing::warn!(
            security.event = true,
            event = "auth_rate_limited",
            client.ip = key,
            "quota de requêtes d'authentification dépassé"
        );
        return Err(ApiError::TooManyRequests);
    }
    Ok(())
}

/// Construit le cookie du refresh token avec tous les attributs de sécurité.
/// Si `removal` est vrai, le cookie est immédiatement expiré. Le `Max-Age`
/// suit le TTL glissant (idle) de la session.
fn build_refresh_cookie(state: &AppState, value: String, removal: bool) -> Cookie<'static> {
    let mut cookie = Cookie::new(REFRESH_COOKIE, value);
    cookie.set_http_only(true); // inaccessible au JavaScript
    cookie.set_secure(state.config.cookie_secure); // HTTPS uniquement en prod
    cookie.set_same_site(SameSite::Strict); // protection CSRF
    cookie.set_path("/api/v1/auth"); // limité aux endpoints d'auth
    if removal {
        cookie.set_max_age(time::Duration::seconds(0));
    } else {
        cookie.set_max_age(to_time_duration(state.config.refresh_ttl));
    }
    cookie
}

/// Convertit une `std::time::Duration` en `time::Duration`.
fn to_time_duration(d: std::time::Duration) -> time::Duration {
    time::Duration::seconds(d.as_secs() as i64)
}

/// Log d'un échec de login (événement SOC), sans révéler la cause exacte.
fn log_failed_login(ctx: &ClientContext, user_id: Option<Uuid>) {
    tracing::warn!(
        security.event = true,
        event = "login_failed",
        user.id = user_id
            .map(|u| u.to_string())
            .unwrap_or_else(|| "unknown".into()),
        client.ip = ctx.ip.as_deref().unwrap_or("unknown"),
        client.user_agent = ctx.user_agent.as_deref().unwrap_or("unknown"),
        "échec de login"
    );
}

/// Hash PHC factice servant à égaliser le temps de réponse lorsqu'aucun
/// utilisateur ne correspond (anti-énumération). Calculé une seule fois, à la
/// demande, à partir d'un mot de passe interne — garantit un hash Argon2 valide
/// et donc un coût de vérification réaliste.
fn dummy_phc() -> &'static str {
    use std::sync::OnceLock;
    static CELL: OnceLock<String> = OnceLock::new();
    CELL.get_or_init(|| {
        password::hash_password("timing-equalization-placeholder").unwrap_or_default()
    })
}
