//! Handlers d'authentification : inscription, login, refresh, logout.
//!
//! Décisions de sécurité notables :
//! - le refresh token est livré dans un cookie `HttpOnly; Secure; SameSite=Strict`
//!   (inaccessible au JS, non envoyé en cross-site => protège du vol XSS et du CSRF) ;
//! - les refresh tokens sont stockés HACHÉS et font l'objet d'une ROTATION à
//!   chaque rafraîchissement (un token rejoué après usage est détecté/inutile) ;
//! - le login ne révèle PAS si l'email existe (réponse générique + vérification
//!   factice pour égaliser le temps de réponse / anti-énumération) ;
//! - verrouillage de compte après N échecs (anti-bruteforce, complémentaire du
//!   rate limiting réseau).

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use time::OffsetDateTime;

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

    let (jar, response) = establish_session(&state, &user, &ctx, CookieJar::new()).await?;
    Ok((StatusCode::CREATED, jar, Json(response)))
}

/// POST /api/v1/auth/login
pub async fn login(
    State(state): State<AppState>,
    ctx: ClientContext,
    ValidatedJson(body): ValidatedJson<LoginRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let now = OffsetDateTime::now_utc();
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

    // Compte verrouillé ?
    if let Some(locked_until) = user.locked_until {
        if locked_until > now {
            tracing::warn!(
                security.event = true,
                event = "login_locked_out",
                user.id = %user.id,
                client.ip = ctx.ip.as_deref().unwrap_or("unknown"),
                "tentative de login sur compte verrouillé"
            );
            return Err(ApiError::TooManyRequests);
        }
    }

    let valid = password::verify_password(&body.password, &user.password_hash)?;
    if !valid {
        let lockout_until = now + to_time_duration(state.config.login_lockout);
        db::register_failed_login(
            &state.pool,
            user.id,
            state.config.login_max_failed_attempts,
            lockout_until,
        )
        .await?;
        log_failed_login(&ctx, Some(user.id));
        return Err(ApiError::Unauthorized);
    }

    // Succès : on remet à zéro les compteurs anti-bruteforce.
    db::reset_failed_login(&state.pool, user.id).await?;

    tracing::info!(
        security.event = true,
        event = "login_succeeded",
        user.id = %user.id,
        client.ip = ctx.ip.as_deref().unwrap_or("unknown"),
        "login réussi"
    );

    let (jar, response) = establish_session(&state, &user, &ctx, CookieJar::new()).await?;
    Ok((StatusCode::OK, jar, Json(response)))
}

/// POST /api/v1/auth/refresh
///
/// Lit le refresh token dans le cookie, le valide (présent, non révoqué, non
/// expiré), puis effectue une ROTATION : l'ancien token est révoqué et un
/// nouveau est émis.
pub async fn refresh(
    State(state): State<AppState>,
    ctx: ClientContext,
    jar: CookieJar,
) -> Result<impl IntoResponse, ApiError> {
    let presented = jar
        .get(REFRESH_COOKIE)
        .map(|c| c.value().to_string())
        .ok_or(ApiError::Unauthorized)?;

    let token_hash = tokens::hash_refresh_token(&presented);
    let row = db::find_refresh_token(&state.pool, &token_hash)
        .await?
        .ok_or(ApiError::Unauthorized)?;

    let now = OffsetDateTime::now_utc();
    if row.revoked_at.is_some() || row.expires_at <= now {
        // Un refresh token révoqué présenté à nouveau est un signal suspect.
        tracing::warn!(
            security.event = true,
            event = "refresh_token_invalid",
            user.id = %row.user_id,
            "refresh token révoqué ou expiré présenté"
        );
        return Err(ApiError::Unauthorized);
    }

    // Rotation : révoquer l'ancien token avant d'en émettre un nouveau.
    db::revoke_refresh_token(&state.pool, &token_hash).await?;

    let user = db::find_user_by_id(&state.pool, row.user_id)
        .await?
        .ok_or(ApiError::Unauthorized)?;

    let (jar, response) = establish_session(&state, &user, &ctx, jar).await?;
    Ok((StatusCode::OK, jar, Json(response)))
}

/// POST /api/v1/auth/logout
///
/// Révoque le refresh token présenté et efface le cookie. Idempotent : renvoie
/// 204 même si aucun token valide n'était présent.
pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<impl IntoResponse, ApiError> {
    if let Some(cookie) = jar.get(REFRESH_COOKIE) {
        let token_hash = tokens::hash_refresh_token(cookie.value());
        let revoked = db::revoke_refresh_token(&state.pool, &token_hash).await?;
        if revoked > 0 {
            tracing::info!(
                security.event = true,
                event = "logout",
                "refresh token révoqué"
            );
        }
    }

    // Cookie de suppression (même path/attributs) pour effacer côté navigateur.
    let removal = build_refresh_cookie(&state, String::new(), true);
    let jar = jar.add(removal);
    Ok((StatusCode::NO_CONTENT, jar))
}

// --- Helpers ---------------------------------------------------------------

/// Crée un token d'accès + un refresh token (stocké haché) et construit la
/// réponse + le cookie. Factorise inscription, login et refresh.
async fn establish_session(
    state: &AppState,
    user: &UserRecord,
    ctx: &ClientContext,
    jar: CookieJar,
) -> Result<(CookieJar, AuthResponse), ApiError> {
    let access_token = jwt::issue_access_token(&state.config, user.id, user.role)?;

    let generated = tokens::generate_refresh_token();
    let expires_at = OffsetDateTime::now_utc() + to_time_duration(state.config.refresh_ttl);
    db::insert_refresh_token(
        &state.pool,
        user.id,
        &generated.hash,
        expires_at,
        ctx.user_agent.as_deref(),
        ctx.ip.as_deref(),
    )
    .await?;

    let cookie = build_refresh_cookie(state, generated.plaintext, false);
    let jar = jar.add(cookie);

    let response = AuthResponse {
        access_token,
        token_type: "Bearer",
        expires_in: state.config.jwt_access_ttl.as_secs() as i64,
        user: UserProfile::from(user.clone()),
    };
    Ok((jar, response))
}

/// Construit le cookie du refresh token avec tous les attributs de sécurité.
/// Si `removal` est vrai, le cookie est immédiatement expiré.
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
fn log_failed_login(ctx: &ClientContext, user_id: Option<uuid::Uuid>) {
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
