//! Émission et vérification des tokens d'accès JWT (HS256, courte durée).
//!
//! Les tokens d'accès sont volontairement éphémères (~15 min). La session
//! longue est portée par un refresh token opaque, révocable et stocké haché
//! en base (cf. `tokens.rs`). Ce découpage limite l'impact d'une fuite de
//! token d'accès.

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::Config;
use crate::errors::ApiError;
use crate::models::user::UserRole;

/// Claims d'un token d'accès. `deny_unknown_fields` rejette tout token dont la
/// structure ne correspond pas exactement (défense en profondeur).
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessClaims {
    /// Identifiant de l'utilisateur (subject).
    pub sub: Uuid,
    /// Rôle au moment de l'émission (sert d'indice ; l'autorisation reste
    /// revérifiée côté handler).
    pub role: UserRole,
    /// Émetteur attendu.
    pub iss: String,
    /// Date d'émission (epoch secondes).
    pub iat: i64,
    /// Expiration (epoch secondes).
    pub exp: i64,
    /// Identifiant unique du token (utile pour l'audit / révocation future).
    pub jti: Uuid,
    /// Identifiant de la SESSION (stable à travers les rotations de refresh
    /// token). Vérifié dans Redis à chaque requête : si la session est révoquée,
    /// le token d'accès est immédiatement invalide (révocation instantanée).
    pub sid: Uuid,
    /// Type de token, fixé à "access" pour empêcher la confusion de tokens.
    pub typ: String,
}

const ACCESS_TOKEN_TYPE: &str = "access";

/// Émet un token d'accès signé pour un utilisateur donné.
pub fn issue_access_token(
    config: &Config,
    user_id: Uuid,
    role: UserRole,
    session_id: Uuid,
) -> Result<String, ApiError> {
    let now = OffsetDateTime::now_utc();
    let exp = now + config.jwt_access_ttl;

    let claims = AccessClaims {
        sub: user_id,
        role,
        iss: config.jwt_issuer.clone(),
        iat: now.unix_timestamp(),
        exp: exp.unix_timestamp(),
        jti: Uuid::new_v4(),
        sid: session_id,
        typ: ACCESS_TOKEN_TYPE.to_string(),
    };

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.expose().as_bytes()),
    )
    .map_err(|e| ApiError::Internal(format!("jwt encode: {e}")))
}

/// Vérifie et décode un token d'accès. Toute anomalie (signature, expiration,
/// émetteur, type) se traduit par une 401 générique — aucun détail n'est exposé.
pub fn verify_access_token(config: &Config, token: &str) -> Result<AccessClaims, ApiError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&[config.jwt_issuer.as_str()]);
    validation.set_required_spec_claims(&["exp", "iss", "sub"]);
    validation.validate_exp = true;
    // Petite tolérance d'horloge entre instances.
    validation.leeway = 5;

    let data = decode::<AccessClaims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.expose().as_bytes()),
        &validation,
    )
    .map_err(|_| ApiError::Unauthorized)?;

    // Refuse un token qui ne serait pas explicitement de type "access".
    if data.claims.typ != ACCESS_TOKEN_TYPE {
        return Err(ApiError::Unauthorized);
    }

    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn cfg() -> Config {
        Config::for_tests("postgres://unused")
    }

    #[test]
    fn issue_then_verify_roundtrip() {
        let config = cfg();
        let uid = Uuid::new_v4();
        let sid = Uuid::new_v4();
        let token = issue_access_token(&config, uid, UserRole::User, sid).unwrap();
        let claims = verify_access_token(&config, &token).unwrap();
        assert_eq!(claims.sub, uid);
        assert_eq!(claims.sid, sid);
        assert_eq!(claims.role, UserRole::User);
        assert_eq!(claims.typ, "access");
        assert_eq!(claims.iss, config.jwt_issuer);
    }

    #[test]
    fn rejects_tampered_token() {
        let config = cfg();
        let token =
            issue_access_token(&config, Uuid::new_v4(), UserRole::Admin, Uuid::new_v4()).unwrap();
        // Modifie un caractère de la signature.
        let mut bytes: Vec<char> = token.chars().collect();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == 'a' { 'b' } else { 'a' };
        let tampered: String = bytes.into_iter().collect();
        assert!(verify_access_token(&config, &tampered).is_err());
    }

    #[test]
    fn rejects_wrong_secret() {
        let config = cfg();
        let token =
            issue_access_token(&config, Uuid::new_v4(), UserRole::User, Uuid::new_v4()).unwrap();
        let mut other = cfg();
        other.jwt_secret = crate::config::Secret::new("a_completely_different_secret_value_0002");
        assert!(verify_access_token(&other, &token).is_err());
    }

    #[test]
    fn rejects_wrong_issuer() {
        let config = cfg();
        let token =
            issue_access_token(&config, Uuid::new_v4(), UserRole::User, Uuid::new_v4()).unwrap();
        let mut other = cfg();
        other.jwt_issuer = "someone-else".to_string();
        assert!(verify_access_token(&other, &token).is_err());
    }
}
