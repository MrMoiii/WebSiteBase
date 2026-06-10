//! DTO des flux d'authentification (inscription, login, réponse de tokens).
//!
//! Choix des bornes :
//! - mot de passe : min 12 (durcissement au-delà du minimum NIST 800-63B),
//!   max 128 pour éviter un DoS par hachage Argon2 d'une chaîne géante ;
//! - email : max 320 (RFC 5321).

use garde::Validate;
use serde::{Deserialize, Serialize};

use super::user::UserProfile;

/// Corps d'inscription.
#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    #[garde(email, length(chars, max = 320))]
    pub email: String,
    #[garde(length(chars, min = 12, max = 128))]
    pub password: String,
    // `inner(...)` applique la règle à la valeur interne quand `Some` ; `None`
    // est ignoré (champ optionnel).
    #[garde(inner(length(chars, min = 1, max = 100)))]
    pub display_name: Option<String>,
}

/// Corps de login. On borne aussi le mot de passe en entrée (anti-DoS) sans
/// imposer la longueur minimale : la vérification se fait par comparaison de
/// hash, et un ancien compte pourrait avoir un format différent.
#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    #[garde(email, length(chars, max = 320))]
    pub email: String,
    #[garde(length(chars, min = 1, max = 128))]
    pub password: String,
}

/// Réponse renvoyée après inscription, login ou refresh.
///
/// Le refresh token n'apparaît PAS ici : il est délivré dans un cookie
/// `HttpOnly; Secure; SameSite=Strict` inaccessible au JavaScript.
#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub token_type: &'static str,
    /// Durée de validité du token d'accès, en secondes.
    pub expires_in: i64,
    pub user: UserProfile,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_register_passes() {
        let r = RegisterRequest {
            email: "alice@example.com".to_string(),
            password: "a-strong-password-123".to_string(),
            display_name: Some("Alice".to_string()),
        };
        assert!(r.validate().is_ok());
    }

    #[test]
    fn short_password_is_rejected() {
        let r = RegisterRequest {
            email: "alice@example.com".to_string(),
            password: "short".to_string(),
            display_name: None,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn invalid_email_is_rejected() {
        let r = RegisterRequest {
            email: "not-an-email".to_string(),
            password: "a-strong-password-123".to_string(),
            display_name: None,
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn unknown_fields_are_rejected_at_deserialization() {
        // `deny_unknown_fields` : un champ non prévu (ex. tentative d'injecter
        // `role`) fait échouer la désérialisation -> rejet par défaut.
        let json = r#"{"email":"a@b.com","password":"a-strong-password-123","role":"admin"}"#;
        let parsed: Result<RegisterRequest, _> = serde_json::from_str(json);
        assert!(parsed.is_err());
    }

    #[test]
    fn empty_display_name_is_rejected() {
        let r = RegisterRequest {
            email: "alice@example.com".to_string(),
            password: "a-strong-password-123".to_string(),
            display_name: Some(String::new()),
        };
        assert!(r.validate().is_err());
    }
}
