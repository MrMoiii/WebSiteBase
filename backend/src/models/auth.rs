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

    fn register(email: &str, password: &str, display_name: Option<&str>) -> RegisterRequest {
        RegisterRequest {
            email: email.to_string(),
            password: password.to_string(),
            display_name: display_name.map(str::to_string),
        }
    }

    #[test]
    fn register_password_length_boundaries() {
        // 12 = borne basse incluse ; 11 = rejeté.
        assert!(register("a@b.co", &"x".repeat(12), None).validate().is_ok());
        assert!(register("a@b.co", &"x".repeat(11), None)
            .validate()
            .is_err());
        // 128 = borne haute incluse ; 129 = rejeté (anti-DoS de hachage).
        assert!(register("a@b.co", &"x".repeat(128), None)
            .validate()
            .is_ok());
        assert!(register("a@b.co", &"x".repeat(129), None)
            .validate()
            .is_err());
    }

    #[test]
    fn register_display_name_boundaries() {
        assert!(register("a@b.co", &"x".repeat(12), Some("y"))
            .validate()
            .is_ok());
        assert!(register("a@b.co", &"x".repeat(12), Some(&"y".repeat(100)))
            .validate()
            .is_ok());
        assert!(register("a@b.co", &"x".repeat(12), Some(&"y".repeat(101)))
            .validate()
            .is_err());
    }

    #[test]
    fn register_email_rejects_overlong_local_part() {
        // Adresse syntaxiquement plausible mais > 320 caractères : rejetée.
        let huge = format!("{}@example.com", "a".repeat(320));
        assert!(register(&huge, &"x".repeat(12), None).validate().is_err());
    }

    #[test]
    fn login_validation_password_min_one() {
        // Login borne le mot de passe à [1, 128] SANS minimum de robustesse.
        let ok = LoginRequest {
            email: "a@b.co".into(),
            password: "x".into(),
        };
        assert!(ok.validate().is_ok());

        let empty = LoginRequest {
            email: "a@b.co".into(),
            password: String::new(),
        };
        assert!(empty.validate().is_err());

        let too_long = LoginRequest {
            email: "a@b.co".into(),
            password: "x".repeat(129),
        };
        assert!(too_long.validate().is_err());
    }

    #[test]
    fn login_rejects_invalid_email_and_unknown_fields() {
        let bad_email = LoginRequest {
            email: "nope".into(),
            password: "secret".into(),
        };
        assert!(bad_email.validate().is_err());

        let json = r#"{"email":"a@b.co","password":"secret","captcha":"x"}"#;
        assert!(serde_json::from_str::<LoginRequest>(json).is_err());
    }
}
