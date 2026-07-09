//! Modèles liés à l'utilisateur : rôle, enregistrement en base, vues publiques
//! et DTO de mise à jour. Toute entrée externe passe par un type strict annoté
//! `#[serde(deny_unknown_fields)]` + `garde` (exigence sécurité #2).

use garde::Validate;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

/// Rôle métier. Mappé sur le type ENUM PostgreSQL `user_role`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserRole {
    User,
    Admin,
}

impl UserRole {
    pub fn is_admin(self) -> bool {
        matches!(self, UserRole::Admin)
    }
}

/// Enregistrement complet d'un utilisateur tel que lu en base.
///
/// Contient `password_hash` : ne JAMAIS sérialiser cette structure vers le
/// client. On expose `UserProfile` à la place.
///
/// Le verrouillage anti-bruteforce (ancien `failed_login_attempts` /
/// `locked_until`) vit désormais dans Redis (`lock:{user_id}`) — cf.
/// `backend/SESSIONS.md` — et ne figure plus dans cet enregistrement.
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub role: UserRole,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

/// Vue publique d'un utilisateur (sans hash ni compteurs internes).
#[derive(Debug, Clone, Serialize)]
pub struct UserProfile {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub role: UserRole,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

impl From<UserRecord> for UserProfile {
    fn from(u: UserRecord) -> Self {
        Self {
            id: u.id,
            email: u.email,
            display_name: u.display_name,
            role: u.role,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

/// DTO de mise à jour de profil. Au moins un champ modifiable est exposé ;
/// les champs sensibles (rôle, email, hash) ne sont PAS modifiables ici.
#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct UpdateProfileRequest {
    /// Nouveau nom d'affichage. `Some("")` est rejeté (longueur min 1).
    #[garde(inner(length(chars, min = 1, max = 100)))]
    pub display_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    fn record(role: UserRole) -> UserRecord {
        UserRecord {
            id: Uuid::nil(),
            email: "alice@example.com".into(),
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$abc$def".into(),
            display_name: Some("Alice".into()),
            role,
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            updated_at: OffsetDateTime::from_unix_timestamp(1_700_000_500).unwrap(),
        }
    }

    #[test]
    fn is_admin_distinguishes_roles() {
        assert!(!UserRole::User.is_admin());
        assert!(UserRole::Admin.is_admin());
    }

    #[test]
    fn profile_from_record_drops_the_password_hash() {
        let rec = record(UserRole::Admin);
        let hash = rec.password_hash.clone();
        let profile = UserProfile::from(rec);
        assert_eq!(profile.id, Uuid::nil());
        assert_eq!(profile.email, "alice@example.com");
        assert_eq!(profile.display_name.as_deref(), Some("Alice"));
        assert_eq!(profile.role, UserRole::Admin);
        // La sérialisation publique ne contient JAMAIS le hash.
        let json = serde_json::to_string(&profile).unwrap();
        assert!(!json.contains(&hash));
        assert!(!json.contains("password"));
    }

    #[test]
    fn role_serde_roundtrip_and_rejects_unknown() {
        assert_eq!(serde_json::to_string(&UserRole::User).unwrap(), "\"user\"");
        assert_eq!(
            serde_json::to_string(&UserRole::Admin).unwrap(),
            "\"admin\""
        );
        assert_eq!(
            serde_json::from_str::<UserRole>("\"admin\"").unwrap(),
            UserRole::Admin
        );
        assert!(serde_json::from_str::<UserRole>("\"superuser\"").is_err());
    }

    #[test]
    fn update_profile_display_name_bounds() {
        // None : autorisé (aucun changement de nom).
        assert!(UpdateProfileRequest { display_name: None }
            .validate()
            .is_ok());
        // 1 caractère : borne basse incluse.
        assert!(UpdateProfileRequest {
            display_name: Some("x".into())
        }
        .validate()
        .is_ok());
        // 100 caractères : borne haute incluse.
        assert!(UpdateProfileRequest {
            display_name: Some("a".repeat(100))
        }
        .validate()
        .is_ok());
        // Vide : rejeté (min 1).
        assert!(UpdateProfileRequest {
            display_name: Some(String::new())
        }
        .validate()
        .is_err());
        // 101 caractères : rejeté (> max).
        assert!(UpdateProfileRequest {
            display_name: Some("a".repeat(101))
        }
        .validate()
        .is_err());
    }

    #[test]
    fn update_profile_rejects_unknown_fields() {
        let json = r#"{"display_name":"x","role":"admin"}"#;
        assert!(serde_json::from_str::<UpdateProfileRequest>(json).is_err());
    }

    #[test]
    fn update_profile_length_counts_chars_not_bytes() {
        // 100 caractères multioctets (é = 2 octets) doivent passer : la règle
        // compte les CARACTÈRES, pas les octets.
        assert!(UpdateProfileRequest {
            display_name: Some("é".repeat(100))
        }
        .validate()
        .is_ok());
        assert!(UpdateProfileRequest {
            display_name: Some("é".repeat(101))
        }
        .validate()
        .is_err());
    }
}
