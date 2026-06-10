//! Modèles liés à l'utilisateur : rôle, enregistrement en base, vues publiques
//! et DTO de mise à jour. Toute entrée externe passe par un type strict annoté
//! `#[serde(deny_unknown_fields)]` + `validator` (exigence sécurité #2).

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;
use validator::Validate;

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
#[derive(Debug, Clone)]
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub role: UserRole,
    pub failed_login_attempts: i32,
    pub locked_until: Option<OffsetDateTime>,
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
    #[validate(length(min = 1, max = 100))]
    pub display_name: Option<String>,
}
