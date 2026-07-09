//! Couche d'accès aux données.
//!
//! Toutes les requêtes utilisent les macros `sqlx::query!` / `query_as!` :
//! elles sont vérifiées à la COMPILATION contre le schéma réel (types,
//! nullabilité, noms de colonnes) et les paramètres sont TOUJOURS liés
//! (`$1`, `$2`…). Aucun SQL n'est construit par concaténation : l'injection
//! SQL est structurellement impossible (exigence sécurité).

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;

use crate::config::Config;
use crate::models::user::{UserProfile, UserRecord, UserRole};

/// Crée le pool de connexions PostgreSQL à partir de la configuration.
pub async fn create_pool(config: &Config) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(config.database_max_connections)
        .acquire_timeout(std::time::Duration::from_secs(5))
        .connect(config.database_url.expose())
        .await
}

// --- Utilisateurs -----------------------------------------------------------

/// Insère un nouvel utilisateur (rôle `user` par défaut au niveau SGBD).
///
/// En cas de violation de l'unicité de l'email, l'erreur sqlx est remontée
/// telle quelle ; le handler la traduit en conflit 409 générique.
pub async fn insert_user(
    pool: &PgPool,
    email: &str,
    password_hash: &str,
    display_name: Option<&str>,
) -> Result<UserRecord, sqlx::Error> {
    sqlx::query_as!(
        UserRecord,
        r#"
        INSERT INTO users (email, password_hash, display_name)
        VALUES ($1, $2, $3)
        RETURNING
            id,
            email,
            password_hash,
            display_name,
            role AS "role!: UserRole",
            created_at,
            updated_at
        "#,
        email,
        password_hash,
        display_name,
    )
    .fetch_one(pool)
    .await
}

/// Recherche un utilisateur par email (insensible à la casse).
pub async fn find_user_by_email(
    pool: &PgPool,
    email: &str,
) -> Result<Option<UserRecord>, sqlx::Error> {
    sqlx::query_as!(
        UserRecord,
        r#"
        SELECT
            id,
            email,
            password_hash,
            display_name,
            role AS "role!: UserRole",
            created_at,
            updated_at
        FROM users
        WHERE lower(email) = lower($1)
        "#,
        email,
    )
    .fetch_optional(pool)
    .await
}

/// Recherche un utilisateur par identifiant.
pub async fn find_user_by_id(pool: &PgPool, id: Uuid) -> Result<Option<UserRecord>, sqlx::Error> {
    sqlx::query_as!(
        UserRecord,
        r#"
        SELECT
            id,
            email,
            password_hash,
            display_name,
            role AS "role!: UserRole",
            created_at,
            updated_at
        FROM users
        WHERE id = $1
        "#,
        id,
    )
    .fetch_optional(pool)
    .await
}

/// Met à jour le nom d'affichage et retourne l'enregistrement à jour.
pub async fn update_display_name(
    pool: &PgPool,
    id: Uuid,
    display_name: Option<&str>,
) -> Result<UserRecord, sqlx::Error> {
    sqlx::query_as!(
        UserRecord,
        r#"
        UPDATE users
        SET display_name = $2
        WHERE id = $1
        RETURNING
            id,
            email,
            password_hash,
            display_name,
            role AS "role!: UserRole",
            created_at,
            updated_at
        "#,
        id,
        display_name,
    )
    .fetch_one(pool)
    .await
}

/// Liste paginée des utilisateurs (vue publique, sans hash).
pub async fn list_users(
    pool: &PgPool,
    limit: i64,
    offset: i64,
) -> Result<Vec<UserProfile>, sqlx::Error> {
    sqlx::query_as!(
        UserProfile,
        r#"
        SELECT
            id,
            email,
            display_name,
            role AS "role!: UserRole",
            created_at,
            updated_at
        FROM users
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#,
        limit,
        offset,
    )
    .fetch_all(pool)
    .await
}

/// Nombre total d'utilisateurs (pour la pagination).
pub async fn count_users(pool: &PgPool) -> Result<i64, sqlx::Error> {
    let row = sqlx::query!(r#"SELECT count(*) AS "count!" FROM users"#)
        .fetch_one(pool)
        .await?;
    Ok(row.count)
}

/// Détermine si une erreur sqlx correspond à une violation d'unicité (23505),
/// utilisée pour transformer un doublon d'email en conflit 409.
pub fn is_unique_violation(err: &sqlx::Error) -> bool {
    matches!(
        err,
        sqlx::Error::Database(db) if db.code().as_deref() == Some("23505")
    )
}
