-- =============================================================================
-- Migration initiale : schéma de gestion des utilisateurs.
-- Exécutée par le rôle propriétaire (droits DDL). Le rôle applicatif ne
-- reçoit que des droits DML (cf. README / SECURITY.md, exigence #9).
-- =============================================================================

-- gen_random_uuid() est fourni par l'extension pgcrypto (présente par défaut
-- en PostgreSQL >= 13 via "pgcrypto"). On l'active explicitement.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Rôle métier de l'utilisateur. Type ENUM => valeurs contraintes au niveau SGBD,
-- impossible d'insérer une valeur hors domaine même par erreur applicative.
CREATE TYPE user_role AS ENUM ('user', 'admin');

-- -----------------------------------------------------------------------------
-- Table des utilisateurs
-- -----------------------------------------------------------------------------
CREATE TABLE users (
    id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    -- L'email est stocké tel que saisi mais l'unicité est insensible à la casse
    -- via l'index unique fonctionnel ci-dessous (évite les doublons Alice/alice).
    email                 TEXT         NOT NULL,
    -- Hash Argon2id complet (inclut sel + paramètres). JAMAIS le mot de passe.
    password_hash         TEXT         NOT NULL,
    display_name          TEXT,
    role                  user_role    NOT NULL DEFAULT 'user',
    -- Compteurs anti-bruteforce (verrouillage de compte applicatif).
    failed_login_attempts INTEGER      NOT NULL DEFAULT 0,
    locked_until          TIMESTAMPTZ,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),

    CONSTRAINT users_email_len_chk        CHECK (char_length(email) <= 320),
    CONSTRAINT users_display_name_len_chk CHECK (display_name IS NULL OR char_length(display_name) <= 100),
    CONSTRAINT users_failed_attempts_chk  CHECK (failed_login_attempts >= 0)
);

-- Unicité insensible à la casse sur l'email.
CREATE UNIQUE INDEX users_email_lower_uidx ON users (lower(email));

-- -----------------------------------------------------------------------------
-- Refresh tokens révocables
-- On ne stocke JAMAIS le token en clair : seulement son empreinte SHA-256.
-- Une fuite de la table ne permet donc pas de rejouer les tokens.
-- -----------------------------------------------------------------------------
CREATE TABLE refresh_tokens (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Empreinte (hex) du secret opaque. Indexée et unique.
    token_hash  TEXT         NOT NULL,
    expires_at  TIMESTAMPTZ  NOT NULL,
    -- Non nul => token révoqué (logout, rotation, compromission).
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- Métadonnées d'audit (sans donnée sensible). IP stockée en TEXT : le
    -- binding reste simple et sans dépendance réseau supplémentaire.
    user_agent  TEXT,
    ip_address  TEXT
);

CREATE UNIQUE INDEX refresh_tokens_hash_uidx ON refresh_tokens (token_hash);
CREATE INDEX refresh_tokens_user_idx ON refresh_tokens (user_id);
-- Permet de purger efficacement les tokens expirés.
CREATE INDEX refresh_tokens_expires_idx ON refresh_tokens (expires_at);

-- -----------------------------------------------------------------------------
-- Déclencheur de mise à jour automatique de updated_at sur users.
-- -----------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_set_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION set_updated_at();
