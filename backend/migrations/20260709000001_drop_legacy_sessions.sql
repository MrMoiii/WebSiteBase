-- =============================================================================
-- Retrait de l'ancien stockage de sessions/verrouillage sur PostgreSQL.
--
-- Depuis la brique « sessions Redis » (cf. backend/SESSIONS.md), Redis est la
-- source de vérité des refresh tokens ET du verrouillage anti-bruteforce. Les
-- objets ci-dessous ne sont plus lus ni écrits par l'application ; on les retire
-- pour réduire la surface (moins de PII stockée durablement) et éviter toute
-- dérive vers deux sources de vérité.
--
-- Exécutée par le rôle propriétaire (droits DDL), comme la migration initiale.
-- =============================================================================

-- Table des refresh tokens : entièrement remplacée par les clés `rt:{hash}` /
-- `sess:{sid}` de Redis (rotation atomique, TTL natif). Ses index tombent avec
-- elle.
DROP TABLE IF EXISTS refresh_tokens;

-- Compteurs de verrouillage applicatif : désormais dans Redis (`lock:{user_id}`),
-- distribués et cohérents entre instances. La contrainte CHECK qui ne portait
-- que sur `failed_login_attempts` est supprimée automatiquement avec la colonne.
ALTER TABLE users DROP COLUMN IF EXISTS failed_login_attempts;
ALTER TABLE users DROP COLUMN IF EXISTS locked_until;
