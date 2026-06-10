-- Script d'initialisation exécuté UNE SEULE FOIS par l'image postgres
-- (premier démarrage, volume vide). Exécuté en tant que POSTGRES_USER, qui est
-- ici `app_owner` (propriétaire, droits DDL).
--
-- But : créer le rôle applicatif `app_user` avec UNIQUEMENT des droits DML, et
-- configurer les droits PAR DÉFAUT pour que les objets créés ensuite par la
-- migration (montée comme 10-init.sql) lui accordent automatiquement le DML.
-- Ainsi le rôle runtime n'a jamais de droits DDL (principe du moindre privilège).

CREATE ROLE app_user LOGIN PASSWORD 'app_dev_pw';

GRANT USAGE ON SCHEMA public TO app_user;

-- Droits par défaut sur les objets FUTURS créés par app_owner dans public.
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public
    GRANT USAGE ON TYPES TO app_user;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO app_user;
