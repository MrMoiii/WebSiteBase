//! Définition VERSIONNÉE et CONTRÔLÉE des index OpenSearch.
//!
//! Principes de sécurité :
//! - le mapping est `dynamic: "strict"` : OpenSearch REFUSE tout champ non
//!   déclaré à l'indexation (pas de pollution de schéma / injection de champ) ;
//! - les listes blanches de champs *interrogeables*, *triables* et
//!   *consultables* sont définies ICI et sont les SEULES surfaces autorisées
//!   (contrôle des champs indexables/consultables — exigence RBAC) ;
//! - le nom physique d'un index est dérivé du préfixe (config) et d'un tenant
//!   serveur (jamais d'une entrée client), tous deux validés `[a-z0-9_-]`.

use serde_json::{json, Value};

use crate::config::is_valid_index_token;
use crate::models::user::UserRole;

/// Version du mapping. Incrémenter à chaque évolution de schéma (réindexation
/// vers `…-v2`, bascule de l'alias) pour des migrations contrôlées.
pub const MAPPING_VERSION: u32 = 1;

/// Champs sur lesquels une recherche plein-texte est autorisée.
///
/// La requête utilisateur n'atteint QUE ces champs, via `multi_match` (le texte
/// est traité comme une donnée analysée, jamais comme du Query DSL) — voir
/// `query.rs`. Toute autre cible est rejetée.
pub const QUERYABLE_FIELDS: &[&str] = &["title", "body", "tags"];

/// Champs autorisés comme critère de tri (liste blanche stricte). `_score` est
/// le tri par pertinence par défaut ; `created_at` et `title.raw` sont des
/// champs `keyword`/`date` triables (pas de tri sur un champ `text` analysé).
pub const SORTABLE_FIELDS: &[&str] = &["_score", "created_at", "title.raw"];

/// Champs `keyword` autorisés comme filtre exact (`term`) DEPUIS le client.
/// Volontairement restreint : `owner_id`/`tenant_id` sont des filtres INTERNES
/// imposés par le serveur, jamais pilotés par le client (anti-IDOR/énumération).
pub const CLIENT_FILTERABLE_FIELDS: &[&str] = &["tags"];

/// Champs renvoyés au client selon le rôle (contrôle des champs CONSULTABLES).
///
/// Un utilisateur standard ne voit qu'un sous-ensemble ; un admin peut voir le
/// corps complet. `tenant_id`/`owner_id` ne sont jamais exposés tels quels.
pub fn returnable_fields(role: UserRole) -> &'static [&'static str] {
    match role {
        UserRole::Admin => &["title", "tags", "created_at", "body"],
        UserRole::User => &["title", "tags", "created_at"],
    }
}

/// Construit le nom physique d'index pour un tenant donné.
///
/// - mono-tenant : `"{prefix}-v{N}"` (un seul index, alias logique `{prefix}`) ;
/// - multi-tenant : `"{prefix}-{tenant}-v{N}"` (index DÉDIÉ par tenant : aucun
///   index partagé entre tenants — exigence d'isolation).
///
/// `tenant` provient TOUJOURS du contexte serveur authentifié et est validé.
/// Retourne `None` si le tenant est invalide (défense en profondeur : ne jamais
/// fabriquer un nom d'index à partir d'une valeur douteuse).
pub fn index_name(prefix: &str, tenant: Option<&str>, version: u32) -> Option<String> {
    match tenant {
        Some(t) if is_valid_index_token(t) => Some(format!("{prefix}-{t}-v{version}")),
        Some(_) => None,
        None => Some(format!("{prefix}-v{version}")),
    }
}

/// Corps de création d'index : settings durcis + mapping strict.
///
/// `number_of_replicas`/`shards` sont des valeurs raisonnables par défaut ;
/// l'essentiel sécurité est `dynamic: strict` et l'absence de champ libre.
pub fn index_definition() -> Value {
    json!({
        "settings": {
            "index": {
                "number_of_shards": 1,
                "number_of_replicas": 1,
                // Borne la pagination profonde au niveau du cluster aussi.
                "max_result_window": 10_000
            }
        },
        "mappings": {
            // Refuse tout champ non déclaré ci-dessous (anti pollution de schéma).
            "dynamic": "strict",
            "properties": {
                "tenant_id":  { "type": "keyword" },
                "owner_id":   { "type": "keyword" },
                "title": {
                    "type": "text",
                    // Sous-champ keyword pour le tri/agrégations exacts.
                    "fields": { "raw": { "type": "keyword", "ignore_above": 256 } }
                },
                "body":       { "type": "text" },
                "tags":       { "type": "keyword" },
                "created_at": { "type": "date" }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mono_tenant_index_name_is_versioned() {
        assert_eq!(
            index_name("documents", None, 1).as_deref(),
            Some("documents-v1")
        );
    }

    #[test]
    fn multi_tenant_index_name_includes_tenant() {
        assert_eq!(
            index_name("documents", Some("acme"), 2).as_deref(),
            Some("documents-acme-v2")
        );
    }

    #[test]
    fn invalid_tenant_yields_no_index_name() {
        // Tentative d'évasion vers un autre index / caractères dangereux.
        for bad in ["../secret", "Acme", "a b", "tenant*", "_cluster", ""] {
            assert!(
                index_name("documents", Some(bad), 1).is_none(),
                "le tenant invalide {bad:?} ne doit pas produire de nom d'index"
            );
        }
    }

    #[test]
    fn admin_sees_more_fields_than_user() {
        assert!(returnable_fields(UserRole::Admin).contains(&"body"));
        assert!(!returnable_fields(UserRole::User).contains(&"body"));
    }
}
