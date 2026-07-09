//! Pagination des listings (endpoint admin).

use garde::Validate;
use serde::{Deserialize, Serialize};

/// Paramètres de pagination passés en query string.
///
/// Bornes strictes : `page_size` plafonné à 100 pour éviter qu'un client ne
/// demande un export massif d'un coup.
#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct PaginationQuery {
    #[garde(inner(range(min = 1)))]
    pub page: Option<i64>,
    #[garde(inner(range(min = 1, max = 100)))]
    pub page_size: Option<i64>,
}

impl PaginationQuery {
    /// Numéro de page effectif (défaut 1).
    pub fn page(&self) -> i64 {
        self.page.unwrap_or(1)
    }

    /// Taille de page effective (défaut 20).
    pub fn page_size(&self) -> i64 {
        self.page_size.unwrap_or(20)
    }

    /// Décalage SQL correspondant.
    ///
    /// On utilise une arithmétique SATURANTE : un `page` très grand (jusqu'à
    /// `i64::MAX`) ne doit jamais provoquer un dépassement d'entier — en build
    /// release celui-ci s'enroulerait silencieusement et pourrait produire un
    /// OFFSET négatif (erreur SQL -> 500), en debug il paniquerait. Le pire cas
    /// devient un OFFSET plafonné (au-delà du nombre de lignes -> page vide).
    pub fn offset(&self) -> i64 {
        self.page()
            .saturating_sub(1)
            .saturating_mul(self.page_size())
    }
}

/// Enveloppe générique d'une réponse paginée.
#[derive(Debug, Serialize)]
pub struct Paginated<T> {
    pub items: Vec<T>,
    pub page: i64,
    pub page_size: i64,
    /// Nombre total d'éléments correspondant au critère.
    pub total: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_is_computed_normally() {
        let q = PaginationQuery {
            page: Some(3),
            page_size: Some(20),
        };
        assert_eq!(q.offset(), 40); // (3 - 1) * 20
    }

    #[test]
    fn offset_uses_defaults() {
        let q = PaginationQuery {
            page: None,
            page_size: None,
        };
        assert_eq!(q.offset(), 0); // (1 - 1) * 20
    }

    #[test]
    fn offset_saturates_instead_of_overflowing() {
        // Un `page` géant ne doit jamais déborder (sinon 500 / panic) : l'offset
        // est plafonné à i64::MAX, ce que PostgreSQL accepte (page vide).
        let q = PaginationQuery {
            page: Some(i64::MAX),
            page_size: Some(100),
        };
        assert_eq!(q.offset(), i64::MAX);
    }

    #[test]
    fn accessors_apply_defaults_and_overrides() {
        let default = PaginationQuery {
            page: None,
            page_size: None,
        };
        assert_eq!(default.page(), 1);
        assert_eq!(default.page_size(), 20);

        let custom = PaginationQuery {
            page: Some(5),
            page_size: Some(50),
        };
        assert_eq!(custom.page(), 5);
        assert_eq!(custom.page_size(), 50);
        assert_eq!(custom.offset(), 200); // (5 - 1) * 50
    }

    #[test]
    fn offset_uses_default_page_size_when_only_page_set() {
        let q = PaginationQuery {
            page: Some(3),
            page_size: None,
        };
        assert_eq!(q.offset(), 40); // (3 - 1) * 20
    }

    #[test]
    fn validation_enforces_positive_ranges() {
        // Valeurs valides (bornes incluses).
        assert!(PaginationQuery {
            page: Some(1),
            page_size: Some(1),
        }
        .validate()
        .is_ok());
        assert!(PaginationQuery {
            page: Some(1),
            page_size: Some(100),
        }
        .validate()
        .is_ok());
        // None : accepté (les défauts s'appliquent).
        assert!(PaginationQuery {
            page: None,
            page_size: None,
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn validation_rejects_out_of_range_values() {
        // page < 1
        assert!(PaginationQuery {
            page: Some(0),
            page_size: Some(20),
        }
        .validate()
        .is_err());
        // page_size < 1
        assert!(PaginationQuery {
            page: Some(1),
            page_size: Some(0),
        }
        .validate()
        .is_err());
        // page_size > 100 (anti-export massif)
        assert!(PaginationQuery {
            page: Some(1),
            page_size: Some(101),
        }
        .validate()
        .is_err());
        // valeurs négatives
        assert!(PaginationQuery {
            page: Some(-1),
            page_size: Some(-5),
        }
        .validate()
        .is_err());
    }

    #[test]
    fn rejects_unknown_query_fields() {
        // `deny_unknown_fields` : un paramètre inattendu fait échouer le parsing.
        let json = r#"{"page":1,"page_size":20,"sort":"email"}"#;
        assert!(serde_json::from_str::<PaginationQuery>(json).is_err());
    }
}
