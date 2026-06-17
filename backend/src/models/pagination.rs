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
}
