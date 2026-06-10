//! Pagination des listings (endpoint admin).

use serde::{Deserialize, Serialize};
use validator::Validate;

/// Paramètres de pagination passés en query string.
///
/// Bornes strictes : `page_size` plafonné à 100 pour éviter qu'un client ne
/// demande un export massif d'un coup.
#[derive(Debug, Deserialize, Validate)]
#[serde(deny_unknown_fields)]
pub struct PaginationQuery {
    #[validate(range(min = 1))]
    pub page: Option<i64>,
    #[validate(range(min = 1, max = 100))]
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
    pub fn offset(&self) -> i64 {
        (self.page() - 1) * self.page_size()
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
