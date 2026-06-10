//! En-têtes de sécurité HTTP ajoutés à chaque réponse (exigence #3).
//!
//! L'API ne sert que du JSON : on applique donc une CSP très restrictive
//! (`default-src 'none'`) sans rien casser. Ces en-têtes protègent surtout les
//! clients navigateur (clickjacking, sniffing MIME, fuite de referrer) et
//! signalent au navigateur d'imposer HTTPS (HSTS, terminaison TLS assurée par
//! le reverse proxy en frontal).

/// Couples (nom, valeur) appliqués via `SetResponseHeaderLayer` dans le routeur.
/// Valeurs statiques ASCII valides (conversion infaillible).
pub const SECURITY_HEADERS: &[(&str, &str)] = &[
    // Force HTTPS pendant 2 ans, sous-domaines inclus.
    (
        "strict-transport-security",
        "max-age=63072000; includeSubDomains; preload",
    ),
    // Empêche le navigateur de "deviner" le type MIME.
    ("x-content-type-options", "nosniff"),
    // Anti-clickjacking (redondant avec frame-ancestors, large compatibilité).
    ("x-frame-options", "DENY"),
    // CSP minimale pour une API JSON : aucun chargement/exécution autorisé.
    (
        "content-security-policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    ),
    // Ne divulgue jamais l'URL d'origine dans le Referer.
    ("referrer-policy", "no-referrer"),
    // Isole les ressources cross-origin.
    ("cross-origin-resource-policy", "same-origin"),
    // Désactive des API navigateur non nécessaires à une API.
    (
        "permissions-policy",
        "geolocation=(), microphone=(), camera=()",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::{HeaderName, HeaderValue};

    #[test]
    fn all_headers_are_valid() {
        // Garantit que chaque couple produit un en-tête HTTP valide.
        for (name, value) in SECURITY_HEADERS {
            assert!(HeaderName::from_bytes(name.as_bytes()).is_ok());
            assert!(HeaderValue::from_str(value).is_ok());
        }
    }

    #[test]
    fn includes_core_protections() {
        let names: Vec<&str> = SECURITY_HEADERS.iter().map(|(n, _)| *n).collect();
        for required in [
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "content-security-policy",
            "referrer-policy",
        ] {
            assert!(names.contains(&required), "en-tête manquant : {required}");
        }
    }
}
