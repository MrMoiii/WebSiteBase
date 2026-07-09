//! Hachage et vérification de mots de passe avec Argon2id.
//!
//! Paramètres conformes aux recommandations OWASP (Password Storage Cheat
//! Sheet) : Argon2id, m = 19 MiB, t = 2, p = 1. Le hash PHC produit embarque
//! le sel et les paramètres, ce qui permet une future montée en coût sans
//! migration destructive.

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};

use crate::errors::ApiError;

/// Coût mémoire en KiB (19 MiB) — recommandation OWASP.
const MEM_COST_KIB: u32 = 19_456;
/// Nombre d'itérations.
const TIME_COST: u32 = 2;
/// Degré de parallélisme.
const PARALLELISM: u32 = 1;

/// Construit l'instance Argon2id configurée.
fn hasher() -> Argon2<'static> {
    // `Params::new` ne peut échouer qu'avec des valeurs hors bornes ; les nôtres
    // sont des constantes valides, donc `expect` ne se déclenchera jamais.
    let params =
        Params::new(MEM_COST_KIB, TIME_COST, PARALLELISM, None).expect("paramètres Argon2 valides");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hache un mot de passe en clair. Retourne une chaîne PHC à stocker en base.
pub fn hash_password(plaintext: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    hasher()
        .hash_password(plaintext.as_bytes(), &salt)
        .map(|h| h.to_string())
        // Le détail de l'erreur reste interne (jamais renvoyé au client).
        .map_err(|e| ApiError::Internal(format!("argon2 hash: {e}")))
}

/// Vérifie un mot de passe contre un hash PHC stocké.
///
/// Retourne `Ok(true)` si le mot de passe correspond, `Ok(false)` sinon.
/// Une erreur n'est remontée que si le hash stocké est corrompu/illisible.
pub fn verify_password(plaintext: &str, phc_hash: &str) -> Result<bool, ApiError> {
    let parsed = PasswordHash::new(phc_hash)
        .map_err(|e| ApiError::Internal(format!("argon2 parse stored hash: {e}")))?;

    match hasher().verify_password(plaintext.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(ApiError::Internal(format!("argon2 verify: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_then_verify_ok() {
        let hash = hash_password("Corr3ct-Horse-Battery").unwrap();
        // Le hash ne doit jamais contenir le mot de passe en clair.
        assert!(!hash.contains("Corr3ct-Horse-Battery"));
        assert!(verify_password("Corr3ct-Horse-Battery", &hash).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_password() {
        let hash = hash_password("Corr3ct-Horse-Battery").unwrap();
        assert!(!verify_password("wrong-password", &hash).unwrap());
    }

    #[test]
    fn hashes_are_salted_and_unique() {
        // Deux hachages du même mot de passe diffèrent grâce au sel aléatoire.
        let a = hash_password("same-password").unwrap();
        let b = hash_password("same-password").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn uses_argon2id() {
        let hash = hash_password("x-very-strong-1").unwrap();
        assert!(hash.starts_with("$argon2id$"));
    }

    #[test]
    fn verify_with_corrupted_hash_is_error_not_false() {
        // Un hash stocké illisible doit remonter une ERREUR interne (corruption
        // à traiter), et non un `Ok(false)` silencieux qui masquerait le problème.
        for corrupt in ["", "not-a-phc-string", "plain$$$text"] {
            assert!(
                verify_password("whatever", corrupt).is_err(),
                "hash corrompu accepté: {corrupt:?}"
            );
        }
    }

    #[test]
    fn verify_wrong_password_is_ok_false_not_error() {
        // Distinction clé : mauvais mot de passe => Ok(false) (pas une erreur).
        let hash = hash_password("the-real-password-12").unwrap();
        assert!(!verify_password("wrong", &hash).unwrap());
    }

    #[test]
    fn handles_empty_and_long_passwords() {
        // Chaîne vide : hachable et vérifiable (la borne min est imposée en amont
        // par la validation du DTO, pas par cette couche cryptographique).
        let h = hash_password("").unwrap();
        assert!(verify_password("", &h).unwrap());
        assert!(!verify_password("x", &h).unwrap());

        // Mot de passe long (128, borne du DTO) : fonctionne.
        let long = "p".repeat(128);
        let h = hash_password(&long).unwrap();
        assert!(verify_password(&long, &h).unwrap());
    }

    #[test]
    fn handles_unicode_passwords() {
        let pw = "コルレクトホース🐴-Éà";
        let h = hash_password(pw).unwrap();
        assert!(verify_password(pw, &h).unwrap());
        assert!(!verify_password("コルレクトホース🐴-Éb", &h).unwrap());
    }
}
