//! Génération et hachage des refresh tokens opaques.
//!
//! Le refresh token remis au client est une valeur aléatoire de 256 bits
//! encodée en base64url. En base, on ne stocke QUE son empreinte SHA-256 :
//! une fuite de la table `refresh_tokens` ne permet donc pas de rejouer les
//! sessions. SHA-256 (et non Argon2) suffit ici car le secret a déjà une
//! entropie maximale (pas de risque de bruteforce hors-ligne).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Un refresh token fraîchement généré : la valeur en clair (à remettre au
/// client une seule fois) et son empreinte (à stocker en base).
pub struct GeneratedRefreshToken {
    pub plaintext: String,
    pub hash: String,
}

/// Génère un nouveau refresh token cryptographiquement aléatoire.
pub fn generate_refresh_token() -> GeneratedRefreshToken {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let plaintext = URL_SAFE_NO_PAD.encode(bytes);
    let hash = hash_refresh_token(&plaintext);
    GeneratedRefreshToken { plaintext, hash }
}

/// Calcule l'empreinte hex d'un refresh token (pour stockage / recherche).
pub fn hash_refresh_token(plaintext: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    let digest = hasher.finalize();
    hex_encode(&digest)
}

/// Encodage hexadécimal minimal (évite une dépendance supplémentaire).
fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // `write!` sur une String ne peut pas échouer.
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_and_hash_are_consistent() {
        let t = generate_refresh_token();
        assert_eq!(t.hash, hash_refresh_token(&t.plaintext));
        // 32 octets en base64url sans padding => 43 caractères.
        assert_eq!(t.plaintext.len(), 43);
        // SHA-256 hex => 64 caractères.
        assert_eq!(t.hash.len(), 64);
    }

    #[test]
    fn tokens_are_unique() {
        let a = generate_refresh_token();
        let b = generate_refresh_token();
        assert_ne!(a.plaintext, b.plaintext);
        assert_ne!(a.hash, b.hash);
    }
}
