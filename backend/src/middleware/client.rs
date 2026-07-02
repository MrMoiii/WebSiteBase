//! Extracteur du contexte client (IP source, User-Agent) pour l'audit SOC, et
//! extracteur de clé de rate limiting résistant à l'usurpation d'IP.
//!
//! L'IP réelle est déterminée à partir de `X-Forwarded-For` en tenant compte
//! du nombre de proxys de confiance (`APP_TRUSTED_PROXY_HOPS`). Sans cette
//! précaution, un client pourrait usurper son IP en injectant un en-tête XFF
//! arbitraire. On ne fait JAMAIS confiance à XFF au-delà des proxys déclarés.
//!
//! IMPORTANT (sécurité) : la MÊME logique sert au rate limiting. `tower_governor`
//! fournit `SmartIpKeyExtractor`, mais celui-ci retient l'IP la plus À GAUCHE de
//! `X-Forwarded-For` — valeur entièrement contrôlée par le client. Un attaquant
//! pourrait donc faire tourner cet en-tête pour obtenir un nouveau « seau » de
//! rate limiting à chaque requête et contourner l'anti-bruteforce réseau.
//! `RateLimitKeyExtractor` (ci-dessous) clé sur l'IP de confiance déterminée
//! ci-dessous, donc non usurpable au-delà des proxys déclarés.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{HeaderMap, Request};
use tower_governor::key_extractor::KeyExtractor;
use tower_governor::GovernorError;

use crate::state::AppState;

/// Contexte de la requête utile aux logs de sécurité.
#[derive(Debug, Clone, Default)]
pub struct ClientContext {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

impl FromRequestParts<AppState> for ClientContext {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user_agent = parts
            .headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            // Borne la longueur loggée pour éviter le log d'un UA géant.
            .map(|s| s.chars().take(256).collect::<String>());

        let peer = peer_ip(&parts.extensions);
        let ip = client_ip(&parts.headers, peer, state.config.trusted_proxy_hops)
            .map(|ip| ip.to_string());

        Ok(ClientContext { ip, user_agent })
    }
}

/// IP du pair TCP (le proxy de confiance le plus proche, en principe).
pub fn peer_ip(extensions: &axum::http::Extensions) -> Option<IpAddr> {
    extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
}

/// Détermine l'IP cliente de confiance en respectant la chaîne de proxys.
///
/// Modèle (standard, ex. nginx `proxy_add_x_forwarded_for`) : chaque proxy
/// AJOUTE à droite l'IP de la connexion qu'il a reçue. Les `trusted_hops`
/// entrées LES PLUS À DROITE sont donc écrites par NOTRE infrastructure et ne
/// peuvent pas être forgées par le client ; l'IP réelle du client est l'entrée
/// immédiatement à gauche de ce segment de confiance, soit l'index
/// `len - trusted_hops`. Tout ce qui se trouve plus à gauche est sous le
/// contrôle de l'attaquant et doit être ignoré.
///
/// - `trusted_hops == 0` : on n'utilise PAS du tout XFF (on garde le pair TCP).
/// - chaîne plus courte que `trusted_hops` (incohérent avec la conf) : on
///   retombe prudemment sur le pair TCP plutôt que de faire confiance à une
///   valeur potentiellement forgée.
pub fn client_ip(headers: &HeaderMap, peer: Option<IpAddr>, trusted_hops: usize) -> Option<IpAddr> {
    if trusted_hops == 0 {
        return peer;
    }

    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let chain: Vec<&str> = xff
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        if chain.len() >= trusted_hops {
            let idx = chain.len() - trusted_hops;
            if let Some(ip) = chain.get(idx).and_then(|s| s.parse::<IpAddr>().ok()) {
                return Some(ip);
            }
        }
    }

    peer
}

/// Extracteur de clé de rate limiting pour `tower_governor`.
///
/// Contrairement à `SmartIpKeyExtractor` (qui retient l'IP la plus à gauche de
/// `X-Forwarded-For`, donc usurpable), il clé sur l'IP de confiance calculée par
/// [`client_ip`] en tenant compte de `trusted_proxy_hops`. Un attaquant ne peut
/// donc pas obtenir un nouveau quota en forgeant l'en-tête XFF.
#[derive(Clone, Debug)]
pub struct RateLimitKeyExtractor {
    trusted_hops: usize,
}

impl RateLimitKeyExtractor {
    pub fn new(trusted_hops: usize) -> Self {
        Self { trusted_hops }
    }
}

impl KeyExtractor for RateLimitKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        let peer = peer_ip(req.extensions());
        client_ip(req.headers(), peer, self.trusted_hops).ok_or(GovernorError::UnableToExtractKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", value.parse().unwrap());
        h
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn zero_hops_ignores_xff_and_keeps_peer() {
        // Aucun proxy de confiance : XFF n'est jamais consulté.
        let headers = headers_with_xff("9.9.9.9");
        let got = client_ip(&headers, Some(ip("203.0.113.7")), 0);
        assert_eq!(got, Some(ip("203.0.113.7")));
    }

    #[test]
    fn one_hop_rejects_spoofed_leftmost_xff() {
        // Le client a forgé "9.9.9.9" ; le proxy de confiance a ajouté l'IP
        // réelle à droite. Avec 1 hop, on doit retenir l'entrée la plus à
        // droite (l'IP réelle), PAS la valeur forgée à gauche.
        let headers = headers_with_xff("9.9.9.9, 203.0.113.7");
        let got = client_ip(&headers, Some(ip("10.0.0.1")), 1);
        assert_eq!(got, Some(ip("203.0.113.7")));
    }

    #[test]
    fn one_hop_single_entry_is_client() {
        // Le client n'a pas envoyé de XFF ; le proxy a ajouté l'IP réelle.
        let headers = headers_with_xff("203.0.113.7");
        let got = client_ip(&headers, Some(ip("10.0.0.1")), 1);
        assert_eq!(got, Some(ip("203.0.113.7")));
    }

    #[test]
    fn two_hops_picks_entry_left_of_trusted_segment() {
        // client(forgé), client_réel, proxyA -> avec 2 proxys de confiance,
        // l'IP réelle est à l'index len-2.
        let headers = headers_with_xff("9.9.9.9, 203.0.113.7, 198.51.100.2");
        let got = client_ip(&headers, Some(ip("10.0.0.1")), 2);
        assert_eq!(got, Some(ip("203.0.113.7")));
    }

    #[test]
    fn chain_shorter_than_hops_falls_back_to_peer() {
        // Incohérence (moins d'entrées que de hops déclarés) : on ne fait pas
        // confiance à la valeur potentiellement forgée, on garde le pair.
        let headers = headers_with_xff("9.9.9.9");
        let got = client_ip(&headers, Some(ip("10.0.0.1")), 2);
        assert_eq!(got, Some(ip("10.0.0.1")));
    }

    #[test]
    fn no_xff_falls_back_to_peer() {
        let headers = HeaderMap::new();
        let got = client_ip(&headers, Some(ip("203.0.113.7")), 1);
        assert_eq!(got, Some(ip("203.0.113.7")));
    }
}
