//! Extracteur du contexte client (IP source, User-Agent) pour l'audit SOC.
//!
//! L'IP réelle est déterminée à partir de `X-Forwarded-For` en tenant compte
//! du nombre de proxys de confiance (`APP_TRUSTED_PROXY_HOPS`). Sans cette
//! précaution, un client pourrait usurper son IP en injectant un en-tête XFF
//! arbitraire. On ne fait JAMAIS confiance à XFF au-delà des proxys déclarés.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

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

        let ip = client_ip(parts, state.config.trusted_proxy_hops);

        Ok(ClientContext { ip, user_agent })
    }
}

/// Détermine l'IP cliente en respectant la chaîne de proxys de confiance.
fn client_ip(parts: &Parts, trusted_hops: usize) -> Option<String> {
    // IP de la connexion TCP directe (le premier proxy, en principe).
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string());

    // Si aucun proxy de confiance n'est déclaré, on n'utilise PAS XFF.
    if trusted_hops == 0 {
        return peer;
    }

    if let Some(xff) = parts
        .headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        let chain: Vec<&str> = xff
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if !chain.is_empty() {
            // Le client réel est à `trusted_hops` positions depuis la droite.
            // Ex. XFF = "client, proxyA" avec 1 hop => index len-1-1 = client.
            let idx = chain.len().saturating_sub(1 + trusted_hops);
            if let Some(candidate) = chain.get(idx) {
                return Some((*candidate).to_string());
            }
        }
    }

    peer
}
