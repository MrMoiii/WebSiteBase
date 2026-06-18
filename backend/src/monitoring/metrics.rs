//! Métriques Prometheus de l'API, exposées en texte sur `/metrics`.
//!
//! Exposeur MINIMAL fait main (aucune dépendance ajoutée, cohérent avec la
//! posture supply-chain du projet) : Prometheus *scrape* ce endpoint et stocke
//! les séries temporelles. On n'y met QUE des agrégats numériques — jamais de
//! `request_id` ni de donnée à forte cardinalité (anti-explosion de séries).
//!
//! Séries exposées :
//! - `http_requests_total{method,route,status,outcome}` (compteur) ;
//! - `http_request_duration_seconds{method,route}` (histogramme de latence).
//!
//! Le taux d'erreur se dérive en PromQL, p. ex. :
//! `sum(rate(http_requests_total{outcome="server_error"}[5m]))
//!   / sum(rate(http_requests_total[5m]))`.
//!
//! Bornage de cardinalité : `method` et `route` sont normalisés vers des
//! ensembles FERMÉS de valeurs `&'static str` (un chemin inconnu => `"other"`),
//! et les valeurs de labels n'ont donc jamais besoin d'échappement.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Mutex;

use crate::monitoring::event::outcome_for;

/// Bornes (en secondes) des buckets de l'histogramme de latence.
const BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

/// Clé d'un compteur de requêtes (toutes les valeurs sont à cardinalité bornée).
#[derive(Clone, PartialEq, Eq, Hash)]
struct CounterKey {
    method: &'static str,
    route: &'static str,
    status: u16,
    outcome: &'static str,
}

/// Clé d'un histogramme de latence.
#[derive(Clone, PartialEq, Eq, Hash)]
struct HistKey {
    method: &'static str,
    route: &'static str,
}

/// Histogramme cumulatif : `buckets[i]` = nb d'observations <= `BUCKETS[i]`.
struct Histogram {
    buckets: [u64; BUCKETS.len()],
    sum: f64,
    count: u64,
}

impl Histogram {
    fn new() -> Self {
        Self {
            buckets: [0; BUCKETS.len()],
            sum: 0.0,
            count: 0,
        }
    }

    fn observe(&mut self, value: f64) {
        for (i, bound) in BUCKETS.iter().enumerate() {
            if value <= *bound {
                self.buckets[i] += 1;
            }
        }
        self.sum += value;
        self.count += 1;
    }
}

#[derive(Default)]
struct Inner {
    counters: HashMap<CounterKey, u64>,
    hists: HashMap<HistKey, Histogram>,
}

/// Registre de métriques partagé (via `AppState`). Verrou bref, jamais tenu
/// au travers d'un `.await`.
pub struct Metrics {
    inner: Mutex<Inner>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Enregistre une requête traitée : incrémente le compteur et l'histogramme.
    /// `method`/`route` sont normalisés vers des valeurs à cardinalité bornée.
    pub fn observe_request(&self, method: &str, path: &str, status: u16, latency_secs: f64) {
        let method = normalize_method(method);
        let route = normalize_route(path);
        let outcome = outcome_for(status);

        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        *g.counters
            .entry(CounterKey {
                method,
                route,
                status,
                outcome,
            })
            .or_insert(0) += 1;
        g.hists
            .entry(HistKey { method, route })
            .or_insert_with(Histogram::new)
            .observe(latency_secs);
    }

    /// Rend les métriques au format texte Prometheus (exposition 0.0.4).
    pub fn render(&self) -> String {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = String::with_capacity(1024);

        out.push_str("# HELP http_requests_total Total HTTP requests handled, by method/route/status/outcome.\n");
        out.push_str("# TYPE http_requests_total counter\n");
        for (k, v) in &g.counters {
            let _ = writeln!(
                out,
                "http_requests_total{{method=\"{}\",route=\"{}\",status=\"{}\",outcome=\"{}\"}} {}",
                k.method, k.route, k.status, k.outcome, v
            );
        }

        out.push_str(
            "# HELP http_request_duration_seconds HTTP request latency in seconds, by method/route.\n",
        );
        out.push_str("# TYPE http_request_duration_seconds histogram\n");
        for (k, h) in &g.hists {
            for (i, bound) in BUCKETS.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "http_request_duration_seconds_bucket{{method=\"{}\",route=\"{}\",le=\"{}\"}} {}",
                    k.method, k.route, bound, h.buckets[i]
                );
            }
            // Bucket +Inf = total des observations.
            let _ = writeln!(
                out,
                "http_request_duration_seconds_bucket{{method=\"{}\",route=\"{}\",le=\"+Inf\"}} {}",
                k.method, k.route, h.count
            );
            let _ = writeln!(
                out,
                "http_request_duration_seconds_sum{{method=\"{}\",route=\"{}\"}} {}",
                k.method, k.route, h.sum
            );
            let _ = writeln!(
                out,
                "http_request_duration_seconds_count{{method=\"{}\",route=\"{}\"}} {}",
                k.method, k.route, h.count
            );
        }

        out
    }
}

/// Normalise la méthode HTTP vers un ensemble fermé (borne la cardinalité).
fn normalize_method(method: &str) -> &'static str {
    match method {
        "GET" => "GET",
        "POST" => "POST",
        "PATCH" => "PATCH",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "HEAD" => "HEAD",
        "OPTIONS" => "OPTIONS",
        _ => "other",
    }
}

/// Normalise le chemin vers le gabarit de route connu (borne la cardinalité :
/// un chemin inconnu, p. ex. sondé par un scanner, est replié sur `"other"`).
fn normalize_route(path: &str) -> &'static str {
    match path {
        "/health" => "/health",
        "/health/ready" => "/health/ready",
        "/metrics" => "/metrics",
        "/api/v1/auth/register" => "/api/v1/auth/register",
        "/api/v1/auth/login" => "/api/v1/auth/login",
        "/api/v1/auth/refresh" => "/api/v1/auth/refresh",
        "/api/v1/auth/logout" => "/api/v1/auth/logout",
        "/api/v1/users/me" => "/api/v1/users/me",
        "/api/v1/admin/users" => "/api/v1/admin/users",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_route_and_method_are_bounded() {
        assert_eq!(normalize_route("/api/v1/../etc/passwd"), "other");
        assert_eq!(normalize_route("/api/v1/users/me"), "/api/v1/users/me");
        assert_eq!(normalize_method("BREW"), "other");
        assert_eq!(normalize_method("POST"), "POST");
    }

    #[test]
    fn counter_and_histogram_render() {
        let m = Metrics::new();
        m.observe_request("GET", "/health", 200, 0.003);
        m.observe_request("GET", "/health", 200, 0.2);
        m.observe_request("POST", "/api/v1/auth/login", 401, 0.05);

        let out = m.render();
        // Compteur agrégé par labels.
        assert!(out.contains(
            "http_requests_total{method=\"GET\",route=\"/health\",status=\"200\",outcome=\"success\"} 2"
        ));
        assert!(out.contains(
            "http_requests_total{method=\"POST\",route=\"/api/v1/auth/login\",status=\"401\",outcome=\"client_error\"} 1"
        ));
        // Histogramme : 2 observations sur /health, dont 1 <= 0.005.
        assert!(out.contains(
            "http_request_duration_seconds_bucket{method=\"GET\",route=\"/health\",le=\"0.005\"} 1"
        ));
        assert!(out.contains(
            "http_request_duration_seconds_bucket{method=\"GET\",route=\"/health\",le=\"+Inf\"} 2"
        ));
        assert!(
            out.contains("http_request_duration_seconds_count{method=\"GET\",route=\"/health\"} 2")
        );
        // Types déclarés (exposition Prometheus).
        assert!(out.contains("# TYPE http_requests_total counter"));
        assert!(out.contains("# TYPE http_request_duration_seconds histogram"));
    }

    #[test]
    fn no_high_cardinality_labels() {
        // Sécurité : aucune étiquette ne doit contenir d'identifiant unique.
        let m = Metrics::new();
        m.observe_request("GET", "/health", 200, 0.01);
        let out = m.render();
        assert!(!out.contains("request_id"));
    }
}
