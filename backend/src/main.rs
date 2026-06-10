// Exigence sécurité #1 : aucun `unsafe` dans le binaire non plus.
#![forbid(unsafe_code)]

//! Binaire mince : délègue toute la logique à la bibliothèque `websitebase_backend`.
//!
//! Supporte un sous-mode `healthcheck` (sans dépendance externe) utilisé par le
//! `HEALTHCHECK` de l'image distroless, qui ne dispose ni de shell ni de curl.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[tokio::main]
async fn main() {
    // Mode healthcheck : effectue une requête HTTP locale et sort 0/1.
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        std::process::exit(healthcheck());
    }

    if let Err(err) = websitebase_backend::run().await {
        // À ce stade, le logger n'est peut-être pas initialisé : on écrit sur
        // stderr. On n'expose aucun secret (les erreurs de config ne citent que
        // le NOM de la variable manquante, jamais sa valeur).
        eprintln!("erreur fatale au démarrage : {err}");
        let mut source = std::error::Error::source(&*err);
        while let Some(cause) = source {
            eprintln!("  cause: {cause}");
            source = cause.source();
        }
        std::process::exit(1);
    }
}

/// Healthcheck autonome : ouvre une connexion TCP vers le port d'écoute local
/// et vérifie que `/health` répond `200`. Retourne 0 si sain, 1 sinon.
fn healthcheck() -> i32 {
    // Détermine le port à interroger depuis APP_BIND_ADDR (défaut 8080).
    let port = std::env::var("APP_BIND_ADDR")
        .ok()
        .and_then(|addr| addr.rsplit(':').next().map(|p| p.to_string()))
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8080);

    let target = format!("127.0.0.1:{port}");
    let stream = match target
        .parse()
        .ok()
        .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok())
    {
        Some(s) => s,
        None => return 1,
    };

    let mut stream = stream;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let request = "GET /health HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(request.as_bytes()).is_err() {
        return 1;
    }

    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return 1;
    }

    // La première ligne doit indiquer un statut 200.
    if response.lines().next().is_some_and(|l| l.contains(" 200 ")) {
        0
    } else {
        1
    }
}
