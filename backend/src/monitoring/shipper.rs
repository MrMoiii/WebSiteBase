//! Acheminement NON BLOQUANT des événements de monitoring vers OpenSearch.
//!
//! Conception : le chemin de requête ne doit JAMAIS être ralenti ni bloqué par
//! l'indexation des logs. La couche middleware se contente d'un `try_send` sur
//! un canal borné ; si le canal est plein (cluster lent/indisponible), l'event
//! est ABANDONNÉ (et compté) plutôt que de créer une contre-pression sur l'API.
//!
//! Une tâche de fond consomme le canal, met en tampon les événements, puis les
//! envoie par lots (`_bulk`) soit quand le lot est plein, soit à intervalle
//! régulier. Les échecs sont loggés, jamais propagés à l'API.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;

use super::client::OpenSearchClient;
use super::event::{self, ApiLogEvent};
use crate::config::MonitoringConfig;

/// Poignée légère (clonable) injectée dans l'état applicatif. Émet des
/// événements vers la tâche de fond sans jamais bloquer.
#[derive(Clone)]
pub struct MonitoringHandle {
    tx: mpsc::Sender<ApiLogEvent>,
    dropped: Arc<AtomicU64>,
}

impl MonitoringHandle {
    /// Enregistre un événement (best-effort). En cas de canal plein, l'event
    /// est abandonné et un compteur est incrémenté (jamais de blocage).
    pub fn record(&self, event: ApiLogEvent) {
        if self.tx.try_send(event).is_err() {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Démarre la tâche de fond et renvoie la poignée à stocker dans l'état.
pub fn spawn(client: OpenSearchClient, cfg: MonitoringConfig) -> MonitoringHandle {
    let (tx, rx) = mpsc::channel::<ApiLogEvent>(cfg.channel_capacity);
    let dropped = Arc::new(AtomicU64::new(0));
    tokio::spawn(run(rx, client, cfg, Arc::clone(&dropped)));
    MonitoringHandle { tx, dropped }
}

/// Boucle de la tâche de fond : tamponne puis vide par lots.
async fn run(
    mut rx: mpsc::Receiver<ApiLogEvent>,
    client: OpenSearchClient,
    cfg: MonitoringConfig,
    dropped: Arc<AtomicU64>,
) {
    let mut buf: Vec<ApiLogEvent> = Vec::with_capacity(cfg.batch_size);
    let mut ticker = tokio::time::interval(cfg.flush_interval);
    // Évite une rafale de ticks si une vidange a pris du retard.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            maybe = rx.recv() => match maybe {
                Some(event) => {
                    buf.push(event);
                    if buf.len() >= cfg.batch_size {
                        flush(&client, &mut buf, &cfg).await;
                    }
                }
                // Canal fermé (arrêt) : on vide une dernière fois puis on sort.
                None => {
                    flush(&client, &mut buf, &cfg).await;
                    break;
                }
            },
            _ = ticker.tick() => {
                flush(&client, &mut buf, &cfg).await;
                report_dropped(&dropped);
            }
        }
    }
}

/// Envoie le tampon courant en un `_bulk` puis le vide. Sur erreur, on logge et
/// on abandonne le lot (les logs sont best-effort, jamais bloquants).
async fn flush(client: &OpenSearchClient, buf: &mut Vec<ApiLogEvent>, cfg: &MonitoringConfig) {
    if buf.is_empty() {
        return;
    }
    let ndjson = event::to_bulk_ndjson(buf, &cfg.index_prefix);
    let count = buf.len();
    buf.clear();

    match client.bulk(ndjson).await {
        Ok(resp) => {
            if resp["errors"].as_bool() == Some(true) {
                tracing::warn!(
                    event = "monitoring_bulk_partial_failure",
                    monitoring.count = count,
                    "échecs partiels lors de l'indexation des logs d'API"
                );
            }
        }
        Err(err) => {
            tracing::warn!(
                event = "monitoring_flush_failed",
                monitoring.count = count,
                error.detail = %err,
                "échec d'envoi des logs d'API à OpenSearch (lot abandonné)"
            );
        }
    }
}

/// Logge (et remet à zéro) le nombre d'événements abandonnés depuis le dernier
/// tick — signal d'engorgement / cluster lent, utile à l'alerting.
fn report_dropped(dropped: &AtomicU64) {
    let n = dropped.swap(0, Ordering::Relaxed);
    if n > 0 {
        tracing::warn!(
            event = "monitoring_events_dropped",
            monitoring.dropped = n,
            "événements de monitoring abandonnés (canal saturé)"
        );
    }
}
