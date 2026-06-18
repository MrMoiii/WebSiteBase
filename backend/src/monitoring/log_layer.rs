//! Couche `tracing` qui expédie CHAQUE événement applicatif vers OpenSearch,
//! corrélé par `request_id`.
//!
//! Ainsi, au-delà de la synthèse par requête (`layer`), toutes les « actions »
//! tracées dans le code — erreurs levées (`ApiError`), événements de sécurité
//! (login, refus d'accès…), événements métier — deviennent des documents
//! OpenSearch (`kind = "event"`) partageant le `request_id` de la requête.
//!
//! Le `request_id` provient du span `http_request` (créé par la `TraceLayer`,
//! champ `correlation_id`) : on le mémorise à la création du span, puis on le
//! rattache à chaque événement émis dans sa portée.
//!
//! Garanties : non bloquant (`record` = `try_send`), et on N'EXPÉDIE PAS les
//! logs internes du monitoring (anti-boucle) ni le bruit des dépendances — seuls
//! les événements de la crate applicative sont envoyés.

use serde_json::{Map, Value};
use time::OffsetDateTime;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

use super::event::{base_doc, LogDoc};

/// Préfixe de cible des logs applicatifs (module path de la crate).
const APP_TARGET: &str = "websitebase_backend";
/// Sous-arbre du monitoring : exclu pour éviter toute boucle d'auto-log.
const SELF_TARGET: &str = "websitebase_backend::monitoring";

/// Couche d'expédition des événements `tracing` vers OpenSearch.
pub struct OpenSearchLogLayer;

/// Correlation id mémorisé dans les extensions d'un span.
struct SpanCorrelation(String);

impl<S> Layer<S> for OpenSearchLogLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    /// À la création d'un span, on extrait `correlation_id` (posé par la
    /// TraceLayer) et on le mémorise dans les extensions du span.
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        let mut v = CorrelationVisitor::default();
        attrs.record(&mut v);
        if let (Some(cid), Some(span)) = (v.value, ctx.span(id)) {
            span.extensions_mut().insert(SpanCorrelation(cid));
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        // N'expédier que les événements de la crate applicative, jamais ceux du
        // monitoring lui-même (anti-boucle) ni le bruit des dépendances.
        let target = event.metadata().target();
        if !target.starts_with(APP_TARGET) || target.starts_with(SELF_TARGET) {
            return;
        }

        // Monitoring désactivé / pas encore initialisé : ne rien faire.
        let Some(handle) = super::global_handle() else {
            return;
        };

        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);

        // request_id : champ explicite de l'événement, sinon span de la requête.
        let mut request_id = visitor.request_id.clone();
        if request_id.is_none() {
            if let Some(scope) = ctx.event_scope(event) {
                for span in scope {
                    if let Some(c) = span.extensions().get::<SpanCorrelation>() {
                        request_id = Some(c.0.clone());
                        break;
                    }
                }
            }
        }

        let meta = event.metadata();
        let mut body = base_doc(OffsetDateTime::now_utc(), "event", meta.level().as_str());
        body.insert("target".into(), Value::String(target.to_string()));
        if let Some(msg) = visitor.message {
            body.insert("message".into(), Value::String(msg));
        }
        if let Some(rid) = request_id {
            body.insert("request_id".into(), Value::String(rid));
        }
        // Champs structurés de l'événement (event=…, user.id=…, error.detail=…).
        for (k, val) in visitor.fields {
            body.entry(k).or_insert(val);
        }

        handle.record(LogDoc {
            timestamp: OffsetDateTime::now_utc(),
            body,
        });
    }
}

/// Visiteur extrayant uniquement `correlation_id` des attributs d'un span.
#[derive(Default)]
struct CorrelationVisitor {
    value: Option<String>,
}

impl Visit for CorrelationVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "correlation_id" {
            self.value = Some(value.to_string());
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "correlation_id" && self.value.is_none() {
            self.value = Some(format!("{value:?}"));
        }
    }
}

/// Visiteur collectant le message + les champs structurés d'un événement.
#[derive(Default)]
struct EventVisitor {
    message: Option<String>,
    request_id: Option<String>,
    fields: Map<String, Value>,
}

impl EventVisitor {
    fn put(&mut self, name: &str, value: Value) {
        match name {
            "message" => {
                self.message = Some(match value {
                    Value::String(s) => s,
                    other => other.to_string(),
                });
            }
            "correlation_id" | "request_id" => {
                if let Value::String(s) = &value {
                    self.request_id = Some(s.clone());
                }
            }
            _ => {
                self.fields.insert(name.to_string(), value);
            }
        }
    }
}

impl Visit for EventVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field.name(), Value::String(value.to_string()));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.put(field.name(), Value::Bool(value));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field.name(), Value::Number(value.into()));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field.name(), Value::Number(value.into()));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.put(
            field.name(),
            serde_json::Number::from_f64(value)
                .map(Value::Number)
                .unwrap_or(Value::Null),
        );
    }
    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.put(field.name(), Value::String(value.to_string()));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.put(field.name(), Value::String(format!("{value:?}")));
    }
}
