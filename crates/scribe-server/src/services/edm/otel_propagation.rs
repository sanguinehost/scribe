// backend/src/services/edm/otel_propagation.rs
use opentelemetry::propagation::TextMapPropagator;
use opentelemetry::Context;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use std::collections::HashMap;
use tracing::Span;
use tracing_opentelemetry::OpenTelemetrySpanExt;

pub struct OtelPropagation;

impl OtelPropagation {
    /// Extracts the current trace context and serializes it to a string.
    pub fn serialize_current_context() -> Option<String> {
        let propagator = TraceContextPropagator::new();
        let context = Span::current().context();
        let mut fields = HashMap::new();
        propagator.inject_context(&context, &mut fields);

        serde_json::to_string(&fields).ok()
    }

    /// Deserializes a context string and returns an OpenTelemetry Context.
    pub fn deserialize_context(data: &str) -> Option<Context> {
        let propagator = TraceContextPropagator::new();
        let fields: HashMap<String, String> = serde_json::from_str(data).ok()?;

        Some(propagator.extract(&fields))
    }
}
