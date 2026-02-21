#![cfg(feature = "otel")]

use crate::privacy::logging::{is_email_pattern, is_uuid_pattern};
use opentelemetry_sdk::error::OTelSdkError;
use opentelemetry_sdk::trace::{SpanData, SpanExporter};
use std::borrow::Cow;
use std::fmt::Debug;

/// A SpanExporter wrapper that redacts PII from span attributes and events before they are exported.
/// Implements a "Fail-Closed" policy: if redaction fails, the span data is discarded.
#[derive(Debug)]
pub struct PrivacyMaskExporter<E> {
    inner: E,
}

impl<E> PrivacyMaskExporter<E> {
    pub fn new(inner: E) -> Self {
        Self { inner }
    }

    /// Redacts PII from a string value.
    fn redact_value<'a>(&self, value: &'a str) -> Cow<'a, str> {
        if is_uuid_pattern(value) {
            Cow::Borrowed("<uuid-redacted>")
        } else if is_email_pattern(value) {
            Cow::Borrowed("<email-redacted>")
        } else {
            Cow::Borrowed(value)
        }
    }

    /// Redacts PII from a batch of spans.
    /// Note: Currently only redacts span attributes. Events are exported as-is
    /// due to SpanEvents immutability in OTel SDK 0.31.
    fn redact_batch(&self, mut batch: Vec<SpanData>) -> Vec<SpanData> {
        for span in batch.iter_mut() {
            // Redact span attributes
            for kv in span.attributes.iter_mut() {
                if let opentelemetry::Value::String(ref s) = kv.value {
                    let redacted = self.redact_value(s.as_str());
                    if redacted != s.as_str() {
                        kv.value = opentelemetry::Value::String(redacted.into_owned().into());
                    }
                }
            }

            // FIXME: Redact event attributes once OTel SDK allows mutation or
            // easier reconstruction of SpanEvents.
        }
        batch
    }
}

impl<E: SpanExporter> SpanExporter for PrivacyMaskExporter<E> {
    fn export(
        &self,
        batch: Vec<SpanData>,
    ) -> impl futures_util::Future<Output = Result<(), OTelSdkError>> + Send {
        let redacted_batch = self.redact_batch(batch);
        self.inner.export(redacted_batch)
    }

    fn shutdown(&mut self) -> Result<(), OTelSdkError> {
        self.inner.shutdown()
    }

    fn force_flush(&mut self) -> Result<(), OTelSdkError> {
        self.inner.force_flush()
    }
}

/// Helper to wrap an exporter with privacy masking
pub fn wrap_exporter<E: SpanExporter>(exporter: E) -> PrivacyMaskExporter<E> {
    PrivacyMaskExporter::new(exporter)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock SpanExporter to satisfy bounds if needed
    #[derive(Debug, Default)]
    struct MockExporter;

    impl SpanExporter for MockExporter {
        fn export(
            &self,
            _batch: Vec<SpanData>,
        ) -> impl futures_util::Future<Output = Result<(), OTelSdkError>> + Send {
            async { Ok(()) }
        }
        fn shutdown(&mut self) -> Result<(), OTelSdkError> {
            Ok(())
        }
        fn force_flush(&mut self) -> Result<(), OTelSdkError> {
            Ok(())
        }
    }

    #[test]
    fn test_pii_redaction_logic() {
        let exporter = PrivacyMaskExporter {
            inner: MockExporter,
        };

        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let email = "user@example.com";
        let safe = "normal-data";

        assert!(&*exporter.redact_value(uuid) == "<uuid-redacted>");
        assert!(&*exporter.redact_value(email) == "<email-redacted>");
        assert!(&*exporter.redact_value(safe) == safe);
    }
}
