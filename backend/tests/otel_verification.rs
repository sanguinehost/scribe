use scribe_backend::logging::init_subscriber;
use tracing::{info, span, Level};

#[tokio::test]
async fn test_otel_redaction_flow() {
    // 1. Initialize subscriber (OTLP layer should be added if features=otel)
    // We don't care if it fails to connect to collector during the test setup,
    // but the layer should be active.
    init_subscriber();

    // 2. Emit a span with PII
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    let email = "user@example.com";

    info!("Starting OTel verification test...");

    {
        let span = tracing::info_span!(
            "verification_span",
            user_id = uuid,
            user_email = email,
            safe_field = "this-should-remain"
        );
        let _enter = span.enter();
        info!("Verification event emitted inside span");
    } // Span ends here

    // 3. Keep it alive briefly to allow the flush
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // 4. Force shutdown to flush spans
    opentelemetry::global::shutdown_tracer_provider();
}
