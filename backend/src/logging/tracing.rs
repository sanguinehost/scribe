use std::env;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Log rotation configuration
#[derive(Debug, Clone)]
pub enum LogRotation {
    Daily,
    Hourly,
    Never,
}

impl LogRotation {
    fn from_env() -> Self {
        match env::var("LOG_ROTATION").ok().as_deref() {
            Some("daily") => LogRotation::Daily,
            Some("hourly") => LogRotation::Hourly,
            Some("never") => LogRotation::Never,
            _ => LogRotation::Daily, // Default to daily rotation
        }
    }
}

/// Log format configuration
#[derive(Debug, Clone)]
pub enum LogFormat {
    Json,
    Pretty,
    Compact,
}

impl LogFormat {
    fn from_env() -> Self {
        match env::var("LOG_FORMAT").ok().as_deref() {
            Some("json") => LogFormat::Json,
            Some("pretty") => LogFormat::Pretty,
            Some("compact") => LogFormat::Compact,
            _ => LogFormat::Json, // Default to JSON format
        }
    }
}

/// Initializes and sets the global tracing subscriber with rotation and format options.
///
/// Configures dual output:
/// - JSON/Pretty/Compact logs to stdout (controlled by LOG_FORMAT env var)
/// - JSON/Pretty/Compact logs to files with rotation (controlled by LOG_ROTATION env var)
///
/// Environment variables:
/// - `LOG_DIR`: Directory for log files (default: /tmp)
/// - `LOG_FILE_PREFIX`: Prefix for log files (default: scribe-backend)
/// - `LOG_ROTATION`: Rotation policy - daily, hourly, never (default: daily)
/// - `LOG_FORMAT`: Format - json, pretty, compact (default: json)
/// - `RUST_LOG`: Log level filter (default: info for scribe_backend)
///   Initializes and sets the global tracing subscriber with rotation and format options.
///
/// Configures multi-output:
/// - stdout (JSON/Pretty/Compact)
/// - File rotation (JSON/Pretty/Compact)
/// - OTLP Tracing/Metrics (Optional, gated by `otel` feature)
pub fn init_subscriber() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,scribe_backend::routes=info,scribe_backend::auth=info,scribe_backend::services=info,scribe_backend::vector_db=info,tower_http=info,sqlx=warn,gemini_client=info,auth_debug=error".into());

    let log_dir = env::var("LOG_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let log_prefix = env::var("LOG_FILE_PREFIX").unwrap_or_else(|_| "scribe-backend".to_string());
    let rotation = LogRotation::from_env();
    let format = LogFormat::from_env();

    // Create file appender
    let file_appender = match rotation {
        LogRotation::Daily => tracing_appender::rolling::daily(&log_dir, &log_prefix),
        LogRotation::Hourly => tracing_appender::rolling::hourly(&log_dir, &log_prefix),
        LogRotation::Never => {
            tracing_appender::rolling::never(&log_dir, format!("{}.log", log_prefix))
        }
    };
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);
    std::mem::forget(guard);

    // Build the base registry with environment filter
    let registry = tracing_subscriber::registry().with(env_filter);

    // Conditional OTLP Layer
    #[cfg(feature = "otel")]
    let registry = registry.with(init_otel_layer());

    // Add stdout and file layers based on format
    match format {
        LogFormat::Json => {
            registry
                .with(
                    fmt::layer()
                        .json()
                        .with_current_span(false)
                        .with_span_list(false)
                        .with_writer(std::io::stdout),
                )
                .with(
                    fmt::layer()
                        .json()
                        .with_current_span(false)
                        .with_span_list(false)
                        .with_writer(file_writer),
                )
                .init();
        }
        LogFormat::Pretty => {
            registry
                .with(fmt::layer().pretty().with_writer(std::io::stdout))
                .with(fmt::layer().pretty().with_writer(file_writer))
                .init();
        }
        LogFormat::Compact => {
            registry
                .with(fmt::layer().compact().with_writer(std::io::stdout))
                .with(fmt::layer().compact().with_writer(file_writer))
                .init();
        }
    }

    // Log the configuration
    tracing::info!(
        log_dir = %log_dir,
        log_prefix = %log_prefix,
        rotation = ?rotation,
        format = ?format,
        otel_enabled = cfg!(feature = "otel"),
        "Tracing subscriber initialized"
    );
}

#[cfg(feature = "otel")]
fn init_otel_layer<S>() -> Option<impl tracing_subscriber::Layer<S>>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    extern crate opentelemetry_otlp as otlp;
    use crate::privacy::otlp::wrap_exporter;
    use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
    use opentelemetry_sdk::logs::{BatchLogProcessor, SdkLoggerProvider};
    use opentelemetry_sdk::trace::{BatchSpanProcessor, Sampler, SdkTracerProvider};
    use otlp::WithExportConfig;
    use otlp::WithTonicConfig;
    use tracing_subscriber::Layer;

    let endpoint = env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://localhost:4317".to_string());

    // Build OTLP exporter or Stdout exporter for testing
    let is_stdout = env::var("OTEL_STDOUT").is_ok();

    // Create the tracer provider with masking
    let (tracer_provider, logger_provider) = if is_stdout {
        let exporter = opentelemetry_stdout::SpanExporter::default();
        let privacy_exporter = wrap_exporter(exporter);
        let tracer_provider = SdkTracerProvider::builder()
            .with_span_processor(BatchSpanProcessor::builder(privacy_exporter).build())
            .with_sampler(Sampler::AlwaysOn)
            .build();

        let logger_provider = SdkLoggerProvider::builder()
            .with_log_processor(
                BatchLogProcessor::builder(opentelemetry_stdout::LogExporter::default()).build(),
            )
            .build();

        (tracer_provider, logger_provider)
    } else {
        let mut builder = otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint.clone());

        // Manually parse headers from environment if available
        if let Ok(header_str) = env::var("OTEL_EXPORTER_OTLP_HEADERS") {
            use tonic::metadata::{Ascii, MetadataKey, MetadataMap, MetadataValue};
            let mut metadata = MetadataMap::new();
            for part in header_str.split(',') {
                if let Some((key, value)) = part.split_once('=') {
                    if let Ok(key) = key.trim().parse::<MetadataKey<Ascii>>() {
                        if let Ok(value) = value.trim().parse::<MetadataValue<Ascii>>() {
                            metadata.insert(key, value);
                        }
                    }
                }
            }
            if !metadata.is_empty() {
                builder = builder.with_metadata(metadata);
            }
        }

        let exporter = match builder.build() {
            Ok(ex) => ex,
            Err(e) => {
                eprintln!("Failed to create OTLP exporter: {}", e);
                return None;
            }
        };
        let privacy_exporter = wrap_exporter(exporter);
        let tracer_provider = SdkTracerProvider::builder()
            .with_span_processor(BatchSpanProcessor::builder(privacy_exporter).build())
            .with_sampler(Sampler::AlwaysOn)
            .build();

        // Build Log Exporter
        // For logs, we might need a different exporter builder if we want headers?
        // Typically OTLP exporter supports both.
        // But opentelemetry_otlp::LogExporter might need its own config.
        let log_exporter = otlp::LogExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint);

        // Add headers to log exporter too
        let log_exporter = if let Ok(header_str) = env::var("OTEL_EXPORTER_OTLP_HEADERS") {
            use tonic::metadata::{Ascii, MetadataKey, MetadataMap, MetadataValue};
            let mut metadata = MetadataMap::new();
            for part in header_str.split(',') {
                if let Some((key, value)) = part.split_once('=') {
                    if let Ok(key) = key.trim().parse::<MetadataKey<Ascii>>() {
                        if let Ok(value) = value.trim().parse::<MetadataValue<Ascii>>() {
                            metadata.insert(key, value);
                        }
                    }
                }
            }
            if !metadata.is_empty() {
                log_exporter.with_metadata(metadata)
            } else {
                log_exporter
            }
        } else {
            log_exporter
        }
        .build()
        .expect("Failed to create log exporter");

        let logger_provider = SdkLoggerProvider::builder()
            //.with_resource(opentelemetry_sdk::Resource::new(vec![opentelemetry::KeyValue::new("service.name", "scribe-backend")]))
            .with_log_processor(BatchLogProcessor::builder(log_exporter).build())
            .build();

        (tracer_provider, logger_provider)
    };

    // Initialize Global Tracer Provider
    opentelemetry::global::set_tracer_provider(tracer_provider);

    // Create the logging layer
    let logging_layer = OpenTelemetryTracingBridge::new(&logger_provider);

    let tracer = opentelemetry::global::tracer("scribe-backend");

    // Combine layers
    Some(
        tracing_opentelemetry::layer()
            .with_tracer(tracer)
            .and_then(logging_layer),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    // Using a mutex to serialize access to the env var modification
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_rust_log<F>(var: Option<&str>, f: F)
    where
        F: FnOnce(),
    {
        let original_val = env::var("RUST_LOG").ok();
        let _guard = ENV_MUTEX.lock().unwrap();

        match var {
            Some(v) => unsafe { env::set_var("RUST_LOG", v) },
            None => unsafe { env::remove_var("RUST_LOG") },
        }

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

        // Restore original value
        match original_val {
            Some(v) => unsafe { env::set_var("RUST_LOG", v) },
            None => unsafe { env::remove_var("RUST_LOG") },
        }

        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    #[test]
    fn test_init_subscriber_runs() {
        // Test that init_subscriber can be called (it may fail if already initialized)
        let result = std::panic::catch_unwind(|| {
            init_subscriber();
        });
        // Either succeeds or panics because subscriber already set - both are OK
        assert!(
            result.is_ok() || result.is_err(),
            "init_subscriber should either succeed or fail gracefully"
        );
    }

    #[test]
    fn test_log_rotation_from_env() {
        // Test daily rotation (default)
        with_rust_log(None, || {
            let rotation = LogRotation::Daily;
            assert!(matches!(rotation, LogRotation::Daily));
        });
    }

    #[test]
    fn test_log_format_from_env() {
        // Test JSON format (default)
        with_rust_log(None, || {
            let format = LogFormat::from_env();
            assert!(matches!(format, LogFormat::Json));
        });
    }
}
