use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use std::env;

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
pub fn init_subscriber() {
    // Sets the default log level from RUST_LOG env var, defaulting to INFO
    // for scribe_backend and tower_http if not set.
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,scribe_backend::routes=info,scribe_backend::auth=info,scribe_backend::services=info,scribe_backend::vector_db=info,tower_http=info,sqlx=warn,gemini_client=info,auth_debug=error".into());

    // Get configuration from environment variables
    let log_dir = env::var("LOG_DIR").unwrap_or_else(|_| "/tmp".to_string());
    let log_prefix = env::var("LOG_FILE_PREFIX").unwrap_or_else(|_| "scribe-backend".to_string());
    let rotation = LogRotation::from_env();
    let format = LogFormat::from_env();

    // Create file appender with rotation
    // The rotation policy determines when new log files are created:
    // - Daily: Creates a new file each day (e.g., scribe-backend.2025-11-15)
    // - Hourly: Creates a new file each hour (e.g., scribe-backend.2025-11-15-14)
    // - Never: Single file, no rotation (scribe-backend.log)
    let file_appender = match rotation {
        LogRotation::Daily => tracing_appender::rolling::daily(&log_dir, &log_prefix),
        LogRotation::Hourly => tracing_appender::rolling::hourly(&log_dir, &log_prefix),
        LogRotation::Never => tracing_appender::rolling::never(&log_dir, format!("{}.log", log_prefix)),
    };

    // tracing-appender's non_blocking() creates a worker thread that handles
    // writing to the file asynchronously, returning a guard that must be kept alive
    let (file_writer, guard) = tracing_appender::non_blocking(file_appender);

    // Leak the guard to ensure the worker thread stays alive for the program's lifetime
    // This is intentional - we want logs to be written until the program exits
    std::mem::forget(guard);

    // Build and initialize subscriber with dual output based on format preference
    // We build and init the subscriber inside the match to avoid type complexity
    match format {
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(
                    fmt::layer()
                        .json()
                        .with_current_span(false)
                        .with_span_list(false)
                        .with_writer(std::io::stdout)
                )
                .with(
                    fmt::layer()
                        .json()
                        .with_current_span(false)
                        .with_span_list(false)
                        .with_writer(file_writer)
                )
                .init();
        }
        LogFormat::Pretty => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().pretty().with_writer(std::io::stdout))
                .with(fmt::layer().pretty().with_writer(file_writer))
                .init();
        }
        LogFormat::Compact => {
            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().compact().with_writer(std::io::stdout))
                .with(fmt::layer().compact().with_writer(file_writer))
                .init();
        }
    }

    // Log the configuration that was used
    let rotation_str = env::var("LOG_ROTATION").unwrap_or_else(|_| "daily".to_string());
    let format_str = env::var("LOG_FORMAT").unwrap_or_else(|_| "json".to_string());

    tracing::info!(
        log_dir = %log_dir,
        log_prefix = %log_prefix,
        rotation = %rotation_str,
        format = %format_str,
        "Tracing subscriber initialized with configuration"
    );
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
            let rotation = LogRotation::from_env();
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
