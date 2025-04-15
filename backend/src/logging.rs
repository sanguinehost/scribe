use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_subscriber() {
    // Sets the default log level from RUST_LOG env var, defaulting to INFO
    // for scribe_backend and tower_http if not set.
    // Uses a JSON formatter for structured logging.
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "scribe_backend=info,tower_http=info".into()),
        )
        .with(fmt::layer().json()) // Use JSON formatter
        .init();

    tracing::info!("Tracing subscriber initialized.");
}

// Declare the test module (it lives in a separate file)
#[cfg(test)]
#[path = "logging_tests.rs"]
mod tests;
