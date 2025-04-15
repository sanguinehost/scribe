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

// Remove the outdated test module declaration using #[path]
/*
// Declare the test module (it lives in a separate file)
#[cfg(test)]
#[path = "logging_tests.rs"]
mod tests;
*/

// --- Unit Tests moved from tests/logging_tests.rs ---
#[cfg(test)]
mod tests {
    use super::*; // Import items from parent module (logging.rs)

    #[test]
    fn test_init_subscriber_runs() {
        // This test primarily ensures the function can be called without panicking.
        // It doesn't verify the logger output, which is harder in unit tests.
        // We expect it might print info during test runs if RUST_LOG isn't set.
        init_subscriber();
        // No panic means success for this basic test.
    }
}
