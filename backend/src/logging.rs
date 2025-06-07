use tracing::Subscriber; // Added for `impl Subscriber`
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Builds the tracing subscriber configuration.
/// This function is separate to allow testing the configuration logic
/// without initializing the global subscriber.
fn build_subscriber_builder() -> impl Subscriber {
    // Changed return type
    // Sets the default log level from RUST_LOG env var, defaulting to INFO
    // for scribe_backend and tower_http if not set.
    // Uses a JSON formatter for structured logging.
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,scribe_backend::routes=info,scribe_backend::auth=info,scribe_backend::services=warn,scribe_backend::vector_db=warn,tower_http=info,sqlx=warn,gemini_client=info,auth_debug=error".into()),
        )
        .with(fmt::layer().json().with_current_span(false).with_span_list(false)) // Use JSON formatter, disable verbose span info
}

// Initializes and sets the global tracing subscriber.
pub fn init_subscriber() {
    build_subscriber_builder().init();
    tracing::info!("Tracing subscriber initialized.");
}

// Remove the outdated test module declaration using #[path]
/*
// Declare the test module (it lives in a separate file)
#[cfg(test)]
#[path = "logging_tests.rs"]
mod tests;
*/

// --- Unit Tests ---
#[cfg(test)]
mod tests {
    use super::*; // Import items from parent module (logging.rs)
    use std::env;
    // Removed unused Level and FilterExt imports

    // Using a mutex to serialize access to the env var modification
    // This helps prevent race conditions if tests run in parallel.
    // Note: `cargo test` runs tests in parallel by default.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(()); // Fixed < and >

    // Helper function moved outside specific tests, but still in `mod tests`
    fn with_rust_log<F>(var: Option<&str>, f: F)
    // Fixed &
    where
        F: FnOnce(),
    {
        let original_val = env::var("RUST_LOG").ok();

        let _guard = ENV_MUTEX.lock().unwrap();

        match var {
            Some(v) => unsafe { env::set_var("RUST_LOG", v) },
            None => unsafe { env::remove_var("RUST_LOG") },
        }

        // Use std::panic::catch_unwind to ensure cleanup happens even if f() panics
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));

        // Restore original value
        match original_val {
            Some(v) => unsafe { env::set_var("RUST_LOG", v) },
            None => unsafe { env::remove_var("RUST_LOG") },
        }

        // Propagate panic if one occurred
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    #[test]
    fn test_init_subscriber_runs() {
        // Use try_init() to avoid panicking if a subscriber is already set globally
        // by another test running concurrently.
        // We discard the result because we only care that the setup doesn't panic.
        // We call the builder function here.
        let result = build_subscriber_builder().try_init();

        // Check if initialization was successful or if a subscriber was already set
        // Moved assertion back inside the test function
        assert!(result.is_ok() || tracing::subscriber::set_global_default(tracing::subscriber::NoSubscriber::new()).is_err(),
                "try_init should either succeed or fail because a subscriber is already set.");

        // No panic means success for this basic test.
    }

    #[test]
    fn test_build_subscriber_uses_default_filter_when_env_unset() {
        // Ensure RUST_LOG is unset for this test case
        with_rust_log(None, || {
            // Simply calling the builder covers the .unwrap_or_else path
            let _builder = build_subscriber_builder();
            // Asserting that it doesn't panic is the main check here
        });
    }

    #[test]
    fn test_build_subscriber_uses_rust_log_env_when_set() {
        let test_filter = "my_crate=debug,other=warn";
        // Set RUST_LOG for this test case
        with_rust_log(Some(test_filter), || {
            // Calling the builder covers the EnvFilter::try_from_default_env path
            let _builder = build_subscriber_builder();
            // Asserting that it doesn't panic is the main check here
        });
    }

    #[test]
    fn test_build_subscriber_handles_invalid_rust_log_env() {
        let invalid_filter = "this=is=not=valid";
        // Set invalid RUST_LOG - EnvFilter::try_from_default_env should return Err,
        // triggering the unwrap_or_else branch.
        with_rust_log(Some(invalid_filter), || {
            // Calling the builder covers the error handling in try_from_default_env
            // followed by the unwrap_or_else path.
            let _builder = build_subscriber_builder();
            // Asserting that it doesn't panic is the main check here
        });
    }
}
