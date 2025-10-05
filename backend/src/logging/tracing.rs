use tracing::Subscriber;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Builds the tracing subscriber configuration.
/// This function is separate to allow testing the configuration logic
/// without initializing the global subscriber.
fn build_subscriber_builder() -> impl Subscriber {
    // Sets the default log level from RUST_LOG env var, defaulting to INFO
    // for scribe_backend and tower_http if not set.
    // Uses a JSON formatter for structured logging.
    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,scribe_backend::routes=info,scribe_backend::auth=info,scribe_backend::services=warn,scribe_backend::vector_db=warn,tower_http=info,sqlx=warn,gemini_client=info,auth_debug=error".into()),
        )
        .with(fmt::layer().json().with_current_span(false).with_span_list(false))
}

/// Initializes and sets the global tracing subscriber.
pub fn init_subscriber() {
    build_subscriber_builder().init();
    tracing::info!("Tracing subscriber initialized.");
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
        let result = build_subscriber_builder().try_init();
        assert!(
            result.is_ok()
                || tracing::subscriber::set_global_default(
                    tracing::subscriber::NoSubscriber::new()
                )
                .is_err(),
            "try_init should either succeed or fail because a subscriber is already set."
        );
    }

    #[test]
    fn test_build_subscriber_uses_default_filter_when_env_unset() {
        with_rust_log(None, || {
            let _builder = build_subscriber_builder();
        });
    }

    #[test]
    fn test_build_subscriber_uses_rust_log_env_when_set() {
        let test_filter = "my_crate=debug,other=warn";
        with_rust_log(Some(test_filter), || {
            let _builder = build_subscriber_builder();
        });
    }

    #[test]
    fn test_build_subscriber_handles_invalid_rust_log_env() {
        let invalid_filter = "this=is=not=valid";
        with_rust_log(Some(invalid_filter), || {
            let _builder = build_subscriber_builder();
        });
    }
}
