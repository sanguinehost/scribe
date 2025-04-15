use axum::{Json, Router, routing::get};
use diesel::PgConnection;
use diesel::r2d2::{ConnectionManager, Pool};
use serde::Serialize;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::trace::{DefaultMakeSpan, TraceLayer}; // Import TraceLayer

// Use modules from the library crate
use scribe_backend::logging::init_subscriber; // Import the new function
use scribe_backend::routes::characters::{get_character, list_characters, upload_character};
use scribe_backend::state::AppState;

#[tokio::main]
async fn main() {
    // Load .env file
    dotenvy::dotenv().ok();

    // Initialize tracing subscriber using the new function
    init_subscriber(); // Call the function from the logging module

    tracing::info!("Starting Scribe backend server..."); // Log startup

    // Set up database connection pool
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    tracing::info!("Connecting to database..."); // Log DB connection attempt
    let manager = ConnectionManager::<PgConnection>::new(database_url);
    let pool = Pool::builder()
        .test_on_check_out(true)
        .build(manager)
        .expect("Failed to create DB pool.");
    tracing::info!("Database connection pool established."); // Log DB success

    let app_state = AppState {
        pool: Arc::new(pool),
    };

    // Build our application with routes, state, and tracing layer
    let app = Router::new()
        .route("/api/health", get(health_check)) // health_check is local to main.rs
        // Character routes
        .route(
            "/api/characters",
            get(list_characters).post(upload_character),
        )
        .route("/api/characters/:id", get(get_character))
        .with_state(app_state) // Pass state to the router
        // Add TraceLayer for request logging
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        );

    // Run our application
    let port = env::var("PORT").unwrap_or_else(|_| "3000".to_string());
    let addr_str = format!("0.0.0.0:{}", port); // Listen on 0.0.0.0 for container compatibility
    let addr: SocketAddr = addr_str.parse().expect("Invalid address format");

    tracing::info!("Listening on {}", addr); // Use tracing::info instead of println!
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Serialize)]
struct HealthStatus {
    status: String,
}

// health_check remains defined locally in main.rs
async fn health_check() -> Json<HealthStatus> {
    tracing::debug!("Health check endpoint called"); // Add a debug log
    Json(HealthStatus {
        status: "ok".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check() {
        let response = health_check().await;
        // Assuming get_body_json is not available here, we check status and basic structure
        assert_eq!(response.0.status, "ok");
        // We can't easily check the exact JSON structure without a helper or full response processing,
        // but testing the inner data structure is a good start for a unit test.
    }
}
