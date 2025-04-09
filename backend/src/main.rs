use axum::{
    routing::{get, post},
    Json,
    Router,
};
use serde::Serialize;
use std::net::SocketAddr;

// Declare modules
pub mod models;
pub mod routes;
pub mod services;

// Import route handlers
use routes::characters::{get_character, list_characters, upload_character};

#[tokio::main]
async fn main() {
    // Build our application with routes.
    let app = Router::new()
        .route("/api/health", get(health_check))
        // Character routes
        .route("/api/characters", get(list_characters).post(upload_character))
        .route("/api/characters/:id", get(get_character));
        // TODO: Add state later if needed: .with_state(AppState)

    // Run our application
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Serialize)]
struct HealthStatus {
    status: String,
}

async fn health_check() -> Json<HealthStatus> {
    Json(HealthStatus { status: "ok".to_string() })
} 