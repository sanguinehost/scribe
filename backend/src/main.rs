use axum::{
    routing::get,
    Json,
    Router,
};
use serde::Serialize;
use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    // Build our application with a single route.
    let app = Router::new().route("/api/health", get(health_check));

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