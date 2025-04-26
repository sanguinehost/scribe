use axum::Json;
use serde::Serialize;

#[derive(Serialize)]
pub struct HealthStatus {
    pub status: String,
}

/// Simple health check endpoint.
pub async fn health_check() -> Json<HealthStatus> {
    tracing::debug!("Health check endpoint called");
    Json(HealthStatus {
        status: "ok".to_string(),
    })
}
