#![cfg(test)]

use anyhow::Result as AnyhowResult;
use axum::{body::Body, http::{Method, Request}};
use http_body_util::BodyExt;
use scribe_backend::test_helpers;
use serde_json::json;
use tower::ServiceExt;
use tracing::info;

#[tokio::test]
async fn debug_rate_limiting_error() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    let payload = json!({
        "username": "debuguser",
        "email": "debug@example.com",
        "password": "DebugPassword123!"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    
    info!("Response status: {}", response.status());
    
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_text = String::from_utf8(body_bytes.to_vec()).unwrap();
    
    info!("Response body: {}", body_text);
    
    Ok(())
}