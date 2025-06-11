#![cfg(test)]

use anyhow::Result as AnyhowResult;
use axum::{body::Body, http::{Method, Request, StatusCode}};
use http_body_util::BodyExt;
use scribe_backend::test_helpers;
use serde_json::json;
use tower::ServiceExt;
use tracing::info;

#[tokio::test]
async fn test_rate_limiting_simple() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing rapid requests to trigger rate limiting");

    // Send 10 requests as fast as possible 
    let mut responses = Vec::new();
    for i in 1..=10 {
        let payload = json!({
            "username": format!("user{}", i),
            "email": format!("user{}@example.com", i),
            "password": "Password123!"
        });

        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/auth/register")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .unwrap();

        let response = test_app.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        responses.push((i, status));
        
        info!("Request {} status: {}", i, status);
        
        // If we get a rate limit, show what the response contains
        if status == StatusCode::TOO_MANY_REQUESTS {
            let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
            let body_text = String::from_utf8(body_bytes.to_vec()).unwrap();
            info!("Rate limited response body: {}", body_text);
            break; // Stop after first rate limit
        }
    }

    // Count how many succeeded vs were rate limited
    let successful = responses.iter().filter(|(_, status)| status == &StatusCode::CREATED).count();
    let rate_limited = responses.iter().filter(|(_, status)| status == &StatusCode::TOO_MANY_REQUESTS).count();
    
    info!("Summary: {} successful, {} rate limited", successful, rate_limited);
    
    // We expect at least one request to be rate limited after the burst
    assert!(rate_limited > 0, "Expected at least one request to be rate limited, got {} successful and {} rate limited", successful, rate_limited);
    
    Ok(())
}