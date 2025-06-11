#![cfg(test)]

use anyhow::Result as AnyhowResult;
use scribe_backend::test_helpers;
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

/// Test rate limiting using actual HTTP client requests to a running server
/// This preserves middleware state between requests unlike oneshot() calls
#[tokio::test]
async fn test_rate_limiting_with_running_server() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing rate limiting with running server at: {}", test_app.address);

    let client = reqwest::Client::new();
    let mut successful = 0;
    let mut rate_limited = 0;

    // Send 10 requests as fast as possible to the running server
    for i in 1..=10 {
        let payload = json!({
            "username": format!("user{}", i),
            "email": format!("user{}@example.com", i),
            "password": "Password123!"
        });

        let response = client
            .post(&format!("{}/api/auth/register", test_app.address))
            .header("content-type", "application/json")
            .json(&payload)
            .send()
            .await?;

        let status = response.status();
        info!("Request {} status: {}", i, status);

        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            rate_limited += 1;
            let body = response.text().await?;
            info!("Rate limited response body: {}", body);
        } else if status == reqwest::StatusCode::CREATED {
            successful += 1;
        } else {
            // Log other status codes to understand what's happening
            let body = response.text().await?;
            info!("Request {} unexpected status {} with body: {}", i, status, body);
        }
    }

    info!("Summary: {} successful, {} rate limited", successful, rate_limited);

    // We expect at least some requests to be rate limited
    // With burst_size(5) and 10 requests, at least 5 should be rate limited
    assert!(rate_limited > 0, 
           "Expected at least one request to be rate limited, got {} successful and {} rate limited", 
           successful, rate_limited);

    Ok(())
}

/// Test rate limiting recovery after waiting
#[tokio::test]
async fn test_rate_limiting_recovery_with_server() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    let client = reqwest::Client::new();

    // First, exhaust the rate limit
    for i in 1..=7 {
        let payload = json!({
            "username": format!("exhaust{}", i),
            "email": format!("exhaust{}@example.com", i),
            "password": "Password123!"
        });

        let response = client
            .post(&format!("{}/api/auth/register", test_app.address))
            .header("content-type", "application/json")
            .json(&payload)
            .send()
            .await?;

        info!("Exhaust request {} status: {}", i, response.status());
    }

    info!("Rate limit should be exhausted, waiting for recovery...");
    
    // Wait for rate limit to recover (2 requests per second, wait 3 seconds)
    sleep(Duration::from_secs(3)).await;

    // Try a request after recovery
    let payload = json!({
        "username": "recovery_user",
        "email": "recovery@example.com",
        "password": "Password123!"
    });

    let response = client
        .post(&format!("{}/api/auth/register", test_app.address))
        .header("content-type", "application/json")
        .json(&payload)
        .send()
        .await?;

    info!("Recovery request status: {}", response.status());

    // This request should succeed after waiting for recovery
    assert_ne!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS,
              "Request should succeed after rate limit recovery period");

    Ok(())
}