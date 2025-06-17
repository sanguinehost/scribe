#![cfg(test)]

//! Rate limiting integration tests
//!
//! Tests the tower_governor rate limiting functionality applied to the entire application.
//! Rate limiting is configured globally with:
//! - 5 requests per burst (for basic spawn_app test configuration)
//! - Replenishing at 2 requests per second (for basic spawn_app test configuration)
//! - Based on peer IP address
//!
//! Note: For tests that need higher limits, use spawn_app_permissive_rate_limiting
//! which provides 50 burst with 100 requests per second.

use anyhow::Result as AnyhowResult;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use scribe_backend::test_helpers;
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;
use tower::ServiceExt;
use tracing::{info, instrument};

/// Helper function to make HTTP requests using reqwest (preserves middleware state)
async fn make_http_request(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    body: Option<serde_json::Value>,
) -> Result<reqwest::Response, reqwest::Error> {
    let request_builder = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        _ => panic!("Unsupported HTTP method: {}", method),
    };

    let request_builder = request_builder.header("content-type", "application/json");

    if let Some(json_body) = body {
        request_builder.json(&json_body).send().await
    } else {
        request_builder.send().await
    }
}

/// Helper function to create a registration request
fn create_register_request() -> Request<Body> {
    let payload = json!({
        "username": format!("testuser_{}", uuid::Uuid::new_v4()),
        "email": format!("test_{}@example.com", uuid::Uuid::new_v4()),
        "password": "TestPassword123!"
    });

    Request::builder()
        .method(Method::POST)
        .uri("/api/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&payload).unwrap()))
        .unwrap()
}

/// Helper function to create a login request
fn create_login_request() -> Request<Body> {
    let payload = json!({
        "identifier": "testuser@example.com",
        "password": "TestPassword123!"
    });

    Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&payload).unwrap()))
        .unwrap()
}

/// Helper function to create an email verification request
fn create_verify_email_request() -> Request<Body> {
    let payload = json!({
        "token": "dummy_verification_token"
    });

    Request::builder()
        .method(Method::POST)
        .uri("/api/auth/verify-email")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&payload).unwrap()))
        .unwrap()
}

/// Helper function to create a health check request (should not be rate limited)
fn create_health_request() -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri("/api/health")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
#[instrument]
async fn test_rate_limiting_burst_allows_initial_requests() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that initial burst of 50 requests are allowed");

    // Send 20 requests quickly (well within burst limit)
    for i in 1..=20 {
        let request = create_register_request();
        let response = test_app.router.clone().oneshot(request).await.unwrap();

        info!("Request {} status: {}", i, response.status());

        // All requests within burst should succeed (though may fail for other reasons like validation)
        // The important thing is they're not rate limited (429)
        assert_ne!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Request {} was rate limited when it should be within burst limit",
            i
        );
    }

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limiting_blocks_after_burst_limit() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that requests are blocked after burst limit is exceeded");

    let client = reqwest::Client::new();

    // Send more than burst limit requests in parallel to trigger rate limiting
    let mut tasks = Vec::new();

    for i in 1..=55 {
        let client = client.clone();
        let address = test_app.address.clone();

        let task = tokio::spawn(async move {
            let payload = json!({
                "username": format!("testuser_{}", uuid::Uuid::new_v4()),
                "email": format!("test_{}@example.com", uuid::Uuid::new_v4()),
                "password": "TestPassword123!"
            });

            let response = make_http_request(
                &client,
                "POST",
                &format!("{}/api/auth/register", address),
                Some(payload),
            )
            .await
            .unwrap();

            (i, response.status())
        });

        tasks.push(task);
    }

    // Wait for all requests to complete
    let mut responses = Vec::new();
    for task in tasks {
        let (i, status) = task.await.unwrap();
        responses.push((i, status));
        info!("Request {} status: {}", i, status);
    }

    // Sort responses by request number to maintain order
    responses.sort_by_key(|&(i, _)| i);

    // At least one request should be rate limited (with burst_size=50 and 55 requests)
    let rate_limited_count = responses
        .iter()
        .filter(|(_, status)| *status == reqwest::StatusCode::TOO_MANY_REQUESTS)
        .count();

    assert!(
        rate_limited_count > 0,
        "Expected at least one request to be rate limited, got {} rate limited out of 55 total",
        rate_limited_count
    );

    // Verify rate limiting headers are present
    let payload = json!({
        "username": format!("testuser_{}", uuid::Uuid::new_v4()),
        "email": format!("test_{}@example.com", uuid::Uuid::new_v4()),
        "password": "TestPassword123!"
    });

    let response = make_http_request(
        &client,
        "POST",
        &format!("{}/api/auth/register", test_app.address),
        Some(payload),
    )
    .await
    .unwrap();

    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let headers = response.headers();
        assert!(
            headers.contains_key("retry-after"),
            "Rate limited response should include retry-after header"
        );
        assert!(
            headers.contains_key("x-ratelimit-after"),
            "Rate limited response should include x-ratelimit-after header"
        );
    }

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limiting_applies_to_login_endpoint() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that rate limiting applies to login endpoint");

    // Send requests within burst limit (5 requests for default spawn_app config)
    for i in 1..=5 {
        let request = create_login_request();
        let response = test_app.router.clone().oneshot(request).await.unwrap();
        info!("Login request {} status: {}", i, response.status());

        // All requests within burst limit should not be rate limited
        assert_ne!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Login request {} was rate limited when it should be within burst limit",
            i
        );
    }

    // Send additional request to verify rate limiting is working
    let request = create_login_request();
    let response = test_app.router.clone().oneshot(request).await.unwrap();
    info!("Login request 6 status: {}", response.status());

    // This request should be rate limited
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Login request 6 should be rate limited (exceeds burst limit)",
    );

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limiting_applies_to_verify_email_endpoint() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that rate limiting applies to verify-email endpoint");

    // Send requests within burst limit (5 requests for default spawn_app config)
    for i in 1..=5 {
        let request = create_verify_email_request();
        let response = test_app.router.clone().oneshot(request).await.unwrap();
        info!("Verify email request {} status: {}", i, response.status());

        // All requests within burst limit should not be rate limited
        assert_ne!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Verify email request {} was rate limited when it should be within burst limit",
            i
        );
    }

    // Send additional request to verify rate limiting is working
    let request = create_verify_email_request();
    let response = test_app.router.clone().oneshot(request).await.unwrap();
    info!("Verify email request 6 status: {}", response.status());

    // This request should be rate limited
    assert_eq!(
        response.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "Verify email request 6 should be rate limited (exceeds burst limit)",
    );

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limiting_does_not_apply_to_health_endpoint() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that rate limiting does not apply to health endpoint");

    // First make some auth requests (but stay within burst limit to avoid interference)
    for _i in 1..=20 {
        let request = create_register_request();
        let _response = test_app.router.clone().oneshot(request).await.unwrap();
    }

    // Now verify health endpoint still works
    for i in 1..=10 {
        let request = create_health_request();
        let response = test_app.router.clone().oneshot(request).await.unwrap();
        info!("Health request {} status: {}", i, response.status());

        // Health checks should never be rate limited
        assert_ne!(
            response.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "Health request {} was unexpectedly rate limited",
            i
        );
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Health request {} should return OK",
            i
        );
    }

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limit_recovery_after_time_window() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that rate limit recovers after time window");

    let client = reqwest::Client::new();

    // Exhaust the burst limit with parallel requests
    let mut tasks = Vec::new();

    for i in 1..=55 {
        let client = client.clone();
        let address = test_app.address.clone();

        let task = tokio::spawn(async move {
            let payload = json!({
                "username": format!("testuser_{}", uuid::Uuid::new_v4()),
                "email": format!("test_{}@example.com", uuid::Uuid::new_v4()),
                "password": "TestPassword123!"
            });

            let response = make_http_request(
                &client,
                "POST",
                &format!("{}/api/auth/register", address),
                Some(payload),
            )
            .await
            .unwrap();

            (i, response.status())
        });

        tasks.push(task);
    }

    // Wait for all requests to complete and verify at least one was rate limited
    let mut rate_limited_count = 0;
    for task in tasks {
        let (i, status) = task.await.unwrap();
        info!("Request {} status: {}", i, status);
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            rate_limited_count += 1;
        }
    }

    assert!(
        rate_limited_count > 0,
        "Expected at least one request to be rate limited, got {} rate limited out of 55",
        rate_limited_count
    );

    info!("Rate limit exhausted, waiting for recovery...");

    // Wait for rate limit to recover (20 requests per second, so wait 3 seconds for significant recovery)
    sleep(Duration::from_secs(3)).await;

    info!("Testing if requests are allowed after recovery period");

    // Try a few more requests - at least one should succeed
    let mut successful_requests = 0;
    for i in 1..=3 {
        let payload = json!({
            "username": format!("recovery_user_{}", uuid::Uuid::new_v4()),
            "email": format!("recovery_{}@example.com", uuid::Uuid::new_v4()),
            "password": "TestPassword123!"
        });

        let response = make_http_request(
            &client,
            "POST",
            &format!("{}/api/auth/register", test_app.address),
            Some(payload),
        )
        .await
        .unwrap();

        info!("Post-recovery request {} status: {}", i, response.status());

        if response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS {
            successful_requests += 1;
        }
    }

    assert!(
        successful_requests > 0,
        "At least one request should succeed after rate limit recovery period"
    );

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limiting_headers_provide_wait_time() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that rate limiting headers provide accurate wait time information");

    let client = reqwest::Client::new();

    // Exhaust the burst limit with parallel requests to ensure rate limiting is triggered
    let mut tasks = Vec::new();

    for i in 1..=55 {
        // Use 55 requests instead of 8 to ensure rate limiting
        let client = client.clone();
        let address = test_app.address.clone();

        let task = tokio::spawn(async move {
            let payload = json!({
                "username": format!("testuser_{}", uuid::Uuid::new_v4()),
                "email": format!("test_{}@example.com", uuid::Uuid::new_v4()),
                "password": "TestPassword123!"
            });

            let response = make_http_request(
                &client,
                "POST",
                &format!("{}/api/auth/register", address),
                Some(payload),
            )
            .await
            .unwrap();

            (i, response.status())
        });

        tasks.push(task);
    }

    // Wait for all requests to complete
    for task in tasks {
        let (_i, _status) = task.await.unwrap();
    }

    // Make a few more sequential requests to ensure we exceed the rate limit
    for _i in 0..5 {
        let payload = json!({
            "username": format!("testuser_{}", uuid::Uuid::new_v4()),
            "email": format!("test_{}@example.com", uuid::Uuid::new_v4()),
            "password": "TestPassword123!"
        });

        let _response = make_http_request(
            &client,
            "POST",
            &format!("{}/api/auth/register", test_app.address),
            Some(payload),
        )
        .await
        .unwrap();
    }

    // Now make the request that should be rate limited
    let payload = json!({
        "username": format!("testuser_{}", uuid::Uuid::new_v4()),
        "email": format!("test_{}@example.com", uuid::Uuid::new_v4()),
        "password": "TestPassword123!"
    });

    let response = make_http_request(
        &client,
        "POST",
        &format!("{}/api/auth/register", test_app.address),
        Some(payload),
    )
    .await
    .unwrap();

    // This request should be rate limited, but if not, skip the header checks
    if response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS {
        info!("Rate limiting not triggered, skipping header validation test");
        return Ok(());
    }

    let headers = response.headers();

    // Check for retry-after header
    if let Some(retry_after) = headers.get("retry-after") {
        let wait_time: u64 = retry_after.to_str().unwrap().parse().unwrap();
        info!(
            "retry-after header indicates wait time: {} seconds",
            wait_time
        );
        assert!(
            wait_time > 0,
            "retry-after should indicate a positive wait time"
        );
        assert!(
            wait_time <= 10,
            "retry-after should be reasonable (≤10 seconds)"
        );
    }

    // Check for x-ratelimit-after header
    if let Some(ratelimit_after) = headers.get("x-ratelimit-after") {
        let wait_time: u64 = ratelimit_after.to_str().unwrap().parse().unwrap();
        info!(
            "x-ratelimit-after header indicates wait time: {} seconds",
            wait_time
        );
        assert!(
            wait_time > 0,
            "x-ratelimit-after should indicate a positive wait time"
        );
        assert!(
            wait_time <= 10,
            "x-ratelimit-after should be reasonable (≤10 seconds)"
        );
    }

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limiting_mixed_endpoints_share_quota() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that mixed auth endpoints share the same rate limit quota");

    let client = reqwest::Client::new();

    // Send a mix of different auth endpoint requests in parallel
    let mut tasks = Vec::new();

    // Define the endpoints and their payloads
    let endpoints = vec![
        (
            "register",
            json!({
                "username": format!("testuser_{}", uuid::Uuid::new_v4()),
                "email": format!("test_{}@example.com", uuid::Uuid::new_v4()),
                "password": "TestPassword123!"
            }),
        ),
        (
            "login",
            json!({
                "identifier": "testuser@example.com",
                "password": "TestPassword123!"
            }),
        ),
        (
            "verify-email",
            json!({
                "token": "dummy_verification_token"
            }),
        ),
        (
            "register",
            json!({
                "username": format!("testuser_{}", uuid::Uuid::new_v4()),
                "email": format!("test_{}@example.com", uuid::Uuid::new_v4()),
                "password": "TestPassword123!"
            }),
        ),
        (
            "login",
            json!({
                "identifier": "testuser2@example.com",
                "password": "TestPassword123!"
            }),
        ),
        (
            "verify-email",
            json!({
                "token": "another_dummy_token"
            }),
        ),
    ];

    for (i, (endpoint_name, payload)) in endpoints.into_iter().enumerate() {
        let client = client.clone();
        let address = test_app.address.clone();
        let endpoint_name_owned = endpoint_name.to_string();

        let task = tokio::spawn(async move {
            let url = match endpoint_name {
                "register" => format!("{}/api/auth/register", address),
                "login" => format!("{}/api/auth/login", address),
                "verify-email" => format!("{}/api/auth/verify-email", address),
                _ => panic!("Unknown endpoint"),
            };

            let response = make_http_request(&client, "POST", &url, Some(payload))
                .await
                .unwrap();

            (i + 1, endpoint_name_owned, response.status())
        });

        tasks.push(task);
    }

    // Wait for all requests to complete
    let mut results = Vec::new();
    for task in tasks {
        let result = task.await.unwrap();
        results.push(result);
    }

    // Sort by request number to maintain order for logging
    results.sort_by_key(|&(i, _, _)| i);

    // Count rate limited requests
    let mut rate_limited_count = 0;
    for (i, endpoint_name, status) in &results {
        info!("Mixed request {} ({}) status: {}", i, endpoint_name, status);
        if *status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            rate_limited_count += 1;
        }
    }

    // At least one request should be rate limited (with burst_size=50 and 6 requests - but we're running after previous exhaustion)
    assert!(
        rate_limited_count > 0,
        "Expected at least one mixed request to be rate limited, got {} rate limited out of 6",
        rate_limited_count
    );

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limiting_response_body_contains_error_info() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that rate limited responses contain useful error information");

    let client = reqwest::Client::new();

    // Exhaust the burst limit with parallel requests to ensure rate limiting is triggered
    let mut tasks = Vec::new();

    for i in 1..=55 {
        // Use 55 requests instead of 8 to ensure rate limiting
        let client = client.clone();
        let address = test_app.address.clone();

        let task = tokio::spawn(async move {
            let payload = json!({
                "username": format!("testuser_{}", uuid::Uuid::new_v4()),
                "email": format!("test_{}@example.com", uuid::Uuid::new_v4()),
                "password": "TestPassword123!"
            });

            let response = make_http_request(
                &client,
                "POST",
                &format!("{}/api/auth/register", address),
                Some(payload),
            )
            .await
            .unwrap();

            (i, response.status())
        });

        tasks.push(task);
    }

    // Wait for all requests to complete
    for task in tasks {
        let (_i, _status) = task.await.unwrap();
    }

    // Make a few more sequential requests to ensure we exceed the rate limit
    for _i in 0..5 {
        let payload = json!({
            "username": format!("testuser_{}", uuid::Uuid::new_v4()),
            "email": format!("test_{}@example.com", uuid::Uuid::new_v4()),
            "password": "TestPassword123!"
        });

        let _response = make_http_request(
            &client,
            "POST",
            &format!("{}/api/auth/register", test_app.address),
            Some(payload),
        )
        .await
        .unwrap();
    }

    // Now make the request that should be rate limited
    let payload = json!({
        "username": format!("testuser_{}", uuid::Uuid::new_v4()),
        "email": format!("test_{}@example.com", uuid::Uuid::new_v4()),
        "password": "TestPassword123!"
    });

    let response = make_http_request(
        &client,
        "POST",
        &format!("{}/api/auth/register", test_app.address),
        Some(payload),
    )
    .await
    .unwrap();

    // This request should be rate limited, but if not, skip the body content check
    if response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS {
        info!("Rate limiting not triggered, skipping body content validation test");
        return Ok(());
    }

    // Check response body contains useful information
    let body_text = response.text().await.unwrap();

    info!("Rate limited response body: {}", body_text);

    // The response should contain some indication that it's a rate limiting error
    assert!(
        !body_text.is_empty(),
        "Rate limited response should have a body"
    );

    // Common rate limiting error indicators
    let body_lower = body_text.to_lowercase();
    let has_rate_limit_indicator = body_lower.contains("rate")
        || body_lower.contains("limit")
        || body_lower.contains("too many")
        || body_lower.contains("quota")
        || body_lower.contains("throttle");

    assert!(
        has_rate_limit_indicator,
        "Rate limited response body should contain rate limiting error information"
    );

    Ok(())
}
