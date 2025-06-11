#![cfg(test)]

//! Rate limiting integration tests
//! 
//! Tests the tower_governor rate limiting functionality applied to the entire application.
//! Rate limiting is configured globally with:
//! - 5 requests per burst
//! - Replenishing at 2 requests per second
//! - Based on peer IP address

use anyhow::Result as AnyhowResult;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use scribe_backend::test_helpers;
use serde_json::json;
use std::time::Duration;
use tokio::time::sleep;
use tower::ServiceExt;
use tracing::{info, instrument};

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

    info!("Testing that initial burst of 5 requests are allowed");

    // Send 5 requests quickly (within burst limit)
    for i in 1..=5 {
        let request = create_register_request();
        let response = test_app.router.clone().oneshot(request).await.unwrap();
        
        info!("Request {} status: {}", i, response.status());
        
        // All requests within burst should succeed (though may fail for other reasons like validation)
        // The important thing is they're not rate limited (429)
        assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS, 
                  "Request {} was rate limited when it should be within burst limit", i);
    }

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limiting_blocks_after_burst_limit() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that requests are blocked after burst limit is exceeded");

    // Send burst limit + 1 requests quickly
    let mut responses = Vec::new();
    for i in 1..=6 {
        let request = create_register_request();
        let response = test_app.router.clone().oneshot(request).await.unwrap();
        responses.push((i, response.status()));
        info!("Request {} status: {}", i, response.status());
    }

    // The 6th request should be rate limited
    let last_status = responses.last().unwrap().1;
    assert_eq!(last_status, StatusCode::TOO_MANY_REQUESTS, 
              "6th request should have been rate limited");

    // Verify rate limiting headers are present
    let request = create_register_request();
    let response = test_app.router.clone().oneshot(request).await.unwrap();
    
    if response.status() == StatusCode::TOO_MANY_REQUESTS {
        let headers = response.headers();
        assert!(headers.contains_key("retry-after"), "Rate limited response should include retry-after header");
        assert!(headers.contains_key("x-ratelimit-after"), "Rate limited response should include x-ratelimit-after header");
    }

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limiting_applies_to_login_endpoint() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that rate limiting applies to login endpoint");

    // Send burst limit + 1 login requests quickly
    for i in 1..=6 {
        let request = create_login_request();
        let response = test_app.router.clone().oneshot(request).await.unwrap();
        info!("Login request {} status: {}", i, response.status());
        
        if i == 6 {
            // The 6th request should be rate limited
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS, 
                      "6th login request should have been rate limited");
        } else {
            // First 5 should not be rate limited
            assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS, 
                      "Login request {} was rate limited when it should be within burst limit", i);
        }
    }

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limiting_applies_to_verify_email_endpoint() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that rate limiting applies to verify-email endpoint");

    // Send burst limit + 1 email verification requests quickly
    for i in 1..=6 {
        let request = create_verify_email_request();
        let response = test_app.router.clone().oneshot(request).await.unwrap();
        info!("Verify email request {} status: {}", i, response.status());
        
        if i == 6 {
            // The 6th request should be rate limited
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS, 
                      "6th verify email request should have been rate limited");
        } else {
            // First 5 should not be rate limited
            assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS, 
                      "Verify email request {} was rate limited when it should be within burst limit", i);
        }
    }

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limiting_does_not_apply_to_health_endpoint() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that rate limiting does not apply to health endpoint");

    // First exhaust the rate limit with auth requests
    for i in 1..=6 {
        let request = create_register_request();
        let _response = test_app.router.clone().oneshot(request).await.unwrap();
    }

    // Now verify health endpoint still works
    for i in 1..=10 {
        let request = create_health_request();
        let response = test_app.router.clone().oneshot(request).await.unwrap();
        info!("Health request {} status: {}", i, response.status());
        
        // Health checks should never be rate limited
        assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS, 
                  "Health request {} was unexpectedly rate limited", i);
        assert_eq!(response.status(), StatusCode::OK, 
                  "Health request {} should return OK", i);
    }

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limit_recovery_after_time_window() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that rate limit recovers after time window");

    // Exhaust the burst limit
    for i in 1..=6 {
        let request = create_register_request();
        let response = test_app.router.clone().oneshot(request).await.unwrap();
        if i == 6 {
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS, 
                      "6th request should be rate limited");
        }
    }

    info!("Rate limit exhausted, waiting for recovery...");
    
    // Wait for rate limit to recover (2 requests per second, so wait 3 seconds for some recovery)
    sleep(Duration::from_secs(3)).await;

    info!("Testing if requests are allowed after recovery period");
    
    // Try a few more requests - at least one should succeed
    let mut successful_requests = 0;
    for i in 1..=3 {
        let request = create_register_request();
        let response = test_app.router.clone().oneshot(request).await.unwrap();
        info!("Post-recovery request {} status: {}", i, response.status());
        
        if response.status() != StatusCode::TOO_MANY_REQUESTS {
            successful_requests += 1;
        }
    }

    assert!(successful_requests > 0, 
           "At least one request should succeed after rate limit recovery period");

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limiting_headers_provide_wait_time() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that rate limiting headers provide accurate wait time information");

    // Exhaust the burst limit
    for _i in 1..=5 {
        let request = create_register_request();
        let _response = test_app.router.clone().oneshot(request).await.unwrap();
    }

    // The 6th request should be rate limited with headers
    let request = create_register_request();
    let response = test_app.router.clone().oneshot(request).await.unwrap();
    
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    
    let headers = response.headers();
    
    // Check for retry-after header
    if let Some(retry_after) = headers.get("retry-after") {
        let wait_time: u64 = retry_after.to_str().unwrap().parse().unwrap();
        info!("retry-after header indicates wait time: {} seconds", wait_time);
        assert!(wait_time > 0, "retry-after should indicate a positive wait time");
        assert!(wait_time <= 10, "retry-after should be reasonable (≤10 seconds)");
    }
    
    // Check for x-ratelimit-after header
    if let Some(ratelimit_after) = headers.get("x-ratelimit-after") {
        let wait_time: u64 = ratelimit_after.to_str().unwrap().parse().unwrap();
        info!("x-ratelimit-after header indicates wait time: {} seconds", wait_time);
        assert!(wait_time > 0, "x-ratelimit-after should indicate a positive wait time");
        assert!(wait_time <= 10, "x-ratelimit-after should be reasonable (≤10 seconds)");
    }

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limiting_mixed_endpoints_share_quota() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that mixed auth endpoints share the same rate limit quota");

    // Send a mix of different auth endpoint requests
    let requests = vec![
        ("register", create_register_request()),
        ("login", create_login_request()),
        ("verify-email", create_verify_email_request()),
        ("register", create_register_request()),
        ("login", create_login_request()),
        ("verify-email", create_verify_email_request()), // This should be rate limited
    ];

    for (i, (endpoint_name, request)) in requests.into_iter().enumerate() {
        let response = test_app.router.clone().oneshot(request).await.unwrap();
        info!("Mixed request {} ({}) status: {}", i + 1, endpoint_name, response.status());
        
        if i == 5 {
            // The 6th request should be rate limited regardless of endpoint
            assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS, 
                      "6th mixed request should have been rate limited");
        } else {
            // First 5 should not be rate limited
            assert_ne!(response.status(), StatusCode::TOO_MANY_REQUESTS, 
                      "Mixed request {} ({}) was rate limited when it should be within burst limit", 
                      i + 1, endpoint_name);
        }
    }

    Ok(())
}

#[tokio::test]
#[instrument]
async fn test_rate_limiting_response_body_contains_error_info() -> AnyhowResult<()> {
    test_helpers::ensure_tracing_initialized();
    let test_app = test_helpers::spawn_app(false, false, false).await;

    info!("Testing that rate limited responses contain useful error information");

    // Exhaust the burst limit
    for _i in 1..=5 {
        let request = create_register_request();
        let _response = test_app.router.clone().oneshot(request).await.unwrap();
    }

    // The 6th request should be rate limited
    let request = create_register_request();
    let response = test_app.router.clone().oneshot(request).await.unwrap();
    
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    
    // Check response body contains useful information
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_text = String::from_utf8(body_bytes.to_vec()).unwrap();
    
    info!("Rate limited response body: {}", body_text);
    
    // The response should contain some indication that it's a rate limiting error
    assert!(!body_text.is_empty(), "Rate limited response should have a body");
    
    // Common rate limiting error indicators
    let body_lower = body_text.to_lowercase();
    let has_rate_limit_indicator = body_lower.contains("rate") 
        || body_lower.contains("limit") 
        || body_lower.contains("too many")
        || body_lower.contains("quota")
        || body_lower.contains("throttle");
    
    assert!(has_rate_limit_indicator, 
           "Rate limited response body should contain rate limiting error information");

    Ok(())
}