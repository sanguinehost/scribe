#![cfg(test)]

use anyhow::Result as AnyhowResult;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    response::Response,
    routing::get,
    Router,
};
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer, key_extractor::GlobalKeyExtractor};
use tower::ServiceExt;
use std::sync::Arc;

/// Test rate limiting with the most minimal configuration possible
/// to verify tower_governor is working at all
#[tokio::test]
async fn test_minimal_rate_limiting() -> AnyhowResult<()> {
    // Create the most basic router with very restrictive rate limiting
    let app = Router::new()
        .route("/test", get(|| async { "ok" }))
        .layer(GovernorLayer {
            config: Arc::new(
                GovernorConfigBuilder::default()
                    .per_second(1)  // Very restrictive: only 1 request per second
                    .burst_size(1)  // Very restrictive: only 1 request in burst
                    .key_extractor(GlobalKeyExtractor)
                    .finish()
                    .unwrap(),
            ),
        });

    // Make first request - should succeed
    let request1 = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .body(Body::empty())
        .unwrap();
    
    let response1 = app.clone().oneshot(request1).await.unwrap();
    println!("Request 1 status: {}", response1.status());
    
    // Make second request immediately - should be rate limited
    let request2 = Request::builder()
        .method(Method::GET)
        .uri("/test")
        .body(Body::empty())
        .unwrap();
    
    let response2 = app.clone().oneshot(request2).await.unwrap();
    println!("Request 2 status: {}", response2.status());
    
    // At least one should be rate limited with such restrictive settings
    let is_rate_limited = response1.status() == StatusCode::TOO_MANY_REQUESTS 
                      || response2.status() == StatusCode::TOO_MANY_REQUESTS;
    
    assert!(is_rate_limited, 
           "Expected at least one request to be rate limited with burst_size(1), got {} and {}", 
           response1.status(), response2.status());

    Ok(())
}