//! Integration tests for the health check endpoint

// Import necessary items
use axum::{
    body::Body,
    http::{Request, Method, StatusCode},
};
use http_body_util::BodyExt; // For `.collect()`
use scribe_backend::test_helpers; // Assuming setup_test_app is here
use tower::ServiceExt; // For `.oneshot`

#[tokio::test]
#[ignore] // Added ignore for CI
async fn health_check_works() {
    // Arrange
    // Use the test helper to get an app instance with the router
    let context = test_helpers::setup_test_app().await;
    let app = context.app; // Get the TestApp containing the router

    // Build the request directly for the router
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/health") // Use relative path for oneshot
        .body(Body::empty())
        .expect("Failed to build request");

    // Act
    // Send the request directly to the router using oneshot
    let response = app.router.oneshot(request).await.expect("Failed to execute request.");

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_text = String::from_utf8(body_bytes.to_vec()).expect("Response not UTF-8");
    // Check the body content (e.g., parsing JSON)
    let json: serde_json::Value = serde_json::from_str(&body_text).expect("Failed to parse JSON");
    assert_eq!(json["status"], "ok");
}
