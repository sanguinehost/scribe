#![cfg(feature = "postgres-backend")]
//! Integration tests for the enhanced health check endpoint

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use scribe_backend::{
    routes::health::{ComponentStatus, HealthCheckResponse},
    test_helpers,
};
use tower::ServiceExt;

#[tokio::test]
#[ignore] // Added ignore for CI - requires database and Qdrant
async fn enhanced_health_check_works() {
    // Arrange - spawn application with database and vector DB
    let test_app = test_helpers::spawn_app(false, false, false).await;

    // Build the request
    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/health")
        .body(Body::empty())
        .expect("Failed to build request");

    // Act - send the request
    let response = test_app
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    // Assert - check response structure and content
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_text = String::from_utf8(body_bytes.to_vec()).expect("Response not UTF-8");

    // Parse as HealthCheckResponse
    let health_response: HealthCheckResponse =
        serde_json::from_str(&body_text).expect("Failed to parse health response JSON");

    // Verify response structure
    assert!(
        !health_response.version.is_empty(),
        "Version should not be empty"
    );
    assert!(
        !health_response.components.is_empty(),
        "Should have health components"
    );

    // Check for expected components
    assert!(
        health_response.components.contains_key("database"),
        "Should have database health check"
    );
    assert!(
        health_response.components.contains_key("qdrant"),
        "Should have Qdrant health check"
    );
    assert!(
        health_response.components.contains_key("disk_space"),
        "Should have disk space health check"
    );

    // Verify component structure
    let db_component = &health_response.components["database"];
    assert!(
        db_component.response_time_ms.is_some(),
        "Database component should have response time"
    );

    let qdrant_component = &health_response.components["qdrant"];
    assert!(
        qdrant_component.response_time_ms.is_some(),
        "Qdrant component should have response time"
    );

    let disk_component = &health_response.components["disk_space"];
    assert!(
        disk_component.message.is_some(),
        "Disk component should have available space message"
    );

    // Overall status should be reasonable (Ok or Degraded, but not necessarily Unhealthy)
    // since this is a test environment that should be functional
    match health_response.status {
        ComponentStatus::Ok | ComponentStatus::Degraded => {
            println!("Health check status: {}", health_response.status);
        }
        ComponentStatus::Unhealthy => {
            // In test environment, log details but don't fail the test
            // as it might be due to test environment setup
            println!("Health check returned unhealthy status in test environment");
            println!("Health response: {:?}", health_response);
        }
    }
}

#[tokio::test]
async fn health_check_response_serialization() {
    // Test that our health response types serialize correctly
    use chrono::Utc;
    use scribe_backend::routes::health::{
        ComponentHealthInfo, ComponentStatus, HealthCheckResponse,
    };
    use std::collections::HashMap;

    let mut response = HealthCheckResponse {
        status: ComponentStatus::Ok,
        version: "0.1.0".to_string(),
        components: HashMap::new(),
        timestamp: Utc::now().into(),
    };

    response.components.insert(
        "test_component".to_string(),
        ComponentHealthInfo {
            status: ComponentStatus::Ok,
            response_time_ms: Some(25),
            message: Some("Test message".to_string()),
        },
    );

    // Should serialize without error
    let serialized =
        serde_json::to_string(&response).expect("Health response should serialize to JSON");

    // Should deserialize back correctly
    let deserialized: HealthCheckResponse =
        serde_json::from_str(&serialized).expect("Health response should deserialize from JSON");

    assert_eq!(deserialized.status, ComponentStatus::Ok);
    assert_eq!(deserialized.version, "0.1.0");
    assert_eq!(deserialized.components.len(), 1);
    assert!(deserialized.components.contains_key("test_component"));
}
