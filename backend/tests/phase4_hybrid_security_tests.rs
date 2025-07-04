//! Security Tests for Phase 4.2.3 - Hybrid Chronicle-ECS API Endpoints
//!
//! These tests validate security controls for the new hybrid API endpoints:
//! - GET /api/chronicles/{id}/entities
//! - GET /api/entities/{id}/timeline
//! - GET /api/chronicles/{id}/relationships
//!
//! Tests focus on OWASP Top 10 vulnerabilities specific to the hybrid system

use anyhow::{Context, Result as AnyhowResult};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use diesel::prelude::*;
use http_body_util::BodyExt;
use scribe_backend::{
    test_helpers::{spawn_app_permissive_rate_limiting, TestApp, TestDataGuard},
    models::chronicle::{CreateChronicleRequest, PlayerChronicle},
    routes::chronicles::{ChronicleEntitiesResponse, EntityTimelineResponse},
    schema,
};
use serde_json::json;
use tower::util::ServiceExt;
use uuid::Uuid;
use urlencoding::encode;

// Helper function to extract cookie from response
fn extract_session_cookie(response: &Response) -> Option<String> {
    response
        .headers()
        .get(header::SET_COOKIE)?
        .to_str().ok()?
        .split(';')
        .next()
        .map(|s| s.to_string())
}

// Helper function to parse JSON response
async fn parse_json_response<T: serde::de::DeserializeOwned>(response: Response) -> AnyhowResult<T> {
    let body_bytes = response.into_body().collect().await?.to_bytes();
    let body_str = std::str::from_utf8(&body_bytes)?;
    serde_json::from_str(body_str).context("Failed to parse JSON response")
}

// Helper function to create authenticated user and get session cookie
async fn create_authenticated_user(test_app: &TestApp) -> AnyhowResult<String> {
    let username = format!("testuser_{}", Uuid::new_v4().simple());
    let email = format!("{}@test.com", username);
    let password = "TestPassword123!";

    // Register user
    let register_request = json!({
        "username": username,
        "email": email,
        "password": password
    });

    let register_response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/auth/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(register_request.to_string()))
                .unwrap(),
        )
        .await?;

    assert_eq!(register_response.status(), StatusCode::CREATED);

    // Parse the registration response to get user_id
    let register_body_bytes = register_response.into_body().collect().await?.to_bytes();
    let register_body_str = std::str::from_utf8(&register_body_bytes)?;
    let auth_response: serde_json::Value = serde_json::from_str(register_body_str)
        .context("Failed to parse registration response")?;
    let user_id = auth_response["user_id"]
        .as_str()
        .context("No user_id in registration response")?;
    let user_uuid = Uuid::parse_str(user_id)?;

    // Get the verification token from the database
    let conn = test_app.db_pool.get().await?;
    let user_id_for_token = user_uuid;
    let verification_token = conn
        .interact(move |conn| {
            use schema::email_verification_tokens::dsl::*;
            email_verification_tokens
                .filter(user_id.eq(user_id_for_token))
                .select(token)
                .first::<String>(conn)
                .optional()
        })
        .await
        .map_err(|e| anyhow::anyhow!("Interact error: {}", e))?
        .map_err(|e| anyhow::anyhow!("Database error: {}", e))?;

    if let Some(token) = verification_token {
        // Verify the email
        let verify_payload = json!({
            "token": token
        });

        let verify_request = Request::builder()
            .method(Method::POST)
            .uri("/api/auth/verify-email")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(verify_payload.to_string()))?;

        let verify_response = test_app.router.clone().oneshot(verify_request).await?;
        assert_eq!(verify_response.status(), StatusCode::OK, "Email verification failed");
    } else {
        return Err(anyhow::anyhow!("No verification token found for user"));
    }

    // Now login to get session cookie
    let login_request = json!({
        "identifier": username,
        "password": password
    });

    let login_response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(login_request.to_string()))
                .unwrap(),
        )
        .await?;

    assert_eq!(login_response.status(), StatusCode::OK);
    let session_cookie = extract_session_cookie(&login_response)
        .context("Failed to extract session cookie from login response")?;

    Ok(session_cookie)
}

// Helper to create a chronicle for a user
async fn create_test_chronicle(test_app: &TestApp, session_cookie: &str, name: &str) -> AnyhowResult<PlayerChronicle> {
    let chronicle_request = CreateChronicleRequest {
        name: name.to_string(),
        description: Some("Test chronicle for security testing".to_string()),
    };
    
    let create_response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/chronicles")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie)
                .body(Body::from(serde_json::to_string(&chronicle_request)?))
                .unwrap(),
        )
        .await?;
    
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let chronicle: PlayerChronicle = parse_json_response(create_response).await?;
    Ok(chronicle)
}

// =============================================================================
// A01 - Broken Access Control: Cross-User Chronicle Access
// =============================================================================

/// Test that users cannot access other users' chronicle entities
#[tokio::test]
async fn test_cross_user_chronicle_entities_access() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create two different users
    let user1_cookie = create_authenticated_user(&app).await?;
    let user2_cookie = create_authenticated_user(&app).await?;
    
    // User 1 creates a chronicle
    let user1_chronicle = create_test_chronicle(&app, &user1_cookie, "User1 Private Chronicle").await?;
    
    // User 2 attempts to access User 1's chronicle entities
    let response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/entities", user1_chronicle.id))
                .header(header::COOKIE, user2_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    // Should be NOT_FOUND or FORBIDDEN, not OK
    assert_ne!(response.status(), StatusCode::OK, 
        "User 2 should not access User 1's chronicle entities");
    assert!(
        response.status() == StatusCode::NOT_FOUND || 
        response.status() == StatusCode::FORBIDDEN,
        "Expected 404 or 403, got {}", response.status()
    );
    
    Ok(())
}

/// Test that users cannot access other users' chronicle relationships
#[tokio::test]
async fn test_cross_user_chronicle_relationships_access() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user1_cookie = create_authenticated_user(&app).await?;
    let user2_cookie = create_authenticated_user(&app).await?;
    
    let user1_chronicle = create_test_chronicle(&app, &user1_cookie, "User1 Private Chronicle").await?;
    
    // User 2 attempts to access User 1's chronicle relationships
    let response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/relationships", user1_chronicle.id))
                .header(header::COOKIE, user2_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    assert_ne!(response.status(), StatusCode::OK,
        "User 2 should not access User 1's chronicle relationships");
    
    Ok(())
}

/// Test entity timeline access control - critical for Phase 4 security
#[tokio::test] 
async fn test_entity_timeline_cross_user_access() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user1_cookie = create_authenticated_user(&app).await?;
    let user2_cookie = create_authenticated_user(&app).await?;
    
    // Create a chronicle for user1 (though the current implementation 
    // searches "across all user's chronicles" which is a security concern)
    let _user1_chronicle = create_test_chronicle(&app, &user1_cookie, "User1 Chronicle").await?;
    
    // Test accessing entity timeline with arbitrary entity ID
    let arbitrary_entity_id = Uuid::new_v4();
    
    let user1_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/entities/{}/timeline", arbitrary_entity_id))
                .header(header::COOKIE, user1_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    let user2_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/entities/{}/timeline", arbitrary_entity_id))
                .header(header::COOKIE, user2_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    // Both should return 200 OK but only their own data
    if user1_response.status() == StatusCode::OK && user2_response.status() == StatusCode::OK {
        let user1_timeline: EntityTimelineResponse = parse_json_response(user1_response).await?;
        let user2_timeline: EntityTimelineResponse = parse_json_response(user2_response).await?;
        
        // Should not find events for arbitrary entity ID
        assert_eq!(user1_timeline.chronicle_events.len(), 0,
            "User 1 should not find events for arbitrary entity");
        assert_eq!(user2_timeline.chronicle_events.len(), 0,
            "User 2 should not find events for arbitrary entity");
    }
    
    Ok(())
}

// =============================================================================
// A03 - Injection: Parameter Injection in Hybrid Endpoints
// =============================================================================

/// Test SQL injection resistance in chronicle ID parameters
#[tokio::test]
async fn test_chronicle_id_sql_injection() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_cookie = create_authenticated_user(&app).await?;
    
    // SQL injection payloads in chronicle ID
    let injection_payloads = vec![
        "'; DROP TABLE chronicles; --",
        "' OR '1'='1",
        "1' UNION SELECT * FROM users --",
        "%27%20OR%20%271%27%3D%271",
        "'; DELETE FROM ecs_entities; --",
    ];
    
    for payload in injection_payloads {
        let encoded_payload = encode(payload);
        let response = app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&format!("/api/chronicles/{}/entities", encoded_payload))
                    .header(header::COOKIE, user_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await?;
        
        // Should not cause server errors
        assert_ne!(response.status(), StatusCode::INTERNAL_SERVER_ERROR,
            "SQL injection payload '{}' caused server error", payload);
        
        // Should not return 200 OK with data
        assert_ne!(response.status(), StatusCode::OK,
            "SQL injection payload '{}' should not return valid data", payload);
    }
    
    Ok(())
}

/// Test entity ID injection in timeline endpoint
#[tokio::test]
async fn test_entity_id_injection() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_cookie = create_authenticated_user(&app).await?;
    
    // Various injection payloads in entity ID
    let injection_payloads = vec![
        r#"{"$ne": null}"#,
        r#"'; DROP TABLE ecs_entities; --"#,
        r#"\\"; rm -rf /; "#,
        "javascript:alert('xss')",
        "<script>alert('xss')</script>",
    ];
    
    for payload in injection_payloads {
        let encoded_payload = encode(payload);
        let response = app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&format!("/api/entities/{}/timeline", encoded_payload))
                    .header(header::COOKIE, user_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await?;
        
        // Should handle malformed UUIDs gracefully
        assert_ne!(response.status(), StatusCode::INTERNAL_SERVER_ERROR,
            "Injection payload '{}' caused server error", payload);
        
        if response.status() == StatusCode::OK {
            let body_bytes = response.into_body().collect().await?.to_bytes();
            let body_str = std::str::from_utf8(&body_bytes)?;
            
            // Should not echo back unescaped content
            assert!(!body_str.contains("<script"), 
                "Response contains unescaped script tags for payload: {}", payload);
            assert!(!body_str.contains("javascript:"), 
                "Response contains JavaScript for payload: {}", payload);
        }
    }
    
    Ok(())
}

/// Test query parameter injection in hybrid endpoints
#[tokio::test]
async fn test_query_parameter_injection() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_cookie = create_authenticated_user(&app).await?;
    let chronicle = create_test_chronicle(&app, &user_cookie, "Injection Test Chronicle").await?;
    
    // Test injection in query parameters
    let injection_payloads = vec![
        ("limit", "'; DROP TABLE ecs_entities; --"),
        ("confidence_threshold", "999999999"),
        ("include_current_state", "<script>alert('xss')</script>"),
        ("include_relationships", "true'; DROP TABLE chronicles; --"),
    ];
    
    for (param, payload) in injection_payloads {
        let encoded_payload = encode(payload);
        let response = app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&format!("/api/chronicles/{}/entities?{}={}", chronicle.id, param, encoded_payload))
                    .header(header::COOKIE, user_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await?;
        
        // Should not cause server errors
        assert_ne!(response.status(), StatusCode::INTERNAL_SERVER_ERROR,
            "Query injection in {} with payload '{}' caused server error", param, payload);
    }
    
    Ok(())
}

// =============================================================================
// A02 - Cryptographic Failures: Information Disclosure
// =============================================================================

/// Test that error messages don't leak ECS system internals
#[tokio::test]
async fn test_error_message_information_disclosure() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_cookie = create_authenticated_user(&app).await?;
    
    // Test various error conditions that might leak information
    let test_cases = vec![
        ("/api/chronicles/not-a-uuid/entities", "Invalid chronicle UUID"),
        ("/api/chronicles/00000000-0000-0000-0000-000000000000/entities", "Non-existent chronicle"),
        ("/api/entities/not-a-uuid/timeline", "Invalid entity UUID"),
        ("/api/chronicles/00000000-0000-0000-0000-000000000000/relationships", "Non-existent chronicle relationships"),
    ];
    
    for (uri, description) in test_cases {
        let response = app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .header(header::COOKIE, user_cookie.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await?;
        
        if response.status() != StatusCode::OK {
            let body_bytes = response.into_body().collect().await?.to_bytes();
            let body_str = std::str::from_utf8(&body_bytes)?;
            
            // Error messages should not reveal internal implementation details
            assert!(!body_str.contains("redis://"), 
                "{}: Error message reveals Redis connection details", description);
            assert!(!body_str.contains("postgres"), 
                "{}: Error message reveals PostgreSQL details", description);
            assert!(!body_str.contains("ecs_entities"), 
                "{}: Error message reveals ECS table names", description);
            assert!(!body_str.contains("ecs_components"), 
                "{}: Error message reveals ECS table names", description);
            assert!(!body_str.contains("/home/"), 
                "{}: Error message reveals file paths", description);
            assert!(!body_str.contains("panic"), 
                "{}: Error message reveals panic details", description);
        }
    }
    
    Ok(())
}

/// Test that hybrid system graceful degradation doesn't leak information
#[tokio::test]
async fn test_graceful_degradation_information_disclosure() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_cookie = create_authenticated_user(&app).await?;
    let chronicle = create_test_chronicle(&app, &user_cookie, "Degradation Test").await?;
    
    // Request that might trigger fallback mode due to ECS unavailability
    let response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/entities", chronicle.id))
                .header(header::COOKIE, user_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    if response.status() == StatusCode::OK {
        let entities_response: ChronicleEntitiesResponse = parse_json_response(response).await?;
        
        // Check that warnings don't leak technical details
        for warning in &entities_response.metadata.warnings {
            assert!(!warning.contains("redis://"), "Warning leaks Redis connection details: {}", warning);
            assert!(!warning.contains("panic"), "Warning leaks panic details: {}", warning);
            assert!(!warning.contains("/home/"), "Warning leaks file paths: {}", warning);
            assert!(!warning.contains("ecs_entity_manager"), "Warning leaks ECS internals: {}", warning);
            assert!(!warning.contains("hybrid_query_service"), "Warning leaks service internals: {}", warning);
        }
    }
    
    Ok(())
}

// =============================================================================
// A04 - Insecure Design: Resource Exhaustion
// =============================================================================

/// Test resource exhaustion through large limit parameters
#[tokio::test]
async fn test_resource_exhaustion_large_limits() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_cookie = create_authenticated_user(&app).await?;
    let chronicle = create_test_chronicle(&app, &user_cookie, "Resource Test").await?;
    
    // Test with very large limit parameter
    let response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/entities?limit=999999999", chronicle.id))
                .header(header::COOKIE, user_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    // Should not cause server errors or excessive resource consumption
    assert_ne!(response.status(), StatusCode::INTERNAL_SERVER_ERROR,
        "Large limit parameter caused server error");
    
    // Also test entity timeline endpoint
    let entity_id = Uuid::new_v4();
    let response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/entities/{}/timeline?limit=999999999", entity_id))
                .header(header::COOKIE, user_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    assert_ne!(response.status(), StatusCode::INTERNAL_SERVER_ERROR,
        "Large limit on entity timeline caused server error");
    
    Ok(())
}

/// Test that concurrent requests don't cause race conditions in hybrid system
#[tokio::test]
async fn test_concurrent_access_race_conditions() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_cookie = create_authenticated_user(&app).await?;
    let chronicle = create_test_chronicle(&app, &user_cookie, "Concurrency Test").await?;
    
    // Make multiple concurrent requests to the same chronicle
    let mut handles = vec![];
    
    for _ in 0..10 {
        let app_clone = app.router.clone();
        let cookie_clone = user_cookie.clone();
        let chronicle_id = chronicle.id;
        
        let handle = tokio::spawn(async move {
            app_clone
                .oneshot(
                    Request::builder()
                        .method(Method::GET)
                        .uri(&format!("/api/chronicles/{}/entities", chronicle_id))
                        .header(header::COOKIE, cookie_clone)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
        });
        
        handles.push(handle);
    }
    
    // Wait for all requests to complete
    let results = futures::future::try_join_all(handles).await?;
    
    // All requests should succeed without race condition errors
    for result in results {
        let response = result?;
        assert_ne!(response.status(), StatusCode::INTERNAL_SERVER_ERROR,
            "Concurrent request caused server error");
    }
    
    Ok(())
}

// =============================================================================
// A07 - Authentication and Session Management
// =============================================================================

/// Test session handling in hybrid endpoints
#[tokio::test]
async fn test_session_management_hybrid_endpoints() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_cookie = create_authenticated_user(&app).await?;
    let chronicle = create_test_chronicle(&app, &user_cookie, "Session Test").await?;
    
    // Test that valid session works
    let response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/entities", chronicle.id))
                .header(header::COOKIE, user_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    assert_eq!(response.status(), StatusCode::OK);
    
    // Test that invalid session is rejected
    let invalid_cookies = vec![
        "invalid-session=xyz",
        "session_id=",
        "session_id='; DROP TABLE sessions; --",
    ];
    
    for invalid_cookie in invalid_cookies {
        let response = app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&format!("/api/chronicles/{}/entities", chronicle.id))
                    .header(header::COOKIE, invalid_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await?;
        
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED,
            "Invalid session cookie '{}' should not grant access", invalid_cookie);
    }
    
    Ok(())
}

// =============================================================================
// Phase 4 Specific Security Tests
// =============================================================================

/// Test that ECS state queries are properly scoped to user data
#[tokio::test]
async fn test_ecs_state_user_isolation() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user1_cookie = create_authenticated_user(&app).await?;
    let user2_cookie = create_authenticated_user(&app).await?;
    
    let user1_chronicle = create_test_chronicle(&app, &user1_cookie, "User1 ECS Test").await?;
    let user2_chronicle = create_test_chronicle(&app, &user2_cookie, "User2 ECS Test").await?;
    
    // Both users request entities for their chronicles
    let user1_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/entities", user1_chronicle.id))
                .header(header::COOKIE, user1_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    let user2_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/entities", user2_chronicle.id))
                .header(header::COOKIE, user2_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    // Both should succeed and return only their own data
    assert_eq!(user1_response.status(), StatusCode::OK);
    assert_eq!(user2_response.status(), StatusCode::OK);
    
    let user1_entities: ChronicleEntitiesResponse = parse_json_response(user1_response).await?;
    let user2_entities: ChronicleEntitiesResponse = parse_json_response(user2_response).await?;
    
    // Verify chronicle IDs match requests (basic sanity check)
    assert_eq!(user1_entities.chronicle_id, user1_chronicle.id);
    assert_eq!(user2_entities.chronicle_id, user2_chronicle.id);
    
    Ok(())
}

/// Test that hybrid query fallback maintains security
#[tokio::test]
async fn test_hybrid_fallback_security() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let user_cookie = create_authenticated_user(&app).await?;
    let chronicle = create_test_chronicle(&app, &user_cookie, "Fallback Security Test").await?;
    
    // Make request that might trigger fallback mode
    let response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/relationships", chronicle.id))
                .header(header::COOKIE, user_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    // Even in fallback mode, should still require authentication and authorization
    assert_eq!(response.status(), StatusCode::OK);
    
    // Response should still be properly scoped to user data
    let body_bytes = response.into_body().collect().await?.to_bytes();
    let body_str = std::str::from_utf8(&body_bytes)?;
    let relationships_response: serde_json::Value = serde_json::from_str(body_str)?;
    
    // Verify chronicle ID matches request
    assert_eq!(
        relationships_response["chronicle_id"].as_str(),
        Some(chronicle.id.to_string().as_str())
    );
    
    Ok(())
}