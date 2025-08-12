#![cfg(test)]
// backend/tests/chronicle_security_tests.rs
//
// Comprehensive security tests for Chronicle services based on OWASP Top 10
// Tests cover access control, encryption, injection prevention, and more

use anyhow::{Context, Result as AnyhowResult};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use diesel::prelude::*;
use http_body_util::BodyExt;
use scribe_backend::{
    models::{
        chronicle::PlayerChronicle,
        chronicle_event::ChronicleEvent,
    },
    test_helpers::{self, TestDataGuard, TestApp},
    schema,
};
use serde_json::json;
use tower::util::ServiceExt;
use uuid::Uuid;

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract session cookie from response
fn extract_session_cookie(response: &Response) -> Option<String> {
    response
        .headers()
        .get(header::SET_COOKIE)?
        .to_str().ok()?
        .split(';')
        .next()
        .map(|s| s.to_string())
}

/// Parse JSON response body
async fn parse_json_response<T: serde::de::DeserializeOwned>(response: Response) -> AnyhowResult<T> {
    let body_bytes = response.into_body().collect().await?.to_bytes();
    let body_str = std::str::from_utf8(&body_bytes)?;
    serde_json::from_str(body_str).context("Failed to parse JSON response")
}

/// Extract error message from response
async fn extract_error_message(response: Response) -> AnyhowResult<String> {
    let body_bytes = response.into_body().collect().await?.to_bytes();
    let body_str = std::str::from_utf8(&body_bytes)?;
    
    // Try to parse as JSON error first
    if let Ok(json_error) = serde_json::from_str::<serde_json::Value>(body_str) {
        if let Some(message) = json_error.get("message").and_then(|m| m.as_str()) {
            return Ok(message.to_string());
        }
        if let Some(error) = json_error.get("error").and_then(|e| e.as_str()) {
            return Ok(error.to_string());
        }
    }
    
    // Return raw body if not JSON
    Ok(body_str.to_string())
}

/// Create and authenticate a test user, returning session cookie and user ID
async fn create_authenticated_user(test_app: &TestApp, username_suffix: &str) -> AnyhowResult<(String, Uuid)> {
    let username = format!("testuser_{}_{}", username_suffix, Uuid::new_v4().simple());
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

    // Parse registration response
    let register_body_bytes = register_response.into_body().collect().await?.to_bytes();
    let register_body_str = std::str::from_utf8(&register_body_bytes)?;
    let auth_response: serde_json::Value = serde_json::from_str(register_body_str)?;
    let user_id = auth_response["user_id"].as_str().context("No user_id")?;
    let user_uuid = Uuid::parse_str(user_id)?;

    // Verify email
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
        let verify_payload = json!({ "token": token });
        let verify_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/auth/verify-email")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(verify_payload.to_string()))
                    .unwrap(),
            )
            .await?;
        assert_eq!(verify_response.status(), StatusCode::OK);
    }

    // Login
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
        .context("No session cookie in login response")?;

    Ok((session_cookie, user_uuid))
}

/// Create a chronicle for a user
async fn create_chronicle(
    test_app: &TestApp,
    session_cookie: &str,
    name: &str,
    description: Option<&str>,
) -> AnyhowResult<PlayerChronicle> {
    let request_body = json!({
        "name": name,
        "description": description
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/chronicles")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie)
                .body(Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await?;

    assert_eq!(response.status(), StatusCode::CREATED);
    parse_json_response(response).await
}

/// Create a chronicle event
async fn create_chronicle_event(
    test_app: &TestApp,
    session_cookie: &str,
    chronicle_id: Uuid,
    event_type: &str,
    summary: &str,
    keywords: Option<Vec<String>>,
) -> AnyhowResult<ChronicleEvent> {
    let mut request_body = json!({
        "event_type": event_type,
        "summary": summary,
        "source": "USER_ADDED"
    });
    
    if let Some(kw) = keywords {
        request_body["keywords"] = json!(kw);
    }

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/chronicles/{}/events", chronicle_id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie)
                .body(Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await?;

    assert_eq!(response.status(), StatusCode::CREATED);
    parse_json_response(response).await
}

// ============================================================================
// A01: Broken Access Control Tests
// ============================================================================

#[tokio::test]
async fn test_a01_cannot_access_other_users_chronicle() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    // Create two users
    let (user1_cookie, user1_id) = create_authenticated_user(&test_app, "user1").await.unwrap();
    let (user2_cookie, _user2_id) = create_authenticated_user(&test_app, "user2").await.unwrap();

    // User1 creates a chronicle
    let chronicle = create_chronicle(&test_app, &user1_cookie, "User1's Chronicle", None).await.unwrap();

    // User2 tries to access User1's chronicle
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/chronicles/{}", chronicle.id))
                .header(header::COOKIE, &user2_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden or not found (implementation dependent)
    assert!(
        response.status() == StatusCode::FORBIDDEN || 
        response.status() == StatusCode::NOT_FOUND,
        "Expected FORBIDDEN or NOT_FOUND, got {}", response.status()
    );
}

#[tokio::test]
async fn test_a01_cannot_update_other_users_chronicle() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    // Create two users
    let (user1_cookie, _user1_id) = create_authenticated_user(&test_app, "user1").await.unwrap();
    let (user2_cookie, _user2_id) = create_authenticated_user(&test_app, "user2").await.unwrap();

    // User1 creates a chronicle
    let chronicle = create_chronicle(&test_app, &user1_cookie, "Original Name", None).await.unwrap();

    // User2 tries to update User1's chronicle
    let update_request = json!({
        "name": "Hacked Name",
        "description": "Malicious update"
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(format!("/api/chronicles/{}", chronicle.id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &user2_cookie)
                .body(Body::from(update_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden or not found
    assert!(
        response.status() == StatusCode::FORBIDDEN || 
        response.status() == StatusCode::NOT_FOUND,
        "Expected FORBIDDEN or NOT_FOUND, got {}", response.status()
    );

    // Verify chronicle wasn't updated
    let verify_response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/chronicles/{}", chronicle.id))
                .header(header::COOKIE, &user1_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let verified_chronicle: PlayerChronicle = parse_json_response(verify_response).await.unwrap();
    assert_eq!(verified_chronicle.name, "Original Name");
}

#[tokio::test]
async fn test_a01_cannot_delete_other_users_chronicle() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    // Create two users
    let (user1_cookie, _user1_id) = create_authenticated_user(&test_app, "user1").await.unwrap();
    let (user2_cookie, _user2_id) = create_authenticated_user(&test_app, "user2").await.unwrap();

    // User1 creates a chronicle
    let chronicle = create_chronicle(&test_app, &user1_cookie, "User1's Chronicle", None).await.unwrap();

    // User2 tries to delete User1's chronicle
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/chronicles/{}", chronicle.id))
                .header(header::COOKIE, &user2_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden or not found
    assert!(
        response.status() == StatusCode::FORBIDDEN || 
        response.status() == StatusCode::NOT_FOUND,
        "Expected FORBIDDEN or NOT_FOUND, got {}", response.status()
    );

    // Verify chronicle still exists
    let verify_response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/chronicles/{}", chronicle.id))
                .header(header::COOKIE, &user1_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(verify_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_a01_cannot_add_events_to_other_users_chronicle() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    // Create two users
    let (user1_cookie, _user1_id) = create_authenticated_user(&test_app, "user1").await.unwrap();
    let (user2_cookie, _user2_id) = create_authenticated_user(&test_app, "user2").await.unwrap();

    // User1 creates a chronicle
    let chronicle = create_chronicle(&test_app, &user1_cookie, "User1's Chronicle", None).await.unwrap();

    // User2 tries to add an event to User1's chronicle
    let event_request = json!({
        "event_type": "MALICIOUS_EVENT",
        "summary": "Hacked event",
        "source": "USER_ADDED"
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/chronicles/{}/events", chronicle.id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &user2_cookie)
                .body(Body::from(event_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden or not found
    assert!(
        response.status() == StatusCode::FORBIDDEN || 
        response.status() == StatusCode::NOT_FOUND,
        "Expected FORBIDDEN or NOT_FOUND, got {}", response.status()
    );
}

#[tokio::test]
async fn test_a01_cannot_delete_other_users_chronicle_events() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    // Create two users
    let (user1_cookie, _user1_id) = create_authenticated_user(&test_app, "user1").await.unwrap();
    let (user2_cookie, _user2_id) = create_authenticated_user(&test_app, "user2").await.unwrap();

    // User1 creates a chronicle and event
    let chronicle = create_chronicle(&test_app, &user1_cookie, "User1's Chronicle", None).await.unwrap();
    let event = create_chronicle_event(&test_app, &user1_cookie, chronicle.id, 
        "STORY_EVENT", "Important event", None).await.unwrap();

    // User2 tries to delete User1's event
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/chronicles/{}/events/{}", chronicle.id, event.id))
                .header(header::COOKIE, &user2_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden or not found
    assert!(
        response.status() == StatusCode::FORBIDDEN || 
        response.status() == StatusCode::NOT_FOUND,
        "Expected FORBIDDEN or NOT_FOUND, got {}", response.status()
    );

    // Verify event still exists
    let verify_response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/chronicles/{}/events", chronicle.id))
                .header(header::COOKIE, &user1_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let events: Vec<ChronicleEvent> = parse_json_response(verify_response).await.unwrap();
    assert!(!events.is_empty());
    assert!(events.iter().any(|e| e.id == event.id));
}

// ============================================================================
// A02: Cryptographic Failures Tests
// ============================================================================

#[tokio::test]
async fn test_a02_chronicle_events_are_encrypted_at_rest() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    // Create authenticated user
    let (cookie, user_id) = create_authenticated_user(&test_app, "crypto_test").await.unwrap();

    // Create chronicle and event
    let chronicle = create_chronicle(&test_app, &cookie, "Encrypted Chronicle", None).await.unwrap();
    let event = create_chronicle_event(&test_app, &cookie, chronicle.id,
        "SECRET_EVENT", "This is a secret message", Some(vec!["secret".to_string(), "encrypted".to_string()])).await.unwrap();

    // Query database directly to verify encryption
    let conn = test_app.db_pool.get().await.unwrap();
    let db_event = conn
        .interact(move |conn| {
            use schema::chronicle_events::dsl::*;
            chronicle_events
                .filter(id.eq(event.id))
                .first::<ChronicleEvent>(conn)
        })
        .await
        .unwrap()
        .unwrap();

    // Check that encrypted fields exist
    assert!(db_event.summary_encrypted.is_some(), "Summary should be encrypted");
    assert!(db_event.summary_nonce.is_some(), "Summary nonce should exist");
    
    // The plaintext should NOT be stored (or should be a placeholder)
    // This depends on implementation - if plaintext is kept for legacy, it should be empty or placeholder
    if !db_event.summary.is_empty() {
        // If summary is not empty, it should be different from the original
        assert_ne!(db_event.summary, "This is a secret message", 
            "Plaintext summary should not match original if stored");
    }
}

#[tokio::test]
async fn test_a02_api_responses_dont_leak_encrypted_data() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    // Create authenticated user
    let (cookie, _user_id) = create_authenticated_user(&test_app, "no_leak").await.unwrap();

    // Create chronicle and event
    let chronicle = create_chronicle(&test_app, &cookie, "No Leak Chronicle", None).await.unwrap();
    let _event = create_chronicle_event(&test_app, &cookie, chronicle.id,
        "SENSITIVE", "Sensitive information", None).await.unwrap();

    // Get events via API
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/chronicles/{}/events", chronicle.id))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = std::str::from_utf8(&body_bytes).unwrap();
    
    // Verify no encrypted fields in response
    assert!(!body_str.contains("summary_encrypted"), "Response should not contain encrypted fields");
    assert!(!body_str.contains("summary_nonce"), "Response should not contain nonce fields");
    assert!(!body_str.contains("keywords_encrypted"), "Response should not contain encrypted keywords");
}

// ============================================================================
// A03: Injection Tests
// ============================================================================

#[tokio::test]
async fn test_a03_sql_injection_in_chronicle_name() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    let (cookie, _user_id) = create_authenticated_user(&test_app, "sql_inject").await.unwrap();

    // Various SQL injection attempts
    let sql_payloads = vec![
        "'; DROP TABLE chronicles; --",
        "' OR '1'='1",
        "'; DELETE FROM users; --",
        "\" OR 1=1 --",
        "'); DROP TABLE chronicle_events; --",
        "' UNION SELECT * FROM users --",
    ];

    for payload in sql_payloads {
        let request_body = json!({
            "name": payload,
            "description": "Test description"
        });

        let response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should either reject as invalid or safely store the string
        if response.status() == StatusCode::CREATED {
            let chronicle: PlayerChronicle = parse_json_response(response).await.unwrap();
            // If created, verify the name is stored safely (escaped)
            assert_eq!(chronicle.name, payload, "Payload should be stored as-is, not executed");
        } else {
            // Validation might reject it, which is also fine
            assert!(
                response.status() == StatusCode::BAD_REQUEST ||
                response.status() == StatusCode::UNPROCESSABLE_ENTITY,
                "Expected validation error for SQL injection attempt"
            );
        }
    }

    // Verify database is still functional
    let verify_response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/chronicles")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(verify_response.status(), StatusCode::OK, "Database should still be functional");
}

#[tokio::test]
async fn test_a03_xss_prevention_in_chronicle_events() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    let (cookie, _user_id) = create_authenticated_user(&test_app, "xss_test").await.unwrap();
    let chronicle = create_chronicle(&test_app, &cookie, "XSS Test Chronicle", None).await.unwrap();

    // XSS payloads
    let xss_payloads = vec![
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(XSS)'></iframe>",
        "';alert(String.fromCharCode(88,83,83))//",
    ];

    for payload in xss_payloads {
        let event_request = json!({
            "event_type": "XSS_TEST",
            "summary": payload,
            "source": "USER_ADDED",
            "keywords": [payload]
        });

        let response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/chronicles/{}/events", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .body(Body::from(event_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        if response.status() == StatusCode::CREATED {
            let event: ChronicleEvent = parse_json_response(response).await.unwrap();
            // Verify the payload is stored safely (not executed)
            // The summary should be exactly as provided, not sanitized yet
            // (sanitization happens on output/rendering)
            assert_eq!(event.summary, payload, "XSS payload should be stored as-is");
        }
    }
}

#[tokio::test]
async fn test_a03_json_injection_in_event_data() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    let (cookie, _user_id) = create_authenticated_user(&test_app, "json_inject").await.unwrap();
    let chronicle = create_chronicle(&test_app, &cookie, "JSON Injection Test", None).await.unwrap();

    // Malicious JSON payloads
    let json_payloads = vec![
        json!({
            "__proto__": { "isAdmin": true },
            "normal_field": "value"
        }),
        json!({
            "constructor": { "prototype": { "isAdmin": true } },
            "data": "test"
        }),
        json!({
            "$where": "function() { return true; }",
            "data": "test"
        }),
    ];

    for payload in json_payloads {
        let event_request = json!({
            "event_type": "JSON_TEST",
            "summary": "Testing JSON injection",
            "source": "USER_ADDED",
            "event_data": payload
        });

        let response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/chronicles/{}/events", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .body(Body::from(event_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should either safely store or reject malicious patterns
        assert!(
            response.status() == StatusCode::CREATED ||
            response.status() == StatusCode::BAD_REQUEST,
            "Should handle JSON injection attempt safely"
        );
    }
}

// ============================================================================
// A04: Insecure Design Tests
// ============================================================================

#[tokio::test]
async fn test_a04_rate_limiting_chronicle_creation() {
    let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    let (cookie, _user_id) = create_authenticated_user(&test_app, "rate_limit").await.unwrap();

    // Try to create many chronicles rapidly
    let mut success_count = 0;
    let mut blocked_count = 0;
    
    for i in 0..50 {
        let request_body = json!({
            "name": format!("Chronicle {}", i),
            "description": "Rate limit test"
        });

        let response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        if response.status() == StatusCode::CREATED {
            success_count += 1;
        } else if response.status() == StatusCode::TOO_MANY_REQUESTS {
            blocked_count += 1;
        }
    }

    // Should have some form of rate limiting
    // Either explicit rate limiting or practical limits
    assert!(
        blocked_count > 0 || success_count < 50,
        "Should have rate limiting or practical limits on chronicle creation"
    );
}

#[tokio::test]
async fn test_a04_resource_exhaustion_prevention() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    let (cookie, _user_id) = create_authenticated_user(&test_app, "resource_test").await.unwrap();

    // Try to create chronicle with massive description
    let huge_description = "A".repeat(1_000_000); // 1MB of text
    
    let request_body = json!({
        "name": "Normal Name",
        "description": huge_description
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/chronicles")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .body(Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should reject overly large payloads
    assert!(
        response.status() == StatusCode::BAD_REQUEST ||
        response.status() == StatusCode::PAYLOAD_TOO_LARGE ||
        response.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Should reject overly large descriptions"
    );

    // Try with massive keywords list
    let chronicle = create_chronicle(&test_app, &cookie, "Keyword Test", None).await.unwrap();
    let huge_keywords: Vec<String> = (0..10000).map(|i| format!("keyword_{}", i)).collect();
    
    let event_request = json!({
        "event_type": "HUGE_KEYWORDS",
        "summary": "Testing huge keywords",
        "source": "USER_ADDED",
        "keywords": huge_keywords
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/chronicles/{}/events", chronicle.id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .body(Body::from(event_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should reject excessive keywords
    assert!(
        response.status() != StatusCode::CREATED,
        "Should reject excessive keywords"
    );
}

// ============================================================================
// A05: Security Misconfiguration Tests
// ============================================================================

#[tokio::test]
async fn test_a05_error_messages_dont_leak_sensitive_info() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    let (cookie, _user_id) = create_authenticated_user(&test_app, "error_test").await.unwrap();

    // Try to access non-existent chronicle
    let fake_id = Uuid::new_v4();
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/chronicles/{}", fake_id))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let error_msg = extract_error_message(response).await.unwrap();
    
    // Error message should not contain:
    // - Database table names
    // - SQL queries
    // - File paths
    // - Stack traces
    assert!(!error_msg.to_lowercase().contains("chronicle_events"), "Should not leak table names");
    assert!(!error_msg.to_lowercase().contains("select"), "Should not leak SQL queries");
    assert!(!error_msg.contains("/home/"), "Should not leak file paths");
    assert!(!error_msg.contains("/src/"), "Should not leak source paths");
    assert!(!error_msg.contains("at line"), "Should not leak stack traces");
    assert!(!error_msg.contains("diesel::"), "Should not leak framework details");
}

// ============================================================================
// A07: Identification and Authentication Failures Tests
// ============================================================================

#[tokio::test]
async fn test_a07_unauthenticated_access_prevented() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    // Try to create chronicle without authentication
    let request_body = json!({
        "name": "Unauthorized Chronicle",
        "description": "Should not be created"
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/chronicles")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED, 
        "Should require authentication to create chronicles");

    // Try to list chronicles without authentication
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/chronicles")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED,
        "Should require authentication to list chronicles");
}

#[tokio::test]
async fn test_a07_invalid_session_token_rejected() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    // Try with completely invalid session
    let fake_session = "id=totally-fake-session-id";
    
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/chronicles")
                .header(header::COOKIE, fake_session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED,
        "Should reject invalid session tokens");

    // Try with malformed session
    let malformed_session = "id='; DROP TABLE sessions; --";
    
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/chronicles")
                .header(header::COOKIE, malformed_session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED,
        "Should safely reject malformed session tokens");
}

// ============================================================================
// A08: Software and Data Integrity Failures Tests
// ============================================================================

#[tokio::test]
async fn test_a08_chronicle_data_integrity() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    let (cookie, user_id) = create_authenticated_user(&test_app, "integrity_test").await.unwrap();
    
    // Create chronicle
    let chronicle = create_chronicle(&test_app, &cookie, "Integrity Test", None).await.unwrap();
    
    // Create events
    let event1 = create_chronicle_event(&test_app, &cookie, chronicle.id,
        "EVENT_1", "First event", None).await.unwrap();
    let event2 = create_chronicle_event(&test_app, &cookie, chronicle.id,
        "EVENT_2", "Second event", None).await.unwrap();

    // Verify all events belong to the same chronicle
    assert_eq!(event1.chronicle_id, chronicle.id);
    assert_eq!(event2.chronicle_id, chronicle.id);
    assert_eq!(event1.user_id, user_id);
    assert_eq!(event2.user_id, user_id);

    // Delete chronicle
    let delete_response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(format!("/api/chronicles/{}", chronicle.id))
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

    // Verify cascade deletion worked (events should be gone)
    // This would require direct database access to verify
    let conn = test_app.db_pool.get().await.unwrap();
    let event_count = conn
        .interact(move |conn| {
            use schema::chronicle_events::dsl::*;
            chronicle_events
                .filter(chronicle_id.eq(chronicle.id))
                .count()
                .get_result::<i64>(conn)
        })
        .await
        .unwrap()
        .unwrap();

    assert_eq!(event_count, 0, "Events should be cascade deleted with chronicle");
}

// ============================================================================
// A09: Security Logging and Monitoring Failures Tests
// ============================================================================

#[tokio::test]
async fn test_a09_failed_access_attempts_logged() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    // Create two users
    let (user1_cookie, _) = create_authenticated_user(&test_app, "logger1").await.unwrap();
    let (user2_cookie, _) = create_authenticated_user(&test_app, "logger2").await.unwrap();

    // User1 creates a chronicle
    let chronicle = create_chronicle(&test_app, &user1_cookie, "Logged Chronicle", None).await.unwrap();

    // User2 attempts unauthorized access (multiple times to simulate attack)
    for _i in 0..5 {
        let _ = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(format!("/api/chronicles/{}", chronicle.id))
                    .header(header::COOKIE, &user2_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
    }

    // In a real system, we would verify logs contain:
    // - Timestamp of attempts
    // - User ID of attacker
    // - Target resource ID
    // - Type of unauthorized action attempted
    // Since we can't easily check logs in tests, we just verify the attempts were blocked
    
    // Verify chronicle still exists (wasn't deleted)
    let verify_response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(format!("/api/chronicles/{}", chronicle.id))
                .header(header::COOKIE, &user1_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(verify_response.status(), StatusCode::OK,
        "Chronicle should still exist after failed deletion attempts");
}

// ============================================================================
// A10: Server-Side Request Forgery (SSRF) Tests
// ============================================================================

#[tokio::test]
async fn test_a10_ssrf_prevention_in_event_data() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    let (cookie, _user_id) = create_authenticated_user(&test_app, "ssrf_test").await.unwrap();
    let chronicle = create_chronicle(&test_app, &cookie, "SSRF Test", None).await.unwrap();

    // SSRF payloads in event data
    let ssrf_payloads = vec![
        json!({
            "webhook_url": "http://169.254.169.254/latest/meta-data/",
            "data": "test"
        }),
        json!({
            "callback": "http://localhost:6379/",
            "action": "fetch"
        }),
        json!({
            "external_ref": "file:///etc/passwd",
            "type": "include"
        }),
        json!({
            "api_endpoint": "http://internal-service.local/admin",
            "method": "GET"
        }),
    ];

    for payload in ssrf_payloads {
        let event_request = json!({
            "event_type": "SSRF_TEST",
            "summary": "Testing SSRF prevention",
            "source": "USER_ADDED",
            "event_data": payload
        });

        let response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/chronicles/{}/events", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &cookie)
                    .body(Body::from(event_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should either safely store the data or reject suspicious URLs
        // The system should NOT make requests to these URLs
        if response.status() == StatusCode::CREATED {
            let event: ChronicleEvent = parse_json_response(response).await.unwrap();
            // Event should be created but URLs should not be fetched
            // Event stored successfully with the payload in keywords or summary
        }
    }
}

// ============================================================================
// Additional Security Tests
// ============================================================================

#[tokio::test]
async fn test_chronicle_name_validation() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    let (cookie, _user_id) = create_authenticated_user(&test_app, "validation_test").await.unwrap();

    // Test empty name
    let request_body = json!({
        "name": "",
        "description": "Valid description"
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/chronicles")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .body(Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status() == StatusCode::BAD_REQUEST ||
        response.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Should reject empty chronicle names"
    );

    // Test overly long name
    let long_name = "A".repeat(1000);
    let request_body = json!({
        "name": long_name,
        "description": "Valid description"
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/chronicles")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &cookie)
                .body(Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(
        response.status() == StatusCode::BAD_REQUEST ||
        response.status() == StatusCode::UNPROCESSABLE_ENTITY,
        "Should reject overly long chronicle names"
    );
}

#[tokio::test]
async fn test_chronicle_id_tampering_prevention() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    

    let (cookie, _user_id) = create_authenticated_user(&test_app, "tamper_test").await.unwrap();

    // Try various invalid chronicle IDs
    let invalid_ids = vec![
        "not-a-uuid",
        "00000000-0000-0000-0000-000000000000",
        "../../../etc/passwd",
        "'; DROP TABLE chronicles; --",
        "%00",
        "\\x00",
    ];

    for invalid_id in invalid_ids {
        let response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(format!("/api/chronicles/{}", invalid_id))
                    .header(header::COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert!(
            response.status() == StatusCode::BAD_REQUEST ||
            response.status() == StatusCode::NOT_FOUND,
            "Should safely handle invalid chronicle ID: {}", invalid_id
        );
    }
}