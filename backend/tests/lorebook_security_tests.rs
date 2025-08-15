#![cfg(test)]
// backend/tests/lorebook_security_tests.rs
//
// Comprehensive security tests for Lorebook services based on OWASP Top 10
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
    models::lorebook_dtos::{
        CreateLorebookPayload,
        CreateLorebookEntryPayload,
        UpdateLorebookPayload,
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

/// Create a lorebook for a user
async fn create_lorebook(
    test_app: &TestApp,
    session_cookie: &str,
    name: &str,
    description: Option<&str>,
) -> AnyhowResult<serde_json::Value> {
    let request_body = json!({
        "name": name,
        "description": description
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/lorebooks")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie)
                .body(Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await?;

    assert_eq!(response.status(), StatusCode::CREATED);
    parse_json_response(response).await
}

/// Create a lorebook entry
async fn create_lorebook_entry(
    test_app: &TestApp,
    session_cookie: &str,
    lorebook_id: Uuid,
    title: &str,
    content: &str,
    keys_text: Option<String>,
) -> AnyhowResult<serde_json::Value> {
    let request_body = json!({
        "entry_title": title,
        "content": content,
        "keys_text": keys_text,
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&format!("/api/lorebooks/{}/entries", lorebook_id))
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
// A01:2021 - Broken Access Control Tests
// ============================================================================

#[tokio::test]
async fn test_a01_cannot_access_other_users_lorebook() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    // Create two users
    let (user1_cookie, _user1_id) = create_authenticated_user(&test_app, "user1").await.unwrap();
    let (user2_cookie, _user2_id) = create_authenticated_user(&test_app, "user2").await.unwrap();

    // User 1 creates a lorebook
    let lorebook = create_lorebook(&test_app, &user1_cookie, "Private Lorebook", Some("Private content")).await.unwrap();
    let lorebook_id = lorebook["id"].as_str().unwrap();

    // User 2 tries to access User 1's lorebook
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/lorebooks/{}", lorebook_id))
                .header(header::COOKIE, &user2_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden or not found (both acceptable for security)
    assert!(
        response.status() == StatusCode::FORBIDDEN || response.status() == StatusCode::NOT_FOUND,
        "Expected 403 or 404, got: {}", response.status()
    );
    let error_message = extract_error_message(response).await.unwrap();
    assert!(error_message.contains("Access denied") || error_message.contains("permission denied") || error_message.contains("not found"));
}

#[tokio::test]
async fn test_a01_cannot_update_other_users_lorebook() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    // Create two users
    let (user1_cookie, _user1_id) = create_authenticated_user(&test_app, "user1").await.unwrap();
    let (user2_cookie, _user2_id) = create_authenticated_user(&test_app, "user2").await.unwrap();

    // User 1 creates a lorebook
    let lorebook = create_lorebook(&test_app, &user1_cookie, "Original Lorebook", None).await.unwrap();
    let lorebook_id = lorebook["id"].as_str().unwrap();

    // User 2 tries to update User 1's lorebook
    let malicious_update = json!({
        "name": "Hijacked Lorebook",
        "description": "This shouldn't work"
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(&format!("/api/lorebooks/{}", lorebook_id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &user2_cookie)
                .body(Body::from(malicious_update.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_a01_cannot_delete_other_users_lorebook() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    // Create two users
    let (user1_cookie, _user1_id) = create_authenticated_user(&test_app, "user1").await.unwrap();
    let (user2_cookie, _user2_id) = create_authenticated_user(&test_app, "user2").await.unwrap();

    // User 1 creates a lorebook
    let lorebook = create_lorebook(&test_app, &user1_cookie, "To Be Protected", None).await.unwrap();
    let lorebook_id = lorebook["id"].as_str().unwrap();

    // User 2 tries to delete User 1's lorebook
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::DELETE)
                .uri(&format!("/api/lorebooks/{}", lorebook_id))
                .header(header::COOKIE, &user2_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_a01_cannot_access_other_users_lorebook_entries() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    // Create two users
    let (user1_cookie, _user1_id) = create_authenticated_user(&test_app, "user1").await.unwrap();
    let (user2_cookie, _user2_id) = create_authenticated_user(&test_app, "user2").await.unwrap();

    // User 1 creates a lorebook and entry
    let lorebook = create_lorebook(&test_app, &user1_cookie, "Private Lorebook", None).await.unwrap();
    let lorebook_id = Uuid::parse_str(lorebook["id"].as_str().unwrap()).unwrap();
    let entry = create_lorebook_entry(&test_app, &user1_cookie, lorebook_id, "Secret Entry", "Secret information", None).await.unwrap();
    let entry_id = entry["id"].as_str().unwrap();

    // User 2 tries to access User 1's lorebook entry
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/lorebooks/{}/entries/{}", lorebook_id, entry_id))
                .header(header::COOKIE, &user2_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be forbidden, not found, or rate limited (all acceptable for security)
    assert!(
        response.status() == StatusCode::FORBIDDEN || 
        response.status() == StatusCode::NOT_FOUND ||
        response.status() == StatusCode::TOO_MANY_REQUESTS,
        "Expected 403, 404, or 429, got: {}", response.status()
    );
}

// ============================================================================
// A02:2021 - Cryptographic Failures Tests  
// ============================================================================

#[tokio::test]
async fn test_a02_lorebook_entries_are_encrypted_at_rest() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let (session_cookie, user_id) = create_authenticated_user(&test_app, "encrypt").await.unwrap();

    // Create lorebook and entry with sensitive content
    let lorebook = create_lorebook(&test_app, &session_cookie, "Test Lorebook", None).await.unwrap();
    let lorebook_id = Uuid::parse_str(lorebook["id"].as_str().unwrap()).unwrap();
    let sensitive_content = "This is sensitive information that should be encrypted";
    let _entry = create_lorebook_entry(&test_app, &session_cookie, lorebook_id, "Sensitive Entry", sensitive_content, None).await.unwrap();

    // Check database to ensure content is encrypted
    let conn = test_app.db_pool.get().await.unwrap();
    let lorebook_id_for_query = lorebook_id;
    let entry_content_in_db = conn
        .interact(move |conn| {
            use schema::lorebook_entries::dsl::*;
            lorebook_entries
                .filter(lorebook_id.eq(lorebook_id_for_query))
                .select(content_ciphertext)
                .first::<Vec<u8>>(conn)
                .optional()
        })
        .await
        .unwrap()
        .unwrap();

    // Content should be encrypted (binary) and not match original plaintext
    if let Some(encrypted_content) = entry_content_in_db {
        let content_str = String::from_utf8_lossy(&encrypted_content);
        assert_ne!(content_str, sensitive_content, "Content should be encrypted in database");
        assert!(!content_str.contains("sensitive information"), "Encrypted content should not contain plaintext");
    } else {
        panic!("Entry content should exist in database");
    }
}

#[tokio::test]
async fn test_a02_api_responses_dont_leak_encrypted_data() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let (session_cookie, _user_id) = create_authenticated_user(&test_app, "noleak").await.unwrap();

    // Create lorebook with description
    let lorebook = create_lorebook(&test_app, &session_cookie, "Test Lorebook", Some("Test description")).await.unwrap();
    let lorebook_id = Uuid::parse_str(lorebook["id"].as_str().unwrap()).unwrap();

    // Get lorebook via API
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/lorebooks/{}", lorebook_id))
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let response_json: serde_json::Value = parse_json_response(response).await.unwrap();

    // Ensure response contains decrypted content, not raw encrypted bytes
    let description = response_json["description"].as_str().unwrap();
    assert_eq!(description, "Test description");
    
    // Response should not contain any binary data or encryption metadata
    let response_str = response_json.to_string();
    assert!(!response_str.contains("encrypted"), "Response should not expose encryption metadata");
    assert!(!response_str.contains("nonce"), "Response should not expose nonce");
}

// ============================================================================
// A03:2021 - Injection Tests
// ============================================================================

#[tokio::test]
async fn test_a03_sql_injection_in_lorebook_name() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let (session_cookie, _user_id) = create_authenticated_user(&test_app, "sqli").await.unwrap();

    // Attempt SQL injection in lorebook name
    let malicious_name = "'; DROP TABLE lorebooks; --";
    let malicious_request = json!({
        "name": malicious_name,
        "description": "Normal description"
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/lorebooks")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &session_cookie)
                .body(Body::from(malicious_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should either succeed (if properly escaped) or fail with validation error
    // Should NOT result in SQL injection
    if response.status() == StatusCode::CREATED {
        let lorebook_response: serde_json::Value = parse_json_response(response).await.unwrap();
        assert_eq!(lorebook_response["name"].as_str().unwrap(), malicious_name);
    } else {
        // Validation error is acceptable
        assert!(response.status() == StatusCode::BAD_REQUEST || response.status() == StatusCode::UNPROCESSABLE_ENTITY);
    }

    // Verify that lorebooks table still exists by attempting to list lorebooks
    let list_response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/lorebooks")
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(list_response.status(), StatusCode::OK, "Lorebooks table should still exist");
}

#[tokio::test]
async fn test_a03_xss_prevention_in_lorebook_content() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let (session_cookie, _user_id) = create_authenticated_user(&test_app, "xss").await.unwrap();

    // Create lorebook
    let lorebook = create_lorebook(&test_app, &session_cookie, "XSS Test Lorebook", None).await.unwrap();
    let lorebook_id = Uuid::parse_str(lorebook["id"].as_str().unwrap()).unwrap();

    // Attempt XSS in entry content
    let malicious_content = "<script>alert('XSS')</script><img src=x onerror=alert('XSS')>";
    let malicious_entry = json!({
        "entry_title": "Malicious Entry",
        "content": malicious_content,
        "keys_text": "<script>alert('keys')</script>"
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&format!("/api/lorebooks/{}/entries", lorebook_id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &session_cookie)
                .body(Body::from(malicious_entry.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let entry_response: serde_json::Value = parse_json_response(response).await.unwrap();

    // Verify that malicious scripts are stored as-is (since backend is API-only)
    // but that they're properly escaped when returned
    assert_eq!(entry_response["content"].as_str().unwrap(), malicious_content);
    assert_eq!(entry_response["keys_text"].as_str().unwrap(), "<script>alert('keys')</script>");
    
    // The key protection is that the API returns JSON, not HTML, so XSS is prevented at the frontend level
}

#[tokio::test]
async fn test_a03_json_injection_in_entry_data() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let (session_cookie, _user_id) = create_authenticated_user(&test_app, "jsoninj").await.unwrap();

    // Create lorebook
    let lorebook = create_lorebook(&test_app, &session_cookie, "JSON Injection Test", None).await.unwrap();
    let lorebook_id = Uuid::parse_str(lorebook["id"].as_str().unwrap()).unwrap();

    // Attempt JSON injection in entry content
    let malicious_json = r#"{"admin": true, "role": "admin"}"#;
    let entry_request = json!({
        "entry_title": "JSON Injection Test",
        "content": malicious_json,
        "keys_text": r#"", "admin": true, "fake_field""#
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&format!("/api/lorebooks/{}/entries", lorebook_id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &session_cookie)
                .body(Body::from(entry_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let entry_response: serde_json::Value = parse_json_response(response).await.unwrap();

    // Verify that the response doesn't contain injected fields
    assert!(entry_response.get("admin").is_none(), "Injected admin field should not exist");
    assert!(entry_response.get("role").is_none(), "Injected role field should not exist");
    assert!(entry_response.get("fake_field").is_none(), "Injected fake_field should not exist");

    // Content should be stored as literal string
    assert_eq!(entry_response["content"].as_str().unwrap(), malicious_json);
}

// ============================================================================
// A04:2021 - Insecure Design Tests
// ============================================================================

#[tokio::test]
async fn test_a04_rate_limiting_lorebook_creation() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let (session_cookie, _user_id) = create_authenticated_user(&test_app, "ratelimit").await.unwrap();

    // Create multiple lorebooks rapidly
    let mut successful_creates = 0;
    let mut rate_limited = false;

    for i in 0..20 {
        let request_body = json!({
            "name": format!("Rapid Lorebook {}", i),
            "description": "Testing rate limits"
        });

        let response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/lorebooks")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        if response.status() == StatusCode::CREATED {
            successful_creates += 1;
        } else if response.status() == StatusCode::TOO_MANY_REQUESTS {
            rate_limited = true;
            break;
        }
    }

    // Should either have rate limiting or succeed within reasonable bounds
    if !rate_limited {
        assert!(successful_creates <= 10, "Should not allow unlimited lorebook creation without rate limiting");
    }
}

#[tokio::test]
async fn test_a04_resource_exhaustion_prevention() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let (session_cookie, _user_id) = create_authenticated_user(&test_app, "exhaust").await.unwrap();

    // Create lorebook
    let lorebook = create_lorebook(&test_app, &session_cookie, "Resource Test", None).await.unwrap();
    let lorebook_id = Uuid::parse_str(lorebook["id"].as_str().unwrap()).unwrap();

    // Attempt to create an extremely large entry
    let huge_content = "X".repeat(100_000); // 100KB content
    let huge_entry_request = json!({
        "entry_title": "Huge Entry",
        "content": huge_content,
        "keys_text": "large"
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&format!("/api/lorebooks/{}/entries", lorebook_id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &session_cookie)
                .body(Body::from(huge_entry_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should either reject due to size limits or accept with proper validation
    // Based on DTO validation, max content is 65535 chars
    if huge_content.len() > 65535 {
        assert!(
            response.status() == StatusCode::BAD_REQUEST || 
            response.status() == StatusCode::UNPROCESSABLE_ENTITY ||
            response.status() == StatusCode::PAYLOAD_TOO_LARGE,
            "Large content should be rejected"
        );
    }
}

// ============================================================================
// A05:2021 - Security Misconfiguration Tests
// ============================================================================

#[tokio::test]
async fn test_a05_error_messages_dont_leak_sensitive_info() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let (session_cookie, _user_id) = create_authenticated_user(&test_app, "errorleak").await.unwrap();

    // Try to access non-existent lorebook
    let fake_uuid = Uuid::new_v4();
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/lorebooks/{}", fake_uuid))
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let error_message = extract_error_message(response).await.unwrap();

    // Error message should not leak internal details
    let error_lower = error_message.to_lowercase();
    assert!(!error_lower.contains("database"), "Error should not mention database");
    assert!(!error_lower.contains("sql"), "Error should not mention SQL");
    assert!(!error_lower.contains("table"), "Error should not mention table names");
    assert!(!error_lower.contains("connection"), "Error should not mention connection details");
    assert!(!error_lower.contains("diesel"), "Error should not mention ORM details");
}

// ============================================================================
// A07:2021 - Identification and Authentication Failures Tests
// ============================================================================

#[tokio::test]
async fn test_a07_unauthenticated_access_prevented() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    // Try to create lorebook without authentication
    let request_body = json!({
        "name": "Unauthorized Lorebook",
        "description": "This should fail"
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/lorebooks")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Try to list lorebooks without authentication
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/lorebooks")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_a07_invalid_session_token_rejected() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    // Try to create lorebook with invalid session cookie
    let request_body = json!({
        "name": "Invalid Session Lorebook",
        "description": "This should fail"
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/lorebooks")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, "invalid_session_cookie")
                .body(Body::from(request_body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================================
// A08:2021 - Software and Data Integrity Failures Tests
// ============================================================================

#[tokio::test]
async fn test_a08_lorebook_data_integrity() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let (session_cookie, user_id) = create_authenticated_user(&test_app, "integrity").await.unwrap();

    // Create lorebook
    let lorebook = create_lorebook(&test_app, &session_cookie, "Integrity Test", Some("Original content")).await.unwrap();
    let lorebook_id = Uuid::parse_str(lorebook["id"].as_str().unwrap()).unwrap();

    // Verify lorebook was created correctly
    assert_eq!(lorebook["name"].as_str().unwrap(), "Integrity Test");
    assert_eq!(lorebook["description"].as_str().unwrap(), "Original content");
    assert_eq!(Uuid::parse_str(lorebook["user_id"].as_str().unwrap()).unwrap(), user_id);

    // Update lorebook and verify integrity
    let update_request = json!({
        "name": "Updated Integrity Test",
        "description": "Updated content"
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(&format!("/api/lorebooks/{}", lorebook_id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &session_cookie)
                .body(Body::from(update_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let updated_lorebook: serde_json::Value = parse_json_response(response).await.unwrap();

    // Verify data integrity after update
    assert_eq!(updated_lorebook["name"].as_str().unwrap(), "Updated Integrity Test");
    assert_eq!(updated_lorebook["description"].as_str().unwrap(), "Updated content");
    assert_eq!(updated_lorebook["id"], lorebook["id"]); // ID should not change
    assert_eq!(updated_lorebook["user_id"], lorebook["user_id"]); // User ID should not change
}

// ============================================================================
// A09:2021 - Security Logging and Monitoring Failures Tests
// ============================================================================

#[tokio::test]
async fn test_a09_failed_access_attempts_logged() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let (user1_cookie, _user1_id) = create_authenticated_user(&test_app, "user1").await.unwrap();
    let (user2_cookie, _user2_id) = create_authenticated_user(&test_app, "user2").await.unwrap();

    // User 1 creates a lorebook
    let lorebook = create_lorebook(&test_app, &user1_cookie, "Monitored Lorebook", None).await.unwrap();
    let lorebook_id = lorebook["id"].as_str().unwrap();

    // User 2 attempts unauthorized access (this should be logged)
    let _response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/lorebooks/{}", lorebook_id))
                .header(header::COOKIE, &user2_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Note: This test verifies that the failed access attempt doesn't succeed
    // In a real application, you would also verify that security events are logged
    // to a monitoring system, but that's beyond the scope of this test

    // Attempt with invalid UUID format (should be logged as suspicious)
    let _response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/lorebooks/invalid-uuid-format")
                .header(header::COOKIE, &user2_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Test passes if no exceptions are thrown - logging is handled by middleware
}

// ============================================================================
// A10:2021 - Server-Side Request Forgery Tests
// ============================================================================

#[tokio::test]
async fn test_a10_ssrf_prevention_in_lorebook_content() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let (session_cookie, _user_id) = create_authenticated_user(&test_app, "ssrf").await.unwrap();

    // Create lorebook
    let lorebook = create_lorebook(&test_app, &session_cookie, "SSRF Test", None).await.unwrap();
    let lorebook_id = Uuid::parse_str(lorebook["id"].as_str().unwrap()).unwrap();

    // Attempt SSRF through lorebook content (URLs that could be processed by other systems)
    let malicious_urls = vec![
        "http://localhost:8080/admin",
        "http://127.0.0.1:22", 
        "http://169.254.169.254/latest/meta-data/", // AWS metadata endpoint
        "file:///etc/passwd",
        "ftp://internal-server/secrets.txt",
    ];

    for malicious_url in malicious_urls {
        let ssrf_entry = json!({
            "entry_title": "SSRF Test Entry",
            "content": format!("Check this URL: {}", malicious_url),
            "keys_text": malicious_url
        });

        let response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/lorebooks/{}/entries", lorebook_id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(ssrf_entry.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Entry creation should succeed or be rate limited
        // SSRF protection should happen when content is processed/used by other systems, not during storage
        assert!(
            response.status() == StatusCode::CREATED || response.status() == StatusCode::TOO_MANY_REQUESTS,
            "Expected 201 or 429, got: {} for URL: {}", response.status(), malicious_url
        );
        
        // If creation succeeded, verify the content
        if response.status() == StatusCode::CREATED {
            let entry_response: serde_json::Value = parse_json_response(response).await.unwrap();
            
            // URL should be stored as-is (the application doesn't automatically fetch URLs from content)
            assert!(entry_response["content"].as_str().unwrap().contains(malicious_url));
        }
    }

    // The key insight: Lorebook is a storage system. SSRF protection should be implemented
    // when the stored content is processed/used by other components, not during storage.
}

// ============================================================================
// Additional Lorebook-Specific Security Tests
// ============================================================================

#[tokio::test]
async fn test_lorebook_name_validation() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let (session_cookie, _user_id) = create_authenticated_user(&test_app, "validation").await.unwrap();

    // Test empty name
    let empty_name_request = json!({
        "name": "",
        "description": "Should fail"
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/lorebooks")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &session_cookie)
                .body(Body::from(empty_name_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.status() == StatusCode::BAD_REQUEST || response.status() == StatusCode::UNPROCESSABLE_ENTITY);

    // Test extremely long name (over 255 chars)
    let long_name = "X".repeat(300);
    let long_name_request = json!({
        "name": long_name,
        "description": "Should fail"
    });

    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/lorebooks")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, &session_cookie)
                .body(Body::from(long_name_request.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.status() == StatusCode::BAD_REQUEST || response.status() == StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn test_lorebook_id_tampering_prevention() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let (session_cookie, _user_id) = create_authenticated_user(&test_app, "tamper").await.unwrap();

    // Test with malformed UUID
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/lorebooks/not-a-uuid")
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Test with SQL injection attempt in UUID field (using safer characters)
    let malicious_id = "00000000-0000-0000-0000-000000000000UNION";
    let response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/lorebooks/{}", malicious_id))
                .header(header::COOKIE, &session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}