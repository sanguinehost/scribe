#![cfg(feature = "postgres-backend")]
#![cfg(test)]
// tests/token_auth_security_tests.rs
//! Comprehensive JWT Token Authentication Security Tests
//!
//! These tests verify the security of our JWT token implementation following OWASP Top 10 2021 guidelines.
//! Tests cover token generation, validation, refresh, bearer extraction, and attack mitigation.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use scribe_backend::test_helpers;
use serde_json::json;
use std::time::Duration;
use tower::ServiceExt;
use tracing::info;
use uuid::Uuid;

/// Helper to extract token from JSON response
async fn extract_token_from_response(body: Body) -> Result<serde_json::Value, String> {
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|e| format!("Failed to read response body: {}", e))?;

    serde_json::from_slice(&bytes).map_err(|e| format!("Failed to parse token response: {}", e))
}

// ==================== TOKEN GENERATION & VALIDATION TESTS ====================

#[tokio::test]
async fn test_token_generation_creates_valid_jwt() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut test_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone(), None);

    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "test_token_gen_user".to_string(),
        "pass123".to_string(),
    )
    .await
    .expect("Should create test user");

    test_guard.add_user(user.id);

    // Login to get tokens
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/token/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "identifier": "test_token_gen_user",
                "password": "pass123"
            })
            .to_string(),
        ))
        .unwrap();

    let login_response = test_app
        .router
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);

    let response_data = extract_token_from_response(login_response.into_body())
        .await
        .unwrap();

    // Verify tokens are present and non-empty
    assert!(
        response_data.get("access_token").is_some(),
        "Access token should be present"
    );
    assert!(
        response_data.get("refresh_token").is_some(),
        "Refresh token should be present"
    );

    let access_token = response_data["access_token"].as_str().unwrap();
    let refresh_token = response_data["refresh_token"].as_str().unwrap();

    assert!(!access_token.is_empty(), "Access token should not be empty");
    assert!(
        !refresh_token.is_empty(),
        "Refresh token should not be empty"
    );
    assert_ne!(access_token, refresh_token, "Tokens should be different");

    // Verify JWT structure (3 parts)
    let access_parts: Vec<&str> = access_token.split('.').collect();
    assert_eq!(
        access_parts.len(),
        3,
        "Access token should have 3 JWT parts"
    );

    let refresh_parts: Vec<&str> = refresh_token.split('.').collect();
    assert_eq!(
        refresh_parts.len(),
        3,
        "Refresh token should have 3 JWT parts"
    );
}

#[tokio::test]
async fn test_bearer_token_extraction_from_header() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut test_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone(), None);

    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "bearer_user".to_string(),
        "pass123".to_string(),
    )
    .await
    .expect("Should create test user");

    test_guard.add_user(user.id);

    // Login to get tokens
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/token/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "identifier": "bearer_user",
                "password": "pass123"
            })
            .to_string(),
        ))
        .unwrap();

    let login_response = test_app
        .router
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);

    let token_data = extract_token_from_response(login_response.into_body())
        .await
        .unwrap();
    let access_token = token_data["access_token"].as_str().unwrap();

    // Make authenticated request with Bearer token
    let auth_request = Request::builder()
        .method(Method::GET)
        .uri("/auth/me")
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .body(Body::empty())
        .unwrap();

    let auth_response = test_app.router.clone().oneshot(auth_request).await.unwrap();
    assert_eq!(
        auth_response.status(),
        StatusCode::OK,
        "Should accept valid Bearer token"
    );
}

#[tokio::test]
async fn test_malformed_bearer_header_is_rejected() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let _test_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone(), None);

    // Test various malformed headers
    let malformed_headers = vec![
        ("Bearer", "Missing token"),
        ("Bearer  ", "Empty token after Bearer"),
        ("Token abc123", "Wrong auth scheme"),
        ("bearer lowercase", "Lowercase bearer"),
        ("Bearer\tabc123", "Tab instead of space"),
    ];

    for (header_value, description) in malformed_headers {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/auth/me")
            .header(header::AUTHORIZATION, header_value)
            .body(Body::empty())
            .unwrap();

        let response = test_app.router.clone().oneshot(request).await.unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Should reject malformed header: {}",
            description
        );
    }
}

// ==================== TOKEN REFRESH TESTS ====================

#[tokio::test]
async fn test_refresh_token_generates_new_access_token() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut test_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone(), None);

    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "refresh_user".to_string(),
        "pass123".to_string(),
    )
    .await
    .expect("Should create test user");

    test_guard.add_user(user.id);

    // Get initial tokens
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/token/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "identifier": "refresh_user",
                "password": "pass123"
            })
            .to_string(),
        ))
        .unwrap();

    let login_response = test_app
        .router
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();
    let initial_tokens = extract_token_from_response(login_response.into_body())
        .await
        .unwrap();
    let initial_access = initial_tokens["access_token"].as_str().unwrap();
    let refresh_token = initial_tokens["refresh_token"].as_str().unwrap();

    // Wait a moment to ensure different iat
    tokio::time::sleep(Duration::from_millis(10)).await;

    // Refresh the access token
    let refresh_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/token/refresh")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "refresh_token": refresh_token
            })
            .to_string(),
        ))
        .unwrap();

    let refresh_response = test_app
        .router
        .clone()
        .oneshot(refresh_request)
        .await
        .unwrap();
    assert_eq!(
        refresh_response.status(),
        StatusCode::OK,
        "Refresh should succeed"
    );

    let refresh_data = extract_token_from_response(refresh_response.into_body())
        .await
        .unwrap();
    let new_access_token = refresh_data["access_token"].as_str().unwrap();

    assert_ne!(
        new_access_token, initial_access,
        "Should generate new access token"
    );

    // Verify new token is valid by using it
    let me_request = Request::builder()
        .method(Method::GET)
        .uri("/auth/me")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", new_access_token),
        )
        .body(Body::empty())
        .unwrap();

    let me_response = test_app.router.clone().oneshot(me_request).await.unwrap();
    assert_eq!(
        me_response.status(),
        StatusCode::OK,
        "New access token should be valid"
    );
}

#[tokio::test]
async fn test_access_token_cannot_be_used_as_refresh_token() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut test_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone(), None);

    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "wrong_refresh_user".to_string(),
        "pass123".to_string(),
    )
    .await
    .expect("Should create test user");

    test_guard.add_user(user.id);

    // Get tokens
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/token/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "identifier": "wrong_refresh_user",
                "password": "pass123"
            })
            .to_string(),
        ))
        .unwrap();

    let login_response = test_app
        .router
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();
    let token_data = extract_token_from_response(login_response.into_body())
        .await
        .unwrap();
    let access_token = token_data["access_token"].as_str().unwrap();

    // Try to use access token as refresh token
    let wrong_refresh = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/token/refresh")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "refresh_token": access_token
            })
            .to_string(),
        ))
        .unwrap();

    let response = test_app
        .router
        .clone()
        .oneshot(wrong_refresh)
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Should reject access token used as refresh token"
    );
}

// ==================== OWASP TOP 10 COMPLIANCE TESTS ====================

// A03:2021 – Injection
#[tokio::test]
async fn test_token_payload_injection_prevention() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let _test_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone(), None);

    // Try login with injection attempts in the identifier
    let injection_payloads = vec![
        ("admin' OR '1'='1", "SQL injection attempt"),
        ("{\"$ne\":null}", "NoSQL injection attempt"),
        ("<script>alert('xss')</script>", "XSS attempt"),
        ("../../../etc/passwd", "Path traversal attempt"),
        ("admin\x00additional", "Null byte injection"),
    ];

    for (payload, description) in injection_payloads {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/auth/token/login")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "identifier": payload,
                    "password": "any_password"
                })
                .to_string(),
            ))
            .unwrap();

        let response = test_app.router.clone().oneshot(request).await.unwrap();

        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "Should safely handle injection attempt: {}",
            description
        );
    }
}

// ==================== DEK SECURITY WITH TOKEN AUTH ====================

#[tokio::test]
async fn test_dek_access_with_token_authentication() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut test_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone(), None);

    // Create user with known password for DEK encryption
    let username = format!("dek_token_user_{}", Uuid::new_v4());
    let password = "test_password_123!";
    let email = format!("{}@test.com", username);

    // Create user with DEK
    let user = scribe_backend::auth::user_store::create_user_in_db(
        &test_app.db_pool,
        &username,
        &password,
        &email,
        Some(secrecy::SecretString::from("test_dek_material_".repeat(2))), // 32 bytes
    )
    .await
    .expect("Should create user with DEK");

    test_guard.add_user(user.id);

    // Login with token endpoint
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/token/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "identifier": username,
                "password": password
            })
            .to_string(),
        ))
        .unwrap();

    let login_response = test_app
        .router
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);

    let token_data = extract_token_from_response(login_response.into_body())
        .await
        .unwrap();
    let access_token = token_data["access_token"].as_str().unwrap();

    // Access protected endpoint that requires DEK
    let protected_request = Request::builder()
        .method(Method::GET)
        .uri("/auth/me")
        .header(header::AUTHORIZATION, format!("Bearer {}", access_token))
        .body(Body::empty())
        .unwrap();

    let protected_response = test_app
        .router
        .clone()
        .oneshot(protected_request)
        .await
        .unwrap();
    assert_eq!(protected_response.status(), StatusCode::OK);

    // Verify user data doesn't expose DEK
    let body = axum::body::to_bytes(protected_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let user_data: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(
        user_data.get("dek").is_none() || user_data["dek"].is_null(),
        "DEK should not be exposed in API responses"
    );
}

#[tokio::test]
async fn test_dek_isolation_between_token_sessions() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut test_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone(), None);

    // Create two users with different DEKs
    let user1_name = format!("dek_iso_user1_{}", Uuid::new_v4());
    let user2_name = format!("dek_iso_user2_{}", Uuid::new_v4());

    let user1 = scribe_backend::auth::user_store::create_user_in_db(
        &test_app.db_pool,
        &user1_name,
        "password1",
        &format!("{}@test.com", user1_name),
        Some(secrecy::SecretString::from(
            "user1_dek_material_unique123456",
        )),
    )
    .await
    .unwrap();

    let user2 = scribe_backend::auth::user_store::create_user_in_db(
        &test_app.db_pool,
        &user2_name,
        "password2",
        &format!("{}@test.com", user2_name),
        Some(secrecy::SecretString::from(
            "user2_dek_material_different456",
        )),
    )
    .await
    .unwrap();

    test_guard.add_user(user1.id);
    test_guard.add_user(user2.id);

    // Get tokens for both users
    let user1_login = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/token/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "identifier": user1_name,
                "password": "password1"
            })
            .to_string(),
        ))
        .unwrap();

    let user1_response = test_app.router.clone().oneshot(user1_login).await.unwrap();
    let user1_tokens = extract_token_from_response(user1_response.into_body())
        .await
        .unwrap();
    let user1_access = user1_tokens["access_token"].as_str().unwrap();

    let user2_login = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/token/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "identifier": user2_name,
                "password": "password2"
            })
            .to_string(),
        ))
        .unwrap();

    let user2_response = test_app.router.clone().oneshot(user2_login).await.unwrap();
    let user2_tokens = extract_token_from_response(user2_response.into_body())
        .await
        .unwrap();
    let user2_access = user2_tokens["access_token"].as_str().unwrap();

    // Verify each token can only access its own user's data
    let user1_me = Request::builder()
        .method(Method::GET)
        .uri("/auth/me")
        .header(header::AUTHORIZATION, format!("Bearer {}", user1_access))
        .body(Body::empty())
        .unwrap();

    let response1 = test_app.router.clone().oneshot(user1_me).await.unwrap();
    let body1 = axum::body::to_bytes(response1.into_body(), usize::MAX)
        .await
        .unwrap();
    let data1: serde_json::Value = serde_json::from_slice(&body1).unwrap();

    assert_eq!(data1["id"].as_str().unwrap(), user1.id.to_string());

    let user2_me = Request::builder()
        .method(Method::GET)
        .uri("/auth/me")
        .header(header::AUTHORIZATION, format!("Bearer {}", user2_access))
        .body(Body::empty())
        .unwrap();

    let response2 = test_app.router.clone().oneshot(user2_me).await.unwrap();
    let body2 = axum::body::to_bytes(response2.into_body(), usize::MAX)
        .await
        .unwrap();
    let data2: serde_json::Value = serde_json::from_slice(&body2).unwrap();

    assert_eq!(data2["id"].as_str().unwrap(), user2.id.to_string());

    // Ensure complete isolation
    assert_ne!(data1["id"], data2["id"], "Users should have different IDs");
}

// ==================== EDGE CASES & ATTACK VECTORS ====================

#[tokio::test]
async fn test_token_refresh_endpoint_security() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut test_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone(), None);

    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "refresh_sec_user".to_string(),
        "pass123".to_string(),
    )
    .await
    .expect("Should create test user");

    test_guard.add_user(user.id);

    // Get initial tokens
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/token/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "identifier": "refresh_sec_user",
                "password": "pass123"
            })
            .to_string(),
        ))
        .unwrap();

    let login_response = test_app
        .router
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();
    let token_data = extract_token_from_response(login_response.into_body())
        .await
        .unwrap();
    let access_token = token_data["access_token"].as_str().unwrap();
    let refresh_token = token_data["refresh_token"].as_str().unwrap();

    // Test 1: Refresh with access token should fail
    let wrong_refresh = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/token/refresh")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "refresh_token": access_token
            })
            .to_string(),
        ))
        .unwrap();

    let response = test_app
        .router
        .clone()
        .oneshot(wrong_refresh)
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Should reject access token as refresh token"
    );

    // Test 2: Refresh with malformed token should fail
    let malformed_refresh = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/token/refresh")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "refresh_token": "malformed.token.here"
            })
            .to_string(),
        ))
        .unwrap();

    let response = test_app
        .router
        .clone()
        .oneshot(malformed_refresh)
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "Should reject malformed refresh token"
    );

    // Test 3: Valid refresh should succeed
    let valid_refresh = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/token/refresh")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "refresh_token": refresh_token
            })
            .to_string(),
        ))
        .unwrap();

    let response = test_app
        .router
        .clone()
        .oneshot(valid_refresh)
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Valid refresh token should work"
    );

    // Verify response contains new access token
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let refresh_response: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(
        refresh_response.get("access_token").is_some(),
        "Refresh response should contain new access token"
    );
    assert_ne!(
        refresh_response["access_token"].as_str().unwrap(),
        access_token,
        "Should generate new access token"
    );
}

// ==================== COMPREHENSIVE INTEGRATION TEST ====================

#[tokio::test]
async fn test_complete_token_authentication_flow() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut test_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone(), None);

    // Step 1: Register new user
    let username = format!("complete_flow_user_{}", Uuid::new_v4());
    let password = "secure_password_123!";
    let email = format!("{}@test.com", username);

    let user = scribe_backend::auth::user_store::create_user_in_db(
        &test_app.db_pool,
        &username,
        &password,
        &email,
        None, // Let system generate DEK
    )
    .await
    .expect("Should create user");

    test_guard.add_user(user.id);
    info!("Created user: {}", user.id);

    // Step 2: Login with token endpoint
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/token/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "identifier": username,
                "password": password
            })
            .to_string(),
        ))
        .unwrap();

    let login_response = test_app
        .router
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();
    assert_eq!(
        login_response.status(),
        StatusCode::OK,
        "Login should succeed"
    );

    let initial_tokens = extract_token_from_response(login_response.into_body())
        .await
        .unwrap();
    let initial_access = initial_tokens["access_token"].as_str().unwrap();
    let initial_refresh = initial_tokens["refresh_token"].as_str().unwrap();
    info!("Received initial tokens");

    // Step 3: Access protected endpoint with access token
    let me_request = Request::builder()
        .method(Method::GET)
        .uri("/auth/me")
        .header(header::AUTHORIZATION, format!("Bearer {}", initial_access))
        .body(Body::empty())
        .unwrap();

    let me_response = test_app.router.clone().oneshot(me_request).await.unwrap();
    assert_eq!(
        me_response.status(),
        StatusCode::OK,
        "Should access protected endpoint"
    );

    let body = axum::body::to_bytes(me_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let user_data: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(user_data["username"].as_str().unwrap(), username);
    info!("Successfully accessed protected endpoint");

    // Step 4: Refresh access token
    let refresh_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/token/refresh")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "refresh_token": initial_refresh
            })
            .to_string(),
        ))
        .unwrap();

    let refresh_response = test_app
        .router
        .clone()
        .oneshot(refresh_request)
        .await
        .unwrap();
    assert_eq!(
        refresh_response.status(),
        StatusCode::OK,
        "Refresh should succeed"
    );

    let body = axum::body::to_bytes(refresh_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let refresh_data: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let new_access_token = refresh_data["access_token"].as_str().unwrap();

    assert_ne!(
        new_access_token, initial_access,
        "Should get new access token"
    );
    info!("Successfully refreshed access token");

    // Step 5: Use new access token
    let new_me_request = Request::builder()
        .method(Method::GET)
        .uri("/auth/me")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", new_access_token),
        )
        .body(Body::empty())
        .unwrap();

    let new_me_response = test_app
        .router
        .clone()
        .oneshot(new_me_request)
        .await
        .unwrap();
    assert_eq!(
        new_me_response.status(),
        StatusCode::OK,
        "New token should work"
    );
    info!("Complete flow successful");

    // Step 6: Verify old access token still works (if not expired)
    let old_token_request = Request::builder()
        .method(Method::GET)
        .uri("/auth/me")
        .header(header::AUTHORIZATION, format!("Bearer {}", initial_access))
        .body(Body::empty())
        .unwrap();

    let old_token_response = test_app
        .router
        .clone()
        .oneshot(old_token_request)
        .await
        .unwrap();
    // Old token should still work if not expired
    assert_eq!(
        old_token_response.status(),
        StatusCode::OK,
        "Old access token should still be valid until expiration"
    );
}
