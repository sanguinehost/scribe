#![cfg(test)]
// backend/tests/recovery_key_tests.rs

use anyhow::{Context, Result as AnyhowResult};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use scribe_backend::{
    models::{
        auth::AuthResponse,
        users::{User},
    },
    crypto,
    test_helpers,
};
use serde_json::{json, Value};
use uuid::Uuid;
use secrecy::{SecretString, ExposeSecret};
use tower::util::ServiceExt;
use base64::Engine;

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Ignored for CI
async fn test_recovery_key_generation_during_registration() -> AnyhowResult<()> {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    // Register a user without providing a recovery key
    let username = format!("recovery_test_{}", Uuid::new_v4());
    let email = format!("{}@test.com", username);
    let password = "password123";

    let payload = json!({
        "username": username,
        "email": email,
        "password": password
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))?;

    let response = test_app.router.clone().oneshot(request).await?;
    
    // Check that registration was successful
    assert_eq!(response.status(), StatusCode::CREATED, "Registration failed");
    
    let body = response.into_body().collect().await?.to_bytes();
    let auth_response: AuthResponse = serde_json::from_slice(&body)?;
    
    // Store user ID for cleanup
    guard.add_user(auth_response.user_id);
    
    // Assert that a recovery key was generated and returned
    assert!(auth_response.recovery_key.is_some(), "Recovery key should be automatically generated");
    let recovery_key = auth_response.recovery_key.unwrap();
    
    // Verify the recovery key is not empty
    assert!(!recovery_key.is_empty(), "Recovery key should not be empty");
    
    // Check that the recovery key is a valid base64url string
    let decode_result = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&recovery_key);
    assert!(decode_result.is_ok(), "Recovery key should be a valid base64url string");
    
    // Check that the decoded bytes are of sufficient length for security (at least 16 bytes)
    let decoded_bytes = decode_result.unwrap();
    assert!(decoded_bytes.len() >= 16, "Recovery key should decode to at least 16 bytes of random data");

    // Check that the user can login with their credentials
    let login_payload = json!({
        "identifier": username,
        "password": password
    });

    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(login_payload.to_string()))?;

    let login_response = test_app.router.clone().oneshot(login_request).await?;
    
    // Check that login is successful
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed");

    // Clean up
    guard.cleanup().await?;
    
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Ignored for CI
async fn test_provided_recovery_key_is_used() -> AnyhowResult<()> {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    // Create a custom recovery key
    let custom_recovery_key = "my-custom-recovery-phrase";
    
    // Register a user with the custom recovery key
    let username = format!("recovery_custom_{}", Uuid::new_v4());
    let email = format!("{}@test.com", username);
    let password = "password123";

    let payload = json!({
        "username": username,
        "email": email,
        "password": password,
        "recovery_phrase": custom_recovery_key
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))?;

    let response = test_app.router.clone().oneshot(request).await?;
    
    // Check that registration was successful
    assert_eq!(response.status(), StatusCode::CREATED, "Registration failed");
    
    let body = response.into_body().collect().await?.to_bytes();
    let auth_response: AuthResponse = serde_json::from_slice(&body)?;
    
    // Store user ID for cleanup
    guard.add_user(auth_response.user_id);
    
    // Assert that the provided recovery key was used and returned
    assert_eq!(auth_response.recovery_key, Some(custom_recovery_key.to_string()), 
        "The provided recovery key should be returned in the response");

    // Clean up
    guard.cleanup().await?;
    
    Ok(())
}

// Test that the DEK can be successfully decrypted with the recovery key
#[tokio::test(flavor = "multi_thread")]
#[ignore] // Ignored for CI
async fn test_recovery_key_decrypts_dek() -> AnyhowResult<()> {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    // Register a user
    let username = format!("recovery_decrypt_{}", Uuid::new_v4());
    let email = format!("{}@test.com", username);
    let password = "password123";

    let payload = json!({
        "username": username,
        "email": email,
        "password": password
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(payload.to_string()))?;

    let response = test_app.router.clone().oneshot(request).await?;
    
    // Check that registration was successful
    assert_eq!(response.status(), StatusCode::CREATED, "Registration failed");
    
    let body = response.into_body().collect().await?.to_bytes();
    let auth_response: AuthResponse = serde_json::from_slice(&body)?;
    
    // Store user ID for cleanup
    let user_id = auth_response.user_id;
    guard.add_user(user_id);
    
    // Get the generated recovery key
    let recovery_key = auth_response.recovery_key.expect("Recovery key should be generated");

    // Retrieve the user from the database to get the encryption fields
    let conn = test_app.db_pool.get().await.context("Failed to get DB connection")?;
    let user = conn.interact(move |conn_inner| {
        scribe_backend::auth::get_user(conn_inner, user_id)
    })
    .await
    .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))?
    .map_err(|e| anyhow::anyhow!("Auth error: {}", e))?;

    // Try to decrypt the DEK using the recovery key
    let recovery_kek_salt = user.recovery_kek_salt.expect("Recovery KEK salt should be set");
    let encrypted_dek_by_recovery = user.encrypted_dek_by_recovery.expect("Encrypted DEK by recovery should be set");
    let recovery_dek_nonce = user.recovery_dek_nonce.expect("Recovery DEK nonce should be set");
    
    // Derive recovery key
    let recovery_secret = SecretString::new(recovery_key.into_boxed_str());
    let recovery_kek = crypto::derive_kek(&recovery_secret, &recovery_kek_salt)
        .map_err(|e| anyhow::anyhow!("Failed to derive recovery KEK: {}", e))?;
    
    // Decrypt DEK
    let decrypted_dek = crypto::decrypt_gcm(&encrypted_dek_by_recovery, &recovery_dek_nonce, &recovery_kek)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt DEK with recovery key: {}", e))?;
    
    // Verify that the decrypted DEK is not empty
    assert!(!decrypted_dek.expose_secret().is_empty(), "Decrypted DEK should not be empty");
    
    // Verify the DEK is 32 bytes (for AES-256)
    assert_eq!(decrypted_dek.expose_secret().len(), 32, "Decrypted DEK should be 32 bytes for AES-256");

    // Clean up
    guard.cleanup().await?;
    
    Ok(())
}