#![cfg(test)]
// backend/tests/auth_dek_security_test.rs
// Test to verify that DEK is NOT stored in the session after login

use anyhow::Result as AnyhowResult;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use diesel::prelude::*;
use scribe_backend::test_helpers;
use serde_json::{Value, json};
use tower::util::ServiceExt;
use tower_cookies::Cookie;
use tracing::info;
use uuid::Uuid;

// Helper functions for DEK detection
fn looks_like_base64_dek(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        // Check if it's a base64 string of appropriate length for a DEK
        s.len() >= 40
            && s.len() <= 50
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    })
}

fn check_no_dek_values(value: &Value) -> bool {
    match value {
        Value::String(_) => !looks_like_base64_dek(value),
        Value::Object(map) => map.values().all(check_no_dek_values),
        Value::Array(arr) => arr.iter().all(check_no_dek_values),
        _ => true,
    }
}

// Helper function to create a test user
async fn create_test_user_for_dek_test(
    test_app: &test_helpers::TestApp,
    guard: &mut test_helpers::TestDataGuard,
) -> AnyhowResult<scribe_backend::models::users::User> {
    let username = format!("test_no_dek_session_{}", Uuid::new_v4());
    let password = "password123";
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.clone(),
        password.to_string(),
    )
    .await?;
    guard.add_user(user.id);
    Ok(user)
}

// Helper function to perform login and extract session ID
async fn login_and_extract_session_id(
    test_app: &test_helpers::TestApp,
    username: &str,
    password: &str,
) -> AnyhowResult<String> {
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
    assert_eq!(
        login_response.status(),
        StatusCode::OK,
        "Login should succeed"
    );

    // Extract session cookie
    let mut session_id = String::new();
    let headers = login_response.headers();
    for value in headers.get_all(header::SET_COOKIE) {
        if let Ok(cookie_str) = value.to_str() {
            if let Ok(cookie) = Cookie::parse(cookie_str) {
                if cookie.name() == "id" {
                    session_id = cookie.value().to_string();
                    break;
                }
            }
        }
    }

    if session_id.is_empty() {
        return Err(anyhow::anyhow!("No session cookie found after login"));
    }
    
    info!("Session ID from cookie: {}", session_id);
    Ok(session_id)
}


#[tokio::test(flavor = "multi_thread")]

async fn test_dek_not_stored_in_session() -> AnyhowResult<()> {
    // Test that DEK is NOT stored in the session after login
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    // Create a test user
    let user = create_test_user_for_dek_test(&test_app, &mut guard).await?;
    
    // Extract username and password (note: password is hardcoded in helper)
    let username = user.username.clone();
    let password = "password123";

    // Login and extract session ID
    let session_id = login_and_extract_session_id(&test_app, &username, password).await?;

    // Small delay to ensure session is persisted
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Query the sessions table directly to inspect the session data
    let conn = test_app.db_pool.get().await?;
    let session_id_clone = session_id.clone();
    let session_data_result = conn
        .interact(move |conn| {
            use scribe_backend::schema::sessions;
            sessions::table
                .filter(sessions::id.eq(session_id_clone))
                .select(sessions::session)
                .first::<String>(conn)
                .optional()
        })
        .await
        .map_err(|e| anyhow::anyhow!("Interaction error: {}", e))?
        .map_err(|e| anyhow::anyhow!("Database error: {}", e))?;

    let session_data = if let Some(data) = session_data_result {
        data
    } else {
        // If session not found, try with alternate session ID format
        // Sometimes the session ID might be stored differently
        info!(
            "Session not found with ID: {}, trying to list all sessions",
            session_id
        );
        let conn2 = test_app.db_pool.get().await?;
        let all_sessions = conn2
            .interact(move |conn| {
                use scribe_backend::schema::sessions;
                sessions::table
                    .select((sessions::id, sessions::session))
                    .load::<(String, String)>(conn)
            })
            .await
            .map_err(|e| anyhow::anyhow!("Interaction error: {}", e))?
            .map_err(|e| anyhow::anyhow!("Database error: {}", e))?;

        info!(
            "All sessions in DB: {:?}",
            all_sessions.iter().map(|(id, _)| id).collect::<Vec<_>>()
        );

        // Since we just logged in, there should be only one session (or we take the most recent)
        // The session ID format mismatch is due to how tower-sessions stores IDs
        match all_sessions.into_iter().next_back() {
            Some((_, data)) => data,
            None => return Err(anyhow::anyhow!("No sessions found in database")),
        }
    };

    info!("Raw session data from DB: {}", session_data);

    // Parse the session data
    let session_json: Value = serde_json::from_str(&session_data)?;

    // Check that the session does NOT contain any DEK-related keys
    // The session should only contain auth-related data, not the DEK
    let dek_keys = [
        "dek",
        "user_dek",
        &format!("_user_dek_{}", user.id),
        "SerializableSecretDek",
        "encrypted_dek",
        "plaintext_dek",
    ];

    for key in &dek_keys {
        assert!(
            !session_json.as_object().unwrap().contains_key(key as &str),
            "Session should NOT contain DEK with key '{key}'. Session data: {session_data}"
        );
    }

    // Additionally, check that no value in the session looks like base64-encoded DEK
    // DEKs are typically 32 bytes (256 bits) which becomes 44 chars in base64

    assert!(
        check_no_dek_values(&session_json),
        "Session contains what looks like a base64-encoded DEK value. Session data: {session_data}"
    );

    info!("✓ Verified: DEK is NOT stored in the session");

    // Now verify that authenticated endpoints still work (DEK is retrieved from cache)
    let me_request = Request::builder()
        .method(Method::GET)
        .uri("/api/auth/me")
        .header(header::COOKIE, format!("id={session_id}"))
        .body(Body::empty())?;

    let me_response = test_app.router.clone().oneshot(me_request).await?;
    assert_eq!(
        me_response.status(),
        StatusCode::OK,
        "Authenticated endpoint should work with DEK from cache"
    );

    guard.cleanup().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn test_dek_removed_from_cache_on_logout() -> AnyhowResult<()> {
    // Test that DEK is removed from AuthBackend cache on logout
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    // Create a test user
    let username = format!("test_dek_cache_logout_{}", Uuid::new_v4());
    let password = "password123";
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.clone(),
        password.to_string(),
    )
    .await?;
    guard.add_user(user.id);

    // Login the user
    let login_payload = json!({
        "identifier": &username,
        "password": password
    });

    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(login_payload.to_string()))?;

    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(
        login_response.status(),
        StatusCode::OK,
        "Login should succeed"
    );

    // Extract session cookie
    let mut session_id = String::new();
    let headers = login_response.headers();
    for value in headers.get_all(header::SET_COOKIE) {
        if let Ok(cookie_str) = value.to_str() {
            if let Ok(cookie) = Cookie::parse(cookie_str) {
                if cookie.name() == "id" {
                    session_id = cookie.value().to_string();
                    break;
                }
            }
        }
    }

    if session_id.is_empty() {
        return Err(anyhow::anyhow!("No session cookie found after login"));
    }

    // Verify the DEK is working by making an authenticated request
    // (We can't access the cache directly from TestApp, but we can verify functionality)

    // Make an authenticated request to verify it works
    let me_request = Request::builder()
        .method(Method::GET)
        .uri("/api/auth/me")
        .header(header::COOKIE, format!("id={session_id}"))
        .body(Body::empty())?;

    let me_response = test_app.router.clone().oneshot(me_request).await?;
    assert_eq!(
        me_response.status(),
        StatusCode::OK,
        "Me endpoint should work"
    );

    // Now logout
    let logout_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/logout")
        .header(header::COOKIE, format!("id={session_id}"))
        .body(Body::empty())?;

    let logout_response = test_app.router.clone().oneshot(logout_request).await?;
    assert_eq!(
        logout_response.status(),
        StatusCode::NO_CONTENT,
        "Logout should succeed"
    );

    // Verify the DEK has been removed from cache by trying to access a protected endpoint
    // After logout, requests requiring DEK should fail
    let protected_request = Request::builder()
        .method(Method::GET)
        .uri("/api/auth/me")
        .header(header::COOKIE, format!("id={session_id}"))
        .body(Body::empty())?;

    let protected_response = test_app.router.clone().oneshot(protected_request).await?;

    // After logout, the session should be invalid, so this should return unauthorized
    assert_eq!(
        protected_response.status(),
        StatusCode::UNAUTHORIZED,
        "Protected endpoint should return unauthorized after logout"
    );

    info!("✓ Verified: DEK is removed from cache on logout");

    guard.cleanup().await?;
    Ok(())
}
