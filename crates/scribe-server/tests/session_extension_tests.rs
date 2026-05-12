#![cfg(feature = "postgres-backend")]
use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use diesel::prelude::*;
use http_body_util::BodyExt;
use scribe_backend::models::users::AccountStatus;
use scribe_backend::schema::users;
use scribe_backend::test_helpers::{spawn_app, TestDataGuard};
use serde_json::json;
use tower::ServiceExt;

/// Test that sessions are automatically extended on authenticated requests
#[tokio::test]
async fn test_session_extends_on_authenticated_requests() {
    // Spawn test app
    let test_app = spawn_app(false, false, false).await;
    let _test_guard = TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

    // Register a test user
    let register_payload = json!({
        "username": "session_test_user",
        "email": "session.test@example.com",
        "password": "SecurePassword123!"
    });

    let register_request = Request::builder()
        .method("POST")
        .uri("/api/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_string(&register_payload).unwrap(),
        ))
        .unwrap();

    let register_response = test_app
        .router
        .clone()
        .clone()
        .oneshot(register_request)
        .await
        .unwrap();
    assert_eq!(register_response.status(), StatusCode::CREATED);

    // Manually verify the email by updating account status
    let conn = test_app
        .db_pool
        .get()
        .await
        .expect("Failed to get DB connection");
    conn.interact(move |conn| {
        diesel::update(users::table.filter(users::email.eq("session.test@example.com")))
            .set(users::account_status.eq(AccountStatus::Active))
            .execute(conn)
            .expect("Failed to update account status");
    })
    .await
    .expect("Failed to interact with DB");

    // Login to create a session
    let login_payload = json!({
        "identifier": "session_test_user",
        "password": "SecurePassword123!"
    });

    let login_request = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
        .unwrap();

    let login_response = test_app
        .router
        .clone()
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);

    // Extract session cookie from login response (before consuming response)
    let cookies = login_response.headers().get_all(header::SET_COOKIE);
    let session_cookie = cookies
        .iter()
        .find(|c| c.to_str().unwrap().starts_with("id="))
        .expect("Missing session cookie")
        .to_str()
        .unwrap()
        .to_string(); // Clone the cookie string before consuming response

    // Parse login response body
    let body_bytes = login_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let login_body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
    let initial_expires_at = login_body["expires_at"]
        .as_str()
        .expect("Missing expires_at in login response");

    // Wait a moment to ensure time difference
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Make an authenticated request to trigger session extension
    let me_request = Request::builder()
        .method("GET")
        .uri("/api/auth/me")
        .header(header::COOKIE, &session_cookie)
        .body(Body::empty())
        .unwrap();

    let me_response = test_app.router.clone().oneshot(me_request).await.unwrap();
    assert_eq!(me_response.status(), StatusCode::OK);

    // Get current session to check if expiry was extended
    let session_request = Request::builder()
        .method("GET")
        .uri("/api/auth/session/current")
        .header(header::COOKIE, &session_cookie)
        .body(Body::empty())
        .unwrap();

    let session_response = test_app
        .router
        .clone()
        .clone()
        .oneshot(session_request)
        .await
        .unwrap();
    assert_eq!(session_response.status(), StatusCode::OK);

    // Parse session response
    let session_body_bytes = session_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let session_body: serde_json::Value = serde_json::from_slice(&session_body_bytes).unwrap();
    let updated_expires_at = session_body["session"]["expires_at"]
        .as_str()
        .expect("Missing expires_at in session response");

    // Parse timestamps
    let initial_time = chrono::DateTime::parse_from_rfc3339(initial_expires_at)
        .expect("Failed to parse initial expiry time");
    let updated_time = chrono::DateTime::parse_from_rfc3339(updated_expires_at)
        .expect("Failed to parse updated expiry time");

    // Verify that session expiry was extended (should be later than initial)
    assert!(
        updated_time > initial_time,
        "Session expiry should be extended after authenticated request. Initial: {}, Updated: {}",
        initial_time,
        updated_time
    );

    println!(
        "✓ Session successfully extended from {} to {}",
        initial_time, updated_time
    );
}
