#![cfg(test)]
// backend/tests/first_user_admin_tests.rs

use anyhow::{Context, Result as AnyhowResult};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use diesel::RunQueryDsl;
use http_body_util::BodyExt;
use scribe_backend::{auth, models::auth::AuthResponse, test_helpers};
use serde_json::json;
use tower::util::ServiceExt;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread")]
#[ignore] // Ignored for CI
async fn test_first_user_is_admin() -> AnyhowResult<()> {
    // Spawn a fresh app with an empty database
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    // Clear all users in the database to ensure we're testing with an empty user table
    let conn = test_app
        .db_pool
        .get()
        .await
        .context("Failed to get DB connection")?;
    conn.interact(|conn_actual| {
        diesel::delete(scribe_backend::schema::users::table).execute(conn_actual)
    })
    .await
    .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))?
    .context("Diesel query failed")?;

    // Check if there are no users in the database
    let conn = test_app
        .db_pool
        .get()
        .await
        .context("Failed to get DB connection")?;
    let any_users = conn
        .interact(auth::are_there_any_users)
        .await
        .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))?
        .map_err(|e| anyhow::anyhow!("Auth error: {}", e))?;

    // Assert that there are no users
    assert!(
        !any_users,
        "Database should have no users at the start of the test"
    );

    // Register the first user
    let first_username = format!("first_admin_user_{}", Uuid::new_v4());
    let first_email = format!("{first_username}@test.com");
    let password = "password123";

    let first_user_payload = json!({
        "username": first_username,
        "email": first_email,
        "password": password
    });

    let first_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(first_user_payload.to_string()))?;

    let first_response = test_app.router.clone().oneshot(first_request).await?;

    // Check that registration was successful
    assert_eq!(
        first_response.status(),
        StatusCode::CREATED,
        "First user registration failed"
    );

    let body = first_response.into_body().collect().await?.to_bytes();
    let first_auth_response: AuthResponse = serde_json::from_slice(&body)?;

    // Store first user ID for cleanup
    guard.add_user(first_auth_response.user_id);

    // Assert that the first user is an Administrator
    assert_eq!(
        first_auth_response.role, "Administrator",
        "First user should be an Administrator"
    );

    // Now register a second user
    let second_username = format!("second_user_{}", Uuid::new_v4());
    let second_email = format!("{second_username}@test.com");

    let second_user_payload = json!({
        "username": second_username,
        "email": second_email,
        "password": password
    });

    let second_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(second_user_payload.to_string()))?;

    let second_response = test_app.router.clone().oneshot(second_request).await?;

    // Check that registration was successful
    assert_eq!(
        second_response.status(),
        StatusCode::CREATED,
        "Second user registration failed"
    );

    let body = second_response.into_body().collect().await?.to_bytes();
    let second_auth_response: AuthResponse = serde_json::from_slice(&body)?;

    // Store second user ID for cleanup
    guard.add_user(second_auth_response.user_id);

    // Assert that the second user is a regular User (not an Administrator)
    assert_eq!(
        second_auth_response.role, "User",
        "Second user should be a regular User"
    );

    // Clean up
    guard.cleanup().await?;

    Ok(())
}

// Test the are_there_any_users function directly
#[tokio::test]
#[ignore] // Ignored for CI
async fn test_are_there_any_users_function() -> AnyhowResult<()> {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    // Clear all users in the database
    let conn = test_app
        .db_pool
        .get()
        .await
        .context("Failed to get DB connection")?;
    conn.interact(|conn_actual| {
        diesel::delete(scribe_backend::schema::users::table).execute(conn_actual)
    })
    .await
    .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))?
    .context("Diesel query failed")?;

    // Check if there are no users (should return false)
    let conn = test_app
        .db_pool
        .get()
        .await
        .context("Failed to get DB connection")?;
    let empty_result = conn
        .interact(auth::are_there_any_users)
        .await
        .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))?
        .map_err(|e| anyhow::anyhow!("Auth error: {}", e))?;

    assert!(
        !empty_result,
        "are_there_any_users should return false when the database is empty"
    );

    // Create a test user
    let username = format!("test_user_{}", Uuid::new_v4());
    let test_user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.clone(),
        "password123".to_string(),
    )
    .await?;

    guard.add_user(test_user.id);

    // Check if there are users (should return true)
    let conn = test_app
        .db_pool
        .get()
        .await
        .context("Failed to get DB connection")?;
    let non_empty_result = conn
        .interact(auth::are_there_any_users)
        .await
        .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))?
        .map_err(|e| anyhow::anyhow!("Auth error: {}", e))?;

    assert!(
        non_empty_result,
        "are_there_any_users should return true when there are users in the database"
    );

    // Clean up
    guard.cleanup().await?;

    Ok(())
}
