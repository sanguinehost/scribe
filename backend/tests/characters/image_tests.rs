#![cfg(test)]
use super::helpers::{insert_test_character, insert_test_user_with_password, run_db_op, spawn_app};
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use reqwest::Client;
use reqwest::StatusCode as ReqwestStatusCode;
use scribe_backend::test_helpers::{TestDataGuard, ensure_tracing_initialized};
use tower::ServiceExt; // For oneshot
use uuid::Uuid;

#[tokio::test]
async fn test_get_character_image_not_implemented() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    let username = format!("get_image_user_{}", Uuid::new_v4());
    let password = "testpassword";
    let (user, dek) = run_db_op(&pool, {
        let username = username.clone();
        let password = password.to_string();
        move |conn| insert_test_user_with_password(conn, &username, &password)
    })
    .await?;
    guard.add_user(user.id);

    let user_id_for_char = user.id;
    let dek_clone = dek.clone();
    let character = run_db_op(&pool, move |conn| {
        insert_test_character(conn, user_id_for_char, "Character For Image", &dek_clone)
    })
    .await?;
    guard.add_character(character.id);

    let request = Request::builder()
        .method("GET")
        .uri(format!("/api/characters/{}/image", character.id)) // This was the original path in the test
        .body(Body::empty())?;

    let response = test_app.router.clone().oneshot(request).await?;
    let status = response.status();
    let body_bytes = to_bytes(response.into_body(), usize::MAX).await?;
    let body_text = String::from_utf8(body_bytes.to_vec())?;

    tracing::info!(status = %status, body = %body_text, "Received response from image endpoint");

    // The original test accepted UNAUTHORIZED, NOT_IMPLEMENTED, or NOT_FOUND.
    // Given the path, UNAUTHORIZED or NOT_FOUND (if auth is strict before hitting handler) are most likely.
    // If the route /api/characters/:id/image truly doesn't exist or isn't fully wired, NOT_FOUND is expected.
    // If it exists but is behind auth, UNAUTHORIZED is expected if not logged in.
    // NOT_IMPLEMENTED would imply the handler is hit and explicitly returns that.
    assert!(
        status == StatusCode::UNAUTHORIZED
            || status == StatusCode::NOT_FOUND
            || status == StatusCode::NOT_IMPLEMENTED,
        "Expected Unauthorized, Not Found, or Not Implemented, got: {} - {}",
        status,
        body_text
    );
    Ok(())
}

#[tokio::test]
async fn test_get_character_image_unauthorized() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app_state = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app_state.db_pool.clone();
    let _guard = TestDataGuard::new(pool.clone());
    let app_router = test_app_state.router;
    let server_addr = spawn_app(app_router).await;
    let client = Client::new();

    let character_id = Uuid::new_v4();
    // This path was `/api/characters/fetch/:id/image` in the original test,
    // which implies a different routing structure than the `not_implemented` test above.
    // We'll keep it as is from the original test.
    let image_url = format!(
        "http://{}/api/characters/fetch/{}/image",
        server_addr, character_id
    );

    let response = client.get(&image_url).send().await?;
    tracing::info!("Test request to URL: {}", image_url);
    tracing::info!("Response status: {}", response.status());

    // Original test expected NOT_FOUND for unauthenticated requests to this specific path.
    assert_eq!(response.status(), ReqwestStatusCode::NOT_FOUND);
    Ok(())
}
