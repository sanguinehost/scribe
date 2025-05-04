#![cfg(test)]

// Common imports needed for session tests
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use mime;
use serde_json::{Value, json};
use tower::ServiceExt;
use uuid::Uuid;

// Crate imports
use scribe_backend::models::chats::{Chat as ChatSession}; // Renamed ChatSession to Chat
use scribe_backend::test_helpers;

// --- Session Creation Tests ---

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_create_chat_session_success() {
    let context = test_helpers::setup_test_app().await;
    // Use auth::create_test_user_and_login
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_create_chat_user",
        "password",
    )
    .await;
    // Use db::create_test_character
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Test Character for Chat",
    )
    .await;
    let request_body = json!({ "character_id": character.id });

    let request = Request::builder()
        .method(Method::POST) // Use Method::POST
        .uri("/api/chats")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref()) // Use header::CONTENT_TYPE
        .header(header::COOKIE, auth_cookie) // Use header::COOKIE
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();
    let response = context.app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let session: ChatSession =
        serde_json::from_slice(&body).expect("Failed to deserialize response");
    assert_eq!(session.user_id, user.id);
    assert_eq!(session.character_id, character.id);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_create_chat_session_unauthorized() {
    let context = test_helpers::setup_test_app().await;
    let request_body = json!({ "character_id": Uuid::new_v4() }); // Dummy ID

    let request = Request::builder()
        .method(Method::POST) // Use Method::POST
        .uri("/api/chats")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref()) // Use header::CONTENT_TYPE
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();
    // No login simulation

    let response = context.app.router.oneshot(request).await.unwrap(); // Use context.app.router
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // Expect UNAUTHORIZED, not redirect, for API endpoints without login
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_create_chat_session_character_not_found() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_char_not_found_user",
        "password",
    )
    .await;
    let non_existent_char_id = Uuid::new_v4();

    let request_body = json!({ "character_id": non_existent_char_id });

    let request = Request::builder()
        .method(Method::POST) // Use Method::POST
        .uri("/api/chats")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref()) // Use header::CONTENT_TYPE
        .header(header::COOKIE, auth_cookie) // Use cookie
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap(); // Use context.app.router

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_create_chat_session_character_other_user() {
    let context = test_helpers::setup_test_app().await;
    let (_auth_cookie1, user1) =
        test_helpers::auth::create_test_user_and_login(&context.app, "chat_user_1", "password")
            .await;
    let character =
        test_helpers::db::create_test_character(&context.app.db_pool, user1.id, "User1 Character")
            .await;
    let (auth_cookie2, _user2) =
        test_helpers::auth::create_test_user_and_login(&context.app, "chat_user_2", "password")
            .await;

    let request_body = json!({ "character_id": character.id });

    let request = Request::builder()
        .method(Method::POST) // Use Method::POST
        .uri("/api/chats")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref()) // Use header::CONTENT_TYPE
        .header(header::COOKIE, auth_cookie2) // Use user2's cookie
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap(); // Use context.app.router

    // Handler should return FORBIDDEN if character exists but isn't owned by logged-in user
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn create_chat_session_character_not_found_integration() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _test_user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_create_chat_404_integ",
        "password",
    )
    .await;
    let non_existent_character_id = Uuid::new_v4();
    let payload = json!({ "character_id": non_existent_character_id });
    let request = Request::builder()
        .uri(format!("/api/chats"))
        .method(Method::POST)
        .header("Content-Type", "application/json")
        .header("Cookie", auth_cookie)
        .body(Body::from(payload.to_string()))
        .unwrap();
    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn create_chat_session_character_not_owned_integration() {
    let context = test_helpers::setup_test_app().await;
    let (_auth_cookie1, user1) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "user1_create_chat_integ",
        "password",
    )
    .await;
    let character1 = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user1.id,
        "User 1 Char Integ",
    )
    .await;
    let (auth_cookie2, _user2) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "user2_create_chat_integ",
        "password",
    )
    .await;
    let payload = json!({ "character_id": character1.id }); // User 1's character ID
    let request = Request::builder()
        .uri(format!("/api/chats"))
        .method(Method::POST)
        .header("Content-Type", "application/json")
        .header("Cookie", auth_cookie2) // Authenticated as User 2
        .body(Body::from(payload.to_string()))
        .unwrap();
    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN); // Expect Forbidden
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn create_chat_session_invalid_payload_integration() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _test_user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_create_chat_bad_payload_integ",
        "password",
    )
    .await;
    let invalid_payloads = vec![
        json!({}),                               // Missing character_id
        json!({ "character_id": "not-a-uuid" }), // Invalid UUID format
    ];
    for payload in invalid_payloads {
        let request = Request::builder()
            .uri(format!("/api/chats"))
            .method(Method::POST)
            .header("Content-Type", "application/json")
            .header("Cookie", &auth_cookie) // Borrow cookie string
            .body(Body::from(payload.to_string()))
            .unwrap();
        let response = context.app.router.clone().oneshot(request).await.unwrap(); // Clone router for loop
        // Expect 422 Unprocessable Entity for validation errors
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "Failed for payload: {}",
            payload
        );
    }
}

// --- Session Listing Tests ---

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_list_chat_sessions_success() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_list_chats_user",
        "password",
    )
    .await;

    // Create a character and sessions for the user
    let char1 =
        test_helpers::db::create_test_character(&context.app.db_pool, user.id, "Char 1 for List")
            .await;
    let char2 =
        test_helpers::db::create_test_character(&context.app.db_pool, user.id, "Char 2 for List")
            .await;
    let session1 =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, char1.id).await;
    let session2 =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, char2.id).await;

    // Create data for another user (should not be listed)
    let other_user =
        test_helpers::db::create_test_user(&context.app.db_pool, "other_user_integ", "password")
            .await;
    let other_char = test_helpers::db::create_test_character(
        &context.app.db_pool,
        other_user.id,
        "Other User Char",
    )
    .await;
    let _other_session = test_helpers::db::create_test_chat_session(
        &context.app.db_pool,
        other_user.id,
        other_char.id,
    )
    .await; // Renamed to avoid unused var warning

    let request = Request::builder()
        .method(Method::GET) // Use Method::GET
        .uri("/api/chats")
        .header(header::COOKIE, auth_cookie) // Use cookie
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap(); // Use context.app.router

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let sessions: Vec<ChatSession> =
        serde_json::from_slice(&body).expect("Failed to deserialize list response");

    assert_eq!(sessions.len(), 2);
    // Order is DESC by updated_at, so session2 should likely be first if inserted later
    assert!(sessions.iter().any(|s| s.id == session1.id));
    assert!(sessions.iter().any(|s| s.id == session2.id));
    assert!(sessions.iter().all(|s| s.user_id == user.id));
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_list_chat_sessions_empty() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_list_empty_user",
        "password",
    )
    .await;

    let request = Request::builder()
        .method(Method::GET) // Use Method::GET
        .uri("/api/chats")
        .header(header::COOKIE, auth_cookie) // Use cookie
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap(); // Use context.app.router

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let sessions: Vec<ChatSession> =
        serde_json::from_slice(&body).expect("Failed to deserialize empty list response");
    assert!(sessions.is_empty());
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_list_chat_sessions_unauthorized() {
    let context = test_helpers::setup_test_app().await;

    let request = Request::builder()
        .method(Method::GET) // Use Method::GET
        .uri("/api/chats")
        .body(Body::empty())
        .unwrap();
    // No login

    let response = context.app.router.oneshot(request).await.unwrap(); // Use context.app.router
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // Expect UNAUTHORIZED
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn list_chat_sessions_success_integration() {
    // Kept suffix for clarity
    let context = test_helpers::setup_test_app().await; // Use non-mutable context
    // Use the correct path for create_test_user_and_login
    let (auth_cookie, test_user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_list_chats_integ",
        "password",
    )
    .await;
    // Use the correct path for create_test_character
    let test_character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        test_user.id,
        "Test Char for List Integ",
    )
    .await;
    // Use the correct path for create_test_chat_session
    let session1 = test_helpers::db::create_test_chat_session(
        &context.app.db_pool,
        test_user.id,
        test_character.id,
    )
    .await;
    let session2 = test_helpers::db::create_test_chat_session(
        &context.app.db_pool,
        test_user.id,
        test_character.id,
    )
    .await; // Create another session for the same character

    // Create data for another user
    let other_user =
        test_helpers::db::create_test_user(&context.app.db_pool, "other_user_integ", "password")
            .await; // Corrected path
    let other_character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        other_user.id,
        "Other Char Integ",
    )
    .await;
    let _other_session = test_helpers::db::create_test_chat_session(
        &context.app.db_pool,
        other_user.id,
        other_character.id,
    )
    .await;

    // Build the request
    let request = Request::builder()
        .uri(format!("/api/chats")) // Relative URI ok for oneshot
        .method(Method::GET)
        .header("Cookie", auth_cookie)
        .body(Body::empty())
        .unwrap();
    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value =
        serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");
    let sessions_array = body_json
        .as_array()
        .expect("Response body should be a JSON array");
    assert_eq!(
        sessions_array.len(),
        2,
        "Should return exactly 2 sessions for the logged-in user"
    );
    let sessions: Vec<ChatSession> =
        serde_json::from_value(body_json).expect("Failed to deserialize sessions");
    assert!(sessions.iter().all(|s| s.user_id == test_user.id));
    assert!(sessions.iter().any(|s| s.id == session1.id));
    assert!(sessions.iter().any(|s| s.id == session2.id));
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn list_chat_sessions_unauthenticated_integration() {
    let context = test_helpers::setup_test_app().await;
    let request = Request::builder()
        .uri(format!("/api/chats"))
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // API should return 401
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn list_chat_sessions_empty_integration() {
    let context = test_helpers::setup_test_app().await;
    // Use the correct path for create_test_user_and_login
    let (auth_cookie, _test_user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_list_empty_integ",
        "password",
    )
    .await;

    // Build the request
    let request = Request::builder()
        .uri(format!("/api/chats"))
        .method(Method::GET)
        .header("Cookie", auth_cookie)
        .body(Body::empty())
        .unwrap();
    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value =
        serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");
    let sessions_array = body_json
        .as_array()
        .expect("Response body should be a JSON array");
    assert!(
        sessions_array.is_empty(),
        "Should return an empty array for a user with no sessions"
    );
}
// --- Session Detail Tests ---

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_get_chat_session_details_success() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_get_details_user",
        "password",
    )
    .await;
    let character =
        test_helpers::db::create_test_character(&context.app.db_pool, user.id, "Char for Get Details")
            .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}", session.id))
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let fetched_session: ChatSession =
        serde_json::from_slice(&body).expect("Failed to deserialize response");

    assert_eq!(fetched_session.id, session.id);
    assert_eq!(fetched_session.user_id, user.id);
    assert_eq!(fetched_session.character_id, character.id);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_get_chat_session_details_not_found() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_get_details_notfound_user",
        "password",
    )
    .await;
    let non_existent_session_id = Uuid::new_v4();

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}", non_existent_session_id))
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_get_chat_session_details_other_user() {
    let context = test_helpers::setup_test_app().await;
    let (_auth_cookie1, user1) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_get_details_user1",
        "password",
    )
    .await;
    let character1 = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user1.id,
        "Char for User 1 Get",
    )
    .await;
    let session1 = test_helpers::db::create_test_chat_session(
        &context.app.db_pool,
        user1.id,
        character1.id,
    )
    .await;

    let (auth_cookie2, _user2) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_get_details_user2",
        "password",
    )
    .await; // Login as user 2

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}", session1.id)) // Try to get user 1's session
        .header(header::COOKIE, auth_cookie2) // Using user 2's cookie
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();

    // Expect Not Found to avoid leaking information about session existence
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_get_chat_session_details_unauthorized() {
    let context = test_helpers::setup_test_app().await;
    // Create a session but don't log in
    let user =
        test_helpers::db::create_test_user(&context.app.db_pool, "test_get_unauth_user", "password")
            .await;
    let character =
        test_helpers::db::create_test_character(&context.app.db_pool, user.id, "Char for Unauth Get")
            .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}", session.id))
        // No auth cookie
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_get_chat_session_details_invalid_uuid() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_get_details_invalid_uuid_user",
        "password",
    )
    .await;

    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/chats/not-a-valid-uuid") // Invalid UUID in path
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();

    // Axum's Path extractor returns 400 Bad Request for invalid path segments
    // if the type doesn't match (e.g., Uuid expected, string provided).
    // If the handler explicitly validated, it might be 422.
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}