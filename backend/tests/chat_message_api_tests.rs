#![cfg(test)]

// Common imports needed for message tests
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use mime; // Although not directly used in requests, often needed indirectly or for consistency
use serde_json; // For deserializing the response
use tower::ServiceExt;
use uuid::Uuid;

// Crate imports
use scribe_backend::models::chats::{ChatMessage, MessageRole};
use scribe_backend::test_helpers;

// --- Tests for GET /api/chats/{id}/messages ---

#[tokio::test]
#[ignore] // Added ignore for CI
async fn get_chat_messages_success_integration() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_get_msgs_integ",
        "password",
    )
    .await;
    let character =
        test_helpers::db::create_test_character(&context.app.db_pool, user.id, "Char for Msgs")
            .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    // Create messages for the session
    let _msg1 = test_helpers::db::create_test_chat_message(
        &context.app.db_pool,
        session.id,
        user.id,
        MessageRole::User,
        "Hello",
    )
    .await;
    let _msg2 = test_helpers::db::create_test_chat_message(
        &context.app.db_pool,
        session.id,
        user.id,
        MessageRole::Assistant,
        "Hi",
    )
    .await;

    // Create messages for another session (should not be listed)
    let other_session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;
    test_helpers::db::create_test_chat_message(
        &context.app.db_pool,
        other_session.id,
        user.id,
        MessageRole::User,
        "Other msg",
    )
    .await;

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/messages", session.id))
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let messages: Vec<ChatMessage> =
        serde_json::from_slice(&body).expect("Failed to deserialize messages");

    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].message_type, MessageRole::User);
    assert_eq!(messages[0].content, "Hello");
    assert_eq!(messages[1].message_type, MessageRole::Assistant);
    assert_eq!(messages[1].content, "Hi");
}


#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn test_get_chat_messages_unauthorized() {
    let context = test_helpers::setup_test_app().await;
    let dummy_session_id = Uuid::new_v4();

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/messages", dummy_session_id))
        .body(Body::empty())
        .unwrap();

    // Act: Make request without authentication
    let response = context.app.router.oneshot(request).await.unwrap();

    // Assert: Check for Unauthorized status
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn test_get_chat_messages_not_found() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_get_messages_not_found_user",
        "password",
    )
    .await;
    let non_existent_session_id = Uuid::new_v4();

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/messages", non_existent_session_id))
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())
        .unwrap();

    // Act: Make request for a non-existent session
    let response = context.app.router.oneshot(request).await.unwrap();

    // Assert: Check for Not Found status
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn test_get_chat_messages_forbidden() {
    let context = test_helpers::setup_test_app().await;

    // Arrange: User A creates a session
    let (_auth_cookie_a, user_a) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_get_messages_forbidden_user_a",
        "password",
    )
    .await;
    let char_a = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user_a.id,
        "User A Character",
    )
    .await;
    let session_a = test_helpers::db::create_test_chat_session(
        &context.app.db_pool,
        user_a.id,
        char_a.id,
    )
    .await;

    // Arrange: User B logs in
    let (auth_cookie_b, _user_b) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "test_get_messages_forbidden_user_b",
        "password",
    )
    .await;

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/messages", session_a.id)) // Use User A's session ID
        .header(header::COOKIE, auth_cookie_b) // Use User B's cookie
        .body(Body::empty())
        .unwrap();

    // Act: User B tries to get messages from User A's session
    let response = context.app.router.oneshot(request).await.unwrap();

    // Assert: Check for Forbidden status
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}