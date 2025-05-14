#![cfg(test)]

// Common imports needed for message tests
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use serde_json; // For deserializing the response
use tower::ServiceExt;
use uuid::Uuid;

// Crate imports
use diesel::prelude::*;
use scribe_backend::{
    models::{
        characters::Character as DbCharacter,
        chats::{MessageRole, NewChat, NewMessage, Chat},
        character_card::NewCharacter,
        users::User,
    },
    schema::{characters, chat_messages, chat_sessions},
    test_helpers::{self}, // Added crypto for generate_salt
};
 // For password hashing
use mime; // For mime::APPLICATION_JSON
use serde_json::json; // For login payload
use anyhow::Context as _; // For .context() on Option/Result
use tower_cookies::Cookie; // Added for parsing cookie

// --- Tests for GET /api/chats/{id}/messages ---

#[tokio::test]
#[ignore] // Added ignore for CI
async fn get_chat_messages_success_integration() -> anyhow::Result<()> {
    unsafe { std::env::set_var("RUST_LOG", "debug"); }
    let test_app = test_helpers::spawn_app(true, false, false).await;

    // Create User A (will own the character and the chat session)
    let username_a = "test_get_msgs_integ_a";
    let password_a = "password_user_a";
    let user_a: User = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username_a.to_string(),
        password_a.to_string(),
    )
    .await
    .context("Failed to create user_a")?;

    // Create Character, owned by User A
    let new_char_a = NewCharacter {
        user_id: user_a.id, // Character now owned by user_a
        spec: "test_spec_chat_msg_integ".to_string(),
        spec_version: "1.0".to_string(),
        name: "Character A for Chat Message Integ Test (Owned by User A)".to_string(),
        visibility: Some("private".to_string()),
        created_at: Some(chrono::Utc::now()),
        updated_at: Some(chrono::Utc::now()),
        ..Default::default()
    };
    let char_a: DbCharacter = test_app.db_pool.get().await
        .context("Failed to get DB connection for char_a creation")?
        .interact(move |conn_inner| {
            diesel::insert_into(characters::table)
                .values(&new_char_a)
                .returning(DbCharacter::as_returning())
                .get_result(conn_inner)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Pool.get().interact error creating char_a: {:?}", e))??;

    // Create Session A (owned by user_a, with char_a)
    let new_session_a = NewChat {
        id: Uuid::new_v4(),
        user_id: user_a.id,
        character_id: char_a.id,
        // Aligning with chat_session_api_tests.rs test_get_chat_session_details_forbidden
        title: Some(format!("Chat Session for {} with Character {}", user_a.username, char_a.name)),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        history_management_strategy: "truncate_summary".to_string(),
        history_management_limit: 15,
        model_name: "gemini-test-model".to_string(),
        visibility: Some("private".to_string()),
    };
    let session_a: Chat = test_app.db_pool.get().await
        .context("Failed to get DB connection for session_a creation")?
        .interact(move |conn_inner| {
            diesel::insert_into(chat_sessions::table)
                .values(&new_session_a)
                .returning(Chat::as_returning())
                .get_result(conn_inner)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Pool.get().interact error creating session_a: {:?}", e))??;

    // Insert a dummy message for session_a to ensure it's not empty
    let dummy_message_content = "Initial message for session_a";
    let new_dummy_message = NewMessage {
        id: Uuid::new_v4(),
        session_id: session_a.id,
        user_id: user_a.id, // Message from user_a
        message_type: MessageRole::User, 
        content: dummy_message_content.as_bytes().to_vec(),
        content_nonce: None, // Plaintext for this test message
        role: Some("user".to_string()),
        parts: None,
        attachments: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    test_app.db_pool.get().await
        .context("Failed to get DB connection for dummy message creation")?
        .interact(move |conn_inner| {
            diesel::insert_into(chat_messages::table)
                .values(&new_dummy_message)
                .execute(conn_inner)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Pool.get().interact error creating dummy message: {:?}", e))??;

    // Arrange: User B (tries to access User A's session)
    let username_b = "test_get_messages_forbidden_user_b";
    let password_b = "password_user_b"; // Define plaintext password for User B
    let user_b: User = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username_b.to_string(),
        password_b.to_string(),
    )
    .await
    .context("Failed to create user_b")?;

    // Arrange: User B logs in
    let login_payload_b = json!({ "identifier": user_b.username.clone(), "password": password_b }); // Use plaintext password_b
    let login_request_b = Request::builder()
        .method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload_b)?))?;
    let login_response_b = test_app.router.clone().oneshot(login_request_b).await?;
    assert_eq!(login_response_b.status(), StatusCode::OK, "Login failed for user_b");
    let raw_cookie_header_b = login_response_b.headers().get(header::SET_COOKIE).context("Set-Cookie missing for B")?.to_str()?;
    let parsed_cookie_b = Cookie::parse(raw_cookie_header_b.to_string())?;
    let auth_cookie_b = format!("{}={}", parsed_cookie_b.name(), parsed_cookie_b.value());

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/chats-api/chats/{}/messages", session_a.id))
        .header(header::COOKIE, auth_cookie_b) // Use User B's cookie
        .body(Body::empty())?;

    // Act: User B tries to get messages from User A's session
    let response = test_app.router.clone().oneshot(request).await?;

    tracing::debug!("get_chat_messages_success_integration: response status = {}", response.status());

    // Assert: Check for Forbidden status
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}