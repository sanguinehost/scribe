#![cfg(test)]

// Common imports needed for message tests
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
// Removed unused: use mime;
use serde_json; // For deserializing the response
use tower::ServiceExt;
use uuid::Uuid;

// Crate imports
use diesel::prelude::*;
use scribe_backend::{
    models::{
        auth::LoginPayload,
        characters::Character as DbCharacter,
        chats::{MessageResponse, MessageRole, NewChat, NewMessage, ChatMessage},
        character_card::NewCharacter,
        chats::ChatSession,
        users::{NewUser, User},
    },
    schema::{characters, chat_messages, chat_sessions, users},
    test_helpers::{self, TestApp},
};
use bcrypt; // For password hashing
use mime; // For mime::APPLICATION_JSON
use serde_json::json; // For login payload
use anyhow::Context as _; // For .context() on Option/Result
use tower_cookies::Cookie; // Added for parsing cookie

// --- Tests for GET /api/chats/{id}/messages ---

#[tokio::test]
#[ignore] // Added ignore for CI
async fn get_chat_messages_success_integration() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().await.context("Failed to get DB connection")?;

    // Create User
    let username = "test_get_msgs_integ";
    let password = "password";
    let hashed_password = bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .context("Failed to hash password")?;
    
    let new_user = NewUser {
        username: username.to_string(),
        email: Some(format!("{}@example.com", username)),
        password_hash: hashed_password,
        data_encryption_key_hash: None,
        salt: None,
        nonce: None,
        dek_details: None,
    };
    let user: User = diesel::insert_into(users::table)
        .values(&new_user)
        .get_result(&mut conn)
        .context("Failed to create test user")?;

    // API Login
    let login_payload = json!({
        "identifier": user.username.clone(),
        "password": password,
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload)?))?;
    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed");
    let raw_cookie_header = login_response
        .headers()
        .get(header::SET_COOKIE)
        .context("Set-Cookie header missing from login response")?
        .to_str()?;
    let parsed_cookie = Cookie::parse(raw_cookie_header.to_string())?;
    assert_eq!(parsed_cookie.name(), "id");
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());

    // Create Character
    let new_character = NewCharacter {
        user_id: user.id,
        name: "Char for Msgs".to_string(),
        description: Some("A test character".to_string()),
        system_prompt: Some("You are a helpful assistant.".to_string()),
        user_persona: Some("A curious user.".to_string()),
        visual_description: Some("Friendly appearance.".to_string()),
        greeting_message: Some("Hello! How can I help?".to_string()),
        data: None,
        image_url: None,
        voice_id: None,
    };
    let character: DbCharacter = diesel::insert_into(characters::table)
        .values(&new_character)
        .get_result(&mut conn)
        .context("Failed to create test character")?;

    // Create Chat Session
    let new_session = NewChat {
        user_id: user.id,
        character_id: Some(character.id),
        title: Some("Test Session for Messages".to_string()),
        settings: None,
        model_name: Some("test-model".to_string()),
        history_compression_threshold: None,
        max_history_tokens: None,
        data: None,
    };
    let session: ChatSession = diesel::insert_into(chat_sessions::table)
        .values(&new_session)
        .get_result(&mut conn)
        .context("Failed to create test chat session")?;

    // Create messages for the session
    let content_msg1 = serde_json::json!([{"type": "text", "text": "Hello"}]);
    let new_msg1 = NewMessage {
        chat_id: session.id,
        user_id: Some(user.id),
        role: MessageRole::User,
        content: content_msg1,
        model_response: None,
        tool_calls: None,
        tool_call_id: None,
        data: None,
        hidden_from_user: None,
        truncated: None,
    };
    let _msg1: ChatMessage = diesel::insert_into(chat_messages::table)
        .values(&new_msg1)
        .get_result(&mut conn)
        .context("Failed to create message 1")?;

    let content_msg2 = serde_json::json!([{"type": "text", "text": "Hi"}]);
    let new_msg2 = NewMessage {
        chat_id: session.id,
        user_id: None,
        role: MessageRole::Assistant,
        content: content_msg2,
        model_response: None,
        tool_calls: None,
        tool_call_id: None,
        data: None,
        hidden_from_user: None,
        truncated: None,
    };
    let _msg2: ChatMessage = diesel::insert_into(chat_messages::table)
        .values(&new_msg2)
        .get_result(&mut conn)
        .context("Failed to create message 2")?;

    // Create messages for another session (should not be listed)
    let new_other_session = NewChat {
        user_id: user.id,
        character_id: Some(character.id),
        title: Some("Other Test Session".to_string()),
        settings: None,
        model_name: Some("test-model".to_string()),
        history_compression_threshold: None,
        max_history_tokens: None,
        data: None,
    };
    let other_session: ChatSession = diesel::insert_into(chat_sessions::table)
        .values(&new_other_session)
        .get_result(&mut conn)
        .context("Failed to create other test chat session")?;

    let content_other_msg = serde_json::json!([{"type": "text", "text": "Other msg"}]);
    let new_other_msg = NewMessage {
        chat_id: other_session.id,
        user_id: Some(user.id),
        role: MessageRole::User,
        content: content_other_msg,
        model_response: None,
        tool_calls: None,
        tool_call_id: None,
        data: None,
        hidden_from_user: None,
        truncated: None,
    };
    let _other_msg: ChatMessage = diesel::insert_into(chat_messages::table)
        .values(&new_other_msg)
        .get_result(&mut conn)
        .context("Failed to create other message")?;

    // Request and assertions
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/messages", session.id))
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())?;

    let response = test_app.router.clone().oneshot(request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await?.to_bytes();
    let messages: Vec<MessageResponse> =
        serde_json::from_slice(&body).expect("Failed to deserialize messages");

    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].message_type, MessageRole::User);
    assert_eq!(messages[0].parts[0]["text"].as_str().unwrap(), "Hello");
    assert_eq!(messages[1].message_type, MessageRole::Assistant);
    assert_eq!(messages[1].parts[0]["text"].as_str().unwrap(), "Hi");
    Ok(())
}


#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn test_get_chat_messages_unauthorized() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false).await;
    let dummy_session_id = Uuid::new_v4();

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/messages", dummy_session_id))
        .body(Body::empty())?;

    // Act: Make request without authentication
    let response = test_app.router.clone().oneshot(request).await?;

    // Assert: Check for Unauthorized status
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn test_get_chat_messages_not_found() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().await.context("Failed to get DB connection")?;

    // Create User
    let username = "test_get_messages_not_found_user";
    let password = "password";
    let hashed_password = bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .context("Failed to hash password")?;
    
    let new_user = NewUser {
        username: username.to_string(),
        email: Some(format!("{}@example.com", username)),
        password_hash: hashed_password,
        data_encryption_key_hash: None,
        salt: None,
        nonce: None,
        dek_details: None,
    };
    let user: User = diesel::insert_into(users::table)
        .values(&new_user)
        .get_result(&mut conn)
        .context("Failed to create test user for not_found test")?;

    // API Login
    let login_payload = json!({ "identifier": user.username.clone(), "password": password });
    let login_request = Request::builder()
        .method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload)?))?;
    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed for not_found test");
    let raw_cookie_header = login_response.headers().get(header::SET_COOKIE).context("Set-Cookie missing for not_found test")?.to_str()?;
    let parsed_cookie = Cookie::parse(raw_cookie_header.to_string())?;
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());

    let non_existent_session_id = Uuid::new_v4();

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/messages", non_existent_session_id))
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())?;

    // Act: Make request for a non-existent session
    let response = test_app.router.clone().oneshot(request).await?;

    // Assert: Check for Not Found status
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn test_get_chat_messages_forbidden() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().await.context("Failed to get DB connection")?;
    let password_a = "password_a";
    let password_b = "password_b";

    // Arrange: User A
    let username_a = "test_get_messages_forbidden_user_a";
    let hashed_password_a = bcrypt::hash(password_a, bcrypt::DEFAULT_COST)
        .context("Failed to hash password for user A")?;
    let new_user_a = NewUser {
        username: username_a.to_string(),
        email: Some(format!("{}@example.com", username_a)),
        password_hash: hashed_password_a,
        data_encryption_key_hash: None, salt: None, nonce: None, dek_details: None,
    };
    let user_a: User = diesel::insert_into(users::table)
        .values(&new_user_a)
        .get_result(&mut conn)
        .context("Failed to create user_a for forbidden test")?;

    // Arrange: Character for User A
    let new_char_a = NewCharacter {
        user_id: user_a.id,
        name: "User A Character".to_string(),
        description: Some("Desc A".to_string()),
        system_prompt: Some("SysPrompt A".to_string()),
        user_persona: Some("Persona A".to_string()),
        visual_description: Some("Visual A".to_string()),
        greeting_message: Some("Greeting A".to_string()),
        data: None, image_url: None, voice_id: None,
    };
    let char_a: DbCharacter = diesel::insert_into(characters::table)
        .values(&new_char_a)
        .get_result(&mut conn)
        .context("Failed to create char_a for forbidden test")?;

    // Arrange: Chat Session for User A
    let new_session_a = NewChat {
        user_id: user_a.id,
        character_id: Some(char_a.id),
        title: Some("Session A".to_string()),
        settings: None, model_name: Some("model-a".to_string()),
        history_compression_threshold: None, max_history_tokens: None, data: None,
    };
    let session_a: ChatSession = diesel::insert_into(chat_sessions::table)
        .values(&new_session_a)
        .get_result(&mut conn)
        .context("Failed to create session_a for forbidden test")?;

    // Arrange: User B
    let username_b = "test_get_messages_forbidden_user_b";
    let hashed_password_b = bcrypt::hash(password_b, bcrypt::DEFAULT_COST)
        .context("Failed to hash password for user B")?;
    let new_user_b = NewUser {
        username: username_b.to_string(),
        email: Some(format!("{}@example.com", username_b)),
        password_hash: hashed_password_b,
        data_encryption_key_hash: None, salt: None, nonce: None, dek_details: None,
    };
    let user_b: User = diesel::insert_into(users::table)
        .values(&new_user_b)
        .get_result(&mut conn)
        .context("Failed to create user_b for forbidden test")?;

    // Arrange: User B logs in
    let login_payload_b = json!({ "identifier": user_b.username.clone(), "password": password_b });
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
        .uri(format!("/api/chats/{}/messages", session_a.id)) // Use User A's session ID
        .header(header::COOKIE, auth_cookie_b) // Use User B's cookie
        .body(Body::empty())?;

    // Act: User B tries to get messages from User A's session
    let response = test_app.router.clone().oneshot(request).await?;

    // Assert: Check for Forbidden status
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}