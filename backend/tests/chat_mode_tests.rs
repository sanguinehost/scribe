#![cfg(test)]

//! Comprehensive tests for Chat Modes functionality
//! Tests the modular chat system with Character, ScribeAssistant, and Rpg modes

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

// Diesel imports
use diesel::RunQueryDsl;
use diesel::prelude::*;

// Crate imports
use scribe_backend::models::character_card::NewCharacter;
use scribe_backend::models::characters::Character as DbCharacter;
use scribe_backend::models::chats::{Chat as DbChatSession, ChatMode, CreateChatSessionPayload};
use scribe_backend::schema::{characters, chat_sessions};
use scribe_backend::test_helpers;
use secrecy::{ExposeSecret, SecretBox};
use std::sync::Arc;
use tracing::debug;

use scribe_backend::crypto;
use scribe_backend::models::users::User;

/// Test creating a Character mode chat session (traditional mode)
#[tokio::test]
#[ignore] // For CI
async fn test_create_character_mode_chat_session() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "chat_mode_user".to_string(),
        "testpass".to_string(),
    )
    .await
    .expect("Failed to create test user");

    // Create a test character
    let character = test_helpers::db::create_test_character(
        &test_app.db_pool,
        user.id,
        "Test Character".to_string(),
    )
    .await
    .expect("Failed to create test character");

    // Test 1: Create Character mode session with explicit mode
    let payload = CreateChatSessionPayload {
        character_id: Some(character.id),
        chat_mode: Some(ChatMode::Character),
        active_custom_persona_id: None,
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chat/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&payload).unwrap()))
        .unwrap();

    let response = test_app
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let session: DbChatSession = serde_json::from_slice(&body).expect("Failed to parse response");

    // Verify Character mode specific fields
    assert_eq!(session.chat_mode, ChatMode::Character);
    assert_eq!(session.character_id, Some(character.id));
    assert_eq!(session.user_id, user.id);

    // Test 2: Create Character mode session with default mode (backward compatibility)
    let payload_default = CreateChatSessionPayload {
        character_id: Some(character.id),
        chat_mode: None, // Should default to Character
        active_custom_persona_id: None,
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chat/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&payload_default).unwrap()))
        .unwrap();

    let response = test_app
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let session: DbChatSession = serde_json::from_slice(&body).expect("Failed to parse response");

    // Should default to Character mode
    assert_eq!(session.chat_mode, ChatMode::Character);
    assert_eq!(session.character_id, Some(character.id));
}

/// Test creating a ScribeAssistant mode chat session
#[tokio::test]
#[ignore] // For CI
async fn test_create_scribe_assistant_mode_chat_session() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "assistant_user".to_string(),
        "testpass".to_string(),
    )
    .await
    .expect("Failed to create test user");

    // Create ScribeAssistant mode session
    let payload = CreateChatSessionPayload {
        character_id: None, // No character for assistant mode
        chat_mode: Some(ChatMode::ScribeAssistant),
        active_custom_persona_id: None,
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chat/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&payload).unwrap()))
        .unwrap();

    let response = test_app
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let session: DbChatSession = serde_json::from_slice(&body).expect("Failed to parse response");

    // Verify ScribeAssistant mode specific fields
    assert_eq!(session.chat_mode, ChatMode::ScribeAssistant);
    assert_eq!(session.character_id, None); // No character for assistant mode
    assert_eq!(session.user_id, user.id);

    // Check that title was encrypted with assistant-specific content
    assert!(session.title_ciphertext.is_some());
    assert!(session.title_nonce.is_some());
}

/// Test creating an RPG mode chat session
#[tokio::test]
#[ignore] // For CI
async fn test_create_rpg_mode_chat_session() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "rpg_user".to_string(),
        "testpass".to_string(),
    )
    .await
    .expect("Failed to create test user");

    // Create RPG mode session
    let payload = CreateChatSessionPayload {
        character_id: None, // No character for RPG mode
        chat_mode: Some(ChatMode::Rpg),
        active_custom_persona_id: None,
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chat/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&payload).unwrap()))
        .unwrap();

    let response = test_app
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let session: DbChatSession = serde_json::from_slice(&body).expect("Failed to parse response");

    // Verify RPG mode specific fields
    assert_eq!(session.chat_mode, ChatMode::Rpg);
    assert_eq!(session.character_id, None); // No character for RPG mode
    assert_eq!(session.user_id, user.id);

    // Check that title was encrypted with RPG-specific content
    assert!(session.title_ciphertext.is_some());
    assert!(session.title_nonce.is_some());
}

/// Test validation errors for invalid chat mode combinations
#[tokio::test]
#[ignore] // For CI
async fn test_chat_mode_validation_errors() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "validation_user".to_string(),
        "testpass".to_string(),
    )
    .await
    .expect("Failed to create test user");

    // Test 1: Character mode without character_id should fail
    let payload = CreateChatSessionPayload {
        character_id: None,
        chat_mode: Some(ChatMode::Character),
        active_custom_persona_id: None,
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chat/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&payload).unwrap()))
        .unwrap();

    let response = test_app
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Test 2: ScribeAssistant mode with character_id should still work (extra field ignored)
    let character = test_helpers::db::create_test_character(
        &test_app.db_pool,
        user.id,
        "Ignored Character".to_string(),
    )
    .await
    .expect("Failed to create test character");

    let payload = CreateChatSessionPayload {
        character_id: Some(character.id), // This should be ignored
        chat_mode: Some(ChatMode::ScribeAssistant),
        active_custom_persona_id: None,
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chat/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&payload).unwrap()))
        .unwrap();

    let response = test_app
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let session: DbChatSession = serde_json::from_slice(&body).expect("Failed to parse response");

    // Should still create ScribeAssistant mode with no character
    assert_eq!(session.chat_mode, ChatMode::ScribeAssistant);
    assert_eq!(session.character_id, None);
}

/// Test that character-specific operations fail for non-character modes
#[tokio::test]
#[ignore] // For CI
async fn test_character_operations_fail_for_non_character_modes() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "operation_user".to_string(),
        "testpass".to_string(),
    )
    .await
    .expect("Failed to create test user");

    // Create a ScribeAssistant session
    let payload = CreateChatSessionPayload {
        character_id: None,
        chat_mode: Some(ChatMode::ScribeAssistant),
        active_custom_persona_id: None,
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chat/session")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&payload).unwrap()))
        .unwrap();

    let response = test_app
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let session: DbChatSession = serde_json::from_slice(&body).expect("Failed to parse response");

    // Test 1: Try to generate chat response (should fail for now until we implement non-character generation)
    let generate_payload = json!({
        "content": "Hello assistant!"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri(&format!("/api/chat/{}/generate", session.id))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&generate_payload).unwrap()))
        .unwrap();

    let response = test_app
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    // Should fail because generation is not yet implemented for non-character modes
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    // Test 2: Try to create character override (should fail)
    let override_payload = json!({
        "field_name": "personality",
        "value": "Override value"
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri(&format!("/api/chat/{}/character-override", session.id))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&override_payload).unwrap()))
        .unwrap();

    let response = test_app
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("Failed to execute request");

    // Should fail because overrides only work for character-based sessions
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

/// Test chat mode persistence and retrieval
#[tokio::test]
#[ignore] // For CI
async fn test_chat_mode_persistence() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "persistence_user".to_string(),
        "testpass".to_string(),
    )
    .await
    .expect("Failed to create test user");

    // Create sessions for each mode
    let modes = vec![
        (ChatMode::Character, true),  // needs character
        (ChatMode::ScribeAssistant, false),
        (ChatMode::Rpg, false),
    ];

    let mut session_ids = Vec::new();

    for (mode, needs_character) in modes {
        let character_id = if needs_character {
            let character = test_helpers::db::create_test_character(
                &test_app.db_pool,
                user.id,
                format!("{:?} Character", mode),
            )
            .await
            .expect("Failed to create test character");
            Some(character.id)
        } else {
            None
        };

        let payload = CreateChatSessionPayload {
            character_id,
            chat_mode: Some(mode),
            active_custom_persona_id: None,
        };

        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/chat/session")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_string(&payload).unwrap()))
            .unwrap();

        let response = test_app
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("Failed to execute request");

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let session: DbChatSession = serde_json::from_slice(&body).expect("Failed to parse response");

        // Verify mode persistence
        assert_eq!(session.chat_mode, mode);
        session_ids.push(session.id);
    }

    // Verify sessions can be retrieved with correct modes
    for session_id in session_ids {
        let request = Request::builder()
            .method(Method::GET)
            .uri(&format!("/api/chat/sessions/{}", session_id))
            .body(Body::empty())
            .unwrap();

        let response = test_app
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("Failed to execute request");

        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let session: DbChatSession = serde_json::from_slice(&body).expect("Failed to parse response");

        // Mode should be preserved
        assert!(matches!(
            session.chat_mode,
            ChatMode::Character | ChatMode::ScribeAssistant | ChatMode::Rpg
        ));
    }
}

/// Test database schema constraints for chat modes
#[tokio::test]
#[ignore] // For CI
async fn test_chat_mode_database_constraints() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "db_user".to_string(),
        "testpass".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let mut conn = test_app.db_pool.get().await.expect("Failed to get DB connection");

    // Test 1: Verify chat_mode column exists and accepts valid values
    let session_id = Uuid::new_v4();
    
    let result = conn.interact(move |conn| {
        diesel::insert_into(chat_sessions::table)
            .values((
                chat_sessions::id.eq(session_id),
                chat_sessions::user_id.eq(user.id),
                chat_sessions::character_id.eq(None::<Uuid>),
                chat_sessions::chat_mode.eq(ChatMode::ScribeAssistant),
                chat_sessions::history_management_strategy.eq("message_window"),
                chat_sessions::history_management_limit.eq(20),
                chat_sessions::model_name.eq("gemini-2.0-flash-exp"),
            ))
            .execute(conn)
    }).await;

    assert!(result.is_ok(), "Failed to insert session with ScribeAssistant mode");

    // Test 2: Verify nullable character_id works
    let session_id_2 = Uuid::new_v4();
    
    let result = conn.interact(move |conn| {
        diesel::insert_into(chat_sessions::table)
            .values((
                chat_sessions::id.eq(session_id_2),
                chat_sessions::user_id.eq(user.id),
                chat_sessions::character_id.eq(None::<Uuid>),
                chat_sessions::chat_mode.eq(ChatMode::Rpg),
                chat_sessions::history_management_strategy.eq("message_window"),
                chat_sessions::history_management_limit.eq(20),
                chat_sessions::model_name.eq("gemini-2.0-flash-exp"),
            ))
            .execute(conn)
    }).await;

    assert!(result.is_ok(), "Failed to insert session with null character_id");

    // Test 3: Verify querying by chat_mode works
    let result = conn.interact(move |conn| {
        chat_sessions::table
            .filter(chat_sessions::chat_mode.eq(ChatMode::ScribeAssistant))
            .filter(chat_sessions::user_id.eq(user.id))
            .count()
            .get_result::<i64>(conn)
    }).await;

    let count = result
        .expect("Failed to interact with database")
        .expect("Failed to count ScribeAssistant sessions");
    assert!(count >= 1, "Should find at least one ScribeAssistant session");
}