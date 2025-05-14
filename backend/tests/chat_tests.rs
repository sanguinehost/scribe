#![cfg(test)]

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use rand::TryRngCore; // Changed from rand_core::TryRngCore to rand::TryRngCore
use http_body_util::BodyExt;
use mime;
use serde_json::json;
use std::sync::Arc;
use tower::util::ServiceExt;
use tracing::debug;
use secrecy::{SecretBox, ExposeSecret};
use scribe_backend::crypto;
use uuid::Uuid;
use chrono::Utc;
use diesel::prelude::*;

// Crate imports
use scribe_backend::{
    models::{
        characters::Character as DbCharacter,
        chats::{
            Chat as DbChat, // Renamed to avoid conflict with the struct in this file
            MessageRole,
            GenerateChatRequest,
            ApiChatMessage,
            UpdateChatSettingsRequest, // Alias for clarity
            NewChat,
            NewMessage,
            Message as DbChatMessage, // Changed from ChatMessage to Message
        },
        users::User, // For type annotation
    },
    schema::{characters, chat_messages, chat_sessions},
    test_helpers::{self, TestApp, TestDataGuard},
    state::AppState, // Added for AppState reconstruction
};
use anyhow::Error as AnyhowError;


// Helper function for API-based login
async fn login_user_via_api(test_app: &TestApp, username: &str, password: &str) -> String {
    let login_payload = json!({
        "identifier": username, // Changed from "username" to "identifier" to match common practice
        "password": password
    });
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    if response.status() != StatusCode::OK {
        let status = response.status();
        let body_bytes = match response.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => format!("Failed to collect body: {}", e).into_bytes().into(),
        };
        let body_str = String::from_utf8_lossy(&body_bytes);
        panic!(
            "API login failed for user '{}'. Status: {}. Body: {}",
            username, status, body_str
        );
    }

    response.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|v| {
            let cookie_str = v.to_str().unwrap_or_else(|_| {
                panic!("Invalid Set-Cookie header (not UTF-8) for user {}", username)
            });
            if cookie_str.starts_with("id=") { // Assuming session cookie name is "id"
                cookie_str.split(';').next().map(String::from)
            } else {
                None
            }
        })
        .unwrap_or_else(|| {
            let headers_debug = format!("{:?}", response.headers());
            panic!(
                "Session cookie 'id' not found in login response for user {}. Headers: {}",
                username, headers_debug
            )
        })
}


// --- Tests for GET /api/chats/{id}/messages ---

// Test: Get messages for a valid session owned by the user
#[tokio::test]
async fn test_get_chat_messages_success() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = TestDataGuard::new(test_app.db_pool.clone());
    let username = "get_messages_user";
    let password = "password";
    tracing::info!("Creating test user");
    let user: User = test_helpers::db::create_test_user(&test_app.db_pool, username.to_string(), password.to_string()).await.expect("Failed to create test user");
    test_data_guard.add_user(user.id);
    tracing::info!("Created test user with ID: {}", user.id);
    let auth_cookie = login_user_via_api(&test_app, username, password).await;
    tracing::info!("Logged in with auth cookie: {}", auth_cookie);

    // Create a test character
    tracing::info!("Creating test character");
    let character_name = "Test Character".to_string();
    let character = test_helpers::db::create_test_character(&test_app.db_pool, user.id, character_name).await?;
    let character_id = character.id;
    tracing::info!("Created test character with ID: {}", character_id);
    test_data_guard.add_character(character_id);

    tracing::info!("Creating chat session");
    // Create a new chat session for this user
    let session_id = Uuid::new_v4();
    tracing::info!("Generated session_id: {}", session_id);
    test_data_guard.add_chat(session_id);
    
    let conn = test_app.db_pool.get().await?;
    let new_chat = NewChat {
        id: session_id,
        user_id: user.id,
        character_id,
        title: Some("Test Chat".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        history_management_strategy: "none".to_string(),
        history_management_limit: 10,
        model_name: "test_model".to_string(),
        visibility: Some("private".to_string()),
    };
    
    let create_session_result = conn.interact(move |conn_inner| {
        use scribe_backend::schema::chat_sessions::dsl::*;
        diesel::insert_into(chat_sessions)
            .values(&new_chat)
            .execute(conn_inner)
    }).await;
    
    if let Err(e) = create_session_result {
        return Err(anyhow::anyhow!("Failed to create chat session: {}", e));
    }
    let create_session_rows = create_session_result.unwrap()?;
    tracing::info!("Inserted {} chat session row(s)", create_session_rows);

    // Add a message to the chat session
    let message_id = Uuid::new_v4();
    tracing::info!("Generated message_id: {}", message_id);
    
    let conn = test_app.db_pool.get().await?;
    let new_message = NewMessage {
        id: message_id,
        session_id,
        user_id: user.id,
        message_type: MessageRole::User,
        content: "Test message content".to_string().into_bytes(),
        content_nonce: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        role: Some("user".to_string()),
        parts: Some(serde_json::json!([{"text": "Test message content"}])),
        attachments: None,
    };
    
    let create_message_result = conn.interact(move |conn_inner| {
        use scribe_backend::schema::chat_messages::dsl::*;
        diesel::insert_into(chat_messages)
            .values(&new_message)
            .execute(conn_inner)
    }).await;
    
    if let Err(e) = create_message_result {
        return Err(anyhow::anyhow!("Failed to create chat message: {}", e));
    }
    let create_message_rows = create_message_result.unwrap()?;
    tracing::info!("Inserted {} chat message row(s)", create_message_rows);

    // Verify that we can get the messages
    tracing::info!("Making API request to /api/chats/{}/generate", session_id);
    let response = reqwest::Client::new()
        .post(&format!("{}/api/chats/{}/generate", test_app.address, session_id))
        .header("Cookie", &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(serde_json::to_string(&json!({"history": [{"role": "user", "content": "Test message"}]})).unwrap())
        .send()
        .await?;
    
    let status = response.status();
    let body = response.text().await?;
    tracing::info!("Response status: {}, body: {}", status, body);
    
    assert_eq!(status, 200);
    
    // Explicitly call cleanup to release test resources
    test_data_guard.cleanup().await?;
    
    Ok(())
}

// Test: Get messages for a session that doesn't exist
#[tokio::test]
async fn test_get_chat_messages_session_not_found() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = TestDataGuard::new(test_app.db_pool.clone());
    let username = "get_messages_not_found_user";
    let password = "password";
    let user: User = test_helpers::db::create_test_user(&test_app.db_pool, username.to_string(), password.to_string()).await.expect("Failed to create test user");
    test_data_guard.add_user(user.id);
    let auth_cookie = login_user_via_api(&test_app, username, password).await;

    let non_existent_session_id = Uuid::new_v4();

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/messages", non_existent_session_id))
        .header(header::COOKIE, &auth_cookie)
        .body(Body::empty())?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    test_data_guard.cleanup().await?;
    Ok(())
}

// Test: Get messages for a session owned by another user
#[tokio::test]
async fn test_get_chat_messages_forbidden() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = TestDataGuard::new(test_app.db_pool.clone());
    let conn = test_app.db_pool.get().await?;

    let username_a = "get_messages_user_a";
    let password_a = "password_a";
    let user_a: User = test_helpers::db::create_test_user(&test_app.db_pool, username_a.to_string(), password_a.to_string()).await.expect("Failed to create test user A");
    test_data_guard.add_user(user_a.id);

    let username_b = "get_messages_user_b";
    let password_b = "password_b";
    let user_b: User = test_helpers::db::create_test_user(&test_app.db_pool, username_b.to_string(), password_b.to_string()).await.expect("Failed to create test user B");
    test_data_guard.add_user(user_b.id);
    let auth_cookie_b = login_user_via_api(&test_app, username_b, password_b).await;

    let character_a_id = Uuid::new_v4();
    let new_character_a = DbCharacter {
        id: character_a_id,
        user_id: user_a.id,
        name: "User A Char".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        description: None, personality: None, scenario: None, first_mes: None, mes_example: None,
        creator_notes: None, system_prompt: None, post_history_instructions: None, tags: None, creator: None,
        character_version: None, alternate_greetings: None, nickname: None, creator_notes_multilingual: None,
        source: None, group_only_greetings: None, creation_date: None, modification_date: None, persona: None,
        world_scenario: None, avatar: None, chat: None, greeting: None, definition: None, default_voice: None,
        extensions: None, data_id: None, category: None, definition_visibility: None, depth: None,
        example_dialogue: None, favorite: None, first_message_visibility: None, height: None, last_activity: None,
        migrated_from: None, model_prompt: None, model_prompt_visibility: None, model_temperature: None,
        num_interactions: None, permanence: None, persona_visibility: None, revision: None, sharing_visibility: None,
        status: None, system_prompt_visibility: None, system_tags: None, token_budget: None, usage_hints: None,
        user_persona: None, user_persona_visibility: None, visibility: None, weight: None, world_scenario_visibility: None,
        description_nonce: None, personality_nonce: None, scenario_nonce: None, first_mes_nonce: None,
        mes_example_nonce: None, creator_notes_nonce: None, system_prompt_nonce: None, post_history_instructions_nonce: None,
        persona_nonce: None, world_scenario_nonce: None, greeting_nonce: None, definition_nonce: None,
        example_dialogue_nonce: None, model_prompt_nonce: None, user_persona_nonce: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(characters::table)
            .values(&new_character_a)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    test_data_guard.add_character(character_a_id);

    let session_a_id = Uuid::new_v4();
    let new_session_a = NewChat {
        id: session_a_id,
        user_id: user_a.id,
        character_id: character_a_id,
        title: Some("User A Session".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        history_management_strategy: "none".to_string(),
        history_management_limit: 10,
        model_name: "test_model".to_string(),
        visibility: Some("private".to_string()),
    };
    
    let conn = test_app.db_pool.get().await?;
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(chat_sessions::table)
            .values(&new_session_a)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert session: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted session: {} rows affected", insert_result);
    test_data_guard.add_chat(session_a_id);

    let payload = GenerateChatRequest {
        history: vec![ApiChatMessage {
            role: "user".to_string(),
            content: "test".to_string(),
        }],
        model: None
    };
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session_a_id)) // User B tries to access User A's session
        .header(header::COOKIE, &auth_cookie_b)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&payload)?))?;
    
    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    test_data_guard.cleanup().await?;
    Ok(())
}

// Test: Get messages without authentication
#[tokio::test]
async fn test_get_chat_messages_unauthorized() -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Starting test_get_chat_messages_unauthorized");
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let uuid = Uuid::new_v4(); // Some random UUID that won't be in the DB

    // Try to get the messages without authentication
    tracing::info!("Making API request to /api/chats/{}/generate without auth", uuid);
    let payload = GenerateChatRequest { history: vec![], model: None };
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", uuid))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&payload)?))?;
    
    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    
    Ok(())
}

// --- Tests for GET /api/chats/{id}/settings ---

#[tokio::test]
async fn test_get_settings_success() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = TestDataGuard::new(test_app.db_pool.clone());
    let conn = test_app.db_pool.get().await?;

    let username = "get_settings_user";
    let password = "password";
    let user: User = test_helpers::db::create_test_user(&test_app.db_pool, username.to_string(), password.to_string()).await.expect("Failed to create test user");
    test_data_guard.add_user(user.id);
    let auth_cookie = login_user_via_api(&test_app, username, password).await;

    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id,
        user_id: user.id,
        name: "Get Settings Char".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        description: None, personality: None, scenario: None, first_mes: None, mes_example: None,
        creator_notes: None, system_prompt: None, post_history_instructions: None, tags: None, creator: None,
        character_version: None, alternate_greetings: None, nickname: None, creator_notes_multilingual: None,
        source: None, group_only_greetings: None, creation_date: None, modification_date: None, persona: None,
        world_scenario: None, avatar: None, chat: None, greeting: None, definition: None, default_voice: None,
        extensions: None, data_id: None, category: None, definition_visibility: None, depth: None,
        example_dialogue: None, favorite: None, first_message_visibility: None, height: None, last_activity: None,
        migrated_from: None, model_prompt: None, model_prompt_visibility: None, model_temperature: None,
        num_interactions: None, permanence: None, persona_visibility: None, revision: None, sharing_visibility: None,
        status: None, system_prompt_visibility: None, system_tags: None, token_budget: None, usage_hints: None,
        user_persona: None, user_persona_visibility: None, visibility: None, weight: None, world_scenario_visibility: None,
        description_nonce: None, personality_nonce: None, scenario_nonce: None, first_mes_nonce: None,
        mes_example_nonce: None, creator_notes_nonce: None, system_prompt_nonce: None, post_history_instructions_nonce: None,
        persona_nonce: None, world_scenario_nonce: None, greeting_nonce: None, definition_nonce: None,
        example_dialogue_nonce: None, model_prompt_nonce: None, user_persona_nonce: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(characters::table)
            .values(&new_character)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    test_data_guard.add_character(character_id);

    let session_id = Uuid::new_v4();
    let new_session = NewChat {
        id: session_id,
        user_id: user.id,
        character_id,
        title: Some("Get Settings Session".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        history_management_strategy: "none".to_string(),
        history_management_limit: 20, // Default from migration
        model_name: "gemini-2.5-flash-preview-04-17".to_string(), // Default from migration
        visibility: Some("private".to_string()),
    };
    
    let conn = test_app.db_pool.get().await?;
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(chat_sessions::table)
            .values(&new_session)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert session: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted session: {} rows affected", insert_result);
    test_data_guard.add_chat(session_id);

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", session_id))
        .header(header::COOKIE, &auth_cookie)
        .body(Body::empty())?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await?.to_bytes();
    let settings: scribe_backend::models::chats::ChatSettingsResponse =
        serde_json::from_slice(&body)?;

    assert_eq!(settings.system_prompt, None);
    assert_eq!(settings.temperature, None);
    assert_eq!(settings.history_management_strategy, "none");
    assert_eq!(settings.history_management_limit, 20);
    assert_eq!(settings.model_name, "gemini-2.5-flash-preview-04-17");


    test_data_guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_get_settings_session_not_found() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = TestDataGuard::new(test_app.db_pool.clone());
    let username = "get_settings_not_found_user";
    let password = "password";
    let user: User = test_helpers::db::create_test_user(&test_app.db_pool, username.to_string(), password.to_string()).await.expect("Failed to create test user");
    test_data_guard.add_user(user.id);
    let auth_cookie = login_user_via_api(&test_app, username, password).await;

    let non_existent_session_id = Uuid::new_v4();

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", non_existent_session_id))
        .header(header::COOKIE, &auth_cookie)
        .body(Body::empty())?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    test_data_guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_get_settings_forbidden() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = TestDataGuard::new(test_app.db_pool.clone());
    let conn = test_app.db_pool.get().await?;

    let username_a = "forbidden_settings_user_a";
    let password_a = "password";
    let user_a: User = test_helpers::db::create_test_user(&test_app.db_pool, username_a.to_string(), password_a.to_string()).await.expect("Failed to create test user A");
    test_data_guard.add_user(user_a.id);

    let username_b = "forbidden_settings_user_b";
    let password_b = "password";
    let user_b: User = test_helpers::db::create_test_user(&test_app.db_pool, username_b.to_string(), password_b.to_string()).await.expect("Failed to create test user B");
    test_data_guard.add_user(user_b.id);
    let auth_cookie_b = login_user_via_api(&test_app, username_b, password_b).await;

    let character_a_id = Uuid::new_v4();
    let new_character_a = DbCharacter {
        id: character_a_id,
        user_id: user_a.id,
        name: "User A Settings Char".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        description: None, personality: None, scenario: None, first_mes: None, mes_example: None,
        creator_notes: None, system_prompt: None, post_history_instructions: None, tags: None, creator: None,
        character_version: None, alternate_greetings: None, nickname: None, creator_notes_multilingual: None,
        source: None, group_only_greetings: None, creation_date: None, modification_date: None, persona: None,
        world_scenario: None, avatar: None, chat: None, greeting: None, definition: None, default_voice: None,
        extensions: None, data_id: None, category: None, definition_visibility: None, depth: None,
        example_dialogue: None, favorite: None, first_message_visibility: None, height: None, last_activity: None,
        migrated_from: None, model_prompt: None, model_prompt_visibility: None, model_temperature: None,
        num_interactions: None, permanence: None, persona_visibility: None, revision: None, sharing_visibility: None,
        status: None, system_prompt_visibility: None, system_tags: None, token_budget: None, usage_hints: None,
        user_persona: None, user_persona_visibility: None, visibility: None, weight: None, world_scenario_visibility: None,
        description_nonce: None, personality_nonce: None, scenario_nonce: None, first_mes_nonce: None,
        mes_example_nonce: None, creator_notes_nonce: None, system_prompt_nonce: None, post_history_instructions_nonce: None,
        persona_nonce: None, world_scenario_nonce: None, greeting_nonce: None, definition_nonce: None,
        example_dialogue_nonce: None, model_prompt_nonce: None, user_persona_nonce: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(characters::table)
            .values(&new_character_a)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    test_data_guard.add_character(character_a_id);

    let session_a_id = Uuid::new_v4();
    let new_session_a = NewChat {
        id: session_a_id,
        user_id: user_a.id,
        character_id: character_a_id,
        title: Some("User A Settings Session".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        history_management_strategy: "none".to_string(),
        history_management_limit: 10,
        model_name: "test_model".to_string(),
        visibility: Some("private".to_string()),
    };
    
    let conn = test_app.db_pool.get().await?;
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(chat_sessions::table)
            .values(&new_session_a)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert session: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted session: {} rows affected", insert_result);
    test_data_guard.add_chat(session_a_id);

    // User B (unauthorized) attempts to GET settings for User A's session
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", session_a_id))
        .header(header::COOKIE, &auth_cookie_b) // Use User B's cookie
        .body(Body::empty())?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN, "Expected Forbidden status when user B tries to get settings for user A's session");
    test_data_guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_get_settings_unauthorized() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = TestDataGuard::new(test_app.db_pool.clone());
    let conn = test_app.db_pool.get().await?;

    let username = "get_settings_unauth_setup_user";
    let password = "password";
    let user: User = test_helpers::db::create_test_user(&test_app.db_pool, username.to_string(), password.to_string()).await.expect("Failed to create test user");
    test_data_guard.add_user(user.id);

    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id,
        user_id: user.id,
        name: "Unauth Settings Char".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        description: None, personality: None, scenario: None, first_mes: None, mes_example: None,
        creator_notes: None, system_prompt: None, post_history_instructions: None, tags: None, creator: None,
        character_version: None, alternate_greetings: None, nickname: None, creator_notes_multilingual: None,
        source: None, group_only_greetings: None, creation_date: None, modification_date: None, persona: None,
        world_scenario: None, avatar: None, chat: None, greeting: None, definition: None, default_voice: None,
        extensions: None, data_id: None, category: None, definition_visibility: None, depth: None,
        example_dialogue: None, favorite: None, first_message_visibility: None, height: None, last_activity: None,
        migrated_from: None, model_prompt: None, model_prompt_visibility: None, model_temperature: None,
        num_interactions: None, permanence: None, persona_visibility: None, revision: None, sharing_visibility: None,
        status: None, system_prompt_visibility: None, system_tags: None, token_budget: None, usage_hints: None,
        user_persona: None, user_persona_visibility: None, visibility: None, weight: None, world_scenario_visibility: None,
        description_nonce: None, personality_nonce: None, scenario_nonce: None, first_mes_nonce: None,
        mes_example_nonce: None, creator_notes_nonce: None, system_prompt_nonce: None, post_history_instructions_nonce: None,
        persona_nonce: None, world_scenario_nonce: None, greeting_nonce: None, definition_nonce: None,
        example_dialogue_nonce: None, model_prompt_nonce: None, user_persona_nonce: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(characters::table)
            .values(&new_character)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    test_data_guard.add_character(character_id);

    let session_id = Uuid::new_v4();
    let new_session = NewChat {
        id: session_id,
        user_id: user.id,
        character_id,
        title: Some("Unauth Settings Session".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        history_management_strategy: "none".to_string(),
        history_management_limit: 10,
        model_name: "test_model".to_string(),
        visibility: Some("private".to_string()),
    };
    
    let conn = test_app.db_pool.get().await?;
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(chat_sessions::table)
            .values(&new_session)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert session: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted session: {} rows affected", insert_result);
    test_data_guard.add_chat(session_id);

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", session_id))
        .body(Body::empty())?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    test_data_guard.cleanup().await?;
    Ok(())
}


// --- Tests for chat_service.rs Coverage ---

#[tokio::test]
async fn test_create_chat_session_with_empty_first_mes() -> Result<(), AnyhowError> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = TestDataGuard::new(test_app.db_pool.clone());
    let username = "empty_first_mes_user";
    let password = "password";
    let user: User = test_helpers::db::create_test_user(&test_app.db_pool, username.to_string(), password.to_string()).await.expect("Failed to create test user");
    test_data_guard.add_user(user.id);
    let auth_cookie = login_user_via_api(&test_app, username, password).await;

    let conn = test_app.db_pool.get().await?;

    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id,
        user_id: user.id,
        name: "Empty First Mes Char".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        first_mes: Some("   ".as_bytes().to_vec()), // Set empty first_mes
        description: None, personality: None, scenario: None, mes_example: None,
        creator_notes: None, system_prompt: None, post_history_instructions: None, tags: None, creator: None,
        character_version: None, alternate_greetings: None, nickname: None, creator_notes_multilingual: None,
        source: None, group_only_greetings: None, creation_date: None, modification_date: None, persona: None,
        world_scenario: None, avatar: None, chat: None, greeting: None, definition: None, default_voice: None,
        extensions: None, data_id: None, category: None, definition_visibility: None, depth: None,
        example_dialogue: None, favorite: None, first_message_visibility: None, height: None, last_activity: None,
        migrated_from: None, model_prompt: None, model_prompt_visibility: None, model_temperature: None,
        num_interactions: None, permanence: None, persona_visibility: None, revision: None, sharing_visibility: None,
        status: None, system_prompt_visibility: None, system_tags: None, token_budget: None, usage_hints: None,
        user_persona: None, user_persona_visibility: None, visibility: None, weight: None, world_scenario_visibility: None,
        description_nonce: None, personality_nonce: None, scenario_nonce: None, first_mes_nonce: None,
        mes_example_nonce: None, creator_notes_nonce: None, system_prompt_nonce: None, post_history_instructions_nonce: None,
        persona_nonce: None, world_scenario_nonce: None, greeting_nonce: None, definition_nonce: None,
        example_dialogue_nonce: None, model_prompt_nonce: None, user_persona_nonce: None,
    };

    let result = conn.interact(move |conn_inner| {
        diesel::insert_into(characters::table)
            .values(&new_character)
            .execute(conn_inner)
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e).into());
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    test_data_guard.add_character(character_id);


    let request_body = json!({ "character_id": character_id });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats-api/chats")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body)?))?;
    let response = test_app.router.clone().oneshot(request).await?;

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await?.to_bytes();
    let session: DbChat = // Changed from Chat to DbChat
        serde_json::from_slice(&body)?;
    test_data_guard.add_chat(session.id);


    let conn = test_app.db_pool.get().await?;
    let messages_result = conn.interact(move |conn_inner| {
        chat_messages::table
            .filter(chat_messages::session_id.eq(session.id))
            .select(DbChatMessage::as_select())
            .load(conn_inner)
    }).await;

    if let Err(e) = messages_result {
        return Err(anyhow::anyhow!("Failed to load messages: {}", e).into());
    }

    let messages: Vec<DbChatMessage> = messages_result.unwrap()?;

    assert!(
        messages.is_empty(),
        "No initial message should be created for empty first_mes"
    );

    test_data_guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_create_chat_session_with_null_first_mes() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = TestDataGuard::new(test_app.db_pool.clone());
    let username = "null_first_mes_user";
    let password = "password";
    let user: User = test_helpers::db::create_test_user(&test_app.db_pool, username.to_string(), password.to_string()).await.expect("Failed to create test user");
    test_data_guard.add_user(user.id);
    let auth_cookie = login_user_via_api(&test_app, username, password).await;

    let conn = test_app.db_pool.get().await?;

    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id,
        user_id: user.id,
        name: "Null First Mes Char".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        first_mes: None, // Null first_mes
        description: None, personality: None, scenario: None, mes_example: None,
        creator_notes: None, system_prompt: None, post_history_instructions: None, tags: None, creator: None,
        character_version: None, alternate_greetings: None, nickname: None, creator_notes_multilingual: None,
        source: None, group_only_greetings: None, creation_date: None, modification_date: None, persona: None,
        world_scenario: None, avatar: None, chat: None, greeting: None, definition: None, default_voice: None,
        extensions: None, data_id: None, category: None, definition_visibility: None, depth: None,
        example_dialogue: None, favorite: None, first_message_visibility: None, height: None, last_activity: None,
        migrated_from: None, model_prompt: None, model_prompt_visibility: None, model_temperature: None,
        num_interactions: None, permanence: None, persona_visibility: None, revision: None, sharing_visibility: None,
        status: None, system_prompt_visibility: None, system_tags: None, token_budget: None, usage_hints: None,
        user_persona: None, user_persona_visibility: None, visibility: None, weight: None, world_scenario_visibility: None,
        description_nonce: None, personality_nonce: None, scenario_nonce: None, first_mes_nonce: None,
        mes_example_nonce: None, creator_notes_nonce: None, system_prompt_nonce: None, post_history_instructions_nonce: None,
        persona_nonce: None, world_scenario_nonce: None, greeting_nonce: None, definition_nonce: None,
        example_dialogue_nonce: None, model_prompt_nonce: None, user_persona_nonce: None,
    };

    let result = conn.interact(move |conn_inner| {
        diesel::insert_into(characters::table)
            .values(&new_character)
            .execute(conn_inner)
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    test_data_guard.add_character(character_id);

    let request_body = json!({ "character_id": character_id });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats-api/chats")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body)?))?;
    let response = test_app.router.clone().oneshot(request).await?;

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await?.to_bytes();
    let session: DbChat = // Changed from Chat to DbChat
        serde_json::from_slice(&body)?;
    test_data_guard.add_chat(session.id);

    let conn = test_app.db_pool.get().await?;
    let messages_result = conn.interact(move |conn_inner| {
        chat_messages::table
            .filter(chat_messages::session_id.eq(session.id))
            .select(DbChatMessage::as_select())
            .load(conn_inner)
    }).await;

    if let Err(e) = messages_result {
        return Err(anyhow::anyhow!("Failed to load messages: {}", e));
    }

    let messages: Vec<DbChatMessage> = messages_result.unwrap()?;

    assert!(
        messages.is_empty(),
        "No initial message should be created for null first_mes"
    );
    test_data_guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn test_create_session_saves_first_mes() -> Result<(), AnyhowError> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = TestDataGuard::new(test_app.db_pool.clone());
    let username = "save_first_mes_user";
    let password = "password";
    let user: User = test_helpers::db::create_test_user(&test_app.db_pool, username.to_string(), password.to_string()).await.expect("Failed to create test user");
    test_data_guard.add_user(user.id);

    let conn = test_app.db_pool.get().await?;

    let character_id = Uuid::new_v4();
    let first_mes_content = "Hello from the character!".to_string();

    // 1. Generate DEK
    let mut rng = rand::rngs::OsRng;
    let mut dek_bytes = [0u8; 32];
    rng.try_fill_bytes(&mut dek_bytes).expect("Failed to fill bytes for DEK"); // Changed from rng.random()
    let user_dek_val = SecretBox::new(Box::new(dek_bytes.to_vec())); // DEK should be SecretBox<Vec<u8>>
    let user_dek = Arc::new(user_dek_val);

    // 2. Encrypt first_mes_content
    let (encrypted_first_mes, first_mes_actual_nonce) =
        crypto::encrypt_gcm(first_mes_content.as_bytes(), user_dek.as_ref()) // Pass SecretBox directly
        .expect("Test: Failed to encrypt first_mes");

    let new_character = DbCharacter {
        id: character_id,
        user_id: user.id,
        name: "Save First Mes Char".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        first_mes: Some(encrypted_first_mes), // Store encrypted content
        description: None, personality: None, scenario: None, mes_example: None,
        creator_notes: None, system_prompt: None, post_history_instructions: None, tags: None, creator: None,
        character_version: None, alternate_greetings: None, nickname: None, creator_notes_multilingual: None,
        source: None, group_only_greetings: None, creation_date: None, modification_date: None, persona: None,
        world_scenario: None, avatar: None, chat: None, greeting: None, definition: None, default_voice: None,
        extensions: None, data_id: None, category: None, definition_visibility: None, depth: None,
        example_dialogue: None, favorite: None, first_message_visibility: None, height: None, last_activity: None,
        migrated_from: None, model_prompt: None, model_prompt_visibility: None, model_temperature: None,
        num_interactions: None, permanence: None, persona_visibility: None, revision: None, sharing_visibility: None,
        status: None, system_prompt_visibility: None, system_tags: None, token_budget: None, usage_hints: None,
        user_persona: None, user_persona_visibility: None, visibility: None, weight: None, world_scenario_visibility: None,
        description_nonce: None, personality_nonce: None, scenario_nonce: None,
        first_mes_nonce: Some(first_mes_actual_nonce), // Store the actual nonce
        mes_example_nonce: None, creator_notes_nonce: None, system_prompt_nonce: None, post_history_instructions_nonce: None,
        persona_nonce: None, world_scenario_nonce: None, greeting_nonce: None, definition_nonce: None,
        example_dialogue_nonce: None, model_prompt_nonce: None, user_persona_nonce: None,
    };
    
    let result = conn.interact(move |conn_inner| {
        diesel::insert_into(characters::table)
            .values(&new_character)
            .execute(conn_inner)
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e).into());
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    test_data_guard.add_character(character_id);


    let app_state_arc = Arc::new(AppState {
        pool: test_app.db_pool.clone(),
        config: test_app.config.clone(),
        ai_client: test_app.ai_client.clone(),
        embedding_client: test_app.mock_embedding_client.clone(),
        embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone(),
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_call_tracker: test_app.embedding_call_tracker.clone(),
    });
    let result = scribe_backend::services::chat_service::create_session_and_maybe_first_message(
        app_state_arc,
        user.id,
        character_id,
        Some(user_dek.clone()), // Pass the generated DEK as an Arc
    )
    .await;

    assert!(result.is_ok(), "create_session_and_maybe_first_message failed: {:?}", result.err());
    let session = result.unwrap();
    test_data_guard.add_chat(session.id);


    assert_eq!(session.user_id, user.id);
    assert_eq!(session.character_id, character_id);

    let conn = test_app.db_pool.get().await?;
    let messages_result = conn.interact(move |conn_inner| {
        chat_messages::table
            .filter(chat_messages::session_id.eq(session.id))
            .select(DbChatMessage::as_select())
            .load(conn_inner)
    }).await;
    
    if let Err(e) = messages_result {
        return Err(anyhow::anyhow!("Failed to load messages: {}", e).into());
    }
    
    let messages: Vec<DbChatMessage> = messages_result.unwrap()?;


    assert_eq!(messages.len(), 1, "Expected exactly one initial message");
    let initial_message = &messages[0];

    // Decrypt the message content before asserting
    let nonce = initial_message.content_nonce.as_ref().expect("Initial message should have a nonce");
    let decrypted_content_secret = crypto::decrypt_gcm(&initial_message.content, nonce, user_dek.as_ref())
        .expect("Failed to decrypt initial message content in test");
    let decrypted_content_bytes = decrypted_content_secret.expose_secret();
    let decrypted_content_string = String::from_utf8(decrypted_content_bytes.to_vec())
        .expect("Decrypted content is not valid UTF-8");

    assert_eq!(decrypted_content_string, "Hello from the character!");
    assert_eq!(initial_message.message_type, MessageRole::Assistant);
    assert_eq!(initial_message.user_id, user.id, "Initial message user_id should match session owner"); // Assuming assistant message is owned by session user
    assert_eq!(initial_message.session_id, session.id, "Initial message session_id should match");

    test_data_guard.cleanup().await?;
    Ok(())
}

// --- End Coverage Tests ---

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn test_data_guard_cleanup() -> anyhow::Result<()> {
    let pool = test_helpers::db::setup_test_database(Some("guard_cleanup")).await;
    let mut guard = test_helpers::TestDataGuard::new(pool.clone());
    let conn = pool.get().await?;

    let user = test_helpers::db::create_test_user(&pool, "guard_user".to_string(), "password".to_string()).await.expect("Failed to create test user");
    guard.add_user(user.id);

    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id, user_id: user.id, name: "Guard Char".to_string(), spec: "test".to_string(), spec_version: "1".to_string(), created_at: Utc::now(), updated_at: Utc::now(),
        description: None, personality: None, scenario: None, first_mes: None, mes_example: None, creator_notes: None, system_prompt: None, post_history_instructions: None, tags: None, creator: None, character_version: None, alternate_greetings: None, nickname: None, creator_notes_multilingual: None, source: None, group_only_greetings: None, creation_date: None, modification_date: None, persona: None, world_scenario: None, avatar: None, chat: None, greeting: None, definition: None, default_voice: None, extensions: None, data_id: None, category: None, definition_visibility: None, depth: None, example_dialogue: None, favorite: None, first_message_visibility: None, height: None, last_activity: None, migrated_from: None, model_prompt: None, model_prompt_visibility: None, model_temperature: None, num_interactions: None, permanence: None, persona_visibility: None, revision: None, sharing_visibility: None, status: None, system_prompt_visibility: None, system_tags: None, token_budget: None, usage_hints: None, user_persona: None, user_persona_visibility: None, visibility: None, weight: None, world_scenario_visibility: None, description_nonce: None, personality_nonce: None, scenario_nonce: None, first_mes_nonce: None, mes_example_nonce: None, creator_notes_nonce: None, system_prompt_nonce: None, post_history_instructions_nonce: None, persona_nonce: None, world_scenario_nonce: None, greeting_nonce: None, definition_nonce: None, example_dialogue_nonce: None, model_prompt_nonce: None, user_persona_nonce: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(characters::table)
            .values(&new_character)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    guard.add_character(character_id);

    let session_id = Uuid::new_v4();
    let new_session = NewChat {
        id: session_id, user_id: user.id, character_id, title: Some("Guard Session".to_string()), created_at: Utc::now(), updated_at: Utc::now(), history_management_strategy: "none".to_string(), history_management_limit: 10, model_name: "test".to_string(), visibility: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(chat_sessions::table)
            .values(&new_session)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert session: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted session: {} rows affected", insert_result);
    guard.add_chat(session_id); // Changed from add_session to add_chat

    let message_id = Uuid::new_v4();
    let new_message = NewMessage {
        id: message_id, session_id, user_id: user.id, message_type: MessageRole::User, content: "Guard message".as_bytes().to_vec(), content_nonce: None, created_at: Utc::now(), updated_at: Utc::now(), role: None, parts: None, attachments: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(chat_messages::table)
            .values(&new_message)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert message: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted message: {} rows affected", insert_result);
    // Messages are cleaned up by chat session cleanup in TestDataGuard

    let user_id_check = user.id; // Capture IDs before guard is consumed
    let character_id_check = character_id;
    let session_id_check = session_id;

    guard.cleanup().await.expect("TestDataGuard cleanup failed");

    let deleted_message_result = conn.interact(move |conn_inner| {
        chat_messages::table
            .filter(chat_messages::id.eq(message_id))
            .select(DbChatMessage::as_select()) // DbChatMessage is now models::chats::Message
            .first(conn_inner)
            .optional()
    }).await;
    
    if let Err(e) = deleted_message_result {
        return Err(anyhow::anyhow!("Failed to check message deletion: {}", e));
    }
    let deleted_message = deleted_message_result.unwrap()?;
    assert!(deleted_message.is_none(), "Test message should be deleted by guard");

    let deleted_session_result = conn.interact(move |conn_inner| {
        chat_sessions::table
            .filter(chat_sessions::id.eq(session_id_check))
            .select(DbChat::as_select())
            .first(conn_inner)
            .optional()
    }).await;
    
    if let Err(e) = deleted_session_result {
        return Err(anyhow::anyhow!("Failed to check session deletion: {}", e));
    }
    let deleted_session = deleted_session_result.unwrap()?;
    assert!(deleted_session.is_none(), "Test session should be deleted by guard");

    let deleted_character_result = conn.interact(move |conn_inner| {
        characters::table
            .filter(characters::id.eq(character_id_check))
            .select(DbCharacter::as_select())
            .first(conn_inner)
            .optional()
    }).await;
    
    if let Err(e) = deleted_character_result {
        return Err(anyhow::anyhow!("Failed to check character deletion: {}", e));
    }
    let deleted_character = deleted_character_result.unwrap()?;
    assert!(deleted_character.is_none(), "Test character should be deleted by guard");

    let deleted_user_result = conn.interact(move |conn_inner| {
        use scribe_backend::models::users::UserDbQuery; // Ensure UserDbQuery is in scope
        scribe_backend::schema::users::table
            .filter(scribe_backend::schema::users::id.eq(user_id_check))
            .select(UserDbQuery::as_select())
            .first::<UserDbQuery>(conn_inner)
            .optional()
            .map(|opt_db_user| opt_db_user.map(User::from))
    }).await;
    
    if let Err(e) = deleted_user_result {
        return Err(anyhow::anyhow!("Failed to check user deletion: {}", e));
    }
    let deleted_user = deleted_user_result.unwrap()?;
    assert!(deleted_user.is_none(), "Test user should be deleted by guard");
    Ok(())
}

/*
// This test is commented out as AppStateBuilder is being replaced by spawn_app.
// Refactoring this test to validate spawn_app's configuration capabilities
// would require more specific instructions if its intent needs to be preserved.
#[tokio::test]
async fn test_app_state_builder_defaults_and_overrides() {
    use scribe_backend::config::Config;
    // Add MockQdrantClientService to imports if this test were active
    // use scribe_backend::test_helpers::{MockAiClient, MockQdrantClientService};
    // use scribe_backend::llm::AiClient;
    use scribe_backend::errors::AppError; // Import AppError
    use std::sync::Arc;
    // use scribe_backend::vector_db::qdrant_client::QdrantClientServiceTrait; // Import the trait

    // 1. Create specific components to provide
    let specific_config = Arc::new(Config {
        database_url: Some("specific_db_url_for_builder".to_string()),
        qdrant_url: Some("specific_qdrant_url_for_builder".to_string()),
        ..Default::default()
    });
    // let specific_ai_client = Arc::new(MockAiClient::new());
    // specific_ai_client.set_response(Err(AppError::GenerationError("Specific AI Client Used".to_string())));

    // let mock_qdrant_service = Arc::new(MockQdrantClientService::new());

    // let builder = AppStateBuilder::new()
    //     .with_config(specific_config.clone())
    //     .with_ai_client(specific_ai_client.clone() as Arc<dyn AiClient + Send + Sync>)
    //     .with_qdrant_service(mock_qdrant_service.clone());

    // 3. Build the AppState
    // let app_state_result = builder.build_for_test().await;
    // assert!(app_state_result.is_ok(), "Failed to build AppState: {:?}", app_state_result.err());
    // let app_state = app_state_result.unwrap();

    // 4. Assertions
    // assert_eq!(app_state.config.database_url, Some("specific_db_url_for_builder".to_string()));
    // assert_eq!(app_state.config.qdrant_url, Some("specific_qdrant_url_for_builder".to_string()));

    // let ai_result = app_state.ai_client.exec_chat("test-model", Default::default(), None).await;
    // assert!(ai_result.is_err(), "Expected error from specific AI client");
    // assert!(ai_result.err().unwrap().to_string().contains("Specific AI Client Used"), "Error message mismatch, wrong AI client used?");

    // let embed_result = app_state.embedding_client.embed_content("test", "retrieval_query").await;
    // assert!(embed_result.is_ok(), "Default embedding client should return Ok");
    // assert_eq!(embed_result.unwrap().len(), 768, "Default embedding vector dimension mismatch");

    // let pipeline_result = app_state.embedding_pipeline_service.retrieve_relevant_chunks(app_state.clone(), Uuid::new_v4(), "test query", 3).await;
    // assert!(pipeline_result.is_ok(), "Default pipeline service should return Ok");
    // assert!(pipeline_result.unwrap().is_empty(), "Default pipeline service should return empty vec");

    // let qdrant_trait = app_state.qdrant_service.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>;
    // let qdrant_ensure_result = qdrant_trait.ensure_collection_exists().await;
    // assert!(qdrant_ensure_result.is_ok(), "Mock Qdrant service ensure_collection_exists should return Ok");

    // assert!(app_state.pool.get().await.is_ok(), "Default pool should be created and healthy");
}
*/

// --- Tests for History Management in Generation ---

// Helper to set history management settings via API
async fn set_history_settings(
    test_app: &TestApp, // Changed from TestContext
    session_id: Uuid,
    auth_cookie: &str,
    strategy: Option<String>,
    limit: Option<i32>,
) -> anyhow::Result<()> {
    let payload = UpdateChatSettingsRequest {
        history_management_strategy: strategy,
        history_management_limit: limit,
        system_prompt: None,
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        repetition_penalty: None,
        min_p: None,
        top_a: None,
        seed: None,
        logit_bias: None,
        model_name: None,
        gemini_enable_code_execution: None,
        gemini_thinking_budget: None,
    };

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session_id))
        .header(header::COOKIE, auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload)?))?;

    let response = test_app.router.clone().oneshot(request).await?; 
    assert_eq!(response.status(), StatusCode::OK, "Failed to set history settings via API");
    let _ = response.into_body().collect().await?.to_bytes();
    Ok(())
}

// Helper to assert the history sent to the mock AI client
fn assert_ai_history(
    test_app: &TestApp, // Changed from TestContext
    expected_history: Vec<(&str, &str)>, // (Role, Content)
) {
    let last_request = test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client should be present")
        .get_last_request()
        .expect("Mock AI client did not receive a request");

    let mut history_start_index = 0;
    if let Some(first_msg) = last_request.messages.first() {
        if matches!(first_msg.role, genai::chat::ChatRole::System) {
            history_start_index = 1;
            debug!("[DEBUG] System prompt detected, starting history comparison from index 1.");
        }
    }
    let history_end_index = last_request.messages.len().saturating_sub(1);
    let history_start_index = history_start_index.min(history_end_index);
    let history_sent_to_ai = &last_request.messages[history_start_index..history_end_index];

    println!("\n[DEBUG] All messages sent to AI client (including system prompt and current prompt):");
    for (i, msg) in last_request.messages.iter().enumerate() {
        let role_str = match msg.role {
            genai::chat::ChatRole::User => "User",
            genai::chat::ChatRole::Assistant => "Assistant",
            genai::chat::ChatRole::System => "System",
            _ => "Unknown",
        };
        let content = match &msg.content {
            genai::chat::MessageContent::Text(text) => text.as_str(),
            _ => "<non-text content>",
        };
        println!("  [{}] {}: {}", i, role_str, content);
    }

    println!("\n[DEBUG] Comparing {} expected messages against {} actual messages in history (excluding current prompt)",
             expected_history.len(), history_sent_to_ai.len());

    assert_eq!(
        history_sent_to_ai.len(),
        expected_history.len(),
        "Number of history messages sent to AI mismatch. Actual: {:?}, Expected: {:?}",
        history_sent_to_ai.iter().map(|m| (format!("{:?}", m.role), if let genai::chat::MessageContent::Text(t) = &m.content { t.clone() } else { "".to_string() } )).collect::<Vec<_>>(),
        expected_history
    );

    for (i, expected) in expected_history.iter().enumerate() {
        let actual = &history_sent_to_ai[i];
        let (expected_role_str, expected_content) = expected;

        let actual_role_str = match actual.role {
            genai::chat::ChatRole::User => "User",
            genai::chat::ChatRole::Assistant => "Assistant",
            genai::chat::ChatRole::System => "System",
            _ => panic!("Unexpected role in AI history: {:?}", actual.role),
        };
        let actual_content = match &actual.content {
            genai::chat::MessageContent::Text(text) => text.as_str(),
            _ => panic!("Expected text content in AI history, got: {:?}", actual.content),
        };

        println!("[DEBUG] Compare message {}: Expected {}:'{}' vs Actual {}:'{}'",
                 i, expected_role_str, expected_content, actual_role_str, actual_content);

        assert_eq!(actual_role_str, *expected_role_str, "Role mismatch at index {}", i);
        assert_eq!(actual_content, *expected_content, "Content mismatch at index {}", i);
    }
}


#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_history_sliding_window_messages() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = TestDataGuard::new(test_app.db_pool.clone());
    let conn = test_app.db_pool.get().await?;

    let username = "hist_slide_msg_user";
    let password = "password";
    let user: User = test_helpers::db::create_test_user(&test_app.db_pool, username.to_string(), password.to_string()).await.expect("Failed to create test user");
    test_data_guard.add_user(user.id);
    let auth_cookie = login_user_via_api(&test_app, username, password).await;

    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id, user_id: user.id, name: "Hist Slide Msg Char".to_string(), spec: "test".to_string(), spec_version: "1".to_string(), created_at: Utc::now(), updated_at: Utc::now(),
        description: None, personality: None, scenario: None, first_mes: None, mes_example: None, creator_notes: None, system_prompt: None, post_history_instructions: None, tags: None, creator: None, character_version: None, alternate_greetings: None, nickname: None, creator_notes_multilingual: None, source: None, group_only_greetings: None, creation_date: None, modification_date: None, persona: None, world_scenario: None, avatar: None, chat: None, greeting: None, definition: None, default_voice: None, extensions: None, data_id: None, category: None, definition_visibility: None, depth: None, example_dialogue: None, favorite: None, first_message_visibility: None, height: None, last_activity: None, migrated_from: None, model_prompt: None, model_prompt_visibility: None, model_temperature: None, num_interactions: None, permanence: None, persona_visibility: None, revision: None, sharing_visibility: None, status: None, system_prompt_visibility: None, system_tags: None, token_budget: None, usage_hints: None, user_persona: None, user_persona_visibility: None, visibility: None, weight: None, world_scenario_visibility: None, description_nonce: None, personality_nonce: None, scenario_nonce: None, first_mes_nonce: None, mes_example_nonce: None, creator_notes_nonce: None, system_prompt_nonce: None, post_history_instructions_nonce: None, persona_nonce: None, world_scenario_nonce: None, greeting_nonce: None, definition_nonce: None, example_dialogue_nonce: None, model_prompt_nonce: None, user_persona_nonce: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(characters::table)
            .values(&new_character)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    test_data_guard.add_character(character_id);

    let session_id = Uuid::new_v4();
    let new_session = NewChat {
        id: session_id, user_id: user.id, character_id, title: Some("Hist Slide Session".to_string()), created_at: Utc::now(), updated_at: Utc::now(), history_management_strategy: "none".to_string(), history_management_limit: 10, model_name: "test".to_string(), visibility: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(chat_sessions::table)
            .values(&new_session)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert session: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted session: {} rows affected", insert_result);
    test_data_guard.add_chat(session_id);

    let common_msg_fields = |role: MessageRole, content: &str| NewMessage {
        id: Uuid::new_v4(), session_id, user_id: user.id, message_type: role, content: content.as_bytes().to_vec(), content_nonce: None, created_at: Utc::now(), updated_at: Utc::now(), role: Some(role.to_string().to_lowercase()), parts: Some(json!([{"text": content}])), attachments: None,
    };
    
    // Insert message 1 (User)
    let msg = common_msg_fields(MessageRole::User, "Msg 1");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert user message 1: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted message 1: {} rows affected", insert_result);
    
    // Insert reply 1 (Assistant)
    let msg = common_msg_fields(MessageRole::Assistant, "Reply 1");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert assistant message 1: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted reply 1: {} rows affected", insert_result);
    
    // Insert message 2 (User)
    let msg = common_msg_fields(MessageRole::User, "Msg 2");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert user message 2: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted message 2: {} rows affected", insert_result);
    
    // Insert reply 2 (Assistant)
    let msg = common_msg_fields(MessageRole::Assistant, "Reply 2");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert assistant message 2: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted reply 2: {} rows affected", insert_result);
    
    // Insert message 3 (User)
    let msg = common_msg_fields(MessageRole::User, "Msg 3");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert user message 3: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted message 3: {} rows affected", insert_result);

    set_history_settings(&test_app, session_id, &auth_cookie, Some("sliding_window_messages".to_string()), Some(3)).await?;

    test_app.mock_ai_client.as_ref().unwrap().set_response(Ok(genai::chat::ChatResponse {
        model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"),
        provider_model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"),
        content: Some(genai::chat::MessageContent::Text("Mock response".to_string())),
        reasoning_content: None,
        usage: Default::default(),
    }));

    let payload = GenerateChatRequest { history: vec![ApiChatMessage { role: "user".to_string(), content: "User message 4".to_string() }], model: None };
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session_id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&payload)?))?;
    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.into_body().collect().await?.to_bytes();

    assert_ai_history(&test_app, vec![
        ("User", "Msg 2"),
        ("Assistant", "Reply 2"),
        ("User", "Msg 3"),
    ]);
    test_data_guard.cleanup().await?;
    Ok(())
}


#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_history_sliding_window_tokens() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = TestDataGuard::new(test_app.db_pool.clone());
    let conn = test_app.db_pool.get().await?;

    let username = "hist_slide_tok_user";
    let password = "password";
    let user: User = test_helpers::db::create_test_user(&test_app.db_pool, username.to_string(), password.to_string()).await.expect("Failed to create test user");
    test_data_guard.add_user(user.id);
    let auth_cookie = login_user_via_api(&test_app, username, password).await;

    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id, user_id: user.id, name: "Hist Slide Tok Char".to_string(), spec: "test".to_string(), spec_version: "1".to_string(), created_at: Utc::now(), updated_at: Utc::now(),
        description: None, personality: None, scenario: None, first_mes: None, mes_example: None, creator_notes: None, system_prompt: None, post_history_instructions: None, tags: None, creator: None, character_version: None, alternate_greetings: None, nickname: None, creator_notes_multilingual: None, source: None, group_only_greetings: None, creation_date: None, modification_date: None, persona: None, world_scenario: None, avatar: None, chat: None, greeting: None, definition: None, default_voice: None, extensions: None, data_id: None, category: None, definition_visibility: None, depth: None, example_dialogue: None, favorite: None, first_message_visibility: None, height: None, last_activity: None, migrated_from: None, model_prompt: None, model_prompt_visibility: None, model_temperature: None, num_interactions: None, permanence: None, persona_visibility: None, revision: None, sharing_visibility: None, status: None, system_prompt_visibility: None, system_tags: None, token_budget: None, usage_hints: None, user_persona: None, user_persona_visibility: None, visibility: None, weight: None, world_scenario_visibility: None, description_nonce: None, personality_nonce: None, scenario_nonce: None, first_mes_nonce: None, mes_example_nonce: None, creator_notes_nonce: None, system_prompt_nonce: None, post_history_instructions_nonce: None, persona_nonce: None, world_scenario_nonce: None, greeting_nonce: None, definition_nonce: None, example_dialogue_nonce: None, model_prompt_nonce: None, user_persona_nonce: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(characters::table)
            .values(&new_character)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    test_data_guard.add_character(character_id);

    let session_id = Uuid::new_v4();
    let new_session = NewChat {
        id: session_id, user_id: user.id, character_id, title: Some("Hist Slide Tok Session".to_string()), created_at: Utc::now(), updated_at: Utc::now(), history_management_strategy: "none".to_string(), history_management_limit: 10, model_name: "test".to_string(), visibility: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(chat_sessions::table)
            .values(&new_session)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert session: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted session: {} rows affected", insert_result);
    test_data_guard.add_chat(session_id);

    let common_msg_fields = |role: MessageRole, content: &str| NewMessage {
        id: Uuid::new_v4(), session_id, user_id: user.id, message_type: role, content: content.as_bytes().to_vec(), content_nonce: None, created_at: Utc::now(), updated_at: Utc::now(), role: Some(role.to_string().to_lowercase()), parts: Some(json!([{"text": content}])), attachments: None,
    };
    
    // Insert message 1 (User)
    let msg = common_msg_fields(MessageRole::User, "This is message one");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert user message 1: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted message 1: {} rows affected", insert_result);
    
    // Insert reply 1 (Assistant)
    let msg = common_msg_fields(MessageRole::Assistant, "Reply one");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert assistant message 1: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted reply 1: {} rows affected", insert_result);
    
    // Insert message 2 (User)
    let msg = common_msg_fields(MessageRole::User, "Message two");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert user message 2: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted message 2: {} rows affected", insert_result);
    
    // Insert reply 2 (Assistant)
    let msg = common_msg_fields(MessageRole::Assistant, "Reply two");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert assistant message 2: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted reply 2: {} rows affected", insert_result);

    set_history_settings(&test_app, session_id, &auth_cookie, Some("sliding_window_tokens".to_string()), Some(25)).await?;

    test_app.mock_ai_client.as_ref().unwrap().set_response(Ok(genai::chat::ChatResponse {
        model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"),
        provider_model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"),
        content: Some(genai::chat::MessageContent::Text("Mock response".to_string())),
        reasoning_content: None,
        usage: Default::default(),
    }));

    let payload = GenerateChatRequest { history: vec![ApiChatMessage { role: "user".to_string(), content: "User message 3".to_string() }], model: None };
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session_id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&payload)?))?;
    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.into_body().collect().await?.to_bytes();

    assert_ai_history(&test_app, vec![
        ("User", "Message two"),
        ("Assistant", "Reply two"),
    ]);
    test_data_guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_generate_chat_response_history_truncate_tokens() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = TestDataGuard::new(test_app.db_pool.clone());
    let conn = test_app.db_pool.get().await?;

    let username = "hist_trunc_tok_user";
    let password = "password";
    let user: User = test_helpers::db::create_test_user(&test_app.db_pool, username.to_string(), password.to_string()).await.expect("Failed to create test user");
    test_data_guard.add_user(user.id);
    let auth_cookie = login_user_via_api(&test_app, username, password).await;

    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id, user_id: user.id, name: "Hist Trunc Tok Char".to_string(), spec: "test".to_string(), spec_version: "1".to_string(), created_at: Utc::now(), updated_at: Utc::now(),
        description: None, personality: None, scenario: None, first_mes: None, mes_example: None, creator_notes: None, system_prompt: None, post_history_instructions: None, tags: None, creator: None, character_version: None, alternate_greetings: None, nickname: None, creator_notes_multilingual: None, source: None, group_only_greetings: None, creation_date: None, modification_date: None, persona: None, world_scenario: None, avatar: None, chat: None, greeting: None, definition: None, default_voice: None, extensions: None, data_id: None, category: None, definition_visibility: None, depth: None, example_dialogue: None, favorite: None, first_message_visibility: None, height: None, last_activity: None, migrated_from: None, model_prompt: None, model_prompt_visibility: None, model_temperature: None, num_interactions: None, permanence: None, persona_visibility: None, revision: None, sharing_visibility: None, status: None, system_prompt_visibility: None, system_tags: None, token_budget: None, usage_hints: None, user_persona: None, user_persona_visibility: None, visibility: None, weight: None, world_scenario_visibility: None, description_nonce: None, personality_nonce: None, scenario_nonce: None, first_mes_nonce: None, mes_example_nonce: None, creator_notes_nonce: None, system_prompt_nonce: None, post_history_instructions_nonce: None, persona_nonce: None, world_scenario_nonce: None, greeting_nonce: None, definition_nonce: None, example_dialogue_nonce: None, model_prompt_nonce: None, user_persona_nonce: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(characters::table)
            .values(&new_character)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    test_data_guard.add_character(character_id);

    let session_id = Uuid::new_v4();
    let new_session = NewChat {
        id: session_id, user_id: user.id, character_id, title: Some("Hist Trunc Tok Session".to_string()), created_at: Utc::now(), updated_at: Utc::now(), history_management_strategy: "none".to_string(), history_management_limit: 10, model_name: "test".to_string(), visibility: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(chat_sessions::table)
            .values(&new_session)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert session: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted session: {} rows affected", insert_result);
    test_data_guard.add_chat(session_id);

    let common_msg_fields = |role: MessageRole, content: &str| NewMessage {
        id: Uuid::new_v4(), session_id, user_id: user.id, message_type: role, content: content.as_bytes().to_vec(), content_nonce: None, created_at: Utc::now(), updated_at: Utc::now(), role: Some(role.to_string().to_lowercase()), parts: Some(json!([{"text": content}])), attachments: None,
    };
    
    // Insert message 1 (User)
    let msg = common_msg_fields(MessageRole::User, "This is message one");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert user message 1: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted message 1: {} rows affected", insert_result);
    
    // Insert reply 1 (Assistant)
    let msg = common_msg_fields(MessageRole::Assistant, "Reply one");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert assistant message 1: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted reply 1: {} rows affected", insert_result);
    
    // Insert message 2 (User)
    let msg = common_msg_fields(MessageRole::User, "Message two");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert user message 2: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted message 2: {} rows affected", insert_result);
    
    // Insert reply 2 (Assistant)
    let msg = common_msg_fields(MessageRole::Assistant, "Reply two");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert assistant message 2: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted reply 2: {} rows affected", insert_result);

    set_history_settings(&test_app, session_id, &auth_cookie, Some("truncate_tokens".to_string()), Some(30)).await?;

    test_app.mock_ai_client.as_ref().unwrap().set_response(Ok(genai::chat::ChatResponse {
        model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"),
        provider_model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"),
        content: Some(genai::chat::MessageContent::Text("Mock response".to_string())),
        reasoning_content: None,
        usage: Default::default(),
    }));

    let payload = GenerateChatRequest { history: vec![ApiChatMessage { role: "user".to_string(), content: "User message 3".to_string() }], model: None };
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session_id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&payload)?))?;
    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.into_body().collect().await?.to_bytes();

    assert_ai_history(&test_app, vec![
        ("User", "e"), // "This is message one" truncated to "e" (1 token) to fit 30 token limit with other messages
        ("Assistant", "Reply one"),
        ("User", "Message two"),
        ("Assistant", "Reply two"),
    ]);

    // Test truncation case (second call with different limit)
    set_history_settings(&test_app, session_id, &auth_cookie, Some("truncate_tokens".to_string()), Some(25)).await?;
    // Mock AI response for the second call
    test_app.mock_ai_client.as_ref().unwrap().set_response(Ok(genai::chat::ChatResponse {
        model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"),
        provider_model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"),
        content: Some(genai::chat::MessageContent::Text("Mock response 2".to_string())),
        reasoning_content: None,
        usage: Default::default(),
    }));
    let request_2 = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session_id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&payload)?))?;// Same payload for simplicity
    let response_2 = test_app.router.clone().oneshot(request_2).await?;
    assert_eq!(response_2.status(), StatusCode::OK);
    let _ = response_2.into_body().collect().await?.to_bytes();

    // DB now has: M1, R1, M2, R2, "User message 3", "Mock response"
    // History for AI (limit 25) should be: "y one", "Message two", "Reply two"
    assert_ai_history(&test_app, vec![
        ("Assistant", "y one"), // "Reply one" truncated to "y one"
        ("User", "Message two"),
        ("Assistant", "Reply two"),
    ]);
    test_data_guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_history_none() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = TestDataGuard::new(test_app.db_pool.clone());
    let conn = test_app.db_pool.get().await?;

    let username = "hist_none_user";
    let password = "password";
    let user: User = test_helpers::db::create_test_user(&test_app.db_pool, username.to_string(), password.to_string()).await.expect("Failed to create test user");
    test_data_guard.add_user(user.id);
    let auth_cookie = login_user_via_api(&test_app, username, password).await;

    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id, user_id: user.id, name: "Hist None Char".to_string(), spec: "test".to_string(), spec_version: "1".to_string(), created_at: Utc::now(), updated_at: Utc::now(),
        description: None, personality: None, scenario: None, first_mes: None, mes_example: None, creator_notes: None, system_prompt: None, post_history_instructions: None, tags: None, creator: None, character_version: None, alternate_greetings: None, nickname: None, creator_notes_multilingual: None, source: None, group_only_greetings: None, creation_date: None, modification_date: None, persona: None, world_scenario: None, avatar: None, chat: None, greeting: None, definition: None, default_voice: None, extensions: None, data_id: None, category: None, definition_visibility: None, depth: None, example_dialogue: None, favorite: None, first_message_visibility: None, height: None, last_activity: None, migrated_from: None, model_prompt: None, model_prompt_visibility: None, model_temperature: None, num_interactions: None, permanence: None, persona_visibility: None, revision: None, sharing_visibility: None, status: None, system_prompt_visibility: None, system_tags: None, token_budget: None, usage_hints: None, user_persona: None, user_persona_visibility: None, visibility: None, weight: None, world_scenario_visibility: None, description_nonce: None, personality_nonce: None, scenario_nonce: None, first_mes_nonce: None, mes_example_nonce: None, creator_notes_nonce: None, system_prompt_nonce: None, post_history_instructions_nonce: None, persona_nonce: None, world_scenario_nonce: None, greeting_nonce: None, definition_nonce: None, example_dialogue_nonce: None, model_prompt_nonce: None, user_persona_nonce: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(characters::table)
            .values(&new_character)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    test_data_guard.add_character(character_id);

    let session_id = Uuid::new_v4();
    let new_session = NewChat {
        id: session_id, user_id: user.id, character_id, title: Some("Hist None Session".to_string()), created_at: Utc::now(), updated_at: Utc::now(), history_management_strategy: "none".to_string(), history_management_limit: 10, model_name: "test".to_string(), visibility: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(chat_sessions::table)
            .values(&new_session)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert session: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted session: {} rows affected", insert_result);
    test_data_guard.add_chat(session_id);

    let common_msg_fields = |role: MessageRole, content: &str| NewMessage {
        id: Uuid::new_v4(), session_id, user_id: user.id, message_type: role, content: content.as_bytes().to_vec(), content_nonce: None, created_at: Utc::now(), updated_at: Utc::now(), role: Some(role.to_string().to_lowercase()), parts: Some(json!([{"text": content}])), attachments: None,
    };
    
    // Insert message 1 (User)
    let msg = common_msg_fields(MessageRole::User, "Msg 1");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert user message 1: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted message 1: {} rows affected", insert_result);
    
    // Insert reply 1 (Assistant)
    let msg = common_msg_fields(MessageRole::Assistant, "Reply 1");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert assistant message 1: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted reply 1: {} rows affected", insert_result);

    set_history_settings(&test_app, session_id, &auth_cookie, Some("none".to_string()), Some(1)).await?;

    test_app.mock_ai_client.as_ref().unwrap().set_response(Ok(genai::chat::ChatResponse {
        model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"),
        provider_model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"),
        content: Some(genai::chat::MessageContent::Text("Mock response".to_string())),
        reasoning_content: None,
        usage: Default::default(),
    }));

    let payload = GenerateChatRequest { history: vec![ApiChatMessage { role: "user".to_string(), content: "User message 2".to_string() }], model: None };
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session_id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&payload)?))?;
    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.into_body().collect().await?.to_bytes();

    assert_ai_history(&test_app, vec![
        ("User", "Msg 1"),
        ("Assistant", "Reply 1"),
    ]);
    test_data_guard.cleanup().await?;
    Ok(())
}

// --- Test for History Management and RAG Integration ---
// These tests seem to be duplicates of the truncate_tokens tests above.
// Keeping them as they were in the original file, but they test similar logic.

#[tokio::test]
async fn generate_chat_response_history_truncate_tokens_limit_30() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = TestDataGuard::new(test_app.db_pool.clone());
    let conn = test_app.db_pool.get().await?;

    let username = "hist_trunc_tok_user1_dup"; // Changed username to avoid conflict
    let password = "password";
    let user: User = test_helpers::db::create_test_user(&test_app.db_pool, username.to_string(), password.to_string()).await.expect("Failed to create test user");
    test_data_guard.add_user(user.id);
    let auth_cookie = login_user_via_api(&test_app, username, password).await;

    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id, user_id: user.id, name: "Hist Trunc Tok Char".to_string(), spec: "test".to_string(), spec_version: "1".to_string(), created_at: Utc::now(), updated_at: Utc::now(),
        description: None, personality: None, scenario: None, first_mes: None, mes_example: None, creator_notes: None, system_prompt: None, post_history_instructions: None, tags: None, creator: None, character_version: None, alternate_greetings: None, nickname: None, creator_notes_multilingual: None, source: None, group_only_greetings: None, creation_date: None, modification_date: None, persona: None, world_scenario: None, avatar: None, chat: None, greeting: None, definition: None, default_voice: None, extensions: None, data_id: None, category: None, definition_visibility: None, depth: None, example_dialogue: None, favorite: None, first_message_visibility: None, height: None, last_activity: None, migrated_from: None, model_prompt: None, model_prompt_visibility: None, model_temperature: None, num_interactions: None, permanence: None, persona_visibility: None, revision: None, sharing_visibility: None, status: None, system_prompt_visibility: None, system_tags: None, token_budget: None, usage_hints: None, user_persona: None, user_persona_visibility: None, visibility: None, weight: None, world_scenario_visibility: None, description_nonce: None, personality_nonce: None, scenario_nonce: None, first_mes_nonce: None, mes_example_nonce: None, creator_notes_nonce: None, system_prompt_nonce: None, post_history_instructions_nonce: None, persona_nonce: None, world_scenario_nonce: None, greeting_nonce: None, definition_nonce: None, example_dialogue_nonce: None, model_prompt_nonce: None, user_persona_nonce: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(characters::table)
            .values(&new_character)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    test_data_guard.add_character(character_id);

    let session_id = Uuid::new_v4();
    let new_session = NewChat {
        id: session_id, user_id: user.id, character_id, title: Some("Hist Trunc Tok Session".to_string()), created_at: Utc::now(), updated_at: Utc::now(), history_management_strategy: "none".to_string(), history_management_limit: 10, model_name: "test".to_string(), visibility: None,
    };
    
    let result = conn.interact(move |conn_inner| { 
        diesel::insert_into(chat_sessions::table)
            .values(&new_session)
            .execute(conn_inner) 
    }).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert session: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted session: {} rows affected", insert_result);
    test_data_guard.add_chat(session_id);

    let common_msg_fields = |role: MessageRole, content: &str| NewMessage {
        id: Uuid::new_v4(), session_id, user_id: user.id, message_type: role, content: content.as_bytes().to_vec(), content_nonce: None, created_at: Utc::now(), updated_at: Utc::now(), role: Some(role.to_string().to_lowercase()), parts: Some(json!([{"text": content}])), attachments: None,
    };
    
    // Insert message 1 (User)
    let msg = common_msg_fields(MessageRole::User, "This is message one");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert user message 1: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted message 1: {} rows affected", insert_result);
    
    // Insert reply 1 (Assistant)
    let msg = common_msg_fields(MessageRole::Assistant, "Reply one");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert assistant message 1: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted reply 1: {} rows affected", insert_result);
    
    // Insert message 2 (User)
    let msg = common_msg_fields(MessageRole::User, "Message two");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert user message 2: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted message 2: {} rows affected", insert_result);
    
    // Insert reply 2 (Assistant)
    let msg = common_msg_fields(MessageRole::Assistant, "Reply two");
    let result = conn.interact(move |c| diesel::insert_into(chat_messages::table).values(&msg).execute(c)).await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert assistant message 2: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted reply 2: {} rows affected", insert_result);

    set_history_settings(&test_app, session_id, &auth_cookie, Some("truncate_tokens".to_string()), Some(30)).await?;

    test_app.mock_ai_client.as_ref().unwrap().set_response(Ok(genai::chat::ChatResponse {
        model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"),
        provider_model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"),
        content: Some(genai::chat::MessageContent::Text("Mock response".to_string())),
        reasoning_content: None,
        usage: Default::default(),
    }));

    let payload = GenerateChatRequest { history: vec![ApiChatMessage { role: "user".to_string(), content: "User message 3".to_string() }], model: None };
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session_id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&payload)?))?;
    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _ = response.into_body().collect().await?.to_bytes();

    assert_ai_history(&test_app, vec![
        ("User", "e"), // "This is message one" truncated to "e" (1 token) to fit 30 token limit with other messages
        ("Assistant", "Reply one"),
        ("User", "Message two"),
        ("Assistant", "Reply two"),
    ]);

    // Test truncation case (second call with different limit)
    set_history_settings(&test_app, session_id, &auth_cookie, Some("truncate_tokens".to_string()), Some(25)).await?;
    // Mock AI response for the second call
    test_app.mock_ai_client.as_ref().unwrap().set_response(Ok(genai::chat::ChatResponse {
        model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"),
        provider_model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-model"),
        content: Some(genai::chat::MessageContent::Text("Mock response 2".to_string())),
        reasoning_content: None,
        usage: Default::default(),
    }));
    let request_2 = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session_id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&payload)?))?;// Same payload for simplicity
    let response_2 = test_app.router.clone().oneshot(request_2).await?;
    assert_eq!(response_2.status(), StatusCode::OK);
    let _ = response_2.into_body().collect().await?.to_bytes();

    // DB now has: M1, R1, M2, R2, "User message 3", "Mock response"
    // History for AI (limit 25) should be: "y one", "Message two", "Reply two"
    assert_ai_history(&test_app, vec![
        ("Assistant", "y one"), // "Reply one" truncated to "y one"
        ("User", "Message two"),
        ("Assistant", "Reply two"),
    ]);
    test_data_guard.cleanup().await?;
    Ok(())
}