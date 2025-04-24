// Integration tests for chat routes

use axum::{
    body::{Body},
    http::{header, Method, Request, StatusCode},
    // Removed Router
};
use bigdecimal::{BigDecimal}; // Removed FromPrimitive, ToPrimitive
use futures::{TryStreamExt}; // Removed StreamExt, stream, Stream
use genai::{
    adapter::AdapterKind, // Added
    chat::{ChatResponse, MessageContent, Usage, ChatStreamEvent, ChatRole}, // Added ChatResponse, MessageContent, Usage, ChatRole // Removed StreamChunk
    // Removed Error as GenAIError
    ModelIden // Added
    // Removed ModelIden
};
use mime;
use serde_json::{json, Value};
use std::{str::FromStr, time::Duration}; // Removed sync::Arc, pin::Pin, convert::Infallible
use tower::ServiceExt;
use uuid::Uuid;
use http_body_util::BodyExt; // Add this back for .collect()

// Crate imports
use scribe_backend::{ // Use crate name directly
    errors::AppError,
    models::{
        chats::{
            ChatSession, ChatMessage, MessageRole, NewChatMessageRequest,
            UpdateChatSettingsRequest, ChatSettingsResponse, // Removed NewChatSession,
            // Removed NewChatMessage, SettingsTuple, DbInsertableChatMessage,
        },
        // Removed characters::Character
        // users::User, // Not directly needed if using test_helpers
    },
    test_helpers::{self}, // Removed TestContext
};

// Helper function to parse SSE stream manually
async fn collect_sse_data(body: axum::body::Body) -> Vec<String> {
    let mut data_chunks = Vec::new();
    let stream = body.into_data_stream();

    stream.try_for_each(|buf| {
        // Parse SSE format: "data: content\n\n"
        let lines = String::from_utf8_lossy(&buf);
        for line in lines.lines() {
            if let Some(data) = line.strip_prefix("data: ") {
                if !data.is_empty() {
                    data_chunks.push(data.to_string());
                }
            }
        }
        futures::future::ready(Ok(()))
    })
    .await
    .expect("Failed to read SSE stream");

    data_chunks
}

#[tokio::test]
async fn test_create_chat_session_success() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::create_test_user_and_login(&context.app, "test_create_chat_user", "password").await;
    let character = test_helpers::create_test_character(&context.app.db_pool, user.id, "Test Character for Chat").await;
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
    let session: ChatSession = serde_json::from_slice(&body).expect("Failed to deserialize response");
    assert_eq!(session.user_id, user.id);
    assert_eq!(session.character_id, character.id);
}

#[tokio::test]
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
async fn test_create_chat_session_character_not_found() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _user) = test_helpers::create_test_user_and_login(&context.app, "test_char_not_found_user", "password").await;
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
    // Optionally check error message structure if your AppError provides it
    // let body = response.into_body().collect().await.unwrap().to_bytes();
    // let error_response: Value = serde_json::from_slice(&body).unwrap();
    // assert!(error_response["error"].as_str().unwrap().contains("Character not found"));
}

#[tokio::test]
async fn test_create_chat_session_character_other_user() {
     let context = test_helpers::setup_test_app().await;
     let (_auth_cookie1, user1) = test_helpers::create_test_user_and_login(&context.app, "chat_user_1", "password").await;
     let character = test_helpers::create_test_character(&context.app.db_pool, user1.id, "User1 Character").await;
     let (auth_cookie2, _user2) = test_helpers::create_test_user_and_login(&context.app, "chat_user_2", "password").await;

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
     // Optionally check error message
     // let body = response.into_body().collect().await.unwrap().to_bytes();
     // let error_response: Value = serde_json::from_slice(&body).unwrap();
     // assert!(error_response["error"].as_str().unwrap().contains("access denied"));
}


#[tokio::test]
async fn test_list_chat_sessions_success() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::create_test_user_and_login(&context.app, "test_list_chats_user", "password").await;

    // Create a character and sessions for the user
    let char1 = test_helpers::create_test_character(&context.app.db_pool, user.id, "Char 1 for List").await;
    let char2 = test_helpers::create_test_character(&context.app.db_pool, user.id, "Char 2 for List").await;
    let session1 = test_helpers::create_test_chat_session(&context.app.db_pool, user.id, char1.id).await;
    let session2 = test_helpers::create_test_chat_session(&context.app.db_pool, user.id, char2.id).await;

    // Create data for another user (should not be listed)
    let other_user = test_helpers::create_test_user(&context.app.db_pool, "other_list_user", "password").await;
    let other_char = test_helpers::create_test_character(&context.app.db_pool, other_user.id, "Other User Char").await;
    let _other_session = test_helpers::create_test_chat_session(&context.app.db_pool, other_user.id, other_char.id).await; // Renamed to avoid unused var warning

    let request = Request::builder()
        .method(Method::GET) // Use Method::GET
        .uri("/api/chats")
        .header(header::COOKIE, auth_cookie) // Use cookie
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap(); // Use context.app.router

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let sessions: Vec<ChatSession> = serde_json::from_slice(&body).expect("Failed to deserialize list response");

    assert_eq!(sessions.len(), 2);
    // Order is DESC by updated_at, so session2 should likely be first if inserted later
    assert!(sessions.iter().any(|s| s.id == session1.id));
    assert!(sessions.iter().any(|s| s.id == session2.id));
    assert!(sessions.iter().all(|s| s.user_id == user.id));
}

#[tokio::test]
async fn test_list_chat_sessions_empty() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _user) = test_helpers::create_test_user_and_login(&context.app, "test_list_empty_user", "password").await;

    let request = Request::builder()
        .method(Method::GET) // Use Method::GET
        .uri("/api/chats")
        .header(header::COOKIE, auth_cookie) // Use cookie
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap(); // Use context.app.router

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let sessions: Vec<ChatSession> = serde_json::from_slice(&body).expect("Failed to deserialize empty list response");
    assert!(sessions.is_empty());
}

#[tokio::test]
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

// TODO: Add tests for get_chat_messages
// TODO: Add tests for generate_chat_response (requires mocking AI client in TestContext)

// --- Test Cases from tests/chat_tests.rs (now integrated) ---

#[tokio::test]
async fn list_chat_sessions_success_integration() { // Kept suffix for clarity
    let context = test_helpers::setup_test_app().await; // Use non-mutable context
    let (auth_cookie, test_user) = test_helpers::create_test_user_and_login(&context.app, "test_list_chats_integ", "password").await;
    let test_character = test_helpers::create_test_character(&context.app.db_pool, test_user.id, "Test Char for List Integ").await;
    let session1 = test_helpers::create_test_chat_session(&context.app.db_pool, test_user.id, test_character.id).await;
    let session2 = test_helpers::create_test_chat_session(&context.app.db_pool, test_user.id, test_character.id).await;
    let other_user = test_helpers::create_test_user(&context.app.db_pool, "other_user_integ", "password").await;
    let other_character = test_helpers::create_test_character(&context.app.db_pool, other_user.id, "Other Char Integ").await;
    let _other_session = test_helpers::create_test_chat_session(&context.app.db_pool, other_user.id, other_character.id).await;
    let request = Request::builder()
        .uri(format!("/api/chats")) // Relative URI ok for oneshot
        .method(Method::GET)
        .header("Cookie", auth_cookie)
        .body(Body::empty())
        .unwrap();
    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");
    let sessions_array = body_json.as_array().expect("Response body should be a JSON array");
    assert_eq!(sessions_array.len(), 2, "Should return exactly 2 sessions for the logged-in user");
    let sessions: Vec<ChatSession> = serde_json::from_value(body_json).expect("Failed to deserialize sessions");
    assert!(sessions.iter().all(|s| s.user_id == test_user.id));
    assert!(sessions.iter().any(|s| s.id == session1.id));
    assert!(sessions.iter().any(|s| s.id == session2.id));
}

#[tokio::test]
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
async fn list_chat_sessions_empty_integration() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _test_user) = test_helpers::create_test_user_and_login(&context.app, "test_list_empty_integ", "password").await;
    let request = Request::builder()
        .uri(format!("/api/chats"))
        .method(Method::GET)
        .header("Cookie", auth_cookie)
        .body(Body::empty())
        .unwrap();
    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");
    let sessions_array = body_json.as_array().expect("Response body should be a JSON array");
    assert!(sessions_array.is_empty(), "Should return an empty array for a user with no sessions");
}

// --- Tests for GET /api/chats/{id}/messages ---

#[tokio::test]
async fn get_chat_messages_success_integration() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, test_user) = test_helpers::create_test_user_and_login(&context.app, "test_get_msgs_integ", "password").await;


// --- Tests for GET /api/chats/{id}/settings ---

#[tokio::test]
async fn get_chat_settings_success() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::create_test_user_and_login(&context.app, "get_settings_user", "password").await;
    let character = test_helpers::create_test_character(&context.app.db_pool, user.id, "Settings Char").await;
    let session = test_helpers::create_test_chat_session(&context.app.db_pool, user.id, character.id).await;

    // Manually update settings in DB for this test
    let expected_prompt = "Test System Prompt";
    let expected_temp = BigDecimal::from_str("0.75").unwrap();
    let expected_tokens = 512_i32;
    let expected_freq_penalty = BigDecimal::from_str("0.2").unwrap();
    let expected_pres_penalty = BigDecimal::from_str("0.1").unwrap();
    let expected_top_k = 40_i32;
    let expected_top_p = BigDecimal::from_str("0.95").unwrap();
    let expected_rep_penalty = BigDecimal::from_str("1.2").unwrap();
    let expected_min_p = BigDecimal::from_str("0.05").unwrap();
    let expected_top_a = BigDecimal::from_str("0.9").unwrap();
    let expected_seed = 12345_i32;
    let expected_logit_bias = serde_json::json!({
        "10001": -100,
        "10002": 100
    });

    // Use update_all_chat_settings to update all fields
    test_helpers::update_all_chat_settings(
        &context.app.db_pool,
        session.id,
        Some(expected_prompt.to_string()),
        Some(expected_temp.clone()),
        Some(expected_tokens),
        Some(expected_freq_penalty.clone()),
        Some(expected_pres_penalty.clone()),
        Some(expected_top_k),
        Some(expected_top_p.clone()),
        Some(expected_rep_penalty.clone()),
        Some(expected_min_p.clone()),
        Some(expected_top_a.clone()),
        Some(expected_seed),
        Some(expected_logit_bias.clone())
    ).await;

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let settings_resp: ChatSettingsResponse = serde_json::from_slice(&body).expect("Failed to deserialize settings response");

    // Check all fields match expected values
    assert_eq!(settings_resp.system_prompt, Some(expected_prompt.to_string()));
    assert_eq!(settings_resp.temperature, Some(expected_temp));
    assert_eq!(settings_resp.max_output_tokens, Some(expected_tokens));
    assert_eq!(settings_resp.frequency_penalty, Some(expected_freq_penalty));
    assert_eq!(settings_resp.presence_penalty, Some(expected_pres_penalty));
    assert_eq!(settings_resp.top_k, Some(expected_top_k));
    assert_eq!(settings_resp.top_p, Some(expected_top_p));
    assert_eq!(settings_resp.repetition_penalty, Some(expected_rep_penalty));
    assert_eq!(settings_resp.min_p, Some(expected_min_p));
    assert_eq!(settings_resp.top_a, Some(expected_top_a));
    assert_eq!(settings_resp.seed, Some(expected_seed));
    assert_eq!(settings_resp.logit_bias, Some(expected_logit_bias));
}

#[tokio::test]
async fn get_chat_settings_defaults() {
    // Test case where settings are NULL in DB
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::create_test_user_and_login(&context.app, "get_defaults_user", "password").await;
    let character = test_helpers::create_test_character(&context.app.db_pool, user.id, "Defaults Char").await;
    let session = test_helpers::create_test_chat_session(&context.app.db_pool, user.id, character.id).await;
    // No settings updated, should be NULL

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let settings_resp: ChatSettingsResponse = serde_json::from_slice(&body).expect("Failed to deserialize settings response");

    // Check all fields are None
    assert_eq!(settings_resp.system_prompt, None);
    assert_eq!(settings_resp.temperature, None);
    assert_eq!(settings_resp.max_output_tokens, None);
    assert_eq!(settings_resp.frequency_penalty, None);
    assert_eq!(settings_resp.presence_penalty, None);
    assert_eq!(settings_resp.top_k, None);
    assert_eq!(settings_resp.top_p, None);
    assert_eq!(settings_resp.repetition_penalty, None);
    assert_eq!(settings_resp.min_p, None);
    assert_eq!(settings_resp.top_a, None);
    assert_eq!(settings_resp.seed, None);
    assert_eq!(settings_resp.logit_bias, None);
}


// --- Tests for PUT /api/chats/{id}/settings ---

#[tokio::test]
async fn update_chat_settings_success_full() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::create_test_user_and_login(&context.app, "update_settings_user", "password").await;
    let character = test_helpers::create_test_character(&context.app.db_pool, user.id, "Update Settings Char").await;
    let session = test_helpers::create_test_chat_session(&context.app.db_pool, user.id, character.id).await;

    let new_prompt = "New System Prompt";
    let new_temp = BigDecimal::from_str("0.9").unwrap();
    let new_tokens = 1024_i32;
    let new_freq_penalty = BigDecimal::from_str("0.3").unwrap();
    let new_pres_penalty = BigDecimal::from_str("0.2").unwrap();
    let new_top_k = 30_i32;
    let new_top_p = BigDecimal::from_str("0.85").unwrap();
    let new_rep_penalty = BigDecimal::from_str("1.1").unwrap();
    let new_min_p = BigDecimal::from_str("0.1").unwrap();
    let new_top_a = BigDecimal::from_str("0.8").unwrap();
    let new_seed = 54321_i32;
    let new_logit_bias = serde_json::json!({
        "20001": -50,
        "20002": 50
    });

    let payload = UpdateChatSettingsRequest {
        system_prompt: Some(new_prompt.to_string()),
        temperature: Some(new_temp.clone()),
        max_output_tokens: Some(new_tokens),
        frequency_penalty: Some(new_freq_penalty.clone()),
        presence_penalty: Some(new_pres_penalty.clone()),
        top_k: Some(new_top_k),
        top_p: Some(new_top_p.clone()),
        repetition_penalty: Some(new_rep_penalty.clone()),
        min_p: Some(new_min_p.clone()),
        top_a: Some(new_top_a.clone()),
        seed: Some(new_seed),
        logit_bias: Some(new_logit_bias.clone()),
    };

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify changes in DB
    let db_settings = test_helpers::get_chat_session_settings(&context.app.db_pool, session.id).await.unwrap();

    // Check all fields
    assert_eq!(db_settings.0, Some(new_prompt.to_string())); // system_prompt
    assert_eq!(db_settings.1, Some(new_temp)); // temperature
    assert_eq!(db_settings.2, Some(new_tokens)); // max_output_tokens
    assert_eq!(db_settings.3, Some(new_freq_penalty)); // frequency_penalty
    assert_eq!(db_settings.4, Some(new_pres_penalty)); // presence_penalty
    assert_eq!(db_settings.5, Some(new_top_k)); // top_k
    assert_eq!(db_settings.6, Some(new_top_p)); // top_p
    assert_eq!(db_settings.7, Some(new_rep_penalty)); // repetition_penalty
    assert_eq!(db_settings.8, Some(new_min_p)); // min_p
    assert_eq!(db_settings.9, Some(new_top_a)); // top_a
    assert_eq!(db_settings.10, Some(new_seed)); // seed

    // For JSON comparison, need to deserialize
    let db_logit_bias: serde_json::Value = serde_json::from_value(db_settings.11.unwrap()).unwrap();
    assert_eq!(db_logit_bias, new_logit_bias); // logit_bias
}

#[tokio::test]
async fn update_chat_settings_success_partial() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::create_test_user_and_login(&context.app, "update_partial_user", "password").await;
    let character = test_helpers::create_test_character(&context.app.db_pool, user.id, "Update Partial Char").await;
    let session = test_helpers::create_test_chat_session(&context.app.db_pool, user.id, character.id).await;

    // Set initial values
    let initial_temp = BigDecimal::from_str("0.5").unwrap();
    test_helpers::update_test_chat_settings(
        &context.app.db_pool,
        session.id,
        Some("Initial Prompt".to_string()),
        Some(initial_temp),
        Some(256)
    ).await;

    let new_temp = BigDecimal::from_str("1.2").unwrap();
    let payload = UpdateChatSettingsRequest {
        system_prompt: None, // Not updating prompt
        temperature: Some(new_temp.clone()),
        max_output_tokens: None, // Not updating tokens
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        repetition_penalty: None,
        min_p: None,
        top_a: None,
        seed: None,
        logit_bias: None,
    };

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify changes in DB
    let db_settings = test_helpers::get_chat_session_settings(&context.app.db_pool, session.id).await.unwrap();
    // Only check the first three fields
    assert_eq!(db_settings.0, Some("Initial Prompt".to_string())); // Should be unchanged
    assert_eq!(db_settings.1, Some(new_temp)); // Should be updated
    assert_eq!(db_settings.2, Some(256)); // Should be unchanged
}

#[tokio::test]
async fn update_chat_settings_invalid_data() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::create_test_user_and_login(&context.app, "update_invalid_user", "password").await;
    let character = test_helpers::create_test_character(&context.app.db_pool, user.id, "Update Invalid Char").await;
    let session = test_helpers::create_test_chat_session(&context.app.db_pool, user.id, character.id).await;

    let invalid_payloads = vec![
        // Temperature validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: Some(BigDecimal::from_str("-0.1").unwrap()), // Negative temperature
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None
        },
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: Some(BigDecimal::from_str("2.1").unwrap()), // Temperature > 2.0
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None
        },
        // Max tokens validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: Some(0), // Zero tokens
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None
        },
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: Some(-100), // Negative tokens
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None
        },
        // Frequency penalty validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: Some(BigDecimal::from_str("-2.1").unwrap()), // < -2.0
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None
        },
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: Some(BigDecimal::from_str("2.1").unwrap()), // > 2.0
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None
        },
        // Presence penalty validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: Some(BigDecimal::from_str("-2.1").unwrap()), // < -2.0
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None
        },
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: Some(BigDecimal::from_str("2.1").unwrap()), // > 2.0
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None
        },
        // Top-k validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: Some(-1), // Negative top_k
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None
        },
        // Top-p validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: Some(BigDecimal::from_str("-0.1").unwrap()), // < 0
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None
        },
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: Some(BigDecimal::from_str("1.1").unwrap()), // > 1.0
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None
        },
        // Repetition penalty validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: Some(BigDecimal::from_str("0").unwrap()), // <= 0
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None
        },
        // Min-p validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: Some(BigDecimal::from_str("-0.1").unwrap()), // < 0
            top_a: None,
            seed: None,
            logit_bias: None
        },
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: Some(BigDecimal::from_str("1.1").unwrap()), // > 1.0
            top_a: None,
            seed: None,
            logit_bias: None
        },
        // Top-a validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: Some(BigDecimal::from_str("-0.1").unwrap()), // < 0
            seed: None,
            logit_bias: None
        },
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: Some(BigDecimal::from_str("1.1").unwrap()), // > 1.0
            seed: None,
            logit_bias: None
        },
        // Invalid logit_bias format
        UpdateChatSettingsRequest {
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
            logit_bias: Some(serde_json::json!(["invalid", "format"])) // Should be object
        },
    ];

    for (i, payload) in invalid_payloads.iter().enumerate() {
        let request = Request::builder()
            .method(Method::PUT)
            .uri(format!("/api/chats/{}/settings", session.id))
            .header(header::COOKIE, &auth_cookie)
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();

        let response = context.app.router.clone().oneshot(request).await.unwrap();
        // Expect Bad Request for validation errors on PUT
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "Failed for payload index {}: {:?}", i, payload);
    }
}

#[tokio::test]
async fn update_chat_settings_forbidden() {
    let context = test_helpers::setup_test_app().await;
    let (_auth_cookie1, user1) = test_helpers::create_test_user_and_login(&context.app, "update_settings_user1", "password").await;
    let character1 = test_helpers::create_test_character(&context.app.db_pool, user1.id, "Update Settings Char 1").await;
    let session1 = test_helpers::create_test_chat_session(&context.app.db_pool, user1.id, character1.id).await;
    let (auth_cookie2, _user2) = test_helpers::create_test_user_and_login(&context.app, "update_settings_user2", "password").await;

    let payload = UpdateChatSettingsRequest {
        system_prompt: Some("Attempted Update".to_string()),
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
    };

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session1.id)) // User 2 tries to update User 1's settings
        .header(header::COOKIE, auth_cookie2)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND); // Handler returns NotFound if update affects 0 rows due to ownership check
}


// --- Tests for POST /api/chats/{id}/generate (using MockAiClient) ---

#[tokio::test]
async fn generate_chat_response_uses_session_settings() {
    use bigdecimal::ToPrimitive;
    use genai::chat::ChatRole;

    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::create_test_user_and_login(&context.app, "gen_settings_user", "password").await;
    let character = test_helpers::create_test_character(&context.app.db_pool, user.id, "Gen Settings Char").await;
    let session = test_helpers::create_test_chat_session(&context.app.db_pool, user.id, character.id).await;

    // Set specific settings for this session
    let test_prompt = "Test system prompt for session";
    let test_temp = BigDecimal::from_str("0.88").unwrap();
    let test_tokens = 444_i32;
    let test_top_p = BigDecimal::from_str("0.92").unwrap();

    // Also add other fields to ensure they are stored correctly
    let test_freq_penalty = BigDecimal::from_str("0.5").unwrap();
    let test_pres_penalty = BigDecimal::from_str("0.3").unwrap();
    let test_top_k = 50_i32;
    let test_rep_penalty = BigDecimal::from_str("1.3").unwrap();
    let test_min_p = BigDecimal::from_str("0.05").unwrap();
    let test_top_a = BigDecimal::from_str("0.75").unwrap();
    let test_seed = 98765_i32;
    let test_logit_bias = serde_json::json!({
        "30001": -20,
        "30002": 20
    });

    test_helpers::update_all_chat_settings(
        &context.app.db_pool,
        session.id,
        Some(test_prompt.to_string()),
        Some(test_temp.clone()),
        Some(test_tokens),
        Some(test_freq_penalty.clone()),
        Some(test_pres_penalty.clone()),
        Some(test_top_k),
        Some(test_top_p.clone()),
        Some(test_rep_penalty.clone()),
        Some(test_min_p.clone()),
        Some(test_top_a.clone()),
        Some(test_seed),
        Some(test_logit_bias.clone())
    ).await;

    let payload = NewChatMessageRequest {
        content: "Hello, world!".to_string(),
        model: Some("test-model".to_string()), // Provide a model name
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify the request sent to the mock AI client
    let last_request = context.app.mock_ai_client.get_last_request().expect("Mock AI client did not receive a request");

    // Check that system prompt is included in the messages
    let has_system_message = last_request.messages.iter().any(|msg| {
        // First check role
        let is_system = match msg.role {
            ChatRole::System => true,
            _ => false
        };

        // Then check content contains the prompt
        let has_prompt = format!("{:?}", msg.content).contains(test_prompt);

        // Both conditions must be true
        is_system && has_prompt
    });
    assert!(has_system_message, "System prompt not found in request messages");

    // Verify the options sent to the mock AI client - only the ones supported by ChatOptions
    let options = context.app.mock_ai_client.get_last_options().expect("Mock AI client did not receive options");

    // Check the temperature - convert from BigDecimal to f64
    if let Some(temp) = options.temperature {
        let expected_temp = test_temp.to_f64().unwrap();
        assert!((temp - expected_temp).abs() < 0.001, "Temperature value doesn't match");
    } else {
        panic!("Expected temperature to be set in options");
    }

    // Check max_tokens - our max_output_tokens should be mapped to max_tokens
    if let Some(tokens) = options.max_tokens {
        assert_eq!(tokens, test_tokens as u32, "Max tokens value doesn't match");
    } else {
        panic!("Expected max_tokens to be set in options");
    }

    // Check top_p - convert from BigDecimal to f64
    if let Some(top_p) = options.top_p {
        let expected_top_p = test_top_p.to_f64().unwrap();
        assert!((top_p - expected_top_p).abs() < 0.001, "Top-p value doesn't match");
    } else {
        panic!("Expected top_p to be set in options");
    }

    // Verify all settings were stored correctly in the database
    let db_settings = test_helpers::get_chat_session_settings(&context.app.db_pool, session.id).await.unwrap();
    assert_eq!(db_settings.0, Some(test_prompt.to_string())); // system_prompt
    assert_eq!(db_settings.1, Some(test_temp)); // temperature
    assert_eq!(db_settings.2, Some(test_tokens)); // max_output_tokens
    assert_eq!(db_settings.3, Some(test_freq_penalty)); // frequency_penalty
    assert_eq!(db_settings.4, Some(test_pres_penalty)); // presence_penalty
    assert_eq!(db_settings.5, Some(test_top_k)); // top_k
    assert_eq!(db_settings.6, Some(test_top_p)); // top_p
    assert_eq!(db_settings.7, Some(test_rep_penalty)); // repetition_penalty
    assert_eq!(db_settings.8, Some(test_min_p)); // min_p
    assert_eq!(db_settings.9, Some(test_top_a)); // top_a
    assert_eq!(db_settings.10, Some(test_seed)); // seed

    // For JSON comparison, deserialize to Value first
    let db_logit_bias: serde_json::Value = serde_json::from_value(db_settings.11.unwrap()).unwrap();
    assert_eq!(db_logit_bias, test_logit_bias); // logit_bias
}

#[tokio::test]
async fn generate_chat_response_uses_default_settings() {
    // --- Setup ---
    let context = test_helpers::setup_test_app().await; // Remove mut
    let (auth_cookie, user) = test_helpers::create_test_user_and_login(
        &context.app,
        "gen_defaults_user",
        "password"
    ).await;
    let character = test_helpers::create_test_character(&context.app.db_pool, user.id, "Gen Defaults Char").await;
    let session = test_helpers::create_test_chat_session(&context.app.db_pool, user.id, character.id).await;
    // No settings updated in DB, should be NULL

    // Setup mock AI response (using the test helper's mock client)
    let expected_response = ChatResponse {
        model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-1.5-flash-latest"),
        provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-1.5-flash-latest"),
        content: Some(MessageContent::Text("Default settings mock response".to_string())),
        reasoning_content: None,
        usage: Usage::default(),
    };
    context.app.mock_ai_client.set_response(Ok(expected_response.clone()));

    // Request body
    let request_body = NewChatMessageRequest { // Use NewChatMessageRequest
        content: "Tell me about defaults".to_string(), // Changed 'message' to 'content'
        model: Some("test-model-defaults".to_string()), // Added model field back based on struct def
    };

    let _request = Request::builder() // Prefix with _
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, &auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify the request sent to the mock AI client
    let last_request = context.app.mock_ai_client.get_last_request().expect("Mock AI client did not receive a request");

    // Check that system prompt is included in the messages
    let has_system_message = last_request.messages.iter().any(|msg| {
        // First check role
        let is_system = match msg.role {
            ChatRole::System => true,
            _ => false
        };

        // Then check content contains the prompt
        // Note: The prompt might not be exactly "Default settings mock response" if it's derived differently
        // Let's make this check more robust if needed, but for now assume it's passed correctly.
        let has_prompt = format!("{:?}", msg.content).contains("Default settings mock response"); // Check against expected mock content

        // Both conditions must be true
        is_system && has_prompt
    });
    // Adjusted assertion: The system prompt is NOT added explicitly by the handler from the mock response content.
    // The handler *should* read the system prompt from the DB (which is NULL here).
    // So, we expect NO system message in the request sent to the LLM.
    let _has_system_message = last_request.messages.iter().any(|msg| matches!(msg.role, ChatRole::System)); // Prefixed again
    assert!(!_has_system_message, "System prompt should NOT be present when NULL in DB");


    // Verify the options sent to the mock AI client - only the ones supported by ChatOptions
    let options = context.app.mock_ai_client.get_last_options().expect("Mock AI client did not receive options");

    // Check the temperature - convert from BigDecimal to f64 for comparison if needed, but options are f64
    // Defaults are applied by the handler *before* calling the AI client if values are None in DB.
    // Check against the expected default values from config or handler logic.
    // Let's assume defaults are 0.75 temp, 512 tokens, 0.95 top_p for now.
    assert_eq!(options.temperature, Some(0.75), "Default temperature mismatch");
    assert_eq!(options.max_tokens, Some(512), "Default max_tokens mismatch"); // Expect u32
    assert_eq!(options.top_p, Some(0.95), "Default top_p mismatch");
    // Add checks for other default options if necessary (top_k, etc.)

    // Verify settings *in the database* are still NULL (as we didn't update them)
    let db_settings = test_helpers::get_chat_session_settings(&context.app.db_pool, session.id).await.unwrap();
    assert_eq!(db_settings.0, None); // system_prompt
    assert_eq!(db_settings.1, None); // temperature
    assert_eq!(db_settings.2, None); // max_output_tokens
    assert_eq!(db_settings.3, None); // frequency_penalty
    assert_eq!(db_settings.4, None); // presence_penalty
    assert_eq!(db_settings.5, None); // top_k
    assert_eq!(db_settings.6, None); // top_p
    assert_eq!(db_settings.7, None); // repetition_penalty
    assert_eq!(db_settings.8, None); // min_p
    assert_eq!(db_settings.9, None); // top_a
    assert_eq!(db_settings.10, None); // seed
    assert_eq!(db_settings.11, None); // logit_bias
}

#[tokio::test]
async fn generate_chat_response_forbidden() {
    let context = test_helpers::setup_test_app().await;
    let (_auth_cookie1, user1) = test_helpers::create_test_user_and_login(&context.app, "gen_settings_user1", "password").await;
    let character1 = test_helpers::create_test_character(&context.app.db_pool, user1.id, "Gen Settings Char 1").await;
    let session1 = test_helpers::create_test_chat_session(&context.app.db_pool, user1.id, character1.id).await;
    let (auth_cookie2, _user2) = test_helpers::create_test_user_and_login(&context.app, "gen_settings_user2", "password").await;

    let payload = NewChatMessageRequest {
        content: "Trying to generate...".to_string(),
        model: Some("forbidden-model".to_string()),
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session1.id)) // User 2 tries to generate in User 1's session
        .header(header::COOKIE, auth_cookie2)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    // The initial DB query in generate_chat_response checks ownership
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// TODO: Add tests for generate_chat_response with other error conditions (e.g., AI client error mocked)


#[tokio::test]
async fn update_chat_settings_not_found() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _user) = test_helpers::create_test_user_and_login(&context.app, "update_settings_404_user", "password").await;
    let non_existent_session_id = Uuid::new_v4();

    let payload = UpdateChatSettingsRequest {
        system_prompt: Some("Attempted Update".to_string()),
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
    };

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", non_existent_session_id))
        .header(header::COOKIE, auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn update_chat_settings_unauthorized() {
    let context = test_helpers::setup_test_app().await;
    let session_id = Uuid::new_v4(); // Dummy ID

     let payload = UpdateChatSettingsRequest {
        system_prompt: Some("Attempted Update".to_string()),
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
    };

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session_id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    // No auth cookie

    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
    let test_character = test_helpers::create_test_character(&context.app.db_pool, test_user.id, "Test Char for Get Msgs Integ").await;
    let session = test_helpers::create_test_chat_session(&context.app.db_pool, test_user.id, test_character.id).await;
    let msg1 = test_helpers::create_test_chat_message(&context.app.db_pool, session.id, MessageRole::User, "Hello Integ").await;
    let msg2 = test_helpers::create_test_chat_message(&context.app.db_pool, session.id, MessageRole::Assistant, "Hi there Integ").await;
    let request = Request::builder()
        .uri(format!("/api/chats/{}/messages", session.id))
        .method(Method::GET)
        .header("Cookie", auth_cookie)
        .body(Body::empty())
        .unwrap();
    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");
    let messages_array = body_json.as_array().expect("Response body should be a JSON array");
    assert_eq!(messages_array.len(), 2, "Should return 2 messages");
    let messages: Vec<ChatMessage> = serde_json::from_value(body_json).unwrap(); // Use ChatMessage here
    assert_eq!(messages[0].id, msg1.id);
    assert_eq!(messages[1].id, msg2.id);
}

#[tokio::test]
async fn get_chat_messages_forbidden_integration() {
    let context = test_helpers::setup_test_app().await;
    let (_auth_cookie1, user1) = test_helpers::create_test_user_and_login(&context.app, "user1_get_msgs_integ", "password").await;
    let character1 = test_helpers::create_test_character(&context.app.db_pool, user1.id, "Char User 1 Integ").await;
    let session1 = test_helpers::create_test_chat_session(&context.app.db_pool, user1.id, character1.id).await;
    let _msg1 = test_helpers::create_test_chat_message(&context.app.db_pool, session1.id, MessageRole::User, "Msg 1 Integ").await;
    let (auth_cookie2, _user2) = test_helpers::create_test_user_and_login(&context.app, "user2_get_msgs_integ", "password").await;
    let request = Request::builder()
        .uri(format!("/api/chats/{}/messages", session1.id)) // Request User 1's session ID
        .method(Method::GET)
        .header("Cookie", auth_cookie2) // Authenticated as User 2
        .body(Body::empty())
        .unwrap();
    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn get_chat_messages_not_found_integration() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _test_user) = test_helpers::create_test_user_and_login(&context.app, "test_get_msgs_404_integ", "password").await;
    let non_existent_session_id = Uuid::new_v4();
    let request = Request::builder()
        .uri(format!("/api/chats/{}/messages", non_existent_session_id))
        .method(Method::GET)
        .header("Cookie", auth_cookie)
        .body(Body::empty())
        .unwrap();
    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_chat_messages_unauthenticated_integration() {
    let context = test_helpers::setup_test_app().await;
    let session_id = Uuid::new_v4(); // Some session ID
    let request = Request::builder()
        .uri(format!("/api/chats/{}/messages", session_id))
        .method(Method::GET)
        .body(Body::empty())
        .unwrap();
    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // Expect UNAUTHORIZED for API
}

#[tokio::test]
async fn get_chat_messages_empty_list_integration() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, test_user) = test_helpers::create_test_user_and_login(&context.app, "test_get_empty_msgs_integ", "password").await;
    let test_character = test_helpers::create_test_character(&context.app.db_pool, test_user.id, "Test Char for Empty Msgs Integ").await;
    let session = test_helpers::create_test_chat_session(&context.app.db_pool, test_user.id, test_character.id).await;
    let request = Request::builder()
        .uri(format!("/api/chats/{}/messages", session.id))
        .method(Method::GET)
        .header("Cookie", auth_cookie)
        .body(Body::empty())
        .unwrap();
    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");
    let messages_array = body_json.as_array().expect("Response body should be a JSON array");
    assert!(messages_array.is_empty(), "Should return an empty array for a session with no messages");
}

// --- Tests for POST /api/chats (from integration tests) ---

#[tokio::test]
async fn create_chat_session_success_integration() {
    let context = test_helpers::setup_test_app().await; // Removed mut unless helpers need it
    let (auth_cookie, test_user) = test_helpers::create_test_user_and_login(&context.app, "test_create_chat_integ", "password").await;
    let test_character = test_helpers::create_test_character(&context.app.db_pool, test_user.id, "Test Char for Create Chat Integ").await;
    let payload = json!({ "character_id": test_character.id });
    let request = Request::builder()
        .uri(format!("/api/chats"))
        .method(Method::POST)
        .header("Content-Type", "application/json")
        .header("Cookie", auth_cookie)
        .body(Body::from(payload.to_string()))
        .unwrap();
    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let created_session: ChatSession = serde_json::from_slice(&body_bytes).expect("Failed to deserialize created session");
    assert_eq!(created_session.user_id, test_user.id);
    assert_eq!(created_session.character_id, test_character.id);
    // Verify in DB
    let session_in_db = test_helpers::get_chat_session_from_db(&context.app.db_pool, created_session.id).await;
    assert!(session_in_db.is_some());
    assert_eq!(session_in_db.unwrap().id, created_session.id);
}

#[tokio::test]
async fn create_chat_session_unauthenticated_integration() {
    let context = test_helpers::setup_test_app().await;
    let character_id = Uuid::new_v4();
    let payload = json!({ "character_id": character_id });
    let request = Request::builder()
        .uri(format!("/api/chats"))
        .method(Method::POST)
        .header("Content-Type", "application/json")
        .body(Body::from(payload.to_string()))
        .unwrap();
    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED); // Expect UNAUTHORIZED for API
}

#[tokio::test]
async fn create_chat_session_character_not_found_integration() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _test_user) = test_helpers::create_test_user_and_login(&context.app, "test_create_chat_404_integ", "password").await;
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
async fn create_chat_session_character_not_owned_integration() {
    let context = test_helpers::setup_test_app().await; // Removed mut
    let (_auth_cookie1, user1) = test_helpers::create_test_user_and_login(&context.app, "user1_create_chat_integ", "password").await;
    let character1 = test_helpers::create_test_character(&context.app.db_pool, user1.id, "User 1 Char Integ").await;
    let (auth_cookie2, _user2) = test_helpers::create_test_user_and_login(&context.app, "user2_create_chat_integ", "password").await;
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
async fn create_chat_session_invalid_payload_integration() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _test_user) = test_helpers::create_test_user_and_login(&context.app, "test_create_chat_bad_payload_integ", "password").await;
    let invalid_payloads = vec![
        json!({}), // Missing character_id
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
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY, "Failed for payload: {}", payload);
    }
}

// TODO: Add tests for POST /api/chats/{id}/generate

// --- Tests for POST /api/chats/{id}/generate (Streaming) ---

#[tokio::test]
async fn generate_chat_response_streaming_success() {
    let mut context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::create_test_user_and_login(&context.app, "stream_ok_user", "password").await;
    let character = context.insert_character(user.id, "Stream OK Char").await;
    let session = context.insert_chat_session(user.id, character.id).await;

    // Configure mock response stream
    use genai::chat::StreamChunk;
    use genai::chat::StreamEnd;
    let mock_stream_items = vec![
        // Ok(ChatStreamEvent::Start), // Start event is optional to include
        Ok(ChatStreamEvent::Chunk(StreamChunk { content: "Hello ".to_string() })),
        Ok(ChatStreamEvent::Chunk(StreamChunk { content: "World!".to_string() })),
        Ok(ChatStreamEvent::Chunk(StreamChunk { content: "".to_string() })), // Test empty chunk
        Ok(ChatStreamEvent::End(StreamEnd::default())),
    ];
    context.app.mock_ai_client.set_stream_response(mock_stream_items);

    let payload = NewChatMessageRequest {
        content: "User message for stream".to_string(),
        model: Some("test-stream-model".to_string()),
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();

    // Assert headers
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::TEXT_EVENT_STREAM.as_ref()
    );

    // Consume and assert stream content
    let body = response.into_body();
    let data_chunks = collect_sse_data(body).await;

    assert_eq!(data_chunks, vec!["Hello ", "World!"]); // Only non-empty data chunks

    // Assert background save (wait a bit for the background task)
    tokio::time::sleep(Duration::from_millis(100)).await; // Adjust timing if needed

    let messages = test_helpers::get_chat_messages_from_db(&context.app.db_pool, session.id).await;
    assert_eq!(messages.len(), 2, "Should have user and AI message after stream");

    let user_msg = messages.first().unwrap();
    assert_eq!(user_msg.message_type, MessageRole::User);
    assert_eq!(user_msg.content, "User message for stream");

    let ai_msg = messages.get(1).unwrap();
    assert_eq!(ai_msg.message_type, MessageRole::Assistant);
    assert_eq!(ai_msg.content, "Hello World!"); // Full concatenated content
}

#[tokio::test]
async fn generate_chat_response_streaming_ai_error() {
    let mut context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::create_test_user_and_login(&context.app, "stream_err_user", "password").await;
    let character = context.insert_character(user.id, "Stream Err Char").await;
    let session = context.insert_chat_session(user.id, character.id).await;

    // Configure mock response stream with an error
    use genai::chat::StreamChunk;
    // use genai::Error as GenAIError; // Correct import path - Already imported above
    let mock_stream_items = vec![
        Ok(ChatStreamEvent::Chunk(StreamChunk { content: "Partial ".to_string() })),
        Err(AppError::GeminiError("Mock AI error during streaming".to_string())),
        Ok(ChatStreamEvent::Chunk(StreamChunk { content: "Should not be sent".to_string() })),
    ];
    context.app.mock_ai_client.set_stream_response(mock_stream_items);

    let payload = NewChatMessageRequest {
        content: "User message for error stream".to_string(),
        model: Some("test-stream-err-model".to_string()),
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();

    // Assert headers
    assert_eq!(response.status(), StatusCode::OK); // SSE connection established successfully
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::TEXT_EVENT_STREAM.as_ref()
    );

    // Consume and assert stream content
    // We need to parse events including the 'event:' line now
    let mut data_chunks = Vec::new();
    let mut error_event_data = None;

    // Removed use http_body_util::BodyExt;
    let body = response.into_body();
    let stream = body.into_data_stream();

    stream.try_for_each(|buf| {
        let lines = String::from_utf8_lossy(&buf);
        let mut current_event = None;
        let mut current_data = String::new();

        for line in lines.lines() {
            if let Some(event_type) = line.strip_prefix("event: ") {
                current_event = Some(event_type.to_string());
            } else if let Some(data) = line.strip_prefix("data: ") {
                current_data.push_str(data);
                // Note: multi-line data isn't handled here, assumes single line data
            } else if line.is_empty() { // End of an event
                if let Some(event_type) = current_event.take() {
                    if event_type == "error" {
                         error_event_data = Some(current_data.clone());
                    } else if event_type == "content" { // Handle content event
                         data_chunks.push(current_data.clone());
                    }
                } else if !current_data.is_empty() { // Default 'message' event (should be content)
                    data_chunks.push(current_data.clone());
                }
                current_data.clear();
            }
        }
        futures::future::ready(Ok(()))
    }).await.expect("Failed to read SSE stream");

    assert_eq!(data_chunks, vec!["Partial "], "Only partial data chunk should be received");
    assert!(error_event_data.is_some(), "Error event should be received");
    // The error message format from the handler should now be just the Display impl of the AppError
    let expected_error_msg = "LLM API error: Mock AI error during streaming";
    assert_eq!(error_event_data.unwrap(), expected_error_msg, "Error event data mismatch");


    // Assert background save (wait a bit)
    tokio::time::sleep(Duration::from_millis(100)).await;

    let messages = test_helpers::get_chat_messages_from_db(&context.app.db_pool, session.id).await;
    assert_eq!(messages.len(), 2, "Should have user and PARTIAL AI message after stream error");

    let user_msg = messages.first().unwrap();
    assert_eq!(user_msg.message_type, MessageRole::User);
    assert_eq!(user_msg.content, "User message for error stream");

    let ai_msg = messages.get(1).unwrap();
    assert_eq!(ai_msg.message_type, MessageRole::Assistant);
    // The background save happens *after* the loop, saving whatever was buffered before the error
    assert_eq!(ai_msg.content, "Partial ", "Partial content should be saved");
}

#[tokio::test]
async fn generate_chat_response_streaming_unauthorized() {
    let context = test_helpers::setup_test_app().await;
    let session_id = Uuid::new_v4(); // Dummy ID

    let payload = NewChatMessageRequest { content: "test".to_string(), model: None };
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session_id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    // No auth cookie

    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
     assert_ne!(
        response.headers().get(header::CONTENT_TYPE).map(|h| h.as_bytes()),
        Some(mime::TEXT_EVENT_STREAM.as_ref().as_bytes()),
        "Content-Type should not be text/event-stream"
    );
}

#[tokio::test]
async fn generate_chat_response_streaming_not_found() {
     let context = test_helpers::setup_test_app().await;
     let (auth_cookie, _user) = test_helpers::create_test_user_and_login(&context.app, "stream_404_user", "password").await;
     let non_existent_session_id = Uuid::new_v4();

     let payload = NewChatMessageRequest { content: "test".to_string(), model: None };
     let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", non_existent_session_id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

     let response = context.app.router.oneshot(request).await.unwrap();
     assert_eq!(response.status(), StatusCode::NOT_FOUND);
      assert_ne!(
        response.headers().get(header::CONTENT_TYPE).map(|h| h.as_bytes()),
        Some(mime::TEXT_EVENT_STREAM.as_ref().as_bytes()),
        "Content-Type should not be text/event-stream"
    );
}

 #[tokio::test]
async fn generate_chat_response_streaming_forbidden() {
    let mut context = test_helpers::setup_test_app().await;
    let (_auth_cookie1, user1) = test_helpers::create_test_user_and_login(&context.app, "stream_forbid_user1", "password").await;
    let character1 = context.insert_character(user1.id, "Stream Forbid Char 1").await;
    let session1 = context.insert_chat_session(user1.id, character1.id).await;
    let (auth_cookie2, _user2) = test_helpers::create_test_user_and_login(&context.app, "stream_forbid_user2", "password").await;

    let payload = NewChatMessageRequest { content: "test".to_string(), model: None };
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session1.id)) // User 2 tries to generate in User 1's session
        .header(header::COOKIE, auth_cookie2)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    // The initial DB query checks ownership and returns NotFound if mismatch
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_ne!(
        response.headers().get(header::CONTENT_TYPE).map(|h| h.as_bytes()),
        Some(mime::TEXT_EVENT_STREAM.as_ref().as_bytes()),
        "Content-Type should not be text/event-stream"
    );
}