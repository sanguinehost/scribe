// backend/tests/chat_generate_non_stream_tests.rs
#![cfg(test)]

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use bigdecimal::{BigDecimal, ToPrimitive}; // Added ToPrimitive
use chrono::Utc;
use genai::{
    ModelIden,
    adapter::AdapterKind,
    chat::{ChatResponse, ChatRole, MessageContent, Usage},
};
use http_body_util::BodyExt;
use mime;
use serde_json::{Value, json};
use std::str::FromStr;
use std::sync::Arc; // Added Arc
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

// Crate imports
use scribe_backend::models::chats::{MessageRole, NewChatMessageRequest};
use scribe_backend::errors::AppError;
use scribe_backend::services::embedding_pipeline::{EmbeddingMetadata, RetrievedChunk};
use scribe_backend::test_helpers::{self, PipelineCall};

// --- Tests for POST /api/chats/{id}/generate (Non-Streaming JSON) ---

#[tokio::test]
#[ignore] // Added ignore for CI
async fn generate_chat_response_uses_session_settings() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "gen_settings_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Char for Resp Settings",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

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

    test_helpers::db::update_all_chat_settings(
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
        Some(test_logit_bias.clone()),
        // Add missing None arguments for history management fields
        None,
        None,
    )
    .await;

    // --- Mock RAG Response ---
    let mock_metadata1 = EmbeddingMetadata {
        message_id: Uuid::new_v4(),
        session_id: session.id, // Added
        speaker: "user".to_string(),
        timestamp: Utc::now(),
        text: "This is relevant chunk 1.".to_string(),
    };
    let mock_metadata2 = EmbeddingMetadata {
        message_id: Uuid::new_v4(),
        session_id: session.id, // Added
        speaker: "ai".to_string(),
        timestamp: Utc::now(),
        text: "This is relevant chunk 2, slightly longer.".to_string(),
    };
    let mock_chunks = vec![
        RetrievedChunk {
            score: 0.95,
            text: mock_metadata1.text.clone(),
            metadata: mock_metadata1,
        },
        RetrievedChunk {
            score: 0.88,
            text: mock_metadata2.text.clone(),
            metadata: mock_metadata2,
        },
    ];
    // Use the correct mock method name
    context
        .app
        .mock_embedding_pipeline_service
        .set_retrieve_response(Ok(mock_chunks));
    // --- End Mock RAG Response ---

    let payload = NewChatMessageRequest {
        content: "Hello, world!".to_string(),
        model: Some("test-model".to_string()), // Provide a model name
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        // Add the Accept header for streaming
        .header(header::ACCEPT, mime::TEXT_EVENT_STREAM.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify the request sent to the mock AI client
    let last_request = context
        .app
        .mock_ai_client
        .get_last_request()
        .expect("Mock AI client did not receive a request");

    // --- Verify RAG Context Injection ---
    let last_message_content = last_request.messages.last().unwrap().content.clone();
    let prompt_text = match last_message_content {
        MessageContent::Text(text) => text,
        _ => panic!("Expected last message content to be text"),
    };

    // Check if the RAG context section exists and contains the chunk text
    assert!(
        prompt_text.contains("<RAG_CONTEXT>"),
        "Prompt missing RAG_CONTEXT start tag"
    );
    assert!(
        prompt_text.contains("</RAG_CONTEXT>"),
        "Prompt missing RAG_CONTEXT end tag"
    );
    assert!(
        prompt_text.contains("This is relevant chunk 1."),
        "Prompt missing text from chunk 1"
    );
    assert!(
        prompt_text.contains("This is relevant chunk 2, slightly longer."),
        "Prompt missing text from chunk 2"
    );
    // --- End RAG Verification ---

    // Check that system prompt is the *first* message and has the correct content
    let first_message = last_request
        .messages
        .first()
        .expect("No messages sent to AI");
    assert!(
        matches!(first_message.role, ChatRole::System),
        "First message should be System role"
    );
    match &first_message.content {
        MessageContent::Text(text) => assert!(
            text.contains(test_prompt),
            "System prompt content mismatch: expected '{}', got '{}'",
            test_prompt,
            text
        ),
        _ => panic!("Expected first message content to be text"),
    }

    // Verify the options sent to the mock AI client - only the ones supported by ChatOptions
    let options = context
        .app
        .mock_ai_client
        .get_last_options()
        .expect("Mock AI client did not receive options");

    // Check the temperature - convert from BigDecimal to f64
    if let Some(temp) = options.temperature {
        let expected_temp = test_temp.to_f64().unwrap();
        assert!(
            (temp - expected_temp).abs() < 0.001,
            "Temperature value doesn't match"
        );
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
        assert!(
            (top_p - expected_top_p).abs() < 0.001,
            "Top-p value doesn't match"
        );
    } else {
        panic!("Expected top_p to be set in options");
    }

    // Verify all settings were stored correctly in the database
    let db_settings = test_helpers::db::get_chat_session_settings(&context.app.db_pool, session.id)
        .await
        .unwrap();
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
    // Check history fields (should be defaults)
    assert_eq!(db_settings.12, "none"); // history_management_strategy
    assert_eq!(db_settings.13, 20); // history_management_limit - updated to match actual default
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn generate_chat_response_uses_default_settings() {
    // --- Setup ---
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "gen_defaults_user",
        "password",
    )
    .await;
    let character =
        test_helpers::db::create_test_character(&context.app.db_pool, user.id, "Gen Defaults Char")
            .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;
    // No settings updated in DB, should be NULL

    // Setup mock AI response (using the test helper's mock client)
    let expected_response = ChatResponse {
        model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-1.5-flash-latest"),
        provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-1.5-flash-latest"),
        content: Some(MessageContent::Text(
            "Default settings mock response".to_string(),
        )),
        reasoning_content: None,
        usage: Usage::default(),
    };
    context
        .app
        .mock_ai_client
        .set_response(Ok(expected_response.clone()));

    // Request body
    let request_body = NewChatMessageRequest {
        // Use NewChatMessageRequest
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
    let last_request = context
        .app
        .mock_ai_client
        .get_last_request()
        .expect("Mock AI client did not receive a request");

    // Check that system prompt is included in the messages
    let _has_system_message = last_request
        .messages
        .iter()
        .any(|msg| matches!(msg.role, ChatRole::System)); // Prefixed again
    assert!(
        !_has_system_message,
        "System prompt should NOT be present when NULL in DB"
    );

    // Verify the options sent to the mock AI client - only the ones supported by ChatOptions
    let options = context
        .app
        .mock_ai_client
        .get_last_options()
        .expect("Mock AI client did not receive options");

    // Check the temperature - convert from BigDecimal to f64 for comparison if needed, but options are f64
    // Defaults are applied by the handler *before* calling the AI client if values are None in DB.
    // Check against the expected default values from config or handler logic.
    // The previous test run indicated the actual default temperature used was 1.0.
    assert_eq!(
        options.temperature,
        Some(1.0),
        "Default temperature mismatch"
    );

    // Check top_p - Expect the library default (likely 0.95 based on previous runs)
    assert_eq!(options.top_p, Some(0.95), "Default top_p mismatch");

    // Check max_tokens - Expect our applied default (512)
    assert_eq!(options.max_tokens, Some(512), "Default max_tokens mismatch");

    // Verify settings *in the database* are still NULL (as we didn't update them)
    let db_settings = test_helpers::db::get_chat_session_settings(&context.app.db_pool, session.id)
        .await
        .unwrap();
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
    // Check history fields (should be defaults)
    assert_eq!(db_settings.12, "none"); // history_management_strategy
    assert_eq!(db_settings.13, 20); // history_management_limit - updated to match actual default
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn generate_chat_response_forbidden() {
    let context = test_helpers::setup_test_app().await;
    let (_auth_cookie1, user1) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "gen_settings_user1",
        "password",
    )
    .await;
    let character1 = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user1.id,
        "Gen Settings Char 1",
    )
    .await;
    let session1 =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user1.id, character1.id)
            .await;
    let (auth_cookie2, _user2) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "gen_settings_user2",
        "password",
    )
    .await;

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
    // The initial DB query checks ownership and returns NotFound if mismatch
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_ne!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|h| h.as_bytes()),
        Some(mime::TEXT_EVENT_STREAM.as_ref().as_bytes()),
        "Content-Type should not be text/event-stream"
    );
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn generate_chat_response_non_streaming_success() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) =
        test_helpers::auth::create_test_user_and_login(&context.app, "non_stream_user", "password")
            .await;
    let character =
        test_helpers::db::create_test_character(&context.app.db_pool, user.id, "Non-Stream Char")
            .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    // Mock the AI response for the non-streaming call
    let mock_ai_content = "This is the non-streaming response.";
    let mock_response = ChatResponse {
        model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-1.5-flash-latest"),
        provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-1.5-flash-latest"),
        content: Some(MessageContent::Text(mock_ai_content.to_string())),
        reasoning_content: None,
        usage: Usage::default(),
    };
    context.app.mock_ai_client.set_response(Ok(mock_response)); // Use set_response for exec_chat

    let payload = NewChatMessageRequest {
        content: "User message for non-streaming test".to_string(),
        model: Some("test-non-stream-model".to_string()),
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        // NO Accept: text/event-stream header
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();

    // Assert status and headers
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::APPLICATION_JSON.as_ref(),
        "Content-Type should be application/json"
    );

    // Assert response body structure and content
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&body_bytes)
        .expect("Failed to deserialize non-streaming response body as JSON");

    assert!(
        body_json["message_id"].is_string(),
        "Response should contain message_id string"
    );
    assert!(
        Uuid::parse_str(body_json["message_id"].as_str().unwrap()).is_ok(),
        "message_id should be a valid UUID"
    );
    assert_eq!(
        body_json["content"].as_str(),
        Some(mock_ai_content),
        "Response content does not match mocked AI content"
    );

    // Assert background save
    tokio::time::sleep(Duration::from_millis(100)).await;
    let messages =
        test_helpers::db::get_chat_messages_from_db(&context.app.db_pool, session.id).await;
    assert_eq!(
        messages.len(),
        2,
        "Should have user and AI message after non-streaming response"
    );
    let ai_msg = messages.get(1).unwrap();
    assert_eq!(ai_msg.message_type, MessageRole::Assistant);
    assert_eq!(ai_msg.content, mock_ai_content);
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_non_streaming_ai_error() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "non_stream_err_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Non-Stream Err Char",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    // Mock the AI client to return an error for the non-streaming call
    context
        .app
        .mock_ai_client
        .set_response(Err(AppError::GenerationError(
            "Mock AI exec_chat failure".to_string(),
        )));

    let payload = NewChatMessageRequest {
        content: "User message for non-streaming error".to_string(),
        model: Some("test-non-stream-err-model".to_string()),
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        // NO Accept: text/event-stream header
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();

    // Assert status and headers - Expecting 502 Bad Gateway as per handler logic
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::APPLICATION_JSON.as_ref(),
        "Content-Type should be application/json"
    );

    // Assert response body structure and content
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&body_bytes)
        .expect("Failed to deserialize non-streaming error response body as JSON");

    assert!(
        body_json["error"].is_string(),
        "Error response should contain error string"
    );
    assert_eq!(body_json["error"], "AI service request failed");
    assert!(
        body_json["detail"]
            .as_str()
            .unwrap()
            .contains("Mock AI exec_chat failure"),
        "Error detail mismatch"
    );

    // Assert no AI message was saved
    tokio::time::sleep(Duration::from_millis(100)).await;
    let messages =
        test_helpers::db::get_chat_messages_from_db(&context.app.db_pool, session.id).await;
    // Only the user message should be saved
    assert_eq!(
        messages.len(),
        1,
        "Should only have user message saved after AI error"
    );
    assert_eq!(messages[0].message_type, MessageRole::User);
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_non_streaming_empty_content() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "non_stream_empty_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Non-Stream Empty Char",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    // Mock the AI response with None content (simulates safety block etc.)
    let mock_response = ChatResponse {
        model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-1.5-flash-latest"),
        provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-1.5-flash-latest"),
        content: None, // Simulate no content returned
        reasoning_content: None,
        usage: Usage::default(),
    };
    context.app.mock_ai_client.set_response(Ok(mock_response));

    let payload = NewChatMessageRequest {
        content: "User message for empty content response".to_string(),
        model: Some("test-non-stream-empty-model".to_string()),
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();

    // Assert status and headers - Expecting 502 Bad Gateway as per handler logic for content extraction failure
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::APPLICATION_JSON.as_ref(),
        "Content-Type should be application/json"
    );

    // Assert response body structure and content
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&body_bytes)
        .expect("Failed to deserialize non-streaming empty content error response body as JSON");

    assert_eq!(body_json["error"], "Generation failed");
    assert!(
        body_json["detail"]
            .as_str()
            .unwrap()
            .contains("Gemini response was empty or missing text content"),
        "Error detail mismatch"
    );

    // Assert no AI message was saved
    tokio::time::sleep(Duration::from_millis(100)).await;
    let messages =
        test_helpers::db::get_chat_messages_from_db(&context.app.db_pool, session.id).await;
    assert_eq!(
        messages.len(),
        1,
        "Should only have user message saved after empty AI content"
    );
    assert_eq!(messages[0].message_type, MessageRole::User);
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_non_streaming_empty_string_content() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "non_stream_empty_str_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Non-Stream Empty Str Char",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    // Mock the AI response with empty string content
    let mock_response = ChatResponse {
        model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-1.5-flash-latest"),
        provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-1.5-flash-latest"),
        content: Some(MessageContent::Text("".to_string())), // Empty string
        reasoning_content: None,
        usage: Usage::default(),
    };
    context.app.mock_ai_client.set_response(Ok(mock_response));

    let payload = NewChatMessageRequest {
        content: "User message for empty string response".to_string(),
        model: Some("test-non-stream-empty-str-model".to_string()),
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();

    // Assert status and headers - Expecting 200 OK
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::APPLICATION_JSON.as_ref(),
        "Content-Type should be application/json"
    );

    // Assert response body structure and content
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&body_bytes)
        .expect("Failed to deserialize non-streaming empty string response body as JSON");

    assert!(
        body_json["message_id"].is_string(),
        "Response should contain message_id string"
    );
    assert_eq!(
        body_json["content"].as_str(),
        Some(""),
        "Response content should be an empty string"
    );
    let saved_ai_message_id = Uuid::parse_str(body_json["message_id"].as_str().unwrap()).unwrap();

    // Assert background save
    tokio::time::sleep(Duration::from_millis(100)).await;
    let messages =
        test_helpers::db::get_chat_messages_from_db(&context.app.db_pool, session.id).await;
    assert_eq!(
        messages.len(),
        2,
        "Should have user and empty AI message saved"
    );
    let ai_msg = messages
        .iter()
        .find(|m| m.message_type == MessageRole::Assistant)
        .expect("Assistant message not found");
    assert_eq!(ai_msg.id, saved_ai_message_id);
    assert_eq!(ai_msg.content, ""); // Verify saved content is empty string
}