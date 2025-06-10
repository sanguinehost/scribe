#![cfg(test)]

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use chrono::Utc;
use diesel::RunQueryDsl as _;
use diesel::prelude::*;
use genai::chat::{ChatStreamEvent, StreamChunk, StreamEnd};
use secrecy::SecretBox;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

use scribe_backend::{
    models::{
        characters::Character as DbCharacter,
        chats::{ApiChatMessage, Chat as ChatSession, GenerateChatRequest, MessageRole, NewChat},
    },
    schema::{characters::dsl as characters_dsl, chat_sessions::dsl as chat_sessions_dsl},
    services::{
        chat::generation::get_session_data_for_generation, // Updated to new path
        hybrid_token_counter::HybridTokenCounter,
        lorebook_service::LorebookService,
        tokenizer_service::TokenizerService,
    },
    state::{AppState, AppStateServices},
    test_helpers::{self, collect_full_sse_events},
};

async fn create_authenticated_user(
    test_app: &test_helpers::TestApp,
) -> (scribe_backend::models::users::User, String) {
    let username = "gen_resp_stream_user";
    let password = "password123";
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await
    .expect("Failed to create test user");

    let login_payload = serde_json::json!({
        "identifier": username,
        "password": password,
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
        .unwrap();

    let login_response = test_app
        .router
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();
    assert_eq!(
        login_response.status(),
        StatusCode::OK,
        "Login request failed"
    );

    let auth_cookie_header = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present on login")
        .to_str()
        .unwrap();
    let parsed_cookie =
        cookie::Cookie::parse(auth_cookie_header).expect("Failed to parse Set-Cookie header");
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());

    (user, auth_cookie)
}

async fn create_test_character_and_session(
    test_app: &test_helpers::TestApp,
    user_id: Uuid,
) -> (DbCharacter, ChatSession) {
    let conn_pool = test_app.db_pool.clone();
    let user_id_clone = user_id;
    let character_name = "Char for Stream Resp".to_string();
    let character: DbCharacter = conn_pool
        .get()
        .await
        .expect("Failed to get DB conn for char create")
        .interact(move |conn_sync| {
            let new_char_card = scribe_backend::models::character_card::NewCharacter {
                user_id: user_id_clone,
                name: character_name,
                spec: "test_spec_v1.0".to_string(),
                spec_version: "1.0".to_string(),
                description: Some(b"Test description".to_vec()),
                greeting: Some(b"Hello".to_vec()),
                visibility: Some("private".to_string()),
                creator: Some("test_creator".to_string()),
                persona: Some(b"Test persona".to_vec()),
                created_at: Some(Utc::now()),
                updated_at: Some(Utc::now()),
                ..Default::default()
            };
            diesel::insert_into(characters_dsl::characters)
                .values(&new_char_card)
                .get_result::<DbCharacter>(conn_sync)
        })
        .await
        .expect("DB interaction for create character failed")
        .expect("Error saving new character");

    let conn_pool = test_app.db_pool.clone();
    let user_id_clone_session = user_id;
    let character_id_clone_session = character.id;
    let session: ChatSession = conn_pool
        .get()
        .await
        .expect("Failed to get DB conn for session create")
        .interact(move |conn_sync| {
            let new_chat_session = NewChat {
                id: Uuid::new_v4(),
                user_id: user_id_clone_session,
                character_id: character_id_clone_session,
                title_ciphertext: None,
                title_nonce: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                history_management_strategy: "truncate".to_string(),
                history_management_limit: 10,
                model_name: "gemini-2.5-flash-preview-05-20".to_string(),
                visibility: Some("private".to_string()),
                active_custom_persona_id: None,
                active_impersonated_character_id: None,
                temperature: None,
                max_output_tokens: None,
                frequency_penalty: None,
                presence_penalty: None,
                top_k: None,
                top_p: None,
                seed: None,
                stop_sequences: None,
                gemini_thinking_budget: None,
                gemini_enable_code_execution: None,
                system_prompt_ciphertext: None,
                system_prompt_nonce: None,
            };
            diesel::insert_into(chat_sessions_dsl::chat_sessions)
                .values(&new_chat_session)
                .returning(ChatSession::as_returning())
                .get_result::<ChatSession>(conn_sync)
        })
        .await
        .expect("DB interaction for create session failed")
        .expect("Error saving new session");

    (character, session)
}

fn setup_mock_ai_responses(test_app: &test_helpers::TestApp) {
    let mock_stream_response = vec![
        Ok(ChatStreamEvent::Chunk(StreamChunk {
            content: "Hello! ".to_string(),
        })),
        Ok(ChatStreamEvent::Chunk(StreamChunk {
            content: "World!".to_string(),
        })),
        Ok(ChatStreamEvent::Chunk(StreamChunk {
            content: String::new(),
        })), // Test empty chunk
        Ok(ChatStreamEvent::End(StreamEnd::default())),
    ];

    if let Some(mock_ai) = test_app.mock_ai_client.as_ref() {
        mock_ai.set_stream_response(mock_stream_response);
    } else {
        panic!("Mock AI client not found in test_app, cannot set stream response.");
    }
}

async fn send_chat_request(
    test_app: &test_helpers::TestApp,
    session_id: Uuid,
    auth_cookie: &str,
) -> axum::response::Response<axum::body::Body> {
    // Set up mock embedding pipeline response before sending the request
    test_app
        .mock_embedding_pipeline_service
        .add_retrieve_response(Ok(vec![])); // Return empty chunks for this test

    let generate_request = GenerateChatRequest {
        history: vec![ApiChatMessage {
            role: "user".to_string(),
            content: "Hello, how are you?".to_string(),
        }],
        model: Some("test-model".to_string()),
        query_text_for_rag: None,
    };

    let chat_request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chat/{session_id}/generate"))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(
            serde_json::to_string(&generate_request).unwrap(),
        ))
        .unwrap();

    test_app.router.clone().oneshot(chat_request).await.unwrap()
}

async fn verify_streaming_response(response: axum::response::Response<axum::body::Body>) {
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Chat generate request failed"
    );

    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .expect("Response should have Content-Type header")
        .to_str()
        .unwrap();

    assert!(
        content_type.contains("text/event-stream"),
        "Response should be SSE stream, got: {content_type}"
    );

    let body_stream = response.into_body();
    let sse_events = collect_full_sse_events(body_stream).await;

    let mut found_hello = false;
    let mut found_world = false;
    let mut found_done = false;

    for event in &sse_events {
        if event.event.as_deref() == Some("content") {
            if event.data.contains("Hello!") {
                found_hello = true;
            }
            if event.data.contains("World!") {
                found_world = true;
            }
        } else if event.event.as_deref() == Some("done") {
            found_done = true;
        }
    }

    assert!(found_hello, "Should receive 'Hello!' in stream");
    assert!(found_world, "Should receive 'World!' in stream");
    assert!(found_done, "Should receive done event");
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn generate_chat_response_streaming_success() {
    let test_app = test_helpers::spawn_app(false, false, false).await;

    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }

    // Set up test data using helper functions
    let (user, auth_cookie) = create_authenticated_user(&test_app).await;
    let (_character, session) = create_test_character_and_session(&test_app, user.id).await;
    setup_mock_ai_responses(&test_app);

    // Send chat request and verify response
    let response = send_chat_request(&test_app, session.id, &auth_cookie).await;
    verify_streaming_response(response).await;

    // Verify that mock calls were made as expected
    // let _ai_calls = test_app.mock_ai_client.as_ref().unwrap().get_calls();
    let _embedding_calls = test_app.mock_embedding_pipeline_service.get_calls();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_first_mes_included_in_history() {
    let test_app = test_helpers::spawn_app(false, false, false).await;

    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }

    // Create test user
    let username = "first_mes_test_user";
    let password = "password123";
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await
    .expect("Failed to create test user");

    // Login to get auth cookie
    let login_payload = serde_json::json!({
        "identifier": username,
        "password": password,
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
        .unwrap();

    let login_response = test_app
        .router
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();
    assert_eq!(
        login_response.status(),
        StatusCode::OK,
        "Login request failed"
    );

    let auth_cookie_header = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present on login")
        .to_str()
        .unwrap();
    let _parsed_cookie =
        cookie::Cookie::parse(auth_cookie_header).expect("Failed to parse Set-Cookie header");
    // Create a dummy session DEK for encrypting first_mes
    let session_dek = SecretBox::new(Box::new(vec![0u8; 32])); // Dummy DEK for testing
    let session_dek_for_char_creation = std::sync::Arc::new(session_dek);

    // Create a test character with first_mes content
    let conn_pool = test_app.db_pool.clone();
    let user_id_clone = user.id;
    let first_mes_content_plain =
        "Hello! I'm the character's first message that should be included.";

    let (encrypted_first_mes, first_mes_nonce) = {
        let (encrypted_content, nonce) = scribe_backend::crypto::encrypt_gcm(
            first_mes_content_plain.as_bytes(),
            session_dek_for_char_creation.as_ref(),
        )
        .expect("Failed to encrypt first_mes_content");
        (Some(encrypted_content), Some(nonce))
    };

    let character: DbCharacter = conn_pool
        .get()
        .await
        .expect("Failed to get DB conn for char create")
        .interact(move |conn_sync| {
            let new_char_card = scribe_backend::models::character_card::NewCharacter {
                user_id: user_id_clone,
                name: "Character with first_mes".to_string(),
                spec: "test_spec_v1.0".to_string(),
                spec_version: "1.0".to_string(),
                description: Some(b"Test description".to_vec()),
                first_mes: encrypted_first_mes, // Use encrypted content
                first_mes_nonce,                // Store the nonce
                greeting: Some(b"Hello".to_vec()),
                visibility: Some("private".to_string()),
                creator: Some("test_creator".to_string()),
                persona: Some(b"Test persona".to_vec()),
                created_at: Some(Utc::now()),
                updated_at: Some(Utc::now()),
                ..Default::default()
            };
            diesel::insert_into(characters_dsl::characters)
                .values(&new_char_card)
                .get_result::<DbCharacter>(conn_sync)
        })
        .await
        .expect("DB interaction for create character failed")
        .expect("Error saving new character");

    // Create a new chat session
    let conn_pool = test_app.db_pool.clone();
    let user_id_clone_session = user.id;
    let character_id_clone_session = character.id;
    let session: ChatSession = conn_pool
        .get()
        .await
        .expect("Failed to get DB conn for session create")
        .interact(move |conn_sync| {
            let new_chat_session = NewChat {
                id: Uuid::new_v4(),
                user_id: user_id_clone_session,
                character_id: character_id_clone_session,
                title_ciphertext: None,
                title_nonce: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                history_management_strategy: "truncate".to_string(),
                history_management_limit: 10,
                model_name: "test-model".to_string(),
                visibility: Some("private".to_string()),
                active_custom_persona_id: None,
                active_impersonated_character_id: None,
                temperature: None,
                max_output_tokens: None,
                frequency_penalty: None,
                presence_penalty: None,
                top_k: None,
                top_p: None,
                seed: None,
                stop_sequences: None,
                gemini_thinking_budget: None,
                gemini_enable_code_execution: None,
                system_prompt_ciphertext: None,
                system_prompt_nonce: None,
            };
            diesel::insert_into(chat_sessions_dsl::chat_sessions)
                .values(&new_chat_session)
                .returning(ChatSession::as_returning())
                .get_result::<ChatSession>(conn_sync)
        })
        .await
        .expect("DB interaction for create session failed")
        .expect("Error saving new chat session");

    // Set up a mock AI client response
    let mock_stream_items = vec![
        Ok(ChatStreamEvent::Chunk(StreamChunk {
            content: "This is the AI response".to_string(),
        })),
        Ok(ChatStreamEvent::End(StreamEnd::default())),
    ];

    test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client should be present")
        .set_stream_response(mock_stream_items);

    // Create a state Arc for testing chat_service directly
    // Create AppState similar to how it's done in spawn_app
    let encryption_service =
        Arc::new(scribe_backend::services::encryption_service::EncryptionService::new());
    let chat_override_service = Arc::new(
        scribe_backend::services::chat_override_service::ChatOverrideService::new(
            test_app.db_pool.clone(),
            encryption_service.clone(),
        ),
    );
    let user_persona_service = Arc::new(
        scribe_backend::services::user_persona_service::UserPersonaService::new(
            test_app.db_pool.clone(),
            encryption_service.clone(),
        ),
    );
    let token_counter_service = Arc::new(HybridTokenCounter::new_local_only(
        TokenizerService::new(&test_app.config.tokenizer_model_path)
            .expect("Failed to create tokenizer for test"),
    ));
    let lorebook_service = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
        test_app.qdrant_service.clone(),
    ));

    let auth_backend = Arc::new(scribe_backend::auth::user_store::Backend::new(
        test_app.db_pool.clone(),
    ));
    let file_storage_service = Arc::new(
        scribe_backend::services::file_storage_service::FileStorageService::new("./test_uploads")
            .expect("Failed to create test file storage service"),
    );

    let services = AppStateServices {
        ai_client: test_app.ai_client.clone(),
        embedding_client: test_app.mock_embedding_client.clone(),
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone(),
        chat_override_service,
        user_persona_service,
        token_counter: token_counter_service,
        encryption_service: encryption_service.clone(),
        lorebook_service,
        auth_backend,
        file_storage_service,
        email_service: Arc::new(scribe_backend::services::email_service::LoggingEmailService::new(
            "http://localhost:3000".to_string(),
        )),
    };

    let state_for_service =
        AppState::new(test_app.db_pool.clone(), test_app.config.clone(), services);
    let state_arc = std::sync::Arc::new(state_for_service);

    // Use get_session_data_for_generation to get the session data
    // This will test our fix for including first_mes when no history exists
    let user_message_content = "First user message";
    let session_dek = SecretBox::new(Box::new(vec![0u8; 32])); // Dummy DEK for testing
    let session_dek_arc = std::sync::Arc::new(session_dek);

    test_app // Add this block
        .mock_embedding_pipeline_service
        .add_retrieve_response(Ok(vec![]));

    let generation_data = get_session_data_for_generation(
        state_arc,
        user.id,
        session.id,
        user_message_content.to_string(),
        Some(session_dek_arc),
    )
    .await
    .expect("Failed to get session data for generation");

    // Extract the managed history from the generation data
    let (managed_history, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _) =
        generation_data;

    // Assert that the history contains the character's first_mes
    assert!(
        !managed_history.is_empty(),
        "Managed history should not be empty"
    );
    assert_eq!(
        managed_history.len(),
        1,
        "Managed history should have exactly 1 message (character's first_mes)"
    );

    // Check first message is the assistant's first_mes
    let first_msg = &managed_history[0];
    assert_eq!(
        first_msg.message_type,
        MessageRole::Assistant,
        "First message role should be Assistant"
    );
    assert_eq!(
        String::from_utf8_lossy(&first_msg.content).as_ref(),
        first_mes_content_plain,
        "First message content should match character's first_mes"
    );
}
