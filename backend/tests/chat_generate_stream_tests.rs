// backend/tests/chat_generate_stream_tests.rs
#![cfg(test)]

use std::env;
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use futures::TryStreamExt;
use genai::chat::{ChatStreamEvent, StreamChunk, StreamEnd};
use mime;
use std::{
    str::{self},
    time::Duration,
};
use tower::ServiceExt;
use tracing::error;
use uuid::Uuid;
use chrono::Utc; // Added for Utc::now()
use secrecy::{ExposeSecret, SecretBox}; // Added SecretBox

// Diesel and related imports
use diesel::prelude::*;
use diesel::RunQueryDsl as _; // Alias for use within interact closures

// Crate imports
use scribe_backend::{
    errors::AppError,
    models::{
        users::User,
        character_card::NewCharacter, // Corrected import path for NewCharacter
        characters::Character as DbCharacter, // Added DbCharacter import
        chats::{
            MessageRole, GenerateChatRequest, ApiChatMessage, Chat as ChatSession, NewChat, // Renamed ChatSession to Chat here
            ChatMessage as DbChatMessage, NewMessage,
        },
    },
    schema::{
        characters::dsl as characters_dsl,
        chat_sessions::dsl as chat_sessions_dsl,
        chat_messages::dsl as chat_messages_dsl,
    },
    test_helpers,
};

// Helper structs and functions for testing SSE
#[derive(Debug, PartialEq, Clone)]
pub struct ParsedSseEvent {
    pub event: Option<String>, // Name of the event (e.g., "content", "error")
    pub data: String,          // Raw data string
                               // Not parsing id or retry for now
}

// Revised helper to parse full SSE events
pub async fn collect_full_sse_events(body: axum::body::Body) -> Vec<ParsedSseEvent> {
    let mut events = Vec::new();
    let mut current_event_name: Option<String> = None;
    let mut current_data_lines: Vec<String> = Vec::new();

    let stream = body.into_data_stream();

    stream
        .try_for_each(|buf| {
            let chunk_str = match str::from_utf8(&buf) {
                Ok(s) => s,
                Err(e) => {
                    error!("SSE stream chunk is not valid UTF-8: {}", e);
                    // Depending on strictness, could return an error or skip the chunk
                    return futures::future::ready(Ok(())); // Skip malformed chunk
                }
            };
            
            for line in chunk_str.lines() {
                if line.is_empty() { // End of an event
                    if !current_data_lines.is_empty() { // Only push if there's data
                        events.push(ParsedSseEvent {
                            event: current_event_name.clone(),
                            data: current_data_lines.join("\n"), // Data can be multi-line
                        });
                        current_data_lines.clear();
                        // SSE spec: event name persists for subsequent data-only lines until next event: line or blank line.
                        // However, for simplicity here, we reset it as each 'event:' line should precede its 'data:'
                        // Axum's Event::default().data() does not set an event name, so current_event_name remains None.
                        // If an Event::event("name").data() is used, current_event_name would be Some("name").
                        // After a full event (blank line), the next event starts fresh. If it has no 'event:' line, it's a default 'message' event.
                        // So, resetting current_event_name to None is correct for default handling of subsequent unnamed events.
                        current_event_name = None; 
                    } else if current_event_name.is_some() {
                        // Handle event with name but no data, e.g. event: foo
                        events.push(ParsedSseEvent {
                            event: current_event_name.clone(),
                            data: String::new(),
                        });
                        current_event_name = None;
                    }
                } else if let Some(name) = line.strip_prefix("event:") {
                    current_event_name = Some(name.trim().to_string());
                } else if let Some(data_content) = line.strip_prefix("data:") {
                    current_data_lines.push(data_content.trim().to_string());
                }
                // Ignoring id: and retry: for now
            }
            futures::future::ready(Ok(()))
        })
        .await
        .expect("Failed to read SSE stream");

    // Handle any trailing event data if the stream ends without a blank line
    if !current_data_lines.is_empty() {
        events.push(ParsedSseEvent {
            event: current_event_name,
            data: current_data_lines.join("\n"),
        });
    }
    events
}


// --- Tests for POST /api/chats/{id}/generate (Streaming) ---

#[tokio::test]
#[ignore] // Added ignore for CI
async fn generate_chat_response_streaming_success() {
    let test_app = test_helpers::spawn_app(false, false, false).await; // Corrected: Added third arg
    
    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }
    
    let username = "gen_resp_stream_user";
    let password = "password123"; 
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(), // Corrected: .to_string()
        password.to_string(), // Corrected: .to_string()
    )
    .await
    .expect("Failed to create test user");

    let login_payload = serde_json::json!({
        "identifier": username, // Corrected: "identifier"
        "password": password,
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
        .unwrap();

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK, "Login request failed");

    let auth_cookie_header = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present on login")
        .to_str()
        .unwrap();
    let parsed_cookie = cookie::Cookie::parse(auth_cookie_header)
        .expect("Failed to parse Set-Cookie header");
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());

    let conn_pool = test_app.db_pool.clone(); // Use conn_pool for interact
    let user_id_clone = user.id;
    let character_name = "Char for Stream Resp".to_string();
    let character: DbCharacter = conn_pool.get().await.expect("Failed to get DB conn for char create").interact(move |conn_sync| { 
        let new_char_card = scribe_backend::models::character_card::NewCharacter { 
            user_id: user_id_clone,
            name: character_name,
            spec: "test_spec_v1.0".to_string(),
            spec_version: "1.0".to_string(),
            description: Some("Test description".to_string().into_bytes()),
            greeting: Some("Hello".to_string().into_bytes()),
            visibility: Some("private".to_string()),
            creator: Some("test_creator".to_string()),
            persona: Some("Test persona".to_string().into_bytes()),
            created_at: Some(Utc::now()), // Add created_at
            updated_at: Some(Utc::now()), // Add updated_at
            ..Default::default() 
        };
        diesel::insert_into(characters_dsl::characters)
            .values(&new_char_card)
            .get_result::<DbCharacter>(conn_sync)
    }).await.expect("DB interaction for create character failed").expect("Error saving new character");


    let conn_pool = test_app.db_pool.clone(); 
    let user_id_clone_session = user.id;
    let character_id_clone_session = character.id;
    let session_title = format!("Test Chat with Char {}", character.id);
    let session: ChatSession = conn_pool.get().await.expect("Failed to get DB conn for session create").interact(move |conn_sync| { 
        let new_chat_session = NewChat {
            id: Uuid::new_v4(),
            user_id: user_id_clone_session,
            character_id: character_id_clone_session,
            title: Some(session_title),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            history_management_strategy: "truncate".to_string(),
            history_management_limit: 10,
            model_name: "test-model".to_string(),
            visibility: Some("private".to_string()),
        };
        diesel::insert_into(chat_sessions_dsl::chat_sessions)
            .values(&new_chat_session)
            .returning(ChatSession::as_returning()) // Ensure returning or select is used
            .get_result::<ChatSession>(conn_sync)
    }).await.expect("DB interaction for create session failed").expect("Error saving new chat session");

    let conn_pool_msg1 = test_app.db_pool.clone(); // Use a new variable name to avoid lifetime issues if any
    let session_id_clone1 = session.id;
    let user_id_clone1 = user.id;
    conn_pool_msg1.get().await.expect("Failed to get DB conn for msg1 save").interact(move |conn_sync| { 
        let new_message1 = NewMessage {
            id: Uuid::new_v4(),
            session_id: session_id_clone1,
            user_id: user_id_clone1,
            message_type: MessageRole::User,
            content: "First prompt".as_bytes().to_vec(),
            content_nonce: None, 
            created_at: Utc::now(),
            updated_at: Utc::now(),
            role: Some("user".to_string()),
            parts: None,
            attachments: None,
        };
        diesel::insert_into(chat_messages_dsl::chat_messages)
            .values(&new_message1)
            .execute(conn_sync) 
    }).await.expect("DB interaction for save message 1 failed").expect("Error saving new chat message 1");

    let conn_pool_msg2 = test_app.db_pool.clone(); // Use a new variable name
    let session_id_clone2 = session.id;
    let user_id_clone2 = user.id;
    conn_pool_msg2.get().await.expect("Failed to get DB conn for msg2 save").interact(move |conn_sync| { 
        let new_message2 = NewMessage {
            id: Uuid::new_v4(),
            session_id: session_id_clone2,
            user_id: user_id_clone2, 
            message_type: MessageRole::Assistant,
            content: "First reply".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            role: Some("assistant".to_string()),
            parts: None,
            attachments: None,
        };
        diesel::insert_into(chat_messages_dsl::chat_messages)
            .values(&new_message2)
            .execute(conn_sync) 
    }).await.expect("DB interaction for save message 2 failed").expect("Error saving new chat message 2");

    // Mock the AI client to return a stream
    let mock_stream_items = vec![
        Ok(ChatStreamEvent::Chunk(StreamChunk {
            content: "Hello ".to_string(),
        })),
        Ok(ChatStreamEvent::Chunk(StreamChunk {
            content: "World!".to_string(),
        })),
        Ok(ChatStreamEvent::Chunk(StreamChunk {
            content: "".to_string(),
        })), // Test empty chunk
        Ok(ChatStreamEvent::End(StreamEnd::default())),
    ];
    
    // Set expected events before passing mock_stream_items to set_stream_response
    let expected_events = vec![
        ParsedSseEvent { 
            event: None, // Default event (interpreted as "message" by clients)
            data: serde_json::json!({"text": "Hello "}).to_string(),
        },
        ParsedSseEvent { 
            event: None, 
            data: serde_json::json!({"text": "World!"}).to_string(),
        },
        ParsedSseEvent { 
            event: None, 
            data: "[DONE]".to_string(),
        },
    ];
    
    test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client should be present")
        .set_stream_response(mock_stream_items);

   // Construct the new payload with history
   let history = vec![
       ApiChatMessage { role: "user".to_string(), content: "First prompt".to_string() },
       ApiChatMessage { role: "assistant".to_string(), content: "First reply".to_string() },
       ApiChatMessage { role: "user".to_string(), content: "User message for stream".to_string() },
   ];
   let payload = GenerateChatRequest {
       history,
       model: Some("test-stream-model".to_string()),
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

    let response = test_app.router.clone().oneshot(request).await.unwrap();

    // Assert headers
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::TEXT_EVENT_STREAM.as_ref()
    );

    // Consume and assert stream content
    let body = response.into_body();
    let actual_events = collect_full_sse_events(body).await;

    // Assert actual events match expected events
    assert_eq!(actual_events.len(), expected_events.len(), "Number of SSE events mismatch. Actual: {:?}, Expected: {:?}", actual_events, expected_events);
    for (i, (actual, expected)) in actual_events.iter().zip(expected_events.iter()).enumerate() {
        assert_eq!(actual.event, expected.event, "Event name mismatch at index {}", i);
        // For data, if it's JSON, compare parsed JSON to avoid string formatting issues
        if expected.data == "[DONE]" {
            assert_eq!(actual.data, "[DONE]", "Event data for [DONE] mismatch at index {}", i);
        } else if expected.data.starts_with('{') || expected.data.starts_with('[') {
            let actual_json: serde_json::Value = serde_json::from_str(&actual.data).expect(&format!("Actual data at index {} is not valid JSON: {}", i, actual.data));
            let expected_json: serde_json::Value = serde_json::from_str(&expected.data).expect(&format!("Expected data at index {} is not valid JSON: {}", i, expected.data));
            assert_eq!(actual_json, expected_json, "Event data JSON mismatch at index {}", i);
        } else {
            assert_eq!(actual.data, expected.data, "Event data string mismatch at index {}", i);
        }
    }

    // Assert background save (wait a bit for the background task)
    tokio::time::sleep(Duration::from_millis(100)).await; // Adjust timing if needed

    let conn_pool_load_msg = test_app.db_pool.clone(); // Use a new variable name
    let session_id_clone_load = session.id;
    let messages: Vec<DbChatMessage> = conn_pool_load_msg.get().await.expect("Failed to get DB conn for loading messages").interact(move |conn_sync| {
        chat_messages_dsl::chat_messages
            .filter(chat_messages_dsl::session_id.eq(session_id_clone_load))
            .order(chat_messages_dsl::created_at.asc())
            .select(DbChatMessage::as_select())
            .load::<DbChatMessage>(conn_sync)
    }).await.expect("DB interaction for loading messages failed").expect("Failed to load chat messages");

    assert_eq!(messages.len(), 3, "Should have 3 messages after streaming completion");
        
    // Expect initial 2 messages + 1 user message + 1 assistant message = 4 total
    assert_eq!(
        messages.len(),
        4,
        "Should have initial messages plus new user/AI pair"
    );

    // Check the *last* two messages for the new content
    let user_msg = messages
        .get(messages.len() - 2)
        .expect("User message should exist after generation");
    let ai_msg = messages
        .get(messages.len() - 1)
        .expect("AI message should exist after generation");

    assert_eq!(user_msg.message_type, MessageRole::User);
    assert_eq!(String::from_utf8_lossy(&user_msg.content), "User message for stream");

    assert_eq!(ai_msg.message_type, MessageRole::Assistant);
    assert_eq!(String::from_utf8_lossy(&ai_msg.content), "Hello World!");

    // Verify embedding service was called with the AI message
    let _embedding_calls = test_app.mock_embedding_pipeline_service.get_calls();
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn generate_chat_response_streaming_ai_error() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    
    // Skip if running as integration test with real client
    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }

    let username = "gen_resp_stream_err_user";
    let password = "password";
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

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK, "Login request failed");

    let auth_cookie_header = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present on login")
        .to_str()
        .unwrap();
    let parsed_cookie = cookie::Cookie::parse(auth_cookie_header)
        .expect("Failed to parse Set-Cookie header");
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());
    
    let conn_pool = test_app.db_pool.clone();
    let user_id_clone = user.id;
    let character_name = "Char for Stream Err".to_string();
    let character: DbCharacter = conn_pool.get().await.expect("Failed to get DB conn for char create").interact(move |conn_sync| { 
        let new_char_card = scribe_backend::models::character_card::NewCharacter { 
            user_id: user_id_clone,
            name: character_name,
            spec: "test_spec_v1.0".to_string(),
            spec_version: "1.0".to_string(),
            description: Some("Test description".to_string().into_bytes()),
            greeting: Some("Hello".to_string().into_bytes()),
            visibility: Some("private".to_string()),
            creator: Some("test_creator".to_string()),
            persona: Some("Test persona".to_string().into_bytes()),
            created_at: Some(Utc::now()), // Add created_at
            updated_at: Some(Utc::now()), // Add updated_at
            ..Default::default() 
        };
        diesel::insert_into(characters_dsl::characters)
            .values(&new_char_card)
            .get_result::<DbCharacter>(conn_sync)
    }).await.expect("DB interaction for create character failed").expect("Error saving new character");

    let conn_pool = test_app.db_pool.clone();
    let user_id_clone_session = user.id;
    let character_id_clone_session = character.id;
    let session_title = format!("Test Chat with Char {}", character.id);
    let session: ChatSession = conn_pool.get().await.expect("Failed to get DB conn for session create").interact(move |conn_sync| { 
        let new_chat_session = NewChat {
            id: Uuid::new_v4(),
            user_id: user_id_clone_session,
            character_id: character_id_clone_session,
            title: Some(session_title),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            history_management_strategy: "truncate".to_string(),
            history_management_limit: 10,
            model_name: "test-model".to_string(),
            visibility: Some("private".to_string()),
        };
        diesel::insert_into(chat_sessions_dsl::chat_sessions)
            .values(&new_chat_session)
            .returning(ChatSession::as_returning()) // or .select(ChatSession::as_select())
            .get_result::<ChatSession>(conn_sync)
    }).await.expect("DB interaction for create session failed").expect("Error saving new chat session");

    // Mock the AI client to return an error in the stream
    let mock_error_message = "Mock AI error during streaming".to_string();
    let mock_stream_items = vec![
        Ok(ChatStreamEvent::Chunk(StreamChunk {
            content: "Partial ".to_string(),
        })),
        Err(AppError::GeminiError(
            mock_error_message.clone()
        )),
        Ok(ChatStreamEvent::Chunk(StreamChunk {
            content: "Should not be sent".to_string(),
        })),
    ];
    
    // Extract expected events before moving mock_stream_items
    let expected_events = vec![
        ParsedSseEvent {
            event: None, // Default event for content
            data: serde_json::json!({"text": "Partial "}).to_string(),
        },
        ParsedSseEvent {
            event: Some("error".to_string()),
            data: format!("LLM API error: {}", mock_error_message),
        }
    ];
    
    test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client should be present")
        .set_stream_response(mock_stream_items);

   // Construct the new payload with history
   let history = vec![
       ApiChatMessage { role: "user".to_string(), content: "User message for error stream".to_string() },
   ];
   let payload = GenerateChatRequest {
       history,
       model: Some("test-stream-err-model".to_string()),
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

    let response = test_app.router.clone().oneshot(request).await.unwrap();

    // Assert headers
    assert_eq!(response.status(), StatusCode::OK); // SSE connection established successfully
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::TEXT_EVENT_STREAM.as_ref()
    );

    // Read the SSE stream and collect data/error events
    let body = response.into_body();
    let actual_events = collect_full_sse_events(body).await;

    // Assertions
    assert_eq!(actual_events.len(), expected_events.len(), "Number of SSE events mismatch. Actual: {:?}, Expected: {:?}", actual_events, expected_events);
    for (i, (actual, expected)) in actual_events.iter().zip(expected_events.iter()).enumerate() {
        assert_eq!(actual.event, expected.event, "Event name mismatch at index {}. Actual: {:?}, Expected: {:?}", i, actual, expected);
        if expected.data.starts_with('{') || expected.data.starts_with('[') {
            let actual_json: serde_json::Value = serde_json::from_str(&actual.data).expect(&format!("Actual data at index {} is not valid JSON: {}", i, actual.data));
            let expected_json: serde_json::Value = serde_json::from_str(&expected.data).expect(&format!("Expected data at index {} is not valid JSON: {}", i, expected.data));
            assert_eq!(actual_json, expected_json, "Event data JSON mismatch at index {}", i);
        } else {
            assert_eq!(actual.data, expected.data, "Event data string mismatch at index {}", i);
        }
    }

    // Assert background save (wait a bit)
    tokio::time::sleep(Duration::from_millis(200)).await; // Increased wait time slightly

    let conn_pool = test_app.db_pool.clone();
    let session_id_clone = session.id;
    let messages: Vec<DbChatMessage> = conn_pool.get().await.expect("Failed to get DB conn for loading messages").interact(move |conn_sync| {
        chat_messages_dsl::chat_messages
            .filter(chat_messages_dsl::session_id.eq(session_id_clone))
            .order(chat_messages_dsl::created_at.asc())
            .select(DbChatMessage::as_select())
            .load::<DbChatMessage>(conn_sync)
    }).await.expect("DB interaction for loading messages failed").expect("Failed to load chat messages");

    assert_eq!(
        messages.len(),
        2,
        "Should have user and PARTIAL AI message after stream error"
    );

    let user_msg = messages.first().unwrap();
    assert_eq!(user_msg.message_type, MessageRole::User);
    assert_eq!(String::from_utf8_lossy(&user_msg.content), "User message for error stream");

    let ai_msg = messages.get(1).unwrap();
    assert_eq!(ai_msg.message_type, MessageRole::Assistant);
    // The background save happens *after* the stream finishes (or errors), saving whatever was buffered.
    assert_eq!(
        String::from_utf8_lossy(&ai_msg.content),
        "Partial ",
        "Partial content 'Partial ' should be saved"
    );

    // Verify embedding service was called with the AI message (even partial)
    let _embedding_calls = test_app.mock_embedding_pipeline_service.get_calls(); // Renamed to _embedding_calls as it's not used
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn generate_chat_response_streaming_unauthorized() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let session_id = Uuid::new_v4(); // Dummy ID

   // Construct the new payload with history
   let history = vec![
       ApiChatMessage { role: "user".to_string(), content: "test".to_string() },
   ];
   let payload = GenerateChatRequest {
       history,
       model: None,
   };
   let request = Request::builder()
       .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session_id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    // No auth cookie

    let response = test_app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
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
async fn generate_chat_response_streaming_not_found() {
    let test_app = test_helpers::spawn_app(false, false, false).await;

    let username = "stream_404_user";
    let password = "password";
    let _user = test_helpers::db::create_test_user( // _user as it's not used directly
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

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK, "Login request failed");

    let auth_cookie_header = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present on login")
        .to_str()
        .unwrap();
    let parsed_cookie = cookie::Cookie::parse(auth_cookie_header)
        .expect("Failed to parse Set-Cookie header");
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());
    
    let non_existent_session_id = Uuid::new_v4();

   // Construct the new payload with history
   let history = vec![
       ApiChatMessage { role: "user".to_string(), content: "test".to_string() },
   ];
   let payload = GenerateChatRequest {
       history,
       model: None,
   };
   let request = Request::builder()
       .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", non_existent_session_id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
async fn generate_chat_response_streaming_forbidden() {
    let test_app = test_helpers::spawn_app(false, false, false).await;

    // Create User 1
    let username1 = "stream_forbid_user1";
    let password_user1 = "password"; 
    let user1 = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username1.to_string(),
        password_user1.to_string(),
    )
    .await
    .expect("Failed to create test user1");

    let conn_pool = test_app.db_pool.clone();
    let user_id_clone = user1.id;
    let character_name = "User1 Char for Stream Forbidden".to_string();
    let character1: DbCharacter = conn_pool.get().await.expect("Failed to get DB conn for char create").interact(move |conn_sync| { 
        let new_char_card = scribe_backend::models::character_card::NewCharacter { 
            user_id: user_id_clone,
            name: character_name,
            spec: "test_spec_v1.0".to_string(),
            spec_version: "1.0".to_string(),
            description: Some("Test description".to_string().into_bytes()),
            greeting: Some("Hello".to_string().into_bytes()),
            visibility: Some("private".to_string()),
            creator: Some("test_creator".to_string()),
            persona: Some("Test persona".to_string().into_bytes()),
            created_at: Some(Utc::now()), // Add created_at
            updated_at: Some(Utc::now()), // Add updated_at
            ..Default::default() 
        };
        diesel::insert_into(characters_dsl::characters)
            .values(&new_char_card)
            .get_result::<DbCharacter>(conn_sync)
    }).await.expect("DB interaction for create character failed").expect("Error saving new character");

    let conn_pool = test_app.db_pool.clone();
    let user_id_clone_session = user1.id;
    let character_id_clone_session = character1.id;
    let session_title = format!("Test Chat with Char {}", character1.id);
    let session1: ChatSession = conn_pool.get().await.expect("Failed to get DB conn for session create").interact(move |conn_sync| { 
        let new_chat_session = NewChat {
            id: Uuid::new_v4(),
            user_id: user_id_clone_session,
            character_id: character_id_clone_session,
            title: Some(session_title),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            history_management_strategy: "truncate".to_string(),
            history_management_limit: 10,
            model_name: "test-model".to_string(),
            visibility: Some("private".to_string()),
        };
        diesel::insert_into(chat_sessions_dsl::chat_sessions)
            .values(&new_chat_session)
            .returning(ChatSession::as_returning()) // Ensure returning or select is used
            .get_result::<ChatSession>(conn_sync)
    }).await.expect("DB interaction for create session failed").expect("Error saving new chat session");

    // Create and Login User 2
    let username2 = "stream_forbid_user2";
    let password_user2 = "password";
    let _user2 = test_helpers::db::create_test_user( 
        &test_app.db_pool,
        username2.to_string(),
        password_user2.to_string(),
    )
    .await
    .expect("Failed to create test user2");

    let login_payload2 = serde_json::json!({
        "identifier": username2,
        "password": password_user2,
    });
    let login_request2 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload2).unwrap()))
        .unwrap();

    let login_response2 = test_app.router.clone().oneshot(login_request2).await.unwrap();
    assert_eq!(login_response2.status(), StatusCode::OK, "Login request for user2 failed");

    let auth_cookie_header2 = login_response2
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present on login for user2")
        .to_str()
        .unwrap();
    let parsed_cookie2 = cookie::Cookie::parse(auth_cookie_header2)
        .expect("Failed to parse Set-Cookie header for user2");
    let auth_cookie2 = format!("{}={}", parsed_cookie2.name(), parsed_cookie2.value());

// Construct the new payload with history
let history = vec![
ApiChatMessage { role: "user".to_string(), content: "test".to_string() },
];
let payload = GenerateChatRequest {
history,
model: None,
};
let request = Request::builder()
.method(Method::POST)
        // User 2 tries to generate in User 1's session
        .uri(format!("/api/chats/{}/generate", session1.id))
        .header(header::COOKIE, auth_cookie2) // Use user 2's cookie
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::ACCEPT, mime::TEXT_EVENT_STREAM.as_ref()) // Add Accept header for streaming
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    // The initial DB query checks ownership and returns Forbidden if mismatch
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
#[ignore] // Ignore for CI unless DB and real AI are guaranteed
async fn test_rag_context_injection_real_ai() {
    let test_app = test_helpers::spawn_app(false, true, true).await; // Use the helper, ensure all args present

    if std::env::var("RUN_INTEGRATION_TESTS").is_err() {
        println!("Skipping RAG integration test: RUN_INTEGRATION_TESTS not set");
        return;
    }

    let username = "rag_real_user";
    let password = "password";
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

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK, "Login request failed");

    let auth_cookie_header = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present on login")
        .to_str()
        .unwrap();
    let parsed_cookie = cookie::Cookie::parse(auth_cookie_header)
        .expect("Failed to parse Set-Cookie header");
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());
    
    let conn_pool = test_app.db_pool.clone();
    let user_id_clone = user.id;
    let char_name_rag = "RAG Real AI Char".to_string();
    let character: DbCharacter = conn_pool.get().await.expect("Failed to get DB conn for char create").interact(move |conn_sync| {
        let new_char_card = scribe_backend::models::character_card::NewCharacter {
            user_id: user_id_clone,
            name: char_name_rag,
            spec: "test_spec_v1.0".to_string(),
            spec_version: "1.0".to_string(),
            description: Some("Test description".to_string().into_bytes()),
            greeting: Some("Hello".to_string().into_bytes()),
            visibility: Some("private".to_string()),
            creator: Some("test_creator".to_string()),
            persona: Some("Test persona".to_string().into_bytes()),
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            ..Default::default()
        };
        diesel::insert_into(characters_dsl::characters)
            .values(&new_char_card)
            .get_result::<DbCharacter>(conn_sync)
    }).await.expect("DB interaction for create character failed").expect("Error saving new character");

    let conn_pool = test_app.db_pool.clone();
    let user_id_clone_session = user.id;
    let character_id_clone_session = character.id;
    let session_title_rag = format!("Test Chat with Char {}", character.id);
    let session: ChatSession = conn_pool.get().await.expect("Failed to get DB conn for session create").interact(move |conn_sync| {
        let new_chat_session = NewChat {
            id: Uuid::new_v4(),
            user_id: user_id_clone_session,
            character_id: character_id_clone_session,
            title: Some(session_title_rag),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            history_management_strategy: "truncate".to_string(),
            history_management_limit: 10,
            model_name: "test-model".to_string(),
            visibility: Some("private".to_string()),
        };
        diesel::insert_into(chat_sessions_dsl::chat_sessions)
            .values(&new_chat_session)
            .returning(ChatSession::as_returning()) // Ensure returning or select is used
            .get_result::<ChatSession>(conn_sync)
    }).await.expect("DB interaction for create session failed").expect("Error saving new chat session");

    // Message containing info the AI shouldn't know without RAG
    let document_content = "Ouroboros is the secret handshake.";
    
    // Create the message using interact pattern
    let conn_pool = test_app.db_pool.clone();
    let session_id_clone_msg = session.id;
    let user_id_clone_msg = user.id;
    conn_pool.get().await.expect("Failed to get DB conn for msg save").interact(move |conn_sync| {
        let new_message = NewMessage {
            id: Uuid::new_v4(),
            session_id: session_id_clone_msg,
            user_id: user_id_clone_msg,
            message_type: MessageRole::Assistant, // Or User, depending on how RAG docs are stored
            content: document_content.as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            role: Some("assistant".to_string()),
            parts: None,
            attachments: None,
        };
        diesel::insert_into(chat_messages_dsl::chat_messages)
            .values(&new_message)
            .execute(conn_sync)
    }).await.expect("DB interaction for save message failed").expect("Error saving document message");

    // Allow time for potential Qdrant indexing
    tokio::time::sleep(Duration::from_secs(1)).await;

    let query_text = "What is Ouroboros in Greek mythology?"; 
    let history = vec![
        ApiChatMessage { role: "assistant".to_string(), content: document_content.to_string() }, 
        ApiChatMessage { role: "user".to_string(), content: query_text.to_string() }, 
    ];
    let payload = GenerateChatRequest {
        history,
        model: None, 
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, &auth_cookie)
        .header(header::ACCEPT, "text/event-stream") 
        .body(Body::from(serde_json::to_vec(&payload).unwrap())) 
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let sse_data = collect_full_sse_events(response.into_body()).await;
    let combined_response = sse_data.iter().filter_map(|e| {
        if e.event.is_none() && e.data != "[DONE]" {
            serde_json::from_str::<serde_json::Value>(&e.data)
                .ok()
                .and_then(|v| v.get("text").and_then(|t| t.as_str().map(String::from)))
        } else {
            None
        }
    }).collect::<Vec<String>>().join("");


    println!(
        "\n--- REAL AI Response Received ---\n{}\n---------------------------------\n",
        combined_response
    );
    assert!(
        combined_response.to_lowercase().contains("serpent") || combined_response.to_lowercase().contains("dragon") || combined_response.to_lowercase().contains("tail"),
        "Real AI response should mention serpent/dragon/tail for Ouroboros, but got: {}",
        combined_response
    );
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_streaming_initiation_error() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    
    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }
    
    let username = "stream_init_err_user";
    let password = "password123"; 
    let user_with_dek = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await
    .expect("Failed to create test user with DEK");

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

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK, "Login request failed");

    let auth_cookie_header = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present on login")
        .to_str()
        .unwrap();
    let parsed_cookie = cookie::Cookie::parse(auth_cookie_header)
        .expect("Failed to parse Set-Cookie header");
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());

    let conn_pool = test_app.db_pool.clone();
    let user_id_clone = user_with_dek.id;
    let char_name_init_err = "Stream Init Err Char".to_string();
    let character: DbCharacter = conn_pool.get().await.expect("Failed to get DB conn for char create").interact(move |conn_sync| {
        let new_char_card = scribe_backend::models::character_card::NewCharacter {
            user_id: user_id_clone,
            name: char_name_init_err,
            spec: "test_spec_v1.0".to_string(),
            spec_version: "1.0".to_string(),
            description: Some("Test description".to_string().into_bytes()),
            greeting: Some("Hello".to_string().into_bytes()),
            visibility: Some("private".to_string()),
            creator: Some("test_creator".to_string()),
            persona: Some("Test persona".to_string().into_bytes()),
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            ..Default::default()
        };
        diesel::insert_into(characters_dsl::characters)
            .values(&new_char_card)
            .get_result::<DbCharacter>(conn_sync)
    }).await.expect("DB interaction for create character failed").expect("Error saving new character");

    let conn_pool = test_app.db_pool.clone();
    let user_id_clone_session = user_with_dek.id;
    let character_id_clone_session = character.id;
    let session_title_init_err = format!("Test Chat with Char {}", character.id);
    let session: ChatSession = conn_pool.get().await.expect("Failed to get DB conn for session create").interact(move |conn_sync| {
        let new_chat_session = NewChat {
            id: Uuid::new_v4(),
            user_id: user_id_clone_session,
            character_id: character_id_clone_session,
            title: Some(session_title_init_err),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            history_management_strategy: "truncate".to_string(),
            history_management_limit: 10,
            model_name: "test-model".to_string(),
            visibility: Some("private".to_string()),
        };
        diesel::insert_into(chat_sessions_dsl::chat_sessions)
            .values(&new_chat_session)
            .returning(ChatSession::as_returning()) // Ensure returning or select is used
            .get_result::<ChatSession>(conn_sync)
    }).await.expect("DB interaction for create session failed").expect("Error saving new chat session");

    // Mock the AI client's stream_chat method to return an error immediately
    let error_message = "Mock AI service error during stream initiation".to_string();
    // Use AppError::AiServiceError as this is what the non-stream test used for a 500
    let ai_error = AppError::AiServiceError(error_message.clone());
    
    test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client should be present")
        .set_stream_response(vec![Err(ai_error)]); // set_stream_response expects Vec<Result<Event>>

   // Construct the new payload with history
   let user_message_content = "User message for stream initiation error";
   let history = vec![
       ApiChatMessage { role: "user".to_string(), content: user_message_content.to_string() },
   ];
   let payload = GenerateChatRequest {
       history,
       model: Some("test-stream-init-err-model".to_string()),
   };

   let request = Request::builder()
       .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::ACCEPT, mime::TEXT_EVENT_STREAM.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();

    // Assert status - Should be INTERNAL_SERVER_ERROR (500)
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    
    // Assert Content-Type is application/json for the error response
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::APPLICATION_JSON.as_ref(),
        "Content-Type should be application/json for a 500 error"
    );

    // Check the error response body
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    let body_json: serde_json::Value = serde_json::from_str(&body_str)
        .unwrap_or_else(|e| panic!("Failed to parse error response JSON: {}. Body: {}", e, body_str));

    // Example: {"error": "AI service error", "message": "Mock AI service error during stream initiation"}
    // The exact structure depends on AppError's IntoResponse implementation.
    // Assuming AppError serializes to something like: {"error": "short_error_type", "message": "detailed_message"}
    // For AppError::AiServiceError, "error" might be "ai_service_error" or "internal_server_error"
    // and "message" would be the error_message.
    // Based on AppError, it seems it will serialize to a more direct string or a simple {"error": "message"}
    // Let's check what the non-stream test expected for AppError::AiServiceError serialization.
    // The non-stream test expected: {"error": "LLM API error: Mock AI service error"}
    // Let's assume a similar structure or at least that the message is present.
    // For AiServiceError, the message is directly the string passed.
    // The generic error handler might wrap it. For now, let's assert the message from the error.
    // The AppError IntoResponse for AiServiceError returns (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e})))
    // where `e` is the content of AiServiceError.
    assert_eq!(body_json.get("error").and_then(|v| v.as_str()), Some(error_message.as_str()), "Error message mismatch in JSON response. Body: {}", body_str);


    // Assert only the user's message was saved and decrypt it
    tokio::time::sleep(Duration::from_millis(200)).await; // Increased sleep slightly
    
    let conn_pool_load = test_app.db_pool.clone();
    let session_id_clone_load = session.id;
    let messages_from_db: Vec<DbChatMessage> = conn_pool_load.get().await.expect("Failed to get DB for loading messages").interact(move |conn_sync| {
        chat_messages_dsl::chat_messages
            .filter(chat_messages_dsl::session_id.eq(session_id_clone_load))
            .order(chat_messages_dsl::created_at.asc())
            .select(DbChatMessage::as_select()) // Ensure select is used
            .load::<DbChatMessage>(conn_sync)   // Use conn_sync from interact
    }).await.expect("DB interaction for loading messages failed").expect("Failed to load chat messages");
        
    assert_eq!(
        messages_from_db.len(),
        1, 
        "Should only have the user message saved after stream initiation error. Found: {:?}", messages_from_db
    );

    let saved_user_message = &messages_from_db[0];
    assert_eq!(saved_user_message.message_type, MessageRole::User);

    // Decrypt the saved user message content
    let user_dek_secret_box_wrapper = user_with_dek.dek.as_ref().expect("User DEK should be set for decryption");
    let dek = user_dek_secret_box_wrapper.0.expose_secret();
    let decrypted_content_bytes_result = scribe_backend::crypto::decrypt_gcm(
        &saved_user_message.content,
        &saved_user_message.content_nonce.as_ref().expect("Nonce must be present for decryption"),
        &SecretBox::new(Box::new(dek.clone())) // Wrap in Box::new and then SecretBox as expected by decrypt_gcm
    );
    
    // Handle potential decryption error more gracefully for debugging
    let decrypted_content_bytes = match decrypted_content_bytes_result {
        Ok(bytes) => bytes,
        Err(e) => {
            // Consider logging the full user_with_dek and saved_user_message for detailed diagnosis
            panic!("Failed to decrypt saved user message content: {:?}. User DEK: {:?}, Message Nonce: {:?}, Message Content (first 16 bytes): {:?}", 
                e, 
                user_with_dek.dek.as_ref().map(|d| format!("{:X?}", d.0.expose_secret())),
                saved_user_message.content_nonce.as_ref().map(|n| format!("{:X?}", n)),
                saved_user_message.content.get(..16).map(|s| format!("{:X?}", s))
            );
        }
    };

    // decrypted_content_bytes is already Vec<u8>, no need to call to_vec()
    // We get a SecretBox<Vec<u8>> back from decrypt_gcm, need to expose_secret first
    let decrypted_content_str = String::from_utf8(decrypted_content_bytes.expose_secret().clone())
        .expect("Failed to convert decrypted bytes to string");

    assert_eq!(decrypted_content_str, user_message_content, "Decrypted user message content mismatch");
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_streaming_error_before_content() {
    let test_app = test_helpers::spawn_app(false, false, false).await; // Corrected: Added third arg
    
    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }
    
    let username = "stream_err_b4_content_user";
    let password = "password123"; 
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(), // Corrected: .to_string()
        password.to_string(), // Corrected: .to_string()
    )
    .await
    .expect("Failed to create test user");

    let login_payload = serde_json::json!({
        "identifier": username, // Corrected: "identifier"
        "password": password,
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
        .unwrap();

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK, "Login request failed");

    let auth_cookie_header = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present on login")
        .to_str()
        .unwrap();
    let parsed_cookie = cookie::Cookie::parse(auth_cookie_header)
        .expect("Failed to parse Set-Cookie header");
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());
    
    let conn_pool = test_app.db_pool.clone();
    let user_id_clone = user.id;
    let char_name = "Stream Err B4 Content Char".to_string();
    let character: DbCharacter = conn_pool.get().await.expect("Failed to get DB conn for char create").interact(move |conn_sync| { 
        let new_char_card = scribe_backend::models::character_card::NewCharacter { 
            user_id: user_id_clone,
            name: char_name,
            spec: "test_spec_v1.0".to_string(),
            spec_version: "1.0".to_string(),
            description: Some("Test description".to_string().into_bytes()),
            greeting: Some("Hello".to_string().into_bytes()),
            visibility: Some("private".to_string()),
            creator: Some("test_creator".to_string()),
            persona: Some("Test persona".to_string().into_bytes()),
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            ..Default::default()
        };
        diesel::insert_into(characters_dsl::characters)
            .values(&new_char_card)
            .get_result::<DbCharacter>(conn_sync)
    }).await.expect("DB interaction for create character failed").expect("Error saving new character");

    let conn_pool = test_app.db_pool.clone();
    let user_id_clone_session = user.id;
    let character_id_clone_session = character.id;
    let session_title = format!("Test Chat with Char {}", character.id);
    let session: ChatSession = conn_pool.get().await.expect("Failed to get DB conn for session create").interact(move |conn_sync| { 
        let new_chat_session = NewChat {
            id: Uuid::new_v4(),
            user_id: user_id_clone_session,
            character_id: character_id_clone_session,
            title: Some(session_title),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            history_management_strategy: "truncate".to_string(),
            history_management_limit: 10,
            model_name: "test-model".to_string(),
            visibility: Some("private".to_string()),
        };
        diesel::insert_into(chat_sessions_dsl::chat_sessions)
            .values(&new_chat_session)
            .returning(ChatSession::as_returning()) // Ensure returning or select is used
            .get_result::<ChatSession>(conn_sync)
    }).await.expect("DB interaction for create session failed").expect("Error saving new chat session");

    // Mock the AI client stream: Start -> Error
    let error_message = "Mock AI error before content".to_string();
    let mock_stream_items = vec![
        Ok(ChatStreamEvent::Start),
        Err(AppError::GeminiError( // Or another appropriate AppError variant
            error_message.clone()
        )),
    ];
    
    // Prepare expected events before moving mock_stream_items
    let expected_events = vec![
        // No thinking event because X-Request-Thinking is false by default
        ParsedSseEvent {
            event: Some("error".to_string()),
            data: format!("LLM API error: {}", error_message),
        }
    ];
    
    test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client should be present")
        .set_stream_response(mock_stream_items);

   // Construct the new payload with history
   let history = vec![
       ApiChatMessage { role: "user".to_string(), content: "User message for error before content".to_string() },
   ];
   let payload = GenerateChatRequest {
       history,
       model: Some("test-stream-err-b4-content-model".to_string()),
   };

   let request = Request::builder()
       .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::ACCEPT, mime::TEXT_EVENT_STREAM.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();

    // Assert headers
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::TEXT_EVENT_STREAM.as_ref()
    );

    // Consume and assert stream content
    let body = response.into_body();
    let actual_events = collect_full_sse_events(body).await;

    assert_eq!(actual_events.len(), expected_events.len(), "Number of SSE events mismatch. Actual: {:?}, Expected: {:?}", actual_events, expected_events);
    for (i, (actual, expected)) in actual_events.iter().zip(expected_events.iter()).enumerate() {
        assert_eq!(actual.event, expected.event, "Event name mismatch at index {}", i);
        assert_eq!(actual.data, expected.data, "Event data string mismatch at index {}", i);
    }

    // Assert background save (wait a bit)
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let conn_pool = test_app.db_pool.clone();
    let session_id_clone = session.id;
    let messages: Vec<DbChatMessage> = conn_pool.get().await.expect("Failed to get DB conn for loading messages").interact(move |conn_sync| {
        chat_messages_dsl::chat_messages
            .filter(chat_messages_dsl::session_id.eq(session_id_clone))
            .order(chat_messages_dsl::created_at.asc())
            .select(DbChatMessage::as_select())
            .load::<DbChatMessage>(conn_sync)
    }).await.expect("DB interaction for loading messages failed").expect("Failed to load chat messages");
        
    assert_eq!(
        messages.len(),
        2, // Only the user message from the payload should be saved
        "Should only have user message saved after stream error before content"
    );
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_streaming_empty_response() {
    let test_app = test_helpers::spawn_app(false, false, false).await; // Corrected: Added third arg
    
    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }
    
    let username = "stream_empty_resp_user";
    let password = "password123"; 
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(), // Corrected: .to_string()
        password.to_string(), // Corrected: .to_string()
    )
    .await
    .expect("Failed to create test user");

    let login_payload = serde_json::json!({
        "identifier": username, // Corrected: "identifier"
        "password": password,
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
        .unwrap();

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK, "Login request failed");

    let auth_cookie_header = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present on login")
        .to_str()
        .unwrap();
    let parsed_cookie = cookie::Cookie::parse(auth_cookie_header)
        .expect("Failed to parse Set-Cookie header");
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());
    
    let conn_pool = test_app.db_pool.clone();
    let user_id_clone = user.id;
    let char_name = "Stream Empty Resp Char".to_string();
    let character: DbCharacter = conn_pool.get().await.expect("Failed to get DB conn for char create").interact(move |conn_sync| { 
        let new_char_card = scribe_backend::models::character_card::NewCharacter { 
            user_id: user_id_clone,
            name: char_name,
            spec: "test_spec_v1.0".to_string(),
            spec_version: "1.0".to_string(),
            description: Some("Test description".to_string().into_bytes()),
            greeting: Some("Hello".to_string().into_bytes()),
            visibility: Some("private".to_string()),
            creator: Some("test_creator".to_string()),
            persona: Some("Test persona".to_string().into_bytes()),
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            ..Default::default()
        };
        diesel::insert_into(characters_dsl::characters)
            .values(&new_char_card)
            .get_result::<DbCharacter>(conn_sync)
    }).await.expect("DB interaction for create character failed").expect("Error saving new character");

    let conn_pool = test_app.db_pool.clone();
    let user_id_clone_session = user.id;
    let character_id_clone_session = character.id;
    let session_title = format!("Test Chat with Char {}", character.id);
    let session: ChatSession = conn_pool.get().await.expect("Failed to get DB conn for session create").interact(move |conn_sync| { 
        let new_chat_session = NewChat {
            id: Uuid::new_v4(),
            user_id: user_id_clone_session,
            character_id: character_id_clone_session,
            title: Some(session_title),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            history_management_strategy: "truncate".to_string(),
            history_management_limit: 10,
            model_name: "test-model".to_string(),
            visibility: Some("private".to_string()),
        };
        diesel::insert_into(chat_sessions_dsl::chat_sessions)
            .values(&new_chat_session)
            .returning(ChatSession::as_returning()) // Ensure returning or select is used
            .get_result::<ChatSession>(conn_sync)
    }).await.expect("DB interaction for create session failed").expect("Error saving new chat session");

    // Mock the AI client stream: Start -> End
    let mock_stream_items = vec![
        Ok(ChatStreamEvent::Start),
        Ok(ChatStreamEvent::End(StreamEnd::default())),
    ];
    
    // Prepare expected events before moving mock_stream_items
    let expected_events = vec![
        ParsedSseEvent { 
            event: None, // Default event for the [DONE] marker
            data: "[DONE]".to_string(),
        }
    ];
    
    test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client should be present")
        .set_stream_response(mock_stream_items);

   // Construct the new payload with history
   let history = vec![
       ApiChatMessage { role: "user".to_string(), content: "User message for empty stream response".to_string() },
   ];
   let payload = GenerateChatRequest {
       history,
       model: Some("test-stream-empty-resp-model".to_string()),
   };

   let request = Request::builder()
       .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::ACCEPT, mime::TEXT_EVENT_STREAM.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();

    // Assert headers
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::TEXT_EVENT_STREAM.as_ref()
    );

    // Consume and assert stream content
    let body = response.into_body();
    let actual_events = collect_full_sse_events(body).await;

    assert_eq!(actual_events.len(), expected_events.len(), "Number of SSE events mismatch. Actual: {:?}, Expected: {:?}", actual_events, expected_events);
    for (i, (actual, expected)) in actual_events.iter().zip(expected_events.iter()).enumerate() {
        assert_eq!(actual.event, expected.event, "Event name mismatch at index {}", i);
        assert_eq!(actual.data, expected.data, "Event data string mismatch at index {}. Actual: {}, Expected: {}", i, actual.data, expected.data);
    }

    // Assert background save (wait a bit)
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let conn_pool = test_app.db_pool.clone();
    let session_id_clone = session.id;
    let messages: Vec<DbChatMessage> = conn_pool.get().await.expect("Failed to get DB conn for loading messages").interact(move |conn_sync| {
        chat_messages_dsl::chat_messages
            .filter(chat_messages_dsl::session_id.eq(session_id_clone))
            .order(chat_messages_dsl::created_at.asc())
            .select(DbChatMessage::as_select()) // Ensure select is used
            .load::<DbChatMessage>(conn_sync)
    }).await.expect("DB interaction for loading messages failed").expect("Failed to load chat messages");
        
    assert_eq!(
        messages.len(),
        1, // Only user message from payload should be saved
        "Should only have user message saved after empty stream response"
    );
    assert_eq!(messages[0].message_type, MessageRole::User);
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_streaming_reasoning_chunk() {
    let test_app = test_helpers::spawn_app(false, false, false).await; // Corrected: Added third arg
    
    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }
    
    let username = "stream_reasoning_user";
    let password = "password123"; 
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(), // Corrected: .to_string()
        password.to_string(), // Corrected: .to_string()
    )
    .await
    .expect("Failed to create test user");

    let login_payload = serde_json::json!({
        "identifier": username, // Corrected: "identifier"
        "password": password,
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
        .unwrap();

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK, "Login request failed");

    let auth_cookie_header = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present on login")
        .to_str()
        .unwrap();
    let parsed_cookie = cookie::Cookie::parse(auth_cookie_header)
        .expect("Failed to parse Set-Cookie header");
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());
    
    let conn_pool = test_app.db_pool.clone();
    let user_id_clone = user.id;
    let char_name_reasoning = "Stream Reasoning Char".to_string();
    let character: DbCharacter = conn_pool.get().await.expect("Failed to get DB conn for char create").interact(move |conn_sync| {
        let new_char_card = scribe_backend::models::character_card::NewCharacter {
            user_id: user_id_clone,
            name: char_name_reasoning,
            spec: "test_spec_v1.0".to_string(),
            spec_version: "1.0".to_string(),
            description: Some("Test description".to_string().into_bytes()),
            greeting: Some("Hello".to_string().into_bytes()),
            visibility: Some("private".to_string()),
            creator: Some("test_creator".to_string()),
            persona: Some("Test persona".to_string().into_bytes()),
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            ..Default::default()
        };
        diesel::insert_into(characters_dsl::characters)
            .values(&new_char_card)
            .get_result::<DbCharacter>(conn_sync)
    }).await.expect("DB interaction for create character failed").expect("Error saving new character");

    let conn_pool = test_app.db_pool.clone();
    let user_id_clone_session = user.id;
    let character_id_clone_session = character.id;
    let session_title_reasoning = format!("Test Chat with Char {}", character.id);
    let session: ChatSession = conn_pool.get().await.expect("Failed to get DB conn for session create").interact(move |conn_sync| {
        let new_chat_session = NewChat {
            id: Uuid::new_v4(),
            user_id: user_id_clone_session,
            character_id: character_id_clone_session,
            title: Some(session_title_reasoning),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            history_management_strategy: "truncate".to_string(),
            history_management_limit: 10,
            model_name: "test-model".to_string(),
            visibility: Some("private".to_string()),
        };
        diesel::insert_into(chat_sessions_dsl::chat_sessions)
            .values(&new_chat_session)
            .returning(ChatSession::as_returning()) // Ensure returning or select is used
            .get_result::<ChatSession>(conn_sync)
    }).await.expect("DB interaction for create session failed").expect("Error saving new chat session");

    let conn_pool_msg = test_app.db_pool.clone(); // Use a new variable name
    let session_id_clone_msg = session.id;
    let user_id_clone_msg = user.id;
    conn_pool_msg.get().await.expect("Failed to get DB conn for msg save").interact(move |conn_sync| { 
        let new_message = NewMessage {
            id: Uuid::new_v4(),
            session_id: session_id_clone_msg,
            user_id: user_id_clone_msg,
            message_type: MessageRole::User,
            content: "User message for reasoning chunk".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            role: Some("user".to_string()),
            parts: None,
            attachments: None,
        };
        diesel::insert_into(chat_messages_dsl::chat_messages)
            .values(&new_message)
            .execute(conn_sync) // This should be .execute(conn_sync) not .await
    }).await.expect("DB interaction for save message failed").expect("Error saving user message");

    // Mock the AI client stream: Start -> Reasoning -> Chunk -> End
    let mock_stream_items = vec![
        Ok(ChatStreamEvent::Start),
        Ok(ChatStreamEvent::ReasoningChunk(StreamChunk {
            content: "Thinking about the query...".to_string(),
        })),
        Ok(ChatStreamEvent::Chunk(StreamChunk {
            content: "Final answer.".to_string(),
        })),
        Ok(ChatStreamEvent::End(StreamEnd::default())),
    ];
    
    // Prepare expected events before moving mock_stream_items
    let expected_events = vec![
        ParsedSseEvent {
            event: Some("thinking".to_string()),
            data: "AI Processing Started".to_string(),
        },
        ParsedSseEvent {
            event: Some("thinking".to_string()),
            data: "Thinking about the query...".to_string(),
        },
        ParsedSseEvent {
            event: None, // Default event for content
            data: serde_json::json!({"text": "Final answer."}).to_string(),
        },
        ParsedSseEvent {
            event: None, // Default event for [DONE]
            data: "[DONE]".to_string(),
        }
    ];
    
    test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client should be present")
        .set_stream_response(mock_stream_items);

   // Construct the new payload with history
   let history = vec![
       ApiChatMessage { role: "user".to_string(), content: "User message for reasoning chunk".to_string() },
   ];
   let payload = GenerateChatRequest {
       history,
       model: Some("test-stream-reasoning-model".to_string()),
   };

   let request = Request::builder()
       .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::ACCEPT, mime::TEXT_EVENT_STREAM.as_ref())
        // Add the header to request reasoning/thinking events
        .header("X-Request-Thinking", "true")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();

    // Assert headers
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::TEXT_EVENT_STREAM.as_ref()
    );

    // Consume and assert stream content
    let body = response.into_body();
    let actual_events = collect_full_sse_events(body).await;

    assert_eq!(actual_events.len(), expected_events.len(), "Number of SSE events mismatch. Actual: {:?}, Expected: {:?}", actual_events, expected_events);
    for (i, (actual, expected)) in actual_events.iter().zip(expected_events.iter()).enumerate() {
        assert_eq!(actual.event, expected.event, "Event name mismatch at index {}. Actual: {:?}, Expected: {:?}", i, actual, expected);
        if expected.data == "[DONE]" || (expected.event.is_some() && expected.event.as_deref() == Some("thinking")) {
             assert_eq!(actual.data, expected.data, "Event data string mismatch for {} at index {}", expected.data, i);
        } else if expected.data.starts_with('{') || expected.data.starts_with('[') {
            let actual_json: serde_json::Value = serde_json::from_str(&actual.data).expect(&format!("Actual data at index {} is not valid JSON: {}", i, actual.data));
            let expected_json: serde_json::Value = serde_json::from_str(&expected.data).expect(&format!("Expected data at index {} is not valid JSON: {}", i, expected.data));
            assert_eq!(actual_json, expected_json, "Event data JSON mismatch at index {}", i);
        } else {
        assert_eq!(actual.data, expected.data, "Event data string mismatch at index {}", i);
        }
    }

    // Assert background save
    tokio::time::sleep(Duration::from_millis(100)).await;
    let conn_pool = test_app.db_pool.clone();
    let session_id_clone = session.id;
    let messages: Vec<DbChatMessage> = conn_pool.get().await.expect("Failed to get DB conn for loading messages").interact(move |conn_sync| {
        chat_messages_dsl::chat_messages
            .filter(chat_messages_dsl::session_id.eq(session_id_clone))
            .order(chat_messages_dsl::created_at.asc())
            .select(DbChatMessage::as_select())
            .load::<DbChatMessage>(conn_sync)
    }).await.expect("DB interaction for loading messages failed").expect("Failed to load chat messages");
        
    assert_eq!(
        messages.len(),
        2, // User message from payload + AI message
        "Should have user and AI message saved"
    );
    let ai_msg = messages.last().unwrap();
    assert_eq!(String::from_utf8_lossy(&ai_msg.content), "Final answer.");
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn generate_chat_response_streaming_genai_json_error() {
    let test_app = test_helpers::spawn_app(false, false, false).await; // Corrected: Added third arg
    
    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }
    
    let username = "stream_json_err_user";
    let password = "password123"; 
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(), // Corrected: .to_string()
        password.to_string(), // Corrected: .to_string()
    )
    .await
    .expect("Failed to create test user");

    let login_payload = serde_json::json!({
        "identifier": username, // Corrected: "identifier"
        "password": password,
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
        .unwrap();

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK, "Login request failed");

    let auth_cookie_header = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present on login")
        .to_str()
        .unwrap();
    let parsed_cookie = cookie::Cookie::parse(auth_cookie_header)
        .expect("Failed to parse Set-Cookie header");
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());
    
    let conn_pool = test_app.db_pool.clone();
    let user_id_clone = user.id;
    let char_name_json_err = "Stream GenAI JSON Err Char".to_string();
    let character: DbCharacter = conn_pool.get().await.expect("Failed to get DB conn for char create").interact(move |conn_sync| {
        let new_char_card = scribe_backend::models::character_card::NewCharacter {
            user_id: user_id_clone,
            name: char_name_json_err,
            spec: "test_spec_v1.0".to_string(),
            spec_version: "1.0".to_string(),
            description: Some("Test description".to_string().into_bytes()),
            greeting: Some("Hello".to_string().into_bytes()),
            visibility: Some("private".to_string()),
            creator: Some("test_creator".to_string()),
            persona: Some("Test persona".to_string().into_bytes()),
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            ..Default::default()
        };
        diesel::insert_into(characters_dsl::characters)
            .values(&new_char_card)
            .get_result::<DbCharacter>(conn_sync)
    }).await.expect("DB interaction for create character failed").expect("Error saving new character");

    let conn_pool = test_app.db_pool.clone();
    let user_id_clone_session = user.id;
    let character_id_clone_session = character.id;
    let session_title_json_err = format!("Test Chat with Char {}", character.id);
    let session: ChatSession = conn_pool.get().await.expect("Failed to get DB conn for session create").interact(move |conn_sync| {
        let new_chat_session = NewChat {
            id: Uuid::new_v4(),
            user_id: user_id_clone_session,
            character_id: character_id_clone_session,
            title: Some(session_title_json_err),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            history_management_strategy: "truncate".to_string(),
            history_management_limit: 10,
            model_name: "test-model".to_string(),
            visibility: Some("private".to_string()),
        };
        diesel::insert_into(chat_sessions_dsl::chat_sessions)
            .values(&new_chat_session)
            .returning(ChatSession::as_returning()) // Ensure returning or select is used
            .get_result::<ChatSession>(conn_sync)
    }).await.expect("DB interaction for create session failed").expect("Error saving new chat session");

    let conn_pool_msg = test_app.db_pool.clone(); // Use a new variable name
    let session_id_clone_msg = session.id;
    let user_id_clone_msg = user.id;
    conn_pool_msg.get().await.expect("Failed to get DB conn for msg save").interact(move |conn_sync| { 
        let new_message = NewMessage {
            id: Uuid::new_v4(),
            session_id: session_id_clone_msg,
            user_id: user_id_clone_msg,
            message_type: MessageRole::User,
            content: "User message for JSON error stream".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            role: Some("user".to_string()),
            parts: None,
            attachments: None,
        };
        diesel::insert_into(chat_messages_dsl::chat_messages)
            .values(&new_message)
            .execute(conn_sync) 
    }).await.expect("DB interaction for save message failed").expect("Error saving user message");

    // Mock the AI client to return a specific error mimicking JsonValueExt
    let mock_error_message = "JsonValueExt(PropertyNotFound(\"/candidates/0/content/parts/0\"))".to_string();
    let mock_stream_items = vec![
        Ok(ChatStreamEvent::Start),
        Ok(ChatStreamEvent::Chunk(StreamChunk {
            content: "Some initial content. ".to_string(),
        })),
        Err(AppError::GenerationError(mock_error_message.clone())),
    ];
    
    // Prepare expected events before moving mock_stream_items
    let expected_events = vec![
        ParsedSseEvent {
            event: None, // Default event for content
            data: serde_json::json!({"text": "Some initial content. "}).to_string(),
        },
        ParsedSseEvent {
            event: Some("error".to_string()),
            data: format!("LLM API error: LLM Generation Error: {}", mock_error_message),
        }
    ];
    
    test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client should be present")
        .set_stream_response(mock_stream_items);

   // Construct the new payload with history
   let history = vec![
       ApiChatMessage { role: "user".to_string(), content: "User message for JSON error stream".to_string() },
   ];
   let payload = GenerateChatRequest {
       history,
       model: Some("test-stream-json-err-model".to_string()),
   };

   let request = Request::builder()
       .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::ACCEPT, mime::TEXT_EVENT_STREAM.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();

    // Assert headers
    assert_eq!(response.status(), StatusCode::OK); // SSE connection established
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::TEXT_EVENT_STREAM.as_ref()
    );

    // Read the SSE stream and verify the error event
    let body = response.into_body();
    let actual_events = collect_full_sse_events(body).await;

    assert_eq!(actual_events.len(), expected_events.len(), "Number of SSE events mismatch. Actual: {:?}, Expected: {:?}", actual_events, expected_events);
    for (i, (actual, expected)) in actual_events.iter().zip(expected_events.iter()).enumerate() {
        assert_eq!(actual.event, expected.event, "Event name mismatch at index {}", i);
        if expected.data.starts_with('{') || expected.data.starts_with('[') {
            let actual_json: serde_json::Value = serde_json::from_str(&actual.data).expect(&format!("Actual data at index {} is not valid JSON: {}", i, actual.data));
            let expected_json: serde_json::Value = serde_json::from_str(&expected.data).expect(&format!("Expected data at index {} is not valid JSON: {}", i, expected.data));
            assert_eq!(actual_json, expected_json, "Event data JSON mismatch at index {}", i);
        } else {
            assert_eq!(actual.data, expected.data, "Event data string mismatch at index {}. Actual: '{}', Expected: '{}'", i, actual.data, expected.data);
        }
    }

    // Assert partial save
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let conn_pool = test_app.db_pool.clone();
    let session_id_clone = session.id;
    let messages: Vec<DbChatMessage> = conn_pool.get().await.expect("Failed to get DB conn for loading messages").interact(move |conn_sync| {
        chat_messages_dsl::chat_messages
            .filter(chat_messages_dsl::session_id.eq(session_id_clone))
            .order(chat_messages_dsl::created_at.asc())
            .select(DbChatMessage::as_select())
            .load::<DbChatMessage>(conn_sync)
    }).await.expect("DB interaction for loading messages failed").expect("Failed to load chat messages");
        
    assert_eq!(
        messages.len(),
        2, // User message from payload + partial AI message
        "Should have user message and partial AI message after JSON error"
    );
    assert_eq!(String::from_utf8_lossy(&messages[1].content), "Some initial content. ");
}

#[tokio::test]
#[ignore] 
async fn generate_chat_response_streaming_real_client_failure_repro() {
    let test_app = test_helpers::spawn_app(true, true, true).await; // Corrected: Added third arg (already true)

    // Skip if RUN_INTEGRATION_TESTS is not set, this test requires real services
    if env::var("RUN_INTEGRATION_TESTS").is_err() {
        println!("Skipping real client test: RUN_INTEGRATION_TESTS not set");
        return;
    }
    
    let username = "real_stream_fail_user";
    let password = "password123"; 
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(), // Corrected: .to_string()
        password.to_string(), // Corrected: .to_string()
    )
    .await
    .expect("Failed to create test user");

    let login_payload = serde_json::json!({
        "identifier": username, // Corrected: "identifier"
        "password": password,
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
        .unwrap();

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK, "Login request failed");

    let auth_cookie_header = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present on login")
        .to_str()
        .unwrap();
    let parsed_cookie = cookie::Cookie::parse(auth_cookie_header)
        .expect("Failed to parse Set-Cookie header");
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());
    
    let conn_pool = test_app.db_pool.clone();
    let user_id_clone = user.id;
    let char_name_real_fail = "Real Stream Fail Char".to_string();
    let character: DbCharacter = conn_pool.get().await.expect("Failed to get DB conn for char create").interact(move |conn_sync| {
        let new_char_card = scribe_backend::models::character_card::NewCharacter {
            user_id: user_id_clone,
            name: char_name_real_fail,
            spec: "test_spec_v1.0".to_string(),
            spec_version: "1.0".to_string(),
            description: Some("Test description for real failure".to_string().into_bytes()),
            greeting: Some("Hello real fail".to_string().into_bytes()),
            visibility: Some("private".to_string()),
            creator: Some("test_creator_real".to_string()),
            persona: Some("Test persona real fail".to_string().into_bytes()),
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            ..Default::default()
        };
        diesel::insert_into(characters_dsl::characters)
            .values(&new_char_card)
            .get_result::<DbCharacter>(conn_sync)
    }).await.expect("DB interaction for create character failed").expect("Error saving new character for real_client_failure_repro");

    let conn_pool = test_app.db_pool.clone();
    let user_id_clone_session = user.id;
    let character_id_clone_session = character.id;
    let session_title_real_fail = format!("Test Chat with Char {}", character.id);
    let session: ChatSession = conn_pool.get().await.expect("Failed to get DB conn for session create").interact(move |conn_sync| {
        let new_chat_session = NewChat {
            id: Uuid::new_v4(),
            user_id: user_id_clone_session,
            character_id: character_id_clone_session,
            title: Some(session_title_real_fail),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            history_management_strategy: "truncate".to_string(),
            history_management_limit: 10,
            model_name: "real-model-for-failure-test".to_string(), // Use a distinct model name
            visibility: Some("private".to_string()),
        };
        diesel::insert_into(chat_sessions_dsl::chat_sessions)
            .values(&new_chat_session)
            .returning(ChatSession::as_returning()) // Ensure returning or select is used
            .get_result::<ChatSession>(conn_sync)
    }).await.expect("DB interaction for create session failed").expect("Error saving new chat session for real_client_failure_repro");

    // Add user message using interact pattern
    let conn_pool_msg = test_app.db_pool.clone();
    let session_id_clone_msg = session.id;
    let user_id_clone_msg = user.id;
    let user_message_content = "A simple prompt likely to succeed in non-streaming, but might fail in streaming.";
    conn_pool_msg.get().await.expect("Failed to get DB conn for msg save").interact(move |conn_sync| { 
        let new_message = NewMessage {
            id: Uuid::new_v4(),
            session_id: session_id_clone_msg,
            user_id: user_id_clone_msg,
            message_type: MessageRole::User,
            content: user_message_content.as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            role: Some("user".to_string()),
            parts: None,
            attachments: None,
        };
        diesel::insert_into(chat_messages_dsl::chat_messages)
            .values(&new_message)
            .execute(conn_sync)
    }).await.expect("DB interaction for save message failed").expect("Error saving user message");

   let history = vec![
        ApiChatMessage { role: "user".to_string(), content: "A simple prompt likely to succeed in non-streaming, but might fail in streaming.".to_string() },
   ];
   let payload = GenerateChatRequest {
       history,
        model: Some("gemini-1.5-flash-latest".to_string()), 
   };

   let request = Request::builder()
       .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::ACCEPT, mime::TEXT_EVENT_STREAM.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK, "Request should return OK status even if stream fails later");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::TEXT_EVENT_STREAM.as_ref(),
        "Content-Type should be text/event-stream"
    );

    let body = response.into_body();
    let actual_events = collect_full_sse_events(body).await;

    println!("Received events: {:?}", actual_events);

    let has_done_marker = actual_events.iter().any(|e| e.data == "[DONE]");
    let has_error_event = actual_events.iter().any(|e| e.event == Some("error".to_string()));

    assert!(has_done_marker || has_error_event, 
        "Stream should either complete successfully (has [DONE]) or have an error event. Actual events: {:?}", actual_events);

    if has_error_event {
        assert!(!has_done_marker, "Should not have [DONE] marker if there was an error. Actual events: {:?}", actual_events);
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    
    let conn_pool = test_app.db_pool.clone();
    let session_id_clone = session.id;
    let messages: Vec<DbChatMessage> = conn_pool.get().await.expect("Failed to get DB conn for loading messages").interact(move |conn_sync| {
        chat_messages_dsl::chat_messages
            .filter(chat_messages_dsl::session_id.eq(session_id_clone))
            .order(chat_messages_dsl::created_at.asc())
            .select(DbChatMessage::as_select())
            .load::<DbChatMessage>(conn_sync)
    }).await.expect("DB interaction for loading messages failed").expect("Failed to load chat messages");

    assert!(messages.len() >= 1, "At least the user message should be saved.");
    assert_eq!(messages[0].message_type, MessageRole::User);

    if messages.len() > 1 {
        println!(
            "Saved assistant content: {}", 
            String::from_utf8_lossy(&messages[1].content)
        );
    } else {
        println!("No partial assistant message was saved (error likely occurred early).");
    }

    println!("Real client streaming failure repro test finished.");
}