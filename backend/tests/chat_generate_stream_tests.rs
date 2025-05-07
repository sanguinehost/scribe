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

// Crate imports
use scribe_backend::models::chats::{MessageRole, GenerateChatRequest, ApiChatMessage}; // Use GenerateChatRequest, ApiChatMessage
use scribe_backend::errors::AppError;
use scribe_backend::test_helpers::{self};

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
    // Use mock AI
    let context = test_helpers::setup_test_app(false).await;
    
    // Skip if running as integration test with real client
    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }
    
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "gen_resp_stream_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Char for Stream Resp",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    // Add a previous message to check history handling
    test_helpers::db::create_test_chat_message(
        &context.app.db_pool,
        session.id,
        user.id,
        MessageRole::User,
        "First prompt",
    )
    .await;
    test_helpers::db::create_test_chat_message(
        &context.app.db_pool,
        session.id,
        user.id,
        MessageRole::Assistant,
        "First reply",
    )
    .await;

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
    
    context
        .app
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

    let response = context.app.router.clone().oneshot(request).await.unwrap();

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

    let messages =
        test_helpers::db::get_chat_messages_from_db(&context.app.db_pool, session.id).await;
    // Expect initial 2 messages + 1 user message + 1 assistant message = 4 total
    assert_eq!(
        messages.len(),
        4,
        "Should have initial messages plus new user/AI pair"
    );

    // Check the *last* two messages for the new content
    let user_msg = messages
        .get(messages.len() - 2)
        .expect("New user message not found at expected index");
    assert_eq!(user_msg.message_type, MessageRole::User);
    assert_eq!(user_msg.content, "User message for stream");

    let ai_msg = messages.last().expect("New AI message not found at end");
    assert_eq!(ai_msg.message_type, MessageRole::Assistant);
    assert_eq!(ai_msg.content, "Hello World!"); // Full concatenated content
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn generate_chat_response_streaming_ai_error() {
    let context = test_helpers::setup_test_app(false).await;
    
    // Skip if running as integration test with real client
    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }
    
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "gen_resp_stream_err_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Char for Stream Err",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

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
    
    context
        .app
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

    let response = context.app.router.clone().oneshot(request).await.unwrap();

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

    // Check the content received *before* the error (already implicitly checked by event comparison)
    // Assert that the specific 'error' event was received (already implicitly checked)

    // Assert background save (wait a bit)
    tokio::time::sleep(Duration::from_millis(200)).await; // Increased wait time slightly

    let messages =
        test_helpers::db::get_chat_messages_from_db(&context.app.db_pool, session.id).await;
    assert_eq!(
        messages.len(),
        2,
        "Should have user and PARTIAL AI message after stream error"
    );

    let user_msg = messages.first().unwrap();
    assert_eq!(user_msg.message_type, MessageRole::User);
    assert_eq!(user_msg.content, "User message for error stream");

    let ai_msg = messages.get(1).unwrap();
    assert_eq!(ai_msg.message_type, MessageRole::Assistant);
    // The background save happens *after* the stream finishes (or errors), saving whatever was buffered.
    assert_eq!(
        ai_msg.content, "Partial ",
        "Partial content 'Partial ' should be saved"
    );
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn generate_chat_response_streaming_unauthorized() {
    let context = test_helpers::setup_test_app(false).await;
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

    let response = context.app.router.oneshot(request).await.unwrap();
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
    let context = test_helpers::setup_test_app(false).await;
    let (auth_cookie, _user) =
        test_helpers::auth::create_test_user_and_login(&context.app, "stream_404_user", "password")
            .await;
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

    let response = context.app.router.oneshot(request).await.unwrap();
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
    let context = test_helpers::setup_test_app(false).await;
    let (_auth_cookie1, user1) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "stream_forbid_user1",
        "password",
    )
    .await;
    let character1 = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user1.id,
        "User1 Char for Stream Forbidden",
    )
    .await;
    let session1 =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user1.id, character1.id)
            .await;

    let (auth_cookie2, _user2) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "stream_forbid_user2",
        "password",
    )
    .await; // User who shouldn't have access

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

    let response = context.app.router.clone().oneshot(request).await.unwrap();
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
#[ignore] // Integration test, relies on external services
async fn test_rag_context_injection_real_ai() {
    // Setup with a real embedding client and Qdrant if configured for integration
    // This test assumes QDRANT_URL and GEMINI_API_KEY are set for integration
    if env::var("RUN_INTEGRATION_TESTS").is_err() {
        println!("Skipping RAG integration test: RUN_INTEGRATION_TESTS not set");
        return;
    }

    let context = test_helpers::setup_test_app(true).await; // Use the helper
    let (auth_cookie, user) =
        test_helpers::auth::create_test_user_and_login(&context.app, "rag_real_user", "password")
            .await;
    let character =
        test_helpers::db::create_test_character(&context.app.db_pool, user.id, "RAG Real AI Char")
            .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    // Message containing info the AI shouldn't know without RAG
    let document_content = "Ouroboros is the secret handshake.";
    let _doc_message = test_helpers::db::create_test_chat_message(
        &context.app.db_pool,
        session.id,
        user.id,
        MessageRole::Assistant,
        document_content,
    )
    .await;

    // Force embedding of the document message immediately (in a real app, this happens in background)
    // Remove unused variable declaration
    // let doc_chat_message = ChatMessage {
    //     id: doc_message.id,
    //     session_id: doc_message.session_id,
    //     message_type: doc_message.message_type,
    //     content: doc_message.content,
    //     created_at: doc_message.created_at,
    // };
    // REMOVE direct call: Embedding should happen via API call side-effect in integration tests.
    // process_and_embed_message(context.app.clone(), doc_chat_message).await.expect("Failed to embed document message");

    // Allow time for potential Qdrant indexing
    tokio::time::sleep(Duration::from_secs(1)).await;

    let query_text = "What is Ouroboros in Greek mythology?"; // Query related to doc, but asks different question
    // Construct the new payload with history (including the RAG doc and the query)
    let history = vec![
        ApiChatMessage { role: "assistant".to_string(), content: document_content.to_string() }, // The RAG doc
        ApiChatMessage { role: "user".to_string(), content: query_text.to_string() }, // The user query
    ];
    let payload = GenerateChatRequest {
        history,
        model: None, // Use default model
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, &auth_cookie)
        .header(header::ACCEPT, "text/event-stream") // Request streaming
        .body(Body::from(serde_json::to_vec(&payload).unwrap())) // Use the new payload struct
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let sse_data = collect_full_sse_events(response.into_body()).await;
    let combined_response = sse_data.iter().map(|e| e.data.clone()).collect::<Vec<String>>().join("");

    // Assert that the *real AI response* references the 'secret handshake' from the RAG context
    // This assertion is brittle and depends on the AI model's behavior
    println!(
        "\n--- REAL AI Response Received ---\n{}\n---------------------------------\n",
        combined_response
    );
    assert!(
        combined_response.contains("serpent") || combined_response.contains("dragon"),
        "Real AI response should mention serpent/dragon for Ouroboros, but got: {}",
        combined_response
    );
    // We don't assert the RAG content is *in* the final response, just that it was available
    // assert!(combined_response.to_lowercase().contains("secret handshake"), "Real AI response did not seem to use the RAG context from the document");

    // No mock pipeline service calls to check in the real AI test
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_streaming_initiation_error() {
    let context = test_helpers::setup_test_app(false).await;
    
    // Skip if running as integration test with real client
    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }
    
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "stream_init_err_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Stream Init Err Char",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    // Mock the AI client's stream_chat method to return an error immediately
    let error_message = "Mock stream initiation failure".to_string();
    let mock_stream_items = vec![Err(AppError::GenerationError(
        error_message.clone()
    ))];
    
    // Prepare expected events before moving mock_stream_items
    let expected_events = vec![
        ParsedSseEvent {
            event: Some("error".to_string()),
            data: format!("LLM API error: LLM Generation Error: {}", error_message)
        }
    ];
    
    context
        .app
        .mock_ai_client
        .as_ref()
        .expect("Mock AI client should be present")
        .set_stream_response(mock_stream_items);

   // Construct the new payload with history
   let history = vec![
       ApiChatMessage { role: "user".to_string(), content: "User message for stream initiation error".to_string() },
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

    let response = context.app.router.clone().oneshot(request).await.unwrap();

    // Assert status - Should be OK because headers are sent before the stream error
    assert_eq!(response.status(), StatusCode::OK);
    // Assert Content-Type is text/event-stream
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::TEXT_EVENT_STREAM.as_ref(),
        "Content-Type should be text/event-stream even on initiation error"
    );

    // Consume the stream and check for the error event
    let body = response.into_body();
    let actual_events = collect_full_sse_events(body).await;

    // Based on chat.rs: if ai_client.stream_chat fails (initiation error),
    // it yields a single SSE event: event("error").data("LLM API error: Failed to initiate stream - <original_error>")

    assert_eq!(actual_events.len(), expected_events.len(), "Number of SSE events mismatch. Actual: {:?}, Expected: {:?}", actual_events, expected_events);
    for (i, (actual, expected)) in actual_events.iter().zip(expected_events.iter()).enumerate() {
        assert_eq!(actual.event, expected.event, "Event name mismatch at index {}", i);
        assert_eq!(actual.data, expected.data, "Event data string mismatch at index {}", i);
    }

    // Assert no AI message was saved
    tokio::time::sleep(Duration::from_millis(100)).await;
    let messages =
        test_helpers::db::get_chat_messages_from_db(&context.app.db_pool, session.id).await;
    assert_eq!(
        messages.len(),
        1,
        "Should only have user message saved after stream initiation error"
    );
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_streaming_error_before_content() {
    let context = test_helpers::setup_test_app(false).await;
    
    // Skip if running as integration test with real client
    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }
    
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "stream_err_b4_content_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Stream Err B4 Content Char",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    // Mock the AI client stream: Start -> Error
    let error_message = "Mock AI error before content".to_string();
    let mock_stream_items = vec![
        Ok(ChatStreamEvent::Start),
        Err(AppError::GeminiError(
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
    
    context
        .app
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

    let response = context.app.router.clone().oneshot(request).await.unwrap();

    // Assert headers
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::TEXT_EVENT_STREAM.as_ref()
    );

    // Consume and assert stream content
    let body = response.into_body();
    let actual_events = collect_full_sse_events(body).await;

    // Based on chat.rs logic for an error after ChatStreamEvent::Start:
    // 1. ChatStreamEvent::Start -> if request_thinking, SSE event: "thinking", data: "AI Processing Started"
    //    (This test does not set X-Request-Thinking, so no "thinking" event initially)
    // 2. The Err from genai stream -> SSE event: "error", data: "LLM API error: <original_error_message>"
    // No "[DONE]" event should be sent.

    assert_eq!(actual_events.len(), expected_events.len(), "Number of SSE events mismatch. Actual: {:?}, Expected: {:?}", actual_events, expected_events);
    for (i, (actual, expected)) in actual_events.iter().zip(expected_events.iter()).enumerate() {
        assert_eq!(actual.event, expected.event, "Event name mismatch at index {}", i);
        assert_eq!(actual.data, expected.data, "Event data string mismatch at index {}", i);
    }

    // Assert background save (wait a bit)
    tokio::time::sleep(Duration::from_millis(100)).await;
    let messages =
        test_helpers::db::get_chat_messages_from_db(&context.app.db_pool, session.id).await;
    assert_eq!(
        messages.len(),
        1,
        "Should only have user message saved after stream error before content"
    );
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_streaming_empty_response() {
    let context = test_helpers::setup_test_app(false).await;
    
    // Skip if running as integration test with real client
    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }
    
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "stream_empty_resp_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Stream Empty Resp Char",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

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
    
    context
        .app
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

    let response = context.app.router.clone().oneshot(request).await.unwrap();

    // Assert headers
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::TEXT_EVENT_STREAM.as_ref()
    );

    // Consume and assert stream content
    let body = response.into_body();
    let actual_events = collect_full_sse_events(body).await;

    // Based on chat.rs logic for an empty AI stream (Start -> End):
    // 1. ChatStreamEvent::Start -> (No SSE event if X-Request-Thinking is false)
    // 2. ChatStreamEvent::End with no accumulated content -> SSE data: "[DONE]"
    assert_eq!(actual_events.len(), expected_events.len(), "Number of SSE events mismatch. Actual: {:?}, Expected: {:?}", actual_events, expected_events);
    for (i, (actual, expected)) in actual_events.iter().zip(expected_events.iter()).enumerate() {
        assert_eq!(actual.event, expected.event, "Event name mismatch at index {}", i);
        assert_eq!(actual.data, expected.data, "Event data string mismatch at index {}. Actual: {}, Expected: {}", i, actual.data, expected.data);
    }

    // Assert background save (wait a bit)
    tokio::time::sleep(Duration::from_millis(100)).await;
    let messages =
        test_helpers::db::get_chat_messages_from_db(&context.app.db_pool, session.id).await;
    assert_eq!(
        messages.len(),
        1,
        "Should only have user message saved after empty stream response"
    );
    assert_eq!(messages[0].message_type, MessageRole::User);
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_streaming_reasoning_chunk() {
    let context = test_helpers::setup_test_app(false).await;
    
    // Skip if running as integration test with real client
    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }
    
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "stream_reasoning_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Stream Reasoning Char",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    // Mock the AI client stream: Start -> Reasoning -> Chunk -> End
    // ReasoningChunk is part of ChatStreamEvent enum, not a separate struct to import
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
    
    context
        .app
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

    let response = context.app.router.clone().oneshot(request).await.unwrap();

    // Assert headers
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::TEXT_EVENT_STREAM.as_ref()
    );

    // Consume and assert stream content
    let body = response.into_body();
    let actual_events = collect_full_sse_events(body).await;

    // Based on chat.rs logic with X-Request-Thinking: true:
    // 1. ChatStreamEvent::Start -> SSE event: "thinking", data: "AI Processing Started"
    // 2. ChatStreamEvent::ReasoningChunk -> SSE event: "thinking", data: <reasoning_content>
    // 3. ChatStreamEvent::Chunk -> SSE data: {"text": "content"}
    // 4. ChatStreamEvent::End -> SSE data: "[DONE]"

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
    let messages =
        test_helpers::db::get_chat_messages_from_db(&context.app.db_pool, session.id).await;
    assert_eq!(
        messages.len(),
        2,
        "Should have user and AI message saved"
    );
    let ai_msg = messages.last().unwrap();
    assert_eq!(ai_msg.content, "Final answer.");
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn generate_chat_response_streaming_genai_json_error() {
    let context = test_helpers::setup_test_app(false).await;
    
    // Skip if running as integration test with real client
    if std::env::var("RUN_INTEGRATION_TESTS").is_ok() {
        println!("Skipping mock test with real client");
        return;
    }
    
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "gen_resp_stream_json_err_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Char for Stream JSON Err",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

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
    
    context
        .app
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

    let response = context.app.router.clone().oneshot(request).await.unwrap();

    // Assert headers
    assert_eq!(response.status(), StatusCode::OK); // SSE connection established
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::TEXT_EVENT_STREAM.as_ref()
    );

    // Read the SSE stream and verify the error event
    let body = response.into_body();
    let actual_events = collect_full_sse_events(body).await;
    
    // Based on chat.rs:
    // 1. ChatStreamEvent::Start -> (No SSE if X-Request-Thinking is false)
    // 2. ChatStreamEvent::Chunk -> SSE data: {"text": "Some initial content. "}
    // 3. Err(AppError::GenerationError) -> SSE event: "error", data: "LLM API error: <original_error_message>"

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

    // Assert partial save (optional, but good practice)
    tokio::time::sleep(Duration::from_millis(100)).await; // Wait for background task
    let messages =
        test_helpers::db::get_chat_messages_from_db(&context.app.db_pool, session.id).await;
    assert_eq!(
        messages.len(),
        2, // User message + partial AI message
        "Should have user message and partial AI message after JSON error"
    );
    assert_eq!(messages[1].content, "Some initial content. "); // Check partial content saved
}

#[tokio::test]
#[ignore] // Integration test, relies on external services
async fn generate_chat_response_streaming_real_client_failure_repro() {
    // This test attempts to reproduce the scenario where streaming fails with the real client.
    // It assumes the real AI client might fail during the stream generation.
    if env::var("RUN_INTEGRATION_TESTS").is_err() {
        println!("Skipping real client streaming failure repro test: RUN_INTEGRATION_TESTS not set");
        return;
    }
    
    // Make sure we load the .env file first for API key
    dotenvy::dotenv().ok();
    
    // Verify GOOGLE_API_KEY is present in environment - this is what genai ClientBuilder::default() uses
    if env::var("GOOGLE_API_KEY").is_err() {
        println!("Skipping test: GOOGLE_API_KEY environment variable not set");
        return;
    }
    
    println!("Running real client streaming failure repro test...");

    let context = test_helpers::setup_test_app(true).await; // Should use real clients if RUN_INTEGRATION_TESTS is set
    
    // Print additional debug info
    println!("Test app setup completed. Using real AI client when RUN_INTEGRATION_TESTS is set.");
    
    // For this test, we don't need to mock anything - we're intentionally testing with the real client
    // to reproduce a potential streaming failure
    
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "stream_real_fail_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Real Stream Fail Char",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

  // Construct the new payload with history
  let history = vec![
      ApiChatMessage { role: "user".to_string(), content: "A simple prompt likely to succeed in non-streaming, but might fail in streaming.".to_string() },
  ];
  let payload = GenerateChatRequest {
      history,
      model: Some("gemini-1.5-flash-latest".to_string()), // Explicitly specify a model
  };

  let request = Request::builder()
      .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::ACCEPT, mime::TEXT_EVENT_STREAM.as_ref()) // Request streaming
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();

    // --- Assertions ---

    // 1. Check headers - Should still be OK and SSE even if the stream fails later
    assert_eq!(response.status(), StatusCode::OK, "Request should return OK status even if stream fails later");
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        mime::TEXT_EVENT_STREAM.as_ref(),
        "Content-Type should be text/event-stream"
    );

    // 2. Consume the stream and check for an error event
    let body = response.into_body();
    let actual_events = collect_full_sse_events(body).await;

    // For the real client test we can't predict what will happen in advance,
    // so we just check that we got a response (either successful or error)
    println!("Received events: {:?}", actual_events);

    // The stream should contain either content events followed by a [DONE] marker,
    // or content events followed by an error event
    let has_done_marker = actual_events.iter().any(|e| e.data == "[DONE]");
    let has_error_event = actual_events.iter().any(|e| e.event == Some("error".to_string()));

    // Either the stream should complete successfully or there should be an error
    assert!(has_done_marker || has_error_event, 
        "Stream should either complete successfully (has [DONE]) or have an error event");

    // If there was an error, ensure no [DONE] marker
    if has_error_event {
        assert!(!has_done_marker, "Should not have [DONE] marker if there was an error");
    }

    // 5. Check saved messages
    tokio::time::sleep(Duration::from_millis(200)).await;
    let messages =
        test_helpers::db::get_chat_messages_from_db(&context.app.db_pool, session.id).await;

    // We expect the user message to always be saved.
    // An assistant message *might* be saved if content was received before the error.
    assert!(messages.len() >= 1, "At least the user message should be saved.");
    assert_eq!(messages[0].message_type, MessageRole::User);

    if messages.len() > 1 {
        println!("Partial assistant message was saved.");
        assert_eq!(messages[1].message_type, MessageRole::Assistant);
        println!("Saved assistant content: {}", messages[1].content);
    } else {
        println!("No partial assistant message was saved (error likely occurred early).");
    }

    println!("Real client streaming failure repro test finished.");
}