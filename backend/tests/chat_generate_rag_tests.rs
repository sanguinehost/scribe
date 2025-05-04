// backend/tests/chat_generate_rag_tests.rs
#![cfg(test)]

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use genai::{
    ModelIden,
    adapter::AdapterKind,
    chat::{ChatResponse, MessageContent, Usage},
};
use http_body_util::BodyExt;
use mime;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

// Crate imports
use scribe_backend::models::chats::{MessageRole, NewChatMessageRequest};
use scribe_backend::services::embedding_pipeline::{EmbeddingMetadata, RetrievedChunk};
use scribe_backend::test_helpers::{self, MockEmbeddingPipelineService, PipelineCall};

#[tokio::test]
// #[ignore] // Added ignore for CI
async fn test_generate_chat_response_triggers_embeddings() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "gen_resp_embed_trigger_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Char for Embed Trigger",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await; // RAG enabled by default in session

    // Create a mock embedding pipeline service
    let _mock_embedding_service = Arc::new(MockEmbeddingPipelineService::new());

    // Mock the AI response
    let mock_ai_content = "Response to trigger embedding.";
    let mock_response = ChatResponse {
        model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-1.5-flash-latest"),
        provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-1.5-flash-latest"),
        content: Some(MessageContent::Text(mock_ai_content.to_string())),
        reasoning_content: None,
        usage: Usage::default(),
    };
    context.app.mock_ai_client.set_response(Ok(mock_response));

    let payload = NewChatMessageRequest {
        content: "User message to trigger embedding".to_string(),
        model: Some("test-embed-trigger-model".to_string()),
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        // Non-streaming request
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Consume the body to ensure the request is fully processed
    let _ = response.into_body().collect().await.unwrap().to_bytes();

    // Poll the tracker until the expected count is reached or timeout
    let tracker = context.app.embedding_call_tracker.clone();
    let start_time = std::time::Instant::now();
    let timeout = Duration::from_secs(2); // 2-second timeout

    loop {
        let calls = tracker.lock().await;
        if calls.len() >= 2 {
            break; // Expected count reached
        }
        drop(calls); // Release lock before sleeping

        if start_time.elapsed() > timeout {
            let calls = tracker.lock().await; // Re-lock to get final count for panic message
            panic!(
                "Timeout waiting for embedding tracker count to reach 2. Current count: {}",
                calls.len()
            );
        }

        tokio::time::sleep(Duration::from_millis(10)).await; // Poll every 10ms
    }

    // Assert that the embedding function was called twice (after polling)
    let calls = tracker.lock().await;
    assert_eq!(
        calls.len(),
        2,
        "Expected embedding function to be called twice (user + assistant)"
    );

    // Verify the IDs match the saved messages
    let messages =
        test_helpers::db::get_chat_messages_from_db(&context.app.db_pool, session.id).await;
    assert_eq!(messages.len(), 2, "Should have user and AI message saved");

    let user_msg = messages
        .iter()
        .find(|m| m.message_type == MessageRole::User)
        .expect("User message not found");
    let ai_msg = messages
        .iter()
        .find(|m| m.message_type == MessageRole::Assistant)
        .expect("Assistant message not found");

    assert!(
        calls.contains(&user_msg.id),
        "Embedding tracker should contain user message ID"
    );
    assert!(
        calls.contains(&ai_msg.id),
        "Embedding tracker should contain assistant message ID"
    );
}

#[tokio::test]
// #[ignore] // Added ignore for CI
async fn test_generate_chat_response_triggers_embeddings_with_existing_session() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "embed_existing_user",
        "password",
    )
    .await;
    let character =
        test_helpers::db::create_test_character(&context.app.db_pool, user.id, "Embed Test Char")
            .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    // Add an existing message (will trigger embedding in background after this request)
    let _doc_message = test_helpers::db::create_test_chat_message(
        &context.app.db_pool,
        session.id,
        user.id,
        MessageRole::User,
        "First message",
    )
    .await;

    let request_body = json!({ "content": "Second user message to trigger embedding" });

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();

    // Reset tracker before the call
    context.app.embedding_call_tracker.lock().await.clear();

    let response = context.app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Poll the tracker until the expected count is reached or timeout
    let tracker = context.app.embedding_call_tracker.clone();
    let start_time = std::time::Instant::now();
    let timeout = Duration::from_secs(2); // 2-second timeout

    loop {
        let calls = tracker.lock().await;
        // Expect *two* calls: one for the "Second user message..." and one for the AI response
        // The first message embedding is triggered by the *previous* request in a real scenario, not this one.
        if calls.len() >= 2 {
            break; // Expected count reached
        }
        drop(calls); // Release lock before sleeping

        if start_time.elapsed() > timeout {
             let calls = tracker.lock().await; // Re-lock to get final count for panic message
             panic!(
                 "Timeout waiting for embedding tracker count to reach 2. Current count: {}",
                 calls.len()
             );
        }

        tokio::time::sleep(Duration::from_millis(10)).await; // Poll every 10ms
    }

    // Assert that the embedding function was called twice (after polling)
    let calls = tracker.lock().await;
    assert_eq!(
        calls.len(),
        2,
        "Expected embedding calls for user message and AI response"
    );
}

#[tokio::test]
// Removed ignore: #[ignore] // Integration test, relies on external services
async fn test_rag_context_injection_in_prompt() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) =
        test_helpers::auth::create_test_user_and_login(&context.app, "rag_user", "password").await;
    let character =
        test_helpers::db::create_test_character(&context.app.db_pool, user.id, "RAG Test Char")
            .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    // Configure mock RAG service to return a specific chunk
    let mock_chunk_text = "The secret code is Ouroboros.".to_string();
    let mock_metadata = EmbeddingMetadata {
        message_id: Uuid::new_v4(),
        session_id: session.id,
        speaker: "Assistant".to_string(),
        timestamp: chrono::Utc::now(),
        text: mock_chunk_text.clone(),
    };
    let mock_retrieved_chunk = RetrievedChunk {
        score: 0.95,
        text: mock_chunk_text.clone(),
        metadata: mock_metadata,
    };
    context
        .app
        .mock_embedding_pipeline_service
        .set_retrieve_response(Ok(vec![mock_retrieved_chunk]));

    // Configure mock AI to just return a simple response
    let mock_ai_response = ChatResponse {
        model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "mock-rag-model"),
        provider_model_iden: genai::ModelIden::new(
            genai::adapter::AdapterKind::Gemini,
            "mock-rag-model",
        ),
        content: Some(genai::chat::MessageContent::Text(
            "Mock AI response to RAG query".to_string(),
        )),
        reasoning_content: None,
        usage: Default::default(),
    };
    context
        .app
        .mock_ai_client
        .set_response(Ok(mock_ai_response));

    let query_text = "What is the secret code?";
    let request_body = json!({ "content": query_text });

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    // Verify RAG service was called correctly
    let pipeline_calls = context.app.mock_embedding_pipeline_service.get_calls();

    // Check for the RetrieveRelevantChunks call
    let retrieve_call = pipeline_calls.iter().find(|call| {
        matches!(call, PipelineCall::RetrieveRelevantChunks { .. })
    });

    assert!(
        retrieve_call.is_some(),
        "Expected at least one RetrieveRelevantChunks call to the pipeline service"
    );

    if let Some(PipelineCall::RetrieveRelevantChunks {
        chat_id,
        query_text: called_query,
        limit,
    }) = retrieve_call {
        assert_eq!(*chat_id, session.id);
        assert_eq!(*called_query, query_text);
        assert_eq!(*limit, 3); // Check the default limit used in the route
    }

    // Check for any ProcessAndEmbedMessage calls
    let process_calls: Vec<_> = pipeline_calls
        .iter()
        .filter(|call| matches!(call, PipelineCall::ProcessAndEmbedMessage { .. }))
        .collect();

    // We expect at least one ProcessAndEmbedMessage call for storing the user's query
    assert!(
        !process_calls.is_empty(),
        "Expected at least one ProcessAndEmbedMessage call to the pipeline service"
    );

    // Verify the AI prompt included the RAG context
    let last_ai_request = context
        .app
        .mock_ai_client
        .get_last_request()
        .expect("AI client was not called");
    let last_user_message = last_ai_request
        .messages
        .last()
        .expect("No messages in AI request");

    // Use matches! macro for enum comparison as ChatRole doesn't impl PartialEq
    assert!(
        matches!(last_user_message.role, genai::chat::ChatRole::User),
        "Last message should be from User"
    );

    // The content field might now be accessed directly without as_ref()
    let last_user_content = match &last_user_message.content {
        genai::chat::MessageContent::Text(text) => text,
        _ => panic!("Last user message content is not text or is None"),
    };

    let expected_rag_prefix = format!("<RAG_CONTEXT>\n- {}\n</RAG_CONTEXT>\n\n", mock_chunk_text);
    assert!(
        last_user_content.starts_with(&expected_rag_prefix),
        "User message content should start with RAG context"
    );
    assert!(
        last_user_content.ends_with(query_text),
        "User message content should end with the original query"
    );

    // Verify AI options (should be defaults as none were set in DB)
    let last_options = context.app.mock_ai_client.get_last_options().expect("No options recorded");
    assert_eq!(last_options.temperature, Some(1.0), "Default temperature mismatch");
    assert_eq!(last_options.max_tokens, Some(512), "Default max_tokens mismatch");
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn generate_chat_response_rag_retrieval_error() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "rag_retrieval_err_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "RAG Retrieval Err Char",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    // Mock RAG service to return an error
    context
        .app
        .mock_embedding_pipeline_service
        .set_retrieve_response(Err(scribe_backend::errors::AppError::VectorDbError(
            "Mock Qdrant retrieval failure".to_string(),
        )));

    // Mock AI response (it should still be called, just without RAG context)
    let mock_ai_content = "Response without RAG context.";
    let mock_response = ChatResponse {
        model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-1.5-flash-latest"),
        provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-1.5-flash-latest"),
        content: Some(MessageContent::Text(mock_ai_content.to_string())),
        reasoning_content: None,
        usage: Usage::default(),
    };
    context.app.mock_ai_client.set_response(Ok(mock_response));

    let payload = NewChatMessageRequest {
        content: "User message for RAG error test".to_string(),
        model: Some("test-rag-err-model".to_string()),
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();

    // Assert status is OK, as RAG failure is handled gracefully
    assert_eq!(response.status(), StatusCode::OK);

    // Verify the AI request was made and did NOT contain RAG context
    let last_request = context
        .app
        .mock_ai_client
        .get_last_request()
        .expect("Mock AI client did not receive a request");

    let last_message_content = last_request.messages.last().unwrap().content.clone();
    let prompt_text = match last_message_content {
        MessageContent::Text(text) => text,
        _ => panic!("Expected last message content to be text"),
    };

    assert!(
        !prompt_text.contains("<RAG_CONTEXT>"),
        "Prompt should NOT contain RAG_CONTEXT start tag after retrieval error"
    );
    assert!(
        !prompt_text.contains("</RAG_CONTEXT>"),
        "Prompt should NOT contain RAG_CONTEXT end tag after retrieval error"
    );
    // Ensure the original user message is still there
    assert_eq!(prompt_text, "User message for RAG error test");

    // Assert background save
    tokio::time::sleep(Duration::from_millis(100)).await;
    let messages =
        test_helpers::db::get_chat_messages_from_db(&context.app.db_pool, session.id).await;
    assert_eq!(
        messages.len(),
        2,
        "Should have user and AI message saved even after RAG error"
    );
    let ai_msg = messages.last().unwrap();
    assert_eq!(ai_msg.content, mock_ai_content);
}