// tests/agentic_chat_integration_tests.rs
// Tests for agentic orchestrator integration with chat generation flow

use scribe_backend::{
    services::{AgenticRequest, QualityMode},
    test_helpers::{TestDataGuard, spawn_app},
    models::chats::{CreateChatSessionPayload, MessageRole, GenerateChatRequest},
};
use reqwest;
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn test_agentic_orchestration_triggered_for_complex_query() -> anyhow::Result<()> {
    let _guard = TestDataGuard::new().await?;
    let app = spawn_app().await;

    // Create authenticated session
    let auth_response = app.post_json("/api/auth/login", &json!({
        "email": "test@example.com",
        "password": "password123"
    })).await;
    assert_eq!(auth_response.status(), 200);

    // Create character for testing
    let character_response = app.post_json("/api/characters", &json!({
        "name": "Test Character",
        "description": "A character for testing agentic integration",
        "system_prompt": "You are a helpful character.",
        "avatar_url": null,
        "is_public": false
    })).await;
    assert_eq!(character_response.status(), 201);
    let character: serde_json::Value = character_response.json().await?;
    let character_id = character["id"].as_str().unwrap();

    // Create chat session
    let session_payload = CreateChatSessionPayload {
        character_id: Some(Uuid::parse_str(character_id)?),
        title: None,
    };
    let session_response = app.post_json("/api/chat/create_session", &session_payload).await;
    assert_eq!(session_response.status(), 201);
    let session: serde_json::Value = session_response.json().await?;
    let session_id = session["id"].as_str().unwrap();

    // Send a complex query that should trigger agentic orchestration
    let complex_query = "I'm really struggling with understanding how Luke's departure affected the group dynamics and relationships. Can you help me analyze the emotional cascading effects across all the characters involved and how their motivations have shifted since then?";
    
    let generate_request = GenerateChatRequest {
        content: complex_query.to_string(),
    };

    let generate_response = app.post_json(
        &format!("/api/chat/{}/generate", session_id),
        &generate_request,
    ).await;

    assert_eq!(generate_response.status(), 200);

    // Verify that the response contains content
    let response_text = generate_response.text().await?;
    assert!(!response_text.is_empty(), "Should receive non-empty response from agentic-enhanced chat");

    // Check if agentic context was used by examining logs or response quality
    // For a more complex query like this, the response should be more contextually rich
    assert!(response_text.len() > 100, "Complex queries should generate substantial responses");

    Ok(())
}

#[tokio::test]
async fn test_agentic_orchestration_skipped_for_simple_query() -> anyhow::Result<()> {
    let _guard = TestDataGuard::new().await?;
    let app = spawn_app().await;

    // Create authenticated session
    let auth_response = app.post_json("/api/auth/login", &json!({
        "email": "test@example.com",
        "password": "password123"
    })).await;
    assert_eq!(auth_response.status(), 200);

    // Create character for testing
    let character_response = app.post_json("/api/characters", &json!({
        "name": "Test Character",
        "description": "A character for testing agentic integration",
        "system_prompt": "You are a helpful character.",
        "avatar_url": null,
        "is_public": false
    })).await;
    assert_eq!(character_response.status(), 201);
    let character: serde_json::Value = character_response.json().await?;
    let character_id = character["id"].as_str().unwrap();

    // Create chat session
    let session_payload = CreateChatSessionPayload {
        character_id: Some(Uuid::parse_str(character_id)?),
        title: None,
    };
    let session_response = app.post_json("/api/chat/create_session", &session_payload).await;
    assert_eq!(session_response.status(), 201);
    let session: serde_json::Value = session_response.json().await?;
    let session_id = session["id"].as_str().unwrap();

    // Send a simple query that should skip agentic orchestration
    let simple_query = "Hi!";
    
    let generate_request = GenerateChatRequest {
        content: simple_query.to_string(),
    };

    let generate_response = app.post_json(
        &format!("/api/chat/{}/generate", session_id),
        &generate_request,
    ).await;

    assert_eq!(generate_response.status(), 200);

    // Verify that the response is received even without agentic processing
    let response_text = generate_response.text().await?;
    assert!(!response_text.is_empty(), "Should receive response even for simple queries");

    Ok(())
}

#[test]
fn test_should_use_agentic_orchestration_complex_query() {
    use scribe_backend::routes::chat::{should_use_agentic_orchestration};
    
    // Test complex narrative query
    let complex_query = "How did Luke's departure from the group affect everyone's emotional state and what are the long-term implications for their relationships and character development?";
    let session_character_id = Some(Uuid::new_v4());
    
    let should_use = should_use_agentic_orchestration(complex_query, &session_character_id);
    assert!(should_use, "Complex narrative queries should trigger agentic orchestration");
}

#[test]
fn test_should_use_agentic_orchestration_simple_query() {
    use scribe_backend::routes::chat::{should_use_agentic_orchestration};
    
    // Test simple query
    let simple_query = "Hi";
    let session_character_id = Some(Uuid::new_v4());
    
    let should_use = should_use_agentic_orchestration(simple_query, &session_character_id);
    assert!(!should_use, "Simple queries should skip agentic orchestration");
}

#[test]
fn test_should_use_agentic_orchestration_medium_query() {
    use scribe_backend::routes::chat::{should_use_agentic_orchestration};
    
    // Test medium-length query without complex keywords
    let medium_query = "What is the weather like today and how are you doing?";
    let session_character_id = Some(Uuid::new_v4());
    
    let should_use = should_use_agentic_orchestration(medium_query, &session_character_id);
    assert!(!should_use, "Medium queries without complex keywords should skip agentic orchestration");
}

#[test]
fn test_should_use_agentic_orchestration_no_character() {
    use scribe_backend::routes::chat::{should_use_agentic_orchestration};
    
    // Test complex query but no character (non-character session)
    let complex_query = "How did the political situation affect the economic relationships between the major factions?";
    let session_character_id = None;
    
    let should_use = should_use_agentic_orchestration(complex_query, &session_character_id);
    assert!(!should_use, "Queries without character sessions should skip agentic orchestration");
}

#[test]
fn test_build_conversation_context_from_history() {
    use scribe_backend::routes::chat::{build_conversation_context_from_history};
    use genai::chat::{ChatMessage as GenAiChatMessage, ChatRole, MessageContent};
    
    // Test with empty history
    let empty_history = vec![];
    let context = build_conversation_context_from_history(&empty_history);
    assert!(context.is_none(), "Empty history should return None");
    
    // Test with some history
    let history = vec![
        GenAiChatMessage {
            role: ChatRole::User,
            content: MessageContent::Text("Hello, how are you?".to_string()),
            options: None,
        },
        GenAiChatMessage {
            role: ChatRole::Assistant,
            content: MessageContent::Text("I'm doing well, thank you for asking!".to_string()),
            options: None,
        },
    ];
    
    let context = build_conversation_context_from_history(&history);
    assert!(context.is_some(), "Non-empty history should return context");
    
    let context_str = context.unwrap();
    assert!(context_str.contains("User:"), "Context should include user messages");
    assert!(context_str.contains("Assistant:"), "Context should include assistant messages");
    assert!(context_str.contains("Hello, how are you?"), "Context should include message content");
}

#[test]
fn test_calculate_agentic_token_budget() {
    use scribe_backend::routes::chat::{calculate_agentic_token_budget, ChatGenerateQueryParams};
    
    let query_params = ChatGenerateQueryParams {
        request_thinking: false,
    };
    
    let budget = calculate_agentic_token_budget(&query_params);
    assert_eq!(budget, 5000, "Should return default token budget");
}

#[test]
fn test_determine_quality_mode() {
    use scribe_backend::routes::chat::{determine_quality_mode, ChatGenerateQueryParams};
    use scribe_backend::services::QualityMode;
    
    let query_params = ChatGenerateQueryParams {
        request_thinking: false,
    };
    
    let quality_mode = determine_quality_mode(&query_params);
    assert_eq!(quality_mode, QualityMode::Balanced, "Should return default balanced quality mode");
}

#[test]
fn test_merge_orchestrated_context() {
    use scribe_backend::routes::chat::{merge_orchestrated_context};
    use scribe_backend::services::embeddings::{RetrievedChunk, RetrievedMetadata, ChronicleEventMetadata};
    
    // Test with empty context
    let existing_chunks = vec![];
    let empty_context = "".to_string();
    let result = merge_orchestrated_context(existing_chunks, empty_context);
    assert_eq!(result.len(), 0, "Empty context should not add chunks");
    
    // Test with meaningful context
    let existing_chunks = vec![];
    let meaningful_context = "Luke's departure created a significant emotional rift in the group dynamics.".to_string();
    let result = merge_orchestrated_context(existing_chunks, meaningful_context.clone());
    assert_eq!(result.len(), 1, "Meaningful context should add one chunk");
    
    let added_chunk = &result[0];
    assert_eq!(added_chunk.text, meaningful_context);
    assert_eq!(added_chunk.score, 0.95);
    assert!(matches!(added_chunk.metadata, RetrievedMetadata::Chronicle(_)));
}

// Unit tests for the agentic orchestrator components are already covered in agentic_orchestrator_tests.rs
// This file focuses on integration with the chat generation flow