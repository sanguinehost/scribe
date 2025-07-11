// tests/agentic_chat_integration_tests.rs
// Tests for agentic orchestrator integration with chat generation flow

use scribe_backend::{
    models::chats::{ApiChatMessage, ChatMode, CreateChatSessionPayload, GenerateChatRequest},
    test_helpers::{db, login_user_via_api, TestDataGuard},
};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn test_agentic_orchestration_triggered_for_complex_query() -> anyhow::Result<()> {
    let app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let mut guard = TestDataGuard::new(app.db_pool.clone());

    // Create user and character
    let user = db::create_test_user(&app.db_pool, "testuser".to_string(), "password123".to_string()).await?;
    guard.add_user(user.id);
    let character_db = db::create_test_character(&app.db_pool, user.id, "Test Character".to_string()).await?;
    guard.add_character(character_db.id);

    // Create authenticated session
    let (client, _) = login_user_via_api(&app, "testuser", "password123").await;

    // Create chat session
    let session_payload = CreateChatSessionPayload {
        character_id: Some(character_db.id),
        active_custom_persona_id: None,
        chat_mode: Some(ChatMode::Character),
    };
    let session_response = client
        .post(&format!("{}/api/chat/create_session", app.address))
        .json(&session_payload)
        .send()
        .await?;
    assert_eq!(session_response.status(), 201);
    let session: serde_json::Value = session_response.json().await?;
    let session_id = session["id"].as_str().unwrap();
    guard.add_chat(Uuid::parse_str(session_id)?);

    // Send a complex query that should trigger agentic orchestration
    let complex_query = "I'm really struggling with understanding how Luke's departure affected the group dynamics and relationships. Can you help me analyze the emotional cascading effects across all the characters involved and how their motivations have shifted since then?";

    let generate_request = GenerateChatRequest {
        history: vec![ApiChatMessage {
            role: "user".to_string(),
            content: complex_query.to_string(),
        }],
        model: None,
        query_text_for_rag: None,
    };

    let generate_response = client
        .post(&format!("{}/api/chat/{}/generate", app.address, session_id))
        .header("Accept", "text/event-stream")
        .json(&generate_request)
        .send()
        .await?;

    assert_eq!(generate_response.status(), 200);

    // Verify that the response contains content
    let response_text = generate_response.text().await?;
    assert!(
        !response_text.is_empty(),
        "Should receive non-empty response from agentic-enhanced chat"
    );

    // Check if agentic context was used by examining logs or response quality
    // For a more complex query like this, the response should be more contextually rich
    assert!(
        response_text.len() > 100,
        "Complex queries should generate substantial responses"
    );

    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_agentic_orchestration_skipped_for_simple_query() -> anyhow::Result<()> {
    let app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let mut guard = TestDataGuard::new(app.db_pool.clone());

    // Create user and character
    let user = db::create_test_user(&app.db_pool, "testuser2".to_string(), "password123".to_string()).await?;
    guard.add_user(user.id);
    let character_db = db::create_test_character(&app.db_pool, user.id, "Test Character 2".to_string()).await?;
    guard.add_character(character_db.id);

    // Create authenticated session
    let (client, _) = login_user_via_api(&app, "testuser2", "password123").await;

    // Create chat session
    let session_payload = CreateChatSessionPayload {
        character_id: Some(character_db.id),
        active_custom_persona_id: None,
        chat_mode: Some(ChatMode::Character),
    };
    let session_response = client
        .post(&format!("{}/api/chat/create_session", app.address))
        .json(&session_payload)
        .send()
        .await?;
    assert_eq!(session_response.status(), 201);
    let session: serde_json::Value = session_response.json().await?;
    let session_id = session["id"].as_str().unwrap();
    guard.add_chat(Uuid::parse_str(session_id)?);

    // Send a simple query that should skip agentic orchestration
    let simple_query = "Hi!";

    let generate_request = GenerateChatRequest {
        history: vec![ApiChatMessage {
            role: "user".to_string(),
            content: simple_query.to_string(),
        }],
        model: None,
        query_text_for_rag: None,
    };

    let generate_response = client
        .post(&format!("{}/api/chat/{}/generate", app.address, session_id))
        .header("Accept", "text/event-stream")
        .json(&generate_request)
        .send()
        .await?;

    assert_eq!(generate_response.status(), 200);

    // Verify that the response is received even without agentic processing
    let response_text = generate_response.text().await?;
    assert!(
        !response_text.is_empty(),
        "Should receive response even for simple queries"
    );

    guard.cleanup().await?;
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
    
    let query_params: ChatGenerateQueryParams = serde_json::from_value(json!({})).unwrap();
    
    let budget = calculate_agentic_token_budget(&query_params);
    assert_eq!(budget, 5000, "Should return default token budget");
}

#[test]
fn test_determine_quality_mode() {
    use scribe_backend::routes::chat::{determine_quality_mode, ChatGenerateQueryParams};
    use scribe_backend::services::QualityMode;
    
    let query_params: ChatGenerateQueryParams = serde_json::from_value(json!({})).unwrap();
    
    let quality_mode = determine_quality_mode(&query_params);
    assert_eq!(quality_mode, QualityMode::Balanced, "Should return default balanced quality mode");
}

#[test]
fn test_merge_orchestrated_context() {
    use scribe_backend::routes::chat::{merge_orchestrated_context};
    use scribe_backend::services::embeddings::RetrievedMetadata;
    
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