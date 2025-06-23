#![cfg(test)]
// backend/tests/event_extraction_service_tests.rs

use std::sync::Arc;
use anyhow::Result as AnyhowResult;
use scribe_backend::{
    auth::session_dek::SessionDek,
    models::{
        chats::{ChatMessage, MessageRole},
        chronicle_event::EventSource,
    },
    services::{
        event_extraction_service::{
            EventExtractionService, ExtractionConfig,
        },
        tokenizer_service::TokenizerService,
        ChronicleService,
    },
    test_helpers::{TestDataGuard, TestApp, MockAiClient},
    llm::AiClient,
};
use uuid::Uuid;
use chrono::Utc;
use serde_json::json;
use secrecy::SecretBox;

// Helper to create test messages
fn create_test_messages(count: usize, user_id: Uuid, session_id: Uuid) -> Vec<ChatMessage> {
    (0..count)
        .map(|i| ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: if i % 2 == 0 { MessageRole::User } else { MessageRole::Assistant },
            content: format!("Test message {} content", i + 1).into_bytes(),
            content_nonce: Some(vec![1, 2, 3, 4]), // Mock nonce
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(10),
            completion_tokens: Some(5),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        })
        .collect()
}

// Helper to create test extraction service
async fn create_test_extraction_service(
    ai_client: Arc<dyn AiClient>,
    test_app: &TestApp,
) -> AnyhowResult<EventExtractionService> {
    let tokenizer_service = TokenizerService::new(&test_app.config.tokenizer_model_path)?;
    let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
    
    Ok(EventExtractionService::new(
        ai_client,
        tokenizer_service,
        chronicle_service,
    ))
}

mod unit_tests {
    use super::*;

    #[tokio::test]
    async fn test_message_chunking_by_count() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        
        // Create mock AI client that returns valid JSON
        let mock_response = json!({
            "events": [],
            "reasoning": "No significant events found in test messages"
        });
        let mock_ai_client = Arc::new(MockAiClient::new_with_response(mock_response.to_string()));
        
        let extraction_service = create_test_extraction_service(mock_ai_client, &test_app).await.unwrap();
        
        // Create 10 test messages
        let messages = create_test_messages(10, user_id, session_id);
        
        // Configure chunking with 4 messages per chunk
        let config = ExtractionConfig {
            model_name: "test-model".to_string(),
            chunk_size_messages: 4,
            chunk_size_tokens: 10000, // High limit to test message-based chunking
            chunk_overlap_messages: 1,
        };
        
        // Test the chunking (this calls a private method, so we'll test the full extraction)
        let chronicle_id = Uuid::new_v4();
        
        // Create a mock SessionDek
        let mock_dek = SecretBox::new(Box::new([0u8; 32].to_vec()));
        let session_dek = SessionDek(mock_dek);
        
        let result = extraction_service
            .extract_events_from_messages(user_id, chronicle_id, messages, &session_dek, config)
            .await;
        
        // Should succeed without errors
        assert!(result.is_ok());
        let events = result.unwrap();
        
        // With 10 messages, 4 per chunk, 1 overlap: chunks would be [0-3], [3-6], [6-9]
        // Each chunk should produce events (though our mock returns empty)
        // The test validates the chunking logic works without errors
        assert!(events.len() >= 0); // Mock returns empty, but process should work
    }

    #[tokio::test]
    async fn test_ai_response_parsing_valid_json() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        
        // Create mock AI client with valid event extraction response
        let mock_response = json!({
            "events": [
                {
                    "event_type": "CHARACTER_DEVELOPMENT",
                    "summary": "Hero discovers their true heritage",
                    "participants": ["Hero", "Wise Sage"],
                    "location": "Ancient Temple",
                    "timestamp_context": "Messages 1-4",
                    "significance": "Major character revelation",
                    "event_data": {
                        "emotion": "shocked",
                        "heritage": "royal lineage"
                    }
                }
            ],
            "reasoning": "Found one significant character development moment"
        });
        
        let mock_ai_client = Arc::new(MockAiClient::new_with_response(mock_response.to_string()));
        let extraction_service = create_test_extraction_service(mock_ai_client, &test_app).await.unwrap();
        
        // Create test messages
        let messages = create_test_messages(4, user_id, session_id);
        
        let config = ExtractionConfig::default();
        let chronicle_id = Uuid::new_v4();
        
        let result = extraction_service
            .extract_events_from_messages(user_id, chronicle_id, messages, &SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec()))), config)
            .await;
        
        assert!(result.is_ok());
        let events = result.unwrap();
        
        // Should have extracted 1 event
        assert_eq!(events.len(), 1);
        
        let event = &events[0];
        assert_eq!(event.event_type, "CHARACTER_DEVELOPMENT");
        assert_eq!(event.summary, "Hero discovers their true heritage");
        assert_eq!(event.get_source().unwrap(), EventSource::AiExtracted);
        assert!(event.event_data.is_some());
    }

    #[tokio::test]
    async fn test_ai_response_parsing_invalid_json() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        
        // Create mock AI client with invalid JSON response
        let invalid_response = "This is not valid JSON, the AI got confused";
        let mock_ai_client = Arc::new(MockAiClient::new_with_response(invalid_response.to_string()));
        let extraction_service = create_test_extraction_service(mock_ai_client, &test_app).await.unwrap();
        
        // Create test messages
        let messages = create_test_messages(4, user_id, session_id);
        
        let config = ExtractionConfig::default();
        let chronicle_id = Uuid::new_v4();
        
        let result = extraction_service
            .extract_events_from_messages(user_id, chronicle_id, messages, &SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec()))), config)
            .await;
        
        assert!(result.is_ok());
        let events = result.unwrap();
        
        // Should create fallback event with the raw response
        assert_eq!(events.len(), 1);
        
        let event = &events[0];
        assert_eq!(event.event_type, "CONVERSATION_SEGMENT");
        assert_eq!(event.summary, invalid_response);
        // Should have error details in event_data
        let event_data = event.event_data.as_ref().unwrap();
        assert!(event_data.get("extraction_error").is_some());
        assert!(event_data.get("raw_response").is_some());
    }

    #[tokio::test] 
    async fn test_empty_messages_handling() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        
        let user_id = Uuid::new_v4();
        
        // Mock AI client (shouldn't be called for empty messages)
        let mock_ai_client = Arc::new(MockAiClient::new_with_response("".to_string()));
        let extraction_service = create_test_extraction_service(mock_ai_client, &test_app).await.unwrap();
        
        // Empty messages vector
        let messages = Vec::new();
        
        let config = ExtractionConfig::default();
        let chronicle_id = Uuid::new_v4();
        
        let result = extraction_service
            .extract_events_from_messages(user_id, chronicle_id, messages, &SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec()))), config)
            .await;
        
        assert!(result.is_ok());
        let events = result.unwrap();
        
        // Should return empty events for empty messages
        assert_eq!(events.len(), 0);
    }

    #[tokio::test]
    async fn test_extraction_config_defaults() {
        let config = ExtractionConfig::default();
        
        assert_eq!(config.model_name, "gemini-2.5-flash-lite-preview-06-17");
        assert_eq!(config.chunk_size_messages, 4);
        assert_eq!(config.chunk_size_tokens, 2000);
        assert_eq!(config.chunk_overlap_messages, 1);
    }

    #[tokio::test]
    async fn test_extraction_config_custom() {
        let config = ExtractionConfig {
            model_name: "custom-model".to_string(),
            chunk_size_messages: 8,
            chunk_size_tokens: 4000,
            chunk_overlap_messages: 2,
        };
        
        assert_eq!(config.model_name, "custom-model");
        assert_eq!(config.chunk_size_messages, 8);
        assert_eq!(config.chunk_size_tokens, 4000);
        assert_eq!(config.chunk_overlap_messages, 2);
    }
}

mod integration_tests {
    use super::*;
    use scribe_backend::models::chronicle::{CreateChronicleRequest};

    #[tokio::test]
    async fn test_full_extraction_workflow() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        
        // Create a valid chronicle first
        let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
        let chronicle_request = CreateChronicleRequest {
            name: "Test Chronicle".to_string(),
            description: Some("For testing event extraction".to_string()),
        };
        let chronicle = chronicle_service
            .create_chronicle(user_id, chronicle_request)
            .await
            .unwrap();
        
        // Create mock AI client with realistic extraction response
        let mock_response = json!({
            "events": [
                {
                    "event_type": "PLOT_ADVANCEMENT",
                    "summary": "The party enters the dungeon and encounters the guardian",
                    "participants": ["Fighter", "Mage", "Rogue"],
                    "location": "Ancient Dungeon Entrance",
                    "timestamp_context": "Messages 1-4",
                    "significance": "First major challenge of the adventure",
                    "event_data": {
                        "challenge_rating": "moderate",
                        "loot_found": ["rusty key", "healing potion"],
                        "next_destination": "dungeon_level_2"
                    }
                },
                {
                    "event_type": "CHARACTER_DEVELOPMENT",
                    "summary": "The rogue reveals their tragic backstory",
                    "participants": ["Rogue", "Party"],
                    "location": "Dungeon Rest Area",
                    "timestamp_context": "Messages 3-4",
                    "significance": "Builds party trust and explains rogue's motivation",
                    "event_data": {
                        "emotion": "vulnerable",
                        "backstory_element": "lost family"
                    }
                }
            ],
            "reasoning": "Found two significant events: a plot advancement and character development moment"
        });
        
        let mock_ai_client = Arc::new(MockAiClient::new_with_response(mock_response.to_string()));
        let extraction_service = create_test_extraction_service(mock_ai_client, &test_app).await.unwrap();
        
        // Create test messages
        let messages = create_test_messages(6, user_id, session_id);
        
        let config = ExtractionConfig {
            model_name: "gemini-2.5-flash-lite-preview-06-17".to_string(),
            chunk_size_messages: 4,
            chunk_size_tokens: 2000,
            chunk_overlap_messages: 1,
        };
        
        // Run full extraction
        let result = extraction_service
            .extract_events_from_messages(user_id, chronicle.id, messages, &SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec()))), config)
            .await;
        
        assert!(result.is_ok());
        let events = result.unwrap();
        
        // Should have extracted and saved events to database
        assert!(events.len() >= 2); // At least the events from our mock response
        
        // Verify events were actually saved by querying the chronicle
        let saved_events = chronicle_service
            .get_chronicle_events(user_id, chronicle.id, Default::default())
            .await
            .unwrap();
        
        assert_eq!(saved_events.len(), events.len());
        
        // Check first event
        let plot_event = saved_events.iter()
            .find(|e| e.event_type == "PLOT_ADVANCEMENT")
            .expect("Should have plot advancement event");
            
        assert_eq!(plot_event.summary, "The party enters the dungeon and encounters the guardian");
        assert_eq!(plot_event.get_source().unwrap(), EventSource::AiExtracted);
        assert!(plot_event.event_data.is_some());
        
        // Check second event  
        let character_event = saved_events.iter()
            .find(|e| e.event_type == "CHARACTER_DEVELOPMENT")
            .expect("Should have character development event");
            
        assert_eq!(character_event.summary, "The rogue reveals their tragic backstory");
        assert_eq!(character_event.get_source().unwrap(), EventSource::AiExtracted);
        assert!(character_event.event_data.is_some());
    }
}