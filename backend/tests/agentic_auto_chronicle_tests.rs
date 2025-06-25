#![cfg(test)]
// backend/tests/agentic_auto_chronicle_tests.rs
//
// Tests that verify the agentic narrative system automatically creates chronicles
// and extracts events during chat flow, replacing the old manual extraction buttons.

use std::sync::Arc;
use scribe_backend::{
    models::{
        chats::{ChatMessage, MessageRole},
        chronicle_event::EventSource,
    },
    services::{
        agentic::{
            factory::AgenticNarrativeFactory,
        },
        ChronicleService,
    },
    test_helpers::{TestDataGuard, MockAiClient},
    auth::session_dek::SessionDek,
};
use serde_json::json;
use uuid::Uuid;
use chrono::Utc;
use secrecy::SecretBox;

// Helper to create test messages
fn create_test_messages(user_id: Uuid, session_id: Uuid) -> Vec<ChatMessage> {
    vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "Hello! I want to start a new adventure where I play as a young wizard named Alex.".as_bytes().to_vec(),
            content_nonce: Some(vec![1, 2, 3, 4]),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(15),
            completion_tokens: Some(0),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        },
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::Assistant,
            content: "Welcome to the mystical realm of Aethermoor! You are Alex, a young wizard who has just arrived at the prestigious Starfall Academy. The ancient towers gleam in the moonlight as you approach the great oak doors.".as_bytes().to_vec(),
            content_nonce: Some(vec![1, 2, 3, 4]),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(20),
            completion_tokens: Some(35),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        },
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "I knock on the doors and wait to see who answers.".as_bytes().to_vec(),
            content_nonce: Some(vec![1, 2, 3, 4]),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(12),
            completion_tokens: Some(0),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        },
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::Assistant,
            content: "The massive doors creak open to reveal Professor Willowshade, a tall elf with silver hair and kind eyes. 'Ah, you must be Alex! We've been expecting you. Welcome to Starfall Academy, young wizard.'".as_bytes().to_vec(),
            content_nonce: Some(vec![1, 2, 3, 4]),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(25),
            completion_tokens: Some(42),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        },
    ]
}

mod agentic_chronicle_tests {
    use super::*;

    #[tokio::test]
    async fn test_agentic_system_auto_creates_chronicle_for_significant_events() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Create mock AI client that simulates triage recognizing significant events
        let triage_response = json!({
            "is_significant": true,
            "summary": "New adventure beginning with character introduction and world-building",
            "event_category": "PLOT",
            "event_type": "ADVENTURE_START",
            "narrative_action": "BEGAN",
            "primary_agent": "Alex",
            "primary_patient": "Adventure",
            "confidence": 0.9
        });

        // Mock planning response that decides to create a chronicle
        let planning_response = json!({
            "reasoning": "This is the start of a new adventure with clear characters and setting. A chronicle should be created to track the story.",
            "actions": [
                {
                    "tool_name": "create_chronicle_event",
                    "parameters": {
                        "chronicle_id": null,
                        "event_type": "ADVENTURE_START",
                        "summary": "Alex arrives at Starfall Academy to begin wizard training",
                        "event_data": {
                            "character": "Alex",
                            "location": "Starfall Academy",
                            "setting": "Aethermoor",
                            "description": "A young wizard named Alex arrives at the prestigious magical academy"
                        }
                    },
                    "reasoning": "Create event documenting the adventure beginning"
                }
            ]
        });

        // For the first call (triage), return the triage_response
        // In a real implementation, we'd need to queue multiple responses,
        // but for this test, we'll use the triage response
        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system using individual services
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            Arc::new(scribe_backend::services::EncryptionService::new()),
            test_app.qdrant_service.clone()
        ));
        
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service.clone(),
            lorebook_service,
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            None, // Use default config
        );

        // Create test messages representing a new adventure starting
        let messages = create_test_messages(user_id, chat_session_id);
        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        // Run the agentic workflow - should auto-create chronicle when no chronicle_id provided
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, None, &messages, &session_dek)
            .await;

        // Verify the workflow succeeded
        assert!(result.is_ok(), "Agentic workflow should succeed: {:?}", result.err());
        let workflow_result = result.unwrap();

        // Verify triage detected significance
        assert!(workflow_result.triage_result.is_significant, "Triage should detect significant events");
        assert!(workflow_result.triage_result.confidence > 0.8, "Should have high confidence");

        // Verify tools were executed (chronicle and events created)
        assert!(!workflow_result.actions_taken.is_empty(), "Should have executed actions");
        assert!(
            workflow_result.actions_taken.iter().any(|action| action.tool_name == "create_chronicle_event"),
            "Should have created chronicle events"
        );

        // Verify chronicle was auto-created in database
        let chronicles = chronicle_service.get_user_chronicles(user_id).await.unwrap();
        
        assert!(!chronicles.is_empty(), "Should have auto-created a chronicle");
        let chronicle = &chronicles[0];
        assert!(chronicle.name.contains("Adventure") || chronicle.name.contains("Alex") || chronicle.name.contains("Starfall"), 
                "Chronicle name should be contextually relevant: {}", chronicle.name);

        // Verify events were extracted to the chronicle
        let events = chronicle_service.get_chronicle_events(user_id, chronicle.id, Default::default()).await.unwrap();
        assert!(!events.is_empty(), "Should have extracted events to the chronicle");
        
        let event = &events[0];
        assert_eq!(event.get_source().unwrap(), EventSource::AiExtracted, "Events should be AI-extracted");
        assert!(event.summary.contains("Alex") || event.summary.contains("adventure"), 
                "Event summary should be contextually relevant: {}", event.summary);
    }

    #[tokio::test]
    async fn test_agentic_system_adds_to_existing_chronicle() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Pre-create a chronicle
        let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
        let chronicle_request = scribe_backend::models::chronicle::CreateChronicleRequest {
            name: "Alex's Adventure".to_string(),
            description: Some("The ongoing adventures of Alex the wizard".to_string()),
        };
        let existing_chronicle = chronicle_service.create_chronicle(user_id, chronicle_request).await.unwrap();

        // Mock AI responses for continuing an existing story
        let triage_response = json!({
            "is_significant": true,
            "summary": "Character meets important NPC and receives guidance",
            "event_category": "CHARACTER",
            "event_type": "CHARACTER_INTERACTION",
            "narrative_action": "MET",
            "primary_agent": "Alex",
            "primary_patient": "Professor Willowshade",
            "confidence": 0.85
        });

        let planning_response = json!({
            "reasoning": "Alex has met Professor Willowshade, an important NPC. This should be recorded as a character interaction event.",
            "actions": [
                {
                    "tool_name": "create_chronicle_event",
                    "parameters": {
                        "chronicle_id": existing_chronicle.id,
                        "event_type": "CHARACTER_INTERACTION",
                        "summary": "Alex meets Professor Willowshade at the academy entrance",
                        "event_data": {
                            "characters": ["Alex", "Professor Willowshade"],
                            "location": "Starfall Academy entrance",
                            "interaction_type": "first_meeting",
                            "description": "The tall elf professor welcomes Alex to the academy"
                        }
                    },
                    "reasoning": "Document the important character introduction"
                }
            ]
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic system using individual services
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            Arc::new(scribe_backend::services::EncryptionService::new()),
            test_app.qdrant_service.clone()
        ));
        
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service.clone(),
            lorebook_service,
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            None, // Use default config
        );

        // Create messages and run workflow with existing chronicle
        let messages = create_test_messages(user_id, chat_session_id);
        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, Some(existing_chronicle.id), &messages, &session_dek)
            .await;

        // Verify workflow succeeded
        assert!(result.is_ok(), "Agentic workflow should succeed: {:?}", result.err());
        let workflow_result = result.unwrap();

        // Verify events were added to existing chronicle
        let events = chronicle_service.get_chronicle_events(user_id, existing_chronicle.id, Default::default()).await.unwrap();
        assert!(!events.is_empty(), "Should have added events to existing chronicle");

        let latest_event = &events[0]; // Events are typically ordered by creation time
        assert_eq!(latest_event.get_source().unwrap(), EventSource::AiExtracted);
        assert!(latest_event.summary.contains("Professor Willowshade") || latest_event.summary.contains("meet"), 
                "Event should document the character meeting: {}", latest_event.summary);

        // Verify no new chronicle was created (should still only have 1)
        let all_chronicles = chronicle_service.get_user_chronicles(user_id).await.unwrap();
        assert_eq!(all_chronicles.len(), 1, "Should not have created a new chronicle");
        assert_eq!(all_chronicles[0].id, existing_chronicle.id, "Should have used existing chronicle");
    }

    #[tokio::test]
    async fn test_agentic_system_ignores_insignificant_chat() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Mock AI triage response for insignificant conversation
        let triage_response = json!({
            "is_significant": false,
            "summary": "General small talk and pleasantries",
            "event_category": "CONVERSATION",
            "event_type": "CASUAL_CHAT",
            "narrative_action": "DISCUSSED",
            "primary_agent": "User",
            "primary_patient": "Assistant",
            "confidence": 0.3
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create agentic system using individual services
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            Arc::new(scribe_backend::services::EncryptionService::new()),
            test_app.qdrant_service.clone()
        ));
        
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service,
            lorebook_service,
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            None, // Use default config
        );

        // Create mundane messages
        let mundane_messages = vec![
            ChatMessage {
                id: Uuid::new_v4(),
                session_id: chat_session_id,
                message_type: MessageRole::User,
                content: "How are you today?".as_bytes().to_vec(),
                content_nonce: Some(vec![1, 2, 3, 4]),
                created_at: Utc::now(),
                user_id,
                prompt_tokens: Some(5),
                completion_tokens: Some(0),
                raw_prompt_ciphertext: None,
                raw_prompt_nonce: None,
                model_name: "gemini-2.5-pro".to_string(),
            },
            ChatMessage {
                id: Uuid::new_v4(),
                session_id: chat_session_id,
                message_type: MessageRole::Assistant,
                content: "I'm doing well, thank you for asking! How can I help you today?".as_bytes().to_vec(),
                content_nonce: Some(vec![1, 2, 3, 4]),
                created_at: Utc::now(),
                user_id,
                prompt_tokens: Some(8),
                completion_tokens: Some(15),
                raw_prompt_ciphertext: None,
                raw_prompt_nonce: None,
                model_name: "gemini-2.5-pro".to_string(),
            },
        ];

        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        // Run workflow on insignificant messages
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, None, &mundane_messages, &session_dek)
            .await;

        // Verify workflow succeeded but took no action
        assert!(result.is_ok(), "Agentic workflow should succeed even for insignificant events");
        let workflow_result = result.unwrap();

        // Verify triage correctly identified as insignificant
        assert!(!workflow_result.triage_result.is_significant, "Triage should detect insignificant events");
        assert!(workflow_result.triage_result.confidence < 0.5, "Should have low confidence for insignificant events");

        // Verify no tools were executed
        assert!(workflow_result.actions_taken.is_empty(), "Should not have executed any actions for insignificant events");

        // Verify no chronicle was created
        let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
        let chronicles = chronicle_service.get_user_chronicles(user_id).await.unwrap();
        assert!(chronicles.is_empty(), "Should not have created any chronicles for insignificant conversation");
    }

    #[tokio::test]
    async fn test_agentic_system_handles_errors_gracefully() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Mock AI client that returns invalid JSON to simulate errors
        let invalid_response = "This is not valid JSON and should cause an error";
        let mock_ai_client = Arc::new(MockAiClient::new_with_response(invalid_response.to_string()));

        // Create agentic system using individual services
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            Arc::new(scribe_backend::services::EncryptionService::new()),
            test_app.qdrant_service.clone()
        ));
        
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service,
            lorebook_service,
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            None, // Use default config
        );

        let messages = create_test_messages(user_id, chat_session_id);
        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        // Run workflow that should fail gracefully
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, None, &messages, &session_dek)
            .await;

        // Verify error handling - should return an error but not crash
        assert!(result.is_err(), "Should return error for invalid AI responses");
        
        // Verify the error is appropriate (JSON parsing or AI client error)
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("JSON") || error.to_string().contains("parse") || error.to_string().contains("AI"),
            "Error should be related to JSON parsing or AI client: {}", error
        );

        // Verify no chronicles were created due to the error
        let chronicle_service = ChronicleService::new(test_app.db_pool.clone());
        let chronicles = chronicle_service.get_user_chronicles(user_id).await.unwrap();
        assert!(chronicles.is_empty(), "Should not have created chronicles when errors occur");
    }
}