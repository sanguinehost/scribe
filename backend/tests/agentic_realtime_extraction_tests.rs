#![cfg(test)]
// backend/tests/agentic_realtime_extraction_tests.rs
//
// Tests that verify the agentic narrative system extracts events in real-time
// during chat sessions, automatically detecting and recording significant narrative events.

use std::sync::Arc;
use scribe_backend::{
    models::{
        chats::{ChatMessage, MessageRole},
        chronicle_event::EventSource,
        chronicle::{CreateChronicleRequest},
    },
    services::{
        agentic::factory::AgenticNarrativeFactory,
    },
    test_helpers::{TestDataGuard, MockAiClient},
    auth::session_dek::SessionDek,
};
use serde_json::json;
use uuid::Uuid;
use chrono::Utc;
use secrecy::SecretBox;

// Helper to create a chat message
fn create_chat_message(
    user_id: Uuid,
    session_id: Uuid,
    role: MessageRole,
    content: &str,
    model_name: &str,
) -> ChatMessage {
    ChatMessage {
        id: Uuid::new_v4(),
        session_id,
        message_type: role,
        content: content.as_bytes().to_vec(),
        content_nonce: Some(vec![1, 2, 3, 4]),
        created_at: Utc::now(),
        user_id,
        prompt_tokens: Some(content.len() as i32 / 4), // Rough estimate
        completion_tokens: if matches!(role, MessageRole::Assistant) { Some(20) } else { Some(0) },
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: model_name.to_string(),
    }
}

mod realtime_extraction_tests {
    use super::*;

    #[tokio::test]
    async fn test_realtime_event_extraction_during_progressive_chat() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Create a chronicle for the ongoing adventure
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
        let create_chronicle_request = CreateChronicleRequest {
            name: "The Dragon's Quest".to_string(),
            description: Some("Epic adventure with dragons and treasures".to_string()),
        };
        let chronicle = chronicle_service.create_chronicle(user_id, create_chronicle_request).await.unwrap();

        // Mock AI response for significant event detection
        let triage_response = json!({
            "is_significant": true,
            "summary": "Character discovers treasure and encounters danger",
            "event_category": "WORLD",
            "event_type": "DISCOVERY",
            "narrative_action": "DISCOVERED",
            "primary_agent": "Hero",
            "primary_patient": "Ancient Treasure",
            "confidence": 0.85
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service,
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

        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        // Simulate a progressive chat session with multiple message exchanges
        let messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I carefully examine the ancient chest I found in the dungeon.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "The chest is ornate, covered in mystical runes that glow faintly blue. As you touch it, you hear a soft click - it's unlocked!", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I open the chest to see what's inside.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "Inside, you discover a magnificent golden amulet and a pouch of ancient coins. But suddenly, you hear footsteps echoing through the dungeon!", "gemini-2.5-pro"),
        ];

        // Run the agentic workflow - should detect significant events in real-time
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, Some(chronicle.id), &messages, &session_dek)
            .await;

        // Verify the workflow succeeded
        assert!(result.is_ok(), "Real-time extraction should succeed: {:?}", result.err());
        let workflow_result = result.unwrap();

        // Verify triage detected significance
        assert!(workflow_result.triage_result.is_significant, "Should detect significant treasure discovery");
        assert!(workflow_result.triage_result.confidence > 0.7, "Should have high confidence: {}", workflow_result.triage_result.confidence);
        assert_eq!(workflow_result.triage_result.event_type, "DISCOVERY", "Should identify as discovery event");

        // Verify tools were executed to record the events
        assert!(!workflow_result.actions_taken.is_empty(), "Should have executed actions for real-time extraction");

        // Verify events were recorded in the chronicle
        let events = chronicle_service.get_chronicle_events(user_id, chronicle.id, Default::default()).await.unwrap();
        assert!(!events.is_empty(), "Should have recorded events from real-time extraction");
        
        let latest_event = &events[0];
        assert_eq!(latest_event.get_source().unwrap(), EventSource::AiExtracted, "Events should be AI-extracted");
        assert!(latest_event.summary.contains("treasure") || latest_event.summary.contains("discover"), 
                "Event should capture treasure discovery: {}", latest_event.summary);
    }

    #[tokio::test]
    async fn test_realtime_extraction_ignores_mundane_chat_progression() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Create a chronicle for tracking
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
        let create_chronicle_request = CreateChronicleRequest {
            name: "Adventure Log".to_string(),
            description: Some("General adventure chronicle".to_string()),
        };
        let chronicle = chronicle_service.create_chronicle(user_id, create_chronicle_request).await.unwrap();

        // Mock AI response for insignificant chat
        let triage_response = json!({
            "is_significant": false,
            "summary": "General conversation and movement without meaningful events",
            "event_category": "CONVERSATION",
            "event_type": "CASUAL_CHAT",
            "narrative_action": "DISCUSSED",
            "primary_agent": "Player",
            "primary_patient": "Assistant",
            "confidence": 0.2
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service,
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

        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        // Simulate mundane chat progression
        let mundane_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I walk down the corridor.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "You walk down the stone corridor. The walls are lined with torches.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "What do I see ahead?", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "The corridor continues straight ahead. You can see more torches lighting the way.", "gemini-2.5-pro"),
        ];

        // Get initial event count
        let initial_events = chronicle_service.get_chronicle_events(user_id, chronicle.id, Default::default()).await.unwrap();
        let initial_count = initial_events.len();

        // Run the agentic workflow on mundane content
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, Some(chronicle.id), &mundane_messages, &session_dek)
            .await;

        // Verify the workflow succeeded but took no action
        assert!(result.is_ok(), "Real-time extraction should handle mundane chat gracefully");
        let workflow_result = result.unwrap();

        // Verify triage correctly identified as insignificant
        assert!(!workflow_result.triage_result.is_significant, "Should detect mundane chat as insignificant");
        assert!(workflow_result.triage_result.confidence < 0.5, "Should have low confidence for mundane chat");

        // Verify no actions were taken
        assert!(workflow_result.actions_taken.is_empty(), "Should not execute actions for mundane chat");

        // Verify no new events were recorded
        let final_events = chronicle_service.get_chronicle_events(user_id, chronicle.id, Default::default()).await.unwrap();
        assert_eq!(final_events.len(), initial_count, "Should not add events for mundane chat");
    }

    #[tokio::test]
    async fn test_realtime_extraction_handles_rapid_message_sequence() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Create a chronicle for the combat scenario
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
        let create_chronicle_request = CreateChronicleRequest {
            name: "Combat Encounter".to_string(),
            description: Some("Fast-paced combat scenario".to_string()),
        };
        let chronicle = chronicle_service.create_chronicle(user_id, create_chronicle_request).await.unwrap();

        // Mock AI response for combat events
        let triage_response = json!({
            "is_significant": true,
            "summary": "Intense combat with multiple actions and outcomes",
            "event_category": "CHARACTER",
            "event_type": "STATE_CHANGE",
            "narrative_action": "ATTACKED",
            "primary_agent": "Hero",
            "primary_patient": "Dragon",
            "confidence": 0.9
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service,
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

        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        // Simulate rapid-fire combat sequence
        let rapid_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I draw my sword and attack the dragon!", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "Your blade strikes true! The dragon roars in fury and breathes fire at you!", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I dodge and cast a lightning spell!", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "Lightning crackles through the air! The dragon staggers, wounded but still dangerous!", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I press the attack with a final strike!", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "With a mighty blow, you defeat the dragon! It crashes to the ground, defeated!", "gemini-2.5-pro"),
        ];

        // Run the agentic workflow on rapid sequence
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, Some(chronicle.id), &rapid_messages, &session_dek)
            .await;

        // Verify the workflow handled rapid sequence successfully
        assert!(result.is_ok(), "Real-time extraction should handle rapid message sequences: {:?}", result.err());
        let workflow_result = result.unwrap();

        // Verify significant combat was detected
        assert!(workflow_result.triage_result.is_significant, "Should detect combat as significant");
        assert!(workflow_result.triage_result.confidence > 0.8, "Should have high confidence for combat");
        assert_eq!(workflow_result.triage_result.event_type, "STATE_CHANGE", "Should identify as state change event");

        // Verify events were recorded
        let events = chronicle_service.get_chronicle_events(user_id, chronicle.id, Default::default()).await.unwrap();
        assert!(!events.is_empty(), "Should have recorded combat events");
        
        let combat_event = &events[0];
        assert!(combat_event.summary.contains("attack") || combat_event.summary.contains("combat") || combat_event.summary.contains("dragon"), 
                "Event should capture combat scenario: {}", combat_event.summary);
    }

    #[tokio::test]
    async fn test_realtime_extraction_with_context_from_previous_messages() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Create a chronicle for the story
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
        let create_chronicle_request = CreateChronicleRequest {
            name: "The Mysterious Quest".to_string(),
            description: Some("A quest with developing plot elements".to_string()),
        };
        let chronicle = chronicle_service.create_chronicle(user_id, create_chronicle_request).await.unwrap();

        // Mock AI response for plot revelation
        let triage_response = json!({
            "is_significant": true,
            "summary": "Major plot revelation about character's true identity",
            "event_category": "PLOT",
            "event_type": "REVELATION",
            "narrative_action": "REVEALED",
            "primary_agent": "Sage",
            "primary_patient": "Hero's Identity",
            "confidence": 0.95
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service,
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

        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        // Simulate a conversation that builds up to a revelation
        let context_building_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I've been having strange dreams about a castle I've never seen before.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "The wise sage looks at you with knowing eyes. 'Tell me more about these dreams, child.'", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "In the dreams, I see myself as a child in royal robes, but I was raised as a peasant.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "The sage nods slowly. 'The time has come for you to learn the truth about your birth.'", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "What truth? Who am I really?", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "'You are the lost prince of Eldoria, hidden away to protect you from those who usurped the throne!'", "gemini-2.5-pro"),
        ];

        // Run the agentic workflow on the revelation sequence
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, Some(chronicle.id), &context_building_messages, &session_dek)
            .await;

        // Verify the workflow succeeded
        assert!(result.is_ok(), "Real-time extraction should handle context-building conversations: {:?}", result.err());
        let workflow_result = result.unwrap();

        // Verify the plot revelation was detected
        assert!(workflow_result.triage_result.is_significant, "Should detect plot revelation as significant");
        assert!(workflow_result.triage_result.confidence > 0.9, "Should have very high confidence for major revelation");
        assert_eq!(workflow_result.triage_result.event_type, "REVELATION", "Should identify as revelation event");

        // Verify actions were taken to record this important plot point
        assert!(!workflow_result.actions_taken.is_empty(), "Should execute actions for major plot revelation");

        // Verify the revelation event was recorded
        let events = chronicle_service.get_chronicle_events(user_id, chronicle.id, Default::default()).await.unwrap();
        assert!(!events.is_empty(), "Should have recorded the revelation event");
        
        let revelation_event = &events[0];
        assert!(revelation_event.summary.contains("prince") || revelation_event.summary.contains("identity") || revelation_event.summary.contains("truth"), 
                "Event should capture the identity revelation: {}", revelation_event.summary);
    }

    #[tokio::test]
    async fn test_realtime_extraction_performance_with_long_messages() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Create a chronicle
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
        let create_chronicle_request = CreateChronicleRequest {
            name: "Performance Test Chronicle".to_string(),
            description: Some("Testing extraction with long content".to_string()),
        };
        let chronicle = chronicle_service.create_chronicle(user_id, create_chronicle_request).await.unwrap();

        // Mock AI response
        let triage_response = json!({
            "is_significant": true,
            "summary": "Epic battle with detailed descriptions and multiple participants",
            "event_category": "PLOT",
            "event_type": "TURNING_POINT",
            "narrative_action": "BATTLED",
            "primary_agent": "Alliance Forces",
            "primary_patient": "Dark Army",
            "confidence": 0.88
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service,
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

        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        // Create long detailed messages (simulating verbose RP)
        let long_content = "The massive battlefield stretches before you, with thousands of warriors clashing in epic combat. Knights in shining armor clash with dark creatures emerging from shadow portals. Magic crackles through the air as wizards on both sides cast powerful spells. You see your allies fighting valiantly - Sir Gareth defending a group of villagers, Lady Elara weaving protective barriers around the wounded, and Captain Marcus leading a charge against a massive troll. The fate of the kingdom hangs in the balance as you prepare to make your move in this climactic battle.".repeat(3);

        let long_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I survey the battlefield and prepare for the final confrontation.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                &long_content, "gemini-2.5-pro"),
        ];

        // Measure extraction time
        let start_time = std::time::Instant::now();
        
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, Some(chronicle.id), &long_messages, &session_dek)
            .await;
        
        let extraction_time = start_time.elapsed();

        // Verify the workflow succeeded and performed reasonably
        assert!(result.is_ok(), "Real-time extraction should handle long messages: {:?}", result.err());
        assert!(extraction_time.as_secs() < 30, "Extraction should complete within reasonable time: {:?}", extraction_time);

        let workflow_result = result.unwrap();

        // Verify the epic battle was detected despite length
        assert!(workflow_result.triage_result.is_significant, "Should detect epic battle as significant");
        assert_eq!(workflow_result.triage_result.event_type, "TURNING_POINT", "Should identify as turning point event");

        // Verify events were recorded
        let events = chronicle_service.get_chronicle_events(user_id, chronicle.id, Default::default()).await.unwrap();
        assert!(!events.is_empty(), "Should have recorded events despite long content");
    }
}