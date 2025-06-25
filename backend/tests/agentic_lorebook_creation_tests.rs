#![cfg(test)]
// backend/tests/agentic_lorebook_creation_tests.rs
//
// Tests that verify the agentic narrative system automatically creates lorebook entries
// when new characters, locations, items, or lore concepts are introduced during chat.

use std::sync::Arc;
use scribe_backend::{
    models::{
        chats::{ChatMessage, MessageRole},
        lorebook_dtos::{CreateLorebookPayload, LorebookEntryType},
    },
    services::{
        agentic::factory::AgenticNarrativeFactory,
        LorebookService,
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

mod lorebook_creation_tests {
    use super::*;

    #[tokio::test]
    async fn test_agentic_system_creates_character_lorebook_entries() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Create a lorebook for the campaign
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service.clone(),
            test_app.qdrant_service.clone()
        ));

        let create_lorebook_request = CreateLorebookPayload {
            name: "Campaign Lorebook".to_string(),
            description: Some("Main campaign world and characters".to_string()),
        };
        let lorebook = lorebook_service.create_lorebook(user_id, create_lorebook_request).await.unwrap();

        // Mock AI response for character introduction
        let triage_response = json!({
            "is_significant": true,
            "summary": "Introduction of new character with background and abilities",
            "event_category": "CHARACTER",
            "event_type": "INTRODUCTION",
            "narrative_action": "INTRODUCED",
            "primary_agent": "Narrator",
            "primary_patient": "Eldara the Wise",
            "confidence": 0.9
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
        
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service,
            lorebook_service.clone(),
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            None, // Use default config
        );

        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        // Simulate conversation introducing a new character
        let character_introduction_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "Who is the mysterious woman in the tower?", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "She is Eldara the Wise, an ancient elven sorceress who has lived for over 800 years. Her silver hair flows like moonlight, and her eyes hold the wisdom of centuries. She is known throughout the realm for her mastery of divination magic and her ability to see glimpses of possible futures. Eldara serves as the guardian of the Sacred Grove and is deeply respected by both the woodland creatures and the human kingdoms alike.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "What is her role in the current conflict?", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "Eldara remains neutral in most political conflicts, but she has prophesied that only through unity between the races can the coming darkness be defeated. She offers guidance to worthy heroes but never intervenes directly, believing that mortals must choose their own path to destiny.", "gemini-2.5-pro"),
        ];

        // Run the agentic workflow - should create character lorebook entry
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, None, &character_introduction_messages, &session_dek)
            .await;

        // Verify the workflow succeeded
        assert!(result.is_ok(), "Agentic lorebook creation should succeed: {:?}", result.err());
        let workflow_result = result.unwrap();

        // Verify triage detected character introduction
        assert!(workflow_result.triage_result.is_significant, "Should detect character introduction as significant");
        assert_eq!(workflow_result.triage_result.event_type, "INTRODUCTION", "Should identify as introduction event");

        // Verify actions were taken to create lorebook entries
        assert!(!workflow_result.actions_taken.is_empty(), "Should have executed actions to create lorebook entries");
        assert!(
            workflow_result.actions_taken.iter().any(|action| action.tool_name == "create_lorebook_entry"),
            "Should have created lorebook entries"
        );

        // Verify lorebook entry was created
        let entries = lorebook_service.get_lorebook_entries(user_id, lorebook.id, Default::default()).await.unwrap();
        assert!(!entries.is_empty(), "Should have created lorebook entries");
        
        let character_entry = &entries[0];
        assert!(character_entry.entry_title.contains("Eldara") || character_entry.content.contains("Eldara"), 
                "Entry should be about Eldara: title='{}', content preview='{}'", 
                character_entry.entry_title, 
                &character_entry.content[..std::cmp::min(100, character_entry.content.len())]);
        assert!(character_entry.content.contains("sorceress") || character_entry.content.contains("elven"), 
                "Entry should contain character details");
    }

    #[tokio::test]
    async fn test_agentic_system_creates_location_lorebook_entries() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Create a lorebook for the world
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service.clone(),
            test_app.qdrant_service.clone()
        ));

        let create_lorebook_request = CreateLorebookPayload {
            name: "World Atlas".to_string(),
            description: Some("Locations and geography of the realm".to_string()),
        };
        let lorebook = lorebook_service.create_lorebook(user_id, create_lorebook_request).await.unwrap();

        // Mock AI response for location discovery
        let triage_response = json!({
            "is_significant": true,
            "summary": "Discovery and exploration of significant new location",
            "event_category": "WORLD",
            "event_type": "DISCOVERY",
            "narrative_action": "DISCOVERED",
            "primary_agent": "Adventurers",
            "primary_patient": "Crystal Caverns",
            "confidence": 0.85
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
        
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service,
            lorebook_service.clone(),
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            None, // Use default config
        );

        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        // Simulate discovering a new location
        let location_discovery_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I follow the hidden path behind the waterfall.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "Behind the cascading water, you discover the entrance to the legendary Crystal Caverns! The cave mouth sparkles with thousands of embedded gems that seem to pulse with their own inner light. The air hums with magical energy, and you can see that the caverns extend deep into the mountain. Ancient dwarven runes are carved around the entrance, and the floor is worn smooth by countless footsteps from ages past.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "What can I learn about this place from the runes?", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "The runes speak of this being a sacred mining site where the ancient dwarves extracted 'starlight crystals' - gems that could store and amplify magical energy. The inscriptions warn that the deeper chambers are protected by ancient guardians and that only those pure of heart may claim the treasures within.", "gemini-2.5-pro"),
        ];

        // Run the agentic workflow - should create location lorebook entry
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, None, &location_discovery_messages, &session_dek)
            .await;

        // Verify the workflow succeeded
        assert!(result.is_ok(), "Agentic location lorebook creation should succeed: {:?}", result.err());
        let workflow_result = result.unwrap();

        // Verify location discovery was detected
        assert!(workflow_result.triage_result.is_significant, "Should detect location discovery as significant");
        assert_eq!(workflow_result.triage_result.event_type, "DISCOVERY", "Should identify as discovery event");

        // Verify lorebook entry was created
        let entries = lorebook_service.get_lorebook_entries(user_id, lorebook.id, Default::default()).await.unwrap();
        assert!(!entries.is_empty(), "Should have created location lorebook entries");
        
        let location_entry = &entries[0];
        assert!(location_entry.entry_title.contains("Crystal") || location_entry.content.contains("Crystal Caverns"), 
                "Entry should be about Crystal Caverns: title='{}', content preview='{}'", 
                location_entry.entry_title, 
                &location_entry.content[..std::cmp::min(100, location_entry.content.len())]);
        assert!(location_entry.content.contains("dwarven") || location_entry.content.contains("starlight"), 
                "Entry should contain location details");
    }

    #[tokio::test]
    async fn test_agentic_system_creates_item_lorebook_entries() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Create a lorebook for artifacts
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service.clone(),
            test_app.qdrant_service.clone()
        ));

        let create_lorebook_request = CreateLorebookPayload {
            name: "Magical Artifacts".to_string(),
            description: Some("Catalog of magical items and their properties".to_string()),
        };
        let lorebook = lorebook_service.create_lorebook(user_id, create_lorebook_request).await.unwrap();

        // Mock AI response for item discovery
        let triage_response = json!({
            "is_significant": true,
            "summary": "Discovery of powerful magical artifact with unique properties",
            "event_category": "WORLD",
            "event_type": "DISCOVERY",
            "narrative_action": "ACQUIRED",
            "primary_agent": "Hero",
            "primary_patient": "Shadowbane Sword",
            "confidence": 0.9
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
        
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service,
            lorebook_service.clone(),
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            None, // Use default config
        );

        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        // Simulate discovering a magical item
        let item_discovery_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I examine the sword resting on the altar.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "Before you lies Shadowbane, a legendary sword forged in the fires of Mount Doom and blessed by the High Priestess of Light. The blade is wreathed in a soft silver glow that pushes back the darkness around it. Its crossguard is shaped like outstretched wings, and the pommel contains a crystal that pulses with holy energy. Runes along the fuller spell out 'Let Light Drive Away Shadow' in the ancient tongue.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "What powers does this sword possess?", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "Shadowbane is especially effective against undead and shadow creatures, dealing double damage to such foes. The sword can emit a bright light on command, illuminating a 30-foot radius. Once per day, the wielder can call upon its power to cast 'Turn Undead' as if they were a high-level cleric. The blade also provides protection against fear effects and dark magic.", "gemini-2.5-pro"),
        ];

        // Run the agentic workflow - should create item lorebook entry
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, None, &item_discovery_messages, &session_dek)
            .await;

        // Verify the workflow succeeded
        assert!(result.is_ok(), "Agentic item lorebook creation should succeed: {:?}", result.err());
        let workflow_result = result.unwrap();

        // Verify item discovery was detected
        assert!(workflow_result.triage_result.is_significant, "Should detect item discovery as significant");
        assert_eq!(workflow_result.triage_result.event_type, "DISCOVERY", "Should identify as discovery event");

        // Verify lorebook entry was created
        let entries = lorebook_service.get_lorebook_entries(user_id, lorebook.id, Default::default()).await.unwrap();
        assert!(!entries.is_empty(), "Should have created item lorebook entries");
        
        let item_entry = &entries[0];
        assert!(item_entry.entry_title.contains("Shadowbane") || item_entry.content.contains("Shadowbane"), 
                "Entry should be about Shadowbane: title='{}', content preview='{}'", 
                item_entry.entry_title, 
                &item_entry.content[..std::cmp::min(100, item_entry.content.len())]);
        assert!(item_entry.content.contains("sword") || item_entry.content.contains("undead"), 
                "Entry should contain item details");
    }

    #[tokio::test]
    async fn test_agentic_system_creates_lore_concept_entries() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Create a lorebook for world lore
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service.clone(),
            test_app.qdrant_service.clone()
        ));

        let create_lorebook_request = CreateLorebookPayload {
            name: "World Lore Compendium".to_string(),
            description: Some("History, cultures, and concepts of the world".to_string()),
        };
        let lorebook = lorebook_service.create_lorebook(user_id, create_lorebook_request).await.unwrap();

        // Mock AI response for lore revelation
        let triage_response = json!({
            "is_significant": true,
            "summary": "Learning about important historical event and magical concept",
            "event_category": "PLOT",
            "event_type": "REVELATION",
            "narrative_action": "LEARNED",
            "primary_agent": "Scholar",
            "primary_patient": "The Great Sundering",
            "confidence": 0.88
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
        
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service,
            lorebook_service.clone(),
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            None, // Use default config
        );

        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        // Simulate learning about world lore
        let lore_learning_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "Tell me about the history of magic in this realm.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "The scholar adjusts her spectacles and begins: 'Long ago, magic flowed freely through all living things in what we call the Age of Unity. But a thousand years past, a catastrophic event known as The Great Sundering tore the magical fabric of reality. The ancient mages, in their hubris, attempted to merge the elemental planes with our world to gain ultimate power.'", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "What happened during The Great Sundering?", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "The ritual went catastrophically wrong. The barriers between planes shattered, creating magical storms that raged for decades. Whole kingdoms were transformed or destroyed. Magic became unpredictable and dangerous. The surviving mages formed the Circle of Binding to contain the chaos, creating the Ley Line network that channels and stabilizes magical energy today. This is why magic requires focus and training now, rather than flowing naturally as it once did.", "gemini-2.5-pro"),
        ];

        // Run the agentic workflow - should create lore lorebook entry
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, None, &lore_learning_messages, &session_dek)
            .await;

        // Verify the workflow succeeded
        assert!(result.is_ok(), "Agentic lore lorebook creation should succeed: {:?}", result.err());
        let workflow_result = result.unwrap();

        // Verify lore revelation was detected
        assert!(workflow_result.triage_result.is_significant, "Should detect lore revelation as significant");
        assert_eq!(workflow_result.triage_result.event_type, "REVELATION", "Should identify as revelation event");

        // Verify lorebook entry was created
        let entries = lorebook_service.get_lorebook_entries(user_id, lorebook.id, Default::default()).await.unwrap();
        assert!(!entries.is_empty(), "Should have created lore lorebook entries");
        
        let lore_entry = &entries[0];
        assert!(lore_entry.entry_title.contains("Sundering") || lore_entry.content.contains("Great Sundering"), 
                "Entry should be about The Great Sundering: title='{}', content preview='{}'", 
                lore_entry.entry_title, 
                &lore_entry.content[..std::cmp::min(100, lore_entry.content.len())]);
        assert!(lore_entry.content.contains("magic") || lore_entry.content.contains("ritual"), 
                "Entry should contain lore details");
    }

    #[tokio::test]
    async fn test_agentic_system_updates_existing_lorebook_entries() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Create a lorebook
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service.clone(),
            test_app.qdrant_service.clone()
        ));

        let create_lorebook_request = CreateLorebookPayload {
            name: "Character Updates".to_string(),
            description: Some("Tracking character development and changes".to_string()),
        };
        let lorebook = lorebook_service.create_lorebook(user_id, create_lorebook_request).await.unwrap();
        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        // Pre-create a basic character entry
        let initial_entry = scribe_backend::models::lorebook_dtos::CreateLorebookEntryPayload {
            entry_title: "Marcus the Brave".to_string(),
            content: "A young knight known for his courage.".to_string(),
            entry_type: LorebookEntryType::Character,
            keywords: vec!["Marcus".to_string(), "knight".to_string()],
        };
        lorebook_service.create_lorebook_entry(user_id, lorebook.id, initial_entry, &session_dek).await.unwrap();

        // Mock AI response for character development
        let triage_response = json!({
            "is_significant": true,
            "summary": "Character undergoes significant development and gains new abilities",
            "event_category": "CHARACTER",
            "event_type": "DEVELOPMENT",
            "narrative_action": "EVOLVED",
            "primary_agent": "Marcus",
            "primary_patient": "Paladin Powers",
            "confidence": 0.92
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
        
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service,
            lorebook_service.clone(),
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            None, // Use default config
        );

        // Simulate character development
        let character_development_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "Marcus, you've proven yourself worthy. I grant you the blessing of the Light.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "Marcus kneels as divine light surrounds him. His sword begins to glow with holy energy, and he feels the power of the Light flowing through him. 'I swear by this sacred blessing to protect the innocent and fight against darkness,' he declares. Marcus has become a true Paladin, gaining the ability to heal wounds, detect evil, and smite undead with divine power.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "What new abilities does Marcus now possess?", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "As a newly blessed Paladin, Marcus can now channel divine magic. He can lay hands on the wounded to heal their injuries, sense the presence of evil creatures within 60 feet, and once per day invoke a powerful smite that deals extra radiant damage to undead and fiends. His armor now gleams with a faint holy aura that provides protection against dark magic.", "gemini-2.5-pro"),
        ];

        // Get initial entry count
        let initial_entries = lorebook_service.get_lorebook_entries(user_id, lorebook.id, Default::default()).await.unwrap();
        let initial_count = initial_entries.len();

        // Run the agentic workflow - should update existing character entry
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, None, &character_development_messages, &session_dek)
            .await;

        // Verify the workflow succeeded
        assert!(result.is_ok(), "Agentic character update should succeed: {:?}", result.err());
        let workflow_result = result.unwrap();

        // Verify character development was detected
        assert!(workflow_result.triage_result.is_significant, "Should detect character development as significant");
        assert_eq!(workflow_result.triage_result.event_type, "DEVELOPMENT", "Should identify as development event");

        // Check if entries were updated (could be update or new entry depending on implementation)
        let final_entries = lorebook_service.get_lorebook_entries(user_id, lorebook.id, Default::default()).await.unwrap();
        
        // Find Marcus-related entries
        let marcus_entries: Vec<_> = final_entries.iter()
            .filter(|entry| entry.entry_title.contains("Marcus") || entry.content.contains("Marcus"))
            .collect();
        
        assert!(!marcus_entries.is_empty(), "Should have Marcus-related entries");
        
        // Check if any entry now contains paladin information
        let has_paladin_info = marcus_entries.iter().any(|entry| 
            entry.content.contains("Paladin") || entry.content.contains("divine") || entry.content.contains("holy")
        );
        assert!(has_paladin_info, "Should have updated Marcus with Paladin information");
    }

    #[tokio::test]
    async fn test_agentic_system_ignores_existing_well_documented_concepts() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let user_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Create a lorebook with existing entries
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service.clone(),
            test_app.qdrant_service.clone()
        ));

        let create_lorebook_request = CreateLorebookPayload {
            name: "Established Lore".to_string(),
            description: Some("Well-documented world information".to_string()),
        };
        let lorebook = lorebook_service.create_lorebook(user_id, create_lorebook_request).await.unwrap();

        // Mock AI response for already-known information
        let triage_response = json!({
            "is_significant": false,
            "summary": "Discussion of well-established lore already documented",
            "event_category": "CONVERSATION",
            "event_type": "CASUAL_DISCUSSION",
            "narrative_action": "DISCUSSED",
            "primary_agent": "Characters",
            "primary_patient": "Known Information",
            "confidence": 0.3
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
        
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service,
            lorebook_service.clone(),
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            None, // Use default config
        );

        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        // Simulate casual discussion of common knowledge
        let common_knowledge_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "The sun is setting, casting long shadows.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "Indeed, the golden hour bathes everything in warm light. It's a peaceful end to the day.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I enjoy watching the sunset from this hill.", "gemini-2.5-pro"),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "This is certainly a beautiful vantage point for watching the day's end.", "gemini-2.5-pro"),
        ];

        // Get initial entry count
        let initial_entries = lorebook_service.get_lorebook_entries(user_id, lorebook.id, Default::default()).await.unwrap();
        let initial_count = initial_entries.len();

        // Run the agentic workflow - should not create new entries
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, None, &common_knowledge_messages, &session_dek)
            .await;

        // Verify the workflow succeeded but took no action
        assert!(result.is_ok(), "Agentic system should handle common knowledge gracefully");
        let workflow_result = result.unwrap();

        // Verify common knowledge was correctly identified as insignificant
        assert!(!workflow_result.triage_result.is_significant, "Should detect common knowledge as insignificant");
        assert!(workflow_result.triage_result.confidence < 0.5, "Should have low confidence for common knowledge");

        // Verify no actions were taken
        assert!(workflow_result.actions_taken.is_empty(), "Should not execute actions for common knowledge");

        // Verify no new entries were created
        let final_entries = lorebook_service.get_lorebook_entries(user_id, lorebook.id, Default::default()).await.unwrap();
        assert_eq!(final_entries.len(), initial_count, "Should not create entries for common knowledge");
    }
}