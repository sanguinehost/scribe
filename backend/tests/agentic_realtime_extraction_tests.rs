#![cfg(test)]
// backend/tests/agentic_realtime_extraction_tests.rs
//
// Tests that verify the agentic narrative system extracts events in real-time
// during chat sessions, automatically detecting and recording significant narrative events.

use std::sync::Arc;
use anyhow::Result as AnyhowResult;
use scribe_backend::{
    models::{
        chats::{ChatMessage, MessageRole},
        chronicle_event::EventSource,
        chronicle::{CreateChronicleRequest},
        users::{NewUser, UserRole, AccountStatus, UserDbQuery},
    },
    services::{
        agentic::factory::AgenticNarrativeFactory,
    },
    test_helpers::{TestDataGuard, MockAiClient, TestApp},
    auth::session_dek::SessionDek,
    schema::users,
};
use serde_json::json;
use uuid::Uuid;
use chrono::Utc;
use secrecy::{SecretBox, SecretString, ExposeSecret};
use diesel::{RunQueryDsl, prelude::*};
use bcrypt;

/// Helper to create agentic services for tests
fn create_agentic_services(test_app: &TestApp) -> (Arc<scribe_backend::services::WorldModelService>, Arc<scribe_backend::services::AgenticOrchestrator>, Arc<scribe_backend::services::AgenticStateUpdateService>) {
    let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
    let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
    let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
        Arc::new(test_app.db_pool.clone()),
        redis_client,
        None,
    ));
    let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
        Default::default(),
        feature_flags.clone(),
        Some(entity_manager.clone()),
        None,
    ));
    let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
        scribe_backend::text_processing::chunking::ChunkConfig {
            metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
            max_size: 500,
            overlap: 50,
        }
    ));
    let rag_service = Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
        Arc::new(test_app.db_pool.clone()),
        Default::default(),
        feature_flags.clone(),
        entity_manager.clone(),
        degradation.clone(),
        concrete_embedding_service,
    ));
    let hybrid_query_service = Arc::new(scribe_backend::services::HybridQueryService::new(
        Arc::new(test_app.db_pool.clone()),
        Default::default(),
        feature_flags,
        entity_manager.clone(),
        rag_service,
        degradation,
    ));
    let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
    
    let world_model_service = Arc::new(scribe_backend::services::WorldModelService::new(
        Arc::new(test_app.db_pool.clone()),
        entity_manager.clone(),
        hybrid_query_service.clone(),
        chronicle_service,
    ));
    
    let agentic_state_update_service = Arc::new(scribe_backend::services::AgenticStateUpdateService::new(
        test_app.ai_client.clone(),
        entity_manager.clone(),
    ));
    
    let agentic_orchestrator = Arc::new(scribe_backend::services::AgenticOrchestrator::new(
        test_app.ai_client.clone(),
        hybrid_query_service,
        Arc::new(test_app.db_pool.clone()),
        agentic_state_update_service.clone(),
    ));
    
    (world_model_service, agentic_orchestrator, agentic_state_update_service)
}

/// Helper to create a test user in the database
async fn create_test_user(test_app: &TestApp) -> AnyhowResult<(Uuid, SessionDek)> {
    let conn = test_app.db_pool.get().await?;
    
    let hashed_password = bcrypt::hash("testpassword", bcrypt::DEFAULT_COST)?;
    let username = format!("realtime_test_user_{}", Uuid::new_v4().simple());
    let email = format!("{}@test.com", username);
    
    // Generate proper crypto keys
    let kek_salt = scribe_backend::crypto::generate_salt()?;
    let dek = scribe_backend::crypto::generate_dek()?;
    
    let secret_password = secrecy::SecretString::new("testpassword".to_string().into());
    let kek = scribe_backend::crypto::derive_kek(&secret_password, &kek_salt)?;
    
    let (encrypted_dek, dek_nonce) = scribe_backend::crypto::encrypt_gcm(dek.expose_secret(), &kek)?;
    
    let new_user = NewUser {
        username,
        password_hash: hashed_password,
        email,
        kek_salt,
        encrypted_dek,
        encrypted_dek_by_recovery: None,
        role: UserRole::User,
        recovery_kek_salt: None,
        dek_nonce,
        recovery_dek_nonce: None,
        account_status: AccountStatus::Active,
    };
    
    let user_db: UserDbQuery = conn
        .interact(move |conn| {
            diesel::insert_into(users::table)
                .values(&new_user)
                .returning(UserDbQuery::as_returning())
                .get_result(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;
    
    let session_dek = SessionDek(SecretBox::new(Box::new(dek.expose_secret().to_vec())));
    Ok((user_db.id, session_dek))
}

// Helper to create a chat message with proper encryption
fn create_chat_message(
    user_id: Uuid,
    session_id: Uuid,
    role: MessageRole,
    content: &str,
    model_name: &str,
    session_dek: &SessionDek,
) -> AnyhowResult<ChatMessage> {
    // Encrypt the content properly
    let (encrypted_content, nonce) = scribe_backend::crypto::encrypt_gcm(
        content.as_bytes(),
        &session_dek.0,
    )?;
    
    Ok(ChatMessage {
        id: Uuid::new_v4(),
        session_id,
        message_type: role,
        content: encrypted_content,
        content_nonce: Some(nonce),
        created_at: Utc::now(),
        user_id,
        prompt_tokens: Some(content.len() as i32 / 4), // Rough estimate
        completion_tokens: if matches!(role, MessageRole::Assistant) { Some(20) } else { Some(0) },
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: model_name.to_string(),
    })
}

mod realtime_extraction_tests {
    use super::*;

    #[tokio::test]
    async fn test_realtime_event_extraction_during_progressive_chat() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
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
            "confidence": 0.85,
            "reasoning": "Treasure discovery is a significant narrative event that should be recorded",
            "actions": [
                {
                    "tool_name": "create_chronicle_event",
                    "parameters": {
                        "event_category": "WORLD",
                        "event_type": "DISCOVERY",
                        "event_subtype": "ITEM_ACQUISITION",
                        "subject": "Hero",
                        "summary": "Hero discovers ancient treasure in dungeon chest",
                        "event_data": {
                            "location": "Dungeon",
                            "action": "Treasure discovery",
                            "items": ["golden amulet", "ancient coins"]
                        }
                    },
                    "reasoning": "Document treasure discovery event"
                }
            ]
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service.clone(),
            test_app.qdrant_service.clone()
        ));
        
        // Create AppState for the test
        let services = scribe_backend::state::AppStateServices {
            ai_client: test_app.ai_client.clone(),
            embedding_client: test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            qdrant_service: test_app.qdrant_service.clone(),
            embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone() as Arc<dyn scribe_backend::services::embeddings::EmbeddingPipelineServiceTrait + Send + Sync>,
            chat_override_service: Arc::new(scribe_backend::services::chat_override_service::ChatOverrideService::new(
                test_app.db_pool.clone(),
                encryption_service.clone()
            )),
            user_persona_service: Arc::new(scribe_backend::services::user_persona_service::UserPersonaService::new(
                test_app.db_pool.clone(),
                encryption_service.clone()
            )),
            token_counter: Arc::new(scribe_backend::services::hybrid_token_counter::HybridTokenCounter::new(
                scribe_backend::services::tokenizer_service::TokenizerService::new(&test_app.config.tokenizer_model_path).unwrap_or_else(|_| {
                    panic!("Failed to create tokenizer for test")
                }),
                None,
                "gemini-2.5-pro"
            )),
            encryption_service: encryption_service.clone(),
            lorebook_service: lorebook_service.clone(),
            auth_backend: Arc::new(scribe_backend::auth::user_store::Backend::new(test_app.db_pool.clone())),
            file_storage_service: Arc::new(scribe_backend::services::file_storage_service::FileStorageService::new("test_files").unwrap()),
            email_service: scribe_backend::services::email_service::create_email_service("development", "http://localhost:3000".to_string(), None).await.unwrap(),
        // ECS Services - minimal test instances
        redis_client: Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
        feature_flags: Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
        ecs_entity_manager: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ))
        },
        ecs_graceful_degradation: Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
            Default::default(),
            Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
            None,
            None,
        )),
        ecs_enhanced_rag_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                degradation,
                concrete_embedding_service,
            ))
        },
        hybrid_query_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            let rag_service = Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                concrete_embedding_service,
            ));
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                rag_service,
                degradation,
            ))
        },
        // Chronicle ECS services for test
        chronicle_service: Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone())),
        chronicle_ecs_translator: Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
            Arc::new(test_app.db_pool.clone())
        )),
        chronicle_event_listener: {
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
            let chronicle_ecs_translator = Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
                Arc::new(test_app.db_pool.clone())
            ));
            Arc::new(scribe_backend::services::ChronicleEventListener::new(
                Default::default(),
                feature_flags,
                chronicle_ecs_translator,
                entity_manager,
                chronicle_service,
            ))
        },
        // Agentic services for test
        world_model_service: {
            let (world_model_service, _, _) = create_agentic_services(&test_app);
            world_model_service
        },
        agentic_state_update_service: {
            let (_, _, agentic_state_update_service) = create_agentic_services(&test_app);
            agentic_state_update_service
        },
        agentic_orchestrator: {
            let (_, agentic_orchestrator, _) = create_agentic_services(&test_app);
            agentic_orchestrator
        },
        };
        let app_state = Arc::new(scribe_backend::state::AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            services,
        ));
        
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service.clone(),
            lorebook_service,
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            app_state,
            None, // Use default config
        );

        // Simulate a progressive chat session with multiple message exchanges
        let messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I carefully examine the ancient chest I found in the dungeon.", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "The chest is ornate, covered in mystical runes that glow faintly blue. As you touch it, you hear a soft click - it's unlocked!", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I open the chest to see what's inside.", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "Inside, you discover a magnificent golden amulet and a pouch of ancient coins. But suddenly, you hear footsteps echoing through the dungeon!", "gemini-2.5-pro", &session_dek).unwrap(),
        ];

        // Run the agentic workflow - should detect significant events in real-time
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, Some(chronicle.id), &messages, &session_dek, None)
            .await;

        // Verify the workflow succeeded
        assert!(result.is_ok(), "Real-time extraction should succeed: {:?}", result.err());
        let workflow_result = result.unwrap();

        // Verify triage detected significance
        let triage = workflow_result.get("triage").expect("Should have triage section");
        assert!(triage.get("is_significant").and_then(|v| v.as_bool()).unwrap_or(false), 
                "Should detect significant treasure discovery");
        let confidence = triage.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);
        assert!(confidence > 0.7, "Should have high confidence: {}", confidence);

        // Verify execution occurred
        let execution = workflow_result.get("execution").expect("Should have execution section");
        assert!(execution.is_array() || execution.is_object(), "Should have execution results for real-time extraction");

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

        let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
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
            "confidence": 0.2,
            "reasoning": "Simple movement and casual conversation lacks narrative significance",
            "actions": []
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service.clone(),
            test_app.qdrant_service.clone()
        ));
        
        // Create AppState for the test
        let services = scribe_backend::state::AppStateServices {
            ai_client: test_app.ai_client.clone(),
            embedding_client: test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            qdrant_service: test_app.qdrant_service.clone(),
            embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone() as Arc<dyn scribe_backend::services::embeddings::EmbeddingPipelineServiceTrait + Send + Sync>,
            chat_override_service: Arc::new(scribe_backend::services::chat_override_service::ChatOverrideService::new(
                test_app.db_pool.clone(),
                encryption_service.clone()
            )),
            user_persona_service: Arc::new(scribe_backend::services::user_persona_service::UserPersonaService::new(
                test_app.db_pool.clone(),
                encryption_service.clone()
            )),
            token_counter: Arc::new(scribe_backend::services::hybrid_token_counter::HybridTokenCounter::new(
                scribe_backend::services::tokenizer_service::TokenizerService::new(&test_app.config.tokenizer_model_path).unwrap_or_else(|_| {
                    panic!("Failed to create tokenizer for test")
                }),
                None,
                "gemini-2.5-pro"
            )),
            encryption_service: encryption_service.clone(),
            lorebook_service: lorebook_service.clone(),
            auth_backend: Arc::new(scribe_backend::auth::user_store::Backend::new(test_app.db_pool.clone())),
            file_storage_service: Arc::new(scribe_backend::services::file_storage_service::FileStorageService::new("test_files").unwrap()),
            email_service: scribe_backend::services::email_service::create_email_service("development", "http://localhost:3000".to_string(), None).await.unwrap(),
        // ECS Services - minimal test instances
        redis_client: Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
        feature_flags: Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
        ecs_entity_manager: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ))
        },
        ecs_graceful_degradation: Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
            Default::default(),
            Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
            None,
            None,
        )),
        ecs_enhanced_rag_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                degradation,
                concrete_embedding_service,
            ))
        },
        hybrid_query_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            let rag_service = Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                concrete_embedding_service,
            ));
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                rag_service,
                degradation,
            ))
        },
        // Chronicle ECS services for test
        chronicle_service: Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone())),
        chronicle_ecs_translator: Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
            Arc::new(test_app.db_pool.clone())
        )),
        chronicle_event_listener: {
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
            let chronicle_ecs_translator = Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
                Arc::new(test_app.db_pool.clone())
            ));
            Arc::new(scribe_backend::services::ChronicleEventListener::new(
                Default::default(),
                feature_flags,
                chronicle_ecs_translator,
                entity_manager,
                chronicle_service,
            ))
        },
        // Agentic services for test
        world_model_service: {
            let (world_model_service, _, _) = create_agentic_services(&test_app);
            world_model_service
        },
        agentic_state_update_service: {
            let (_, _, agentic_state_update_service) = create_agentic_services(&test_app);
            agentic_state_update_service
        },
        agentic_orchestrator: {
            let (_, agentic_orchestrator, _) = create_agentic_services(&test_app);
            agentic_orchestrator
        },
        };
        let app_state = Arc::new(scribe_backend::state::AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            services,
        ));
        
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service.clone(),
            lorebook_service,
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            app_state,
            None, // Use default config
        );

        // Simulate mundane chat progression
        let mundane_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I walk down the corridor.", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "You walk down the stone corridor. The walls are lined with torches.", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "What do I see ahead?", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "The corridor continues straight ahead. You can see more torches lighting the way.", "gemini-2.5-pro", &session_dek).unwrap(),
        ];

        // Get initial event count
        let initial_events = chronicle_service.get_chronicle_events(user_id, chronicle.id, Default::default()).await.unwrap();
        let initial_count = initial_events.len();

        // Run the agentic workflow on mundane content
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, Some(chronicle.id), &mundane_messages, &session_dek, None)
            .await;

        // Verify the workflow succeeded but took no action
        assert!(result.is_ok(), "Real-time extraction should handle mundane chat gracefully");
        let workflow_result = result.unwrap();

        // Verify triage correctly identified as insignificant
        let triage = workflow_result.get("triage").expect("Should have triage section");
        assert!(!triage.get("is_significant").and_then(|v| v.as_bool()).unwrap_or(true), 
                "Should detect mundane chat as insignificant");
        assert!(triage.get("confidence").and_then(|v| v.as_f64()).unwrap_or(1.0) < 0.5, 
                "Should have low confidence for mundane chat");

        // For insignificant content, there should be no execution section or action_taken should be "none"
        if let Some(action) = workflow_result.get("action_taken") {
            assert_eq!(action.as_str().unwrap_or(""), "none", "Should not take action for mundane chat");
        }

        // Verify no new events were recorded
        let final_events = chronicle_service.get_chronicle_events(user_id, chronicle.id, Default::default()).await.unwrap();
        assert_eq!(final_events.len(), initial_count, "Should not add events for mundane chat");
    }

    #[tokio::test]
    async fn test_realtime_extraction_handles_rapid_message_sequence() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
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
            "confidence": 0.9,
            "reasoning": "Epic dragon combat with spell casting and weapon strikes is highly significant",
            "actions": [
                {
                    "tool_name": "create_chronicle_event",
                    "parameters": {
                        "event_category": "CHARACTER",
                        "event_type": "STATE_CHANGE",
                        "event_subtype": "COMBAT_ENCOUNTER",
                        "subject": "Hero",
                        "summary": "Hero defeats mighty dragon in epic battle using sword and lightning magic",
                        "event_data": {
                            "location": "Dragon's Lair",
                            "action": "Combat sequence",
                            "opponent": "Dragon",
                            "methods": ["sword strike", "lightning spell"],
                            "outcome": "Victory"
                        }
                    },
                    "reasoning": "Record the epic dragon battle outcome"
                }
            ]
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service.clone(),
            test_app.qdrant_service.clone()
        ));
        
        // Create AppState for the test
        let services = scribe_backend::state::AppStateServices {
            ai_client: test_app.ai_client.clone(),
            embedding_client: test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            qdrant_service: test_app.qdrant_service.clone(),
            embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone() as Arc<dyn scribe_backend::services::embeddings::EmbeddingPipelineServiceTrait + Send + Sync>,
            chat_override_service: Arc::new(scribe_backend::services::chat_override_service::ChatOverrideService::new(
                test_app.db_pool.clone(),
                encryption_service.clone()
            )),
            user_persona_service: Arc::new(scribe_backend::services::user_persona_service::UserPersonaService::new(
                test_app.db_pool.clone(),
                encryption_service.clone()
            )),
            token_counter: Arc::new(scribe_backend::services::hybrid_token_counter::HybridTokenCounter::new(
                scribe_backend::services::tokenizer_service::TokenizerService::new(&test_app.config.tokenizer_model_path).unwrap_or_else(|_| {
                    panic!("Failed to create tokenizer for test")
                }),
                None,
                "gemini-2.5-pro"
            )),
            encryption_service: encryption_service.clone(),
            lorebook_service: lorebook_service.clone(),
            auth_backend: Arc::new(scribe_backend::auth::user_store::Backend::new(test_app.db_pool.clone())),
            file_storage_service: Arc::new(scribe_backend::services::file_storage_service::FileStorageService::new("test_files").unwrap()),
            email_service: scribe_backend::services::email_service::create_email_service("development", "http://localhost:3000".to_string(), None).await.unwrap(),
        // ECS Services - minimal test instances
        redis_client: Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
        feature_flags: Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
        ecs_entity_manager: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ))
        },
        ecs_graceful_degradation: Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
            Default::default(),
            Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
            None,
            None,
        )),
        ecs_enhanced_rag_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                degradation,
                concrete_embedding_service,
            ))
        },
        hybrid_query_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            let rag_service = Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                concrete_embedding_service,
            ));
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                rag_service,
                degradation,
            ))
        },
        // Chronicle ECS services for test
        chronicle_service: Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone())),
        chronicle_ecs_translator: Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
            Arc::new(test_app.db_pool.clone())
        )),
        chronicle_event_listener: {
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
            let chronicle_ecs_translator = Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
                Arc::new(test_app.db_pool.clone())
            ));
            Arc::new(scribe_backend::services::ChronicleEventListener::new(
                Default::default(),
                feature_flags,
                chronicle_ecs_translator,
                entity_manager,
                chronicle_service,
            ))
        },
        // Agentic services for test
        world_model_service: {
            let (world_model_service, _, _) = create_agentic_services(&test_app);
            world_model_service
        },
        agentic_state_update_service: {
            let (_, _, agentic_state_update_service) = create_agentic_services(&test_app);
            agentic_state_update_service
        },
        agentic_orchestrator: {
            let (_, agentic_orchestrator, _) = create_agentic_services(&test_app);
            agentic_orchestrator
        },
        };
        let app_state = Arc::new(scribe_backend::state::AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            services,
        ));
        
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service.clone(),
            lorebook_service,
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            app_state,
            None, // Use default config
        );

        // Simulate rapid-fire combat sequence
        let rapid_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I draw my sword and attack the dragon!", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "Your blade strikes true! The dragon roars in fury and breathes fire at you!", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I dodge and cast a lightning spell!", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "Lightning crackles through the air! The dragon staggers, wounded but still dangerous!", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I press the attack with a final strike!", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "With a mighty blow, you defeat the dragon! It crashes to the ground, defeated!", "gemini-2.5-pro", &session_dek).unwrap(),
        ];

        // Run the agentic workflow on rapid sequence
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, Some(chronicle.id), &rapid_messages, &session_dek, None)
            .await;

        // Verify the workflow handled rapid sequence successfully
        assert!(result.is_ok(), "Real-time extraction should handle rapid message sequences: {:?}", result.err());
        let workflow_result = result.unwrap();

        // Verify significant combat was detected
        let triage = workflow_result.get("triage").expect("Should have triage section");
        assert!(triage.get("is_significant").and_then(|v| v.as_bool()).unwrap_or(false), "Should detect combat as significant");
        assert!(triage.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0) > 0.8, "Should have high confidence for combat");
        assert_eq!(triage.get("event_type").and_then(|v| v.as_str()).unwrap_or(""), "STATE_CHANGE", "Should identify as state change event");

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

        let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
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
            "confidence": 0.95,
            "reasoning": "Major character identity revelation is a crucial plot turning point",
            "actions": [
                {
                    "tool_name": "create_chronicle_event",
                    "parameters": {
                        "event_category": "PLOT",
                        "event_type": "REVELATION",
                        "event_subtype": "SECRET_REVELATION",
                        "subject": "Hero",
                        "summary": "Hero learns from wise sage that they are the lost prince of Eldoria",
                        "event_data": {
                            "location": "Sage's dwelling",
                            "action": "Identity revelation",
                            "revealed_identity": "Lost Prince of Eldoria",
                            "revealer": "Wise Sage",
                            "implications": "Rightful claim to throne"
                        }
                    },
                    "reasoning": "Document this major plot revelation about the hero's true identity"
                }
            ]
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service.clone(),
            test_app.qdrant_service.clone()
        ));
        
        // Create AppState for the test
        let services = scribe_backend::state::AppStateServices {
            ai_client: test_app.ai_client.clone(),
            embedding_client: test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            qdrant_service: test_app.qdrant_service.clone(),
            embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone() as Arc<dyn scribe_backend::services::embeddings::EmbeddingPipelineServiceTrait + Send + Sync>,
            chat_override_service: Arc::new(scribe_backend::services::chat_override_service::ChatOverrideService::new(
                test_app.db_pool.clone(),
                encryption_service.clone()
            )),
            user_persona_service: Arc::new(scribe_backend::services::user_persona_service::UserPersonaService::new(
                test_app.db_pool.clone(),
                encryption_service.clone()
            )),
            token_counter: Arc::new(scribe_backend::services::hybrid_token_counter::HybridTokenCounter::new(
                scribe_backend::services::tokenizer_service::TokenizerService::new(&test_app.config.tokenizer_model_path).unwrap_or_else(|_| {
                    panic!("Failed to create tokenizer for test")
                }),
                None,
                "gemini-2.5-pro"
            )),
            encryption_service: encryption_service.clone(),
            lorebook_service: lorebook_service.clone(),
            auth_backend: Arc::new(scribe_backend::auth::user_store::Backend::new(test_app.db_pool.clone())),
            file_storage_service: Arc::new(scribe_backend::services::file_storage_service::FileStorageService::new("test_files").unwrap()),
            email_service: scribe_backend::services::email_service::create_email_service("development", "http://localhost:3000".to_string(), None).await.unwrap(),
        // ECS Services - minimal test instances
        redis_client: Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
        feature_flags: Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
        ecs_entity_manager: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ))
        },
        ecs_graceful_degradation: Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
            Default::default(),
            Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
            None,
            None,
        )),
        ecs_enhanced_rag_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                degradation,
                concrete_embedding_service,
            ))
        },
        hybrid_query_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            let rag_service = Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                concrete_embedding_service,
            ));
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                rag_service,
                degradation,
            ))
        },
        // Chronicle ECS services for test
        chronicle_service: Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone())),
        chronicle_ecs_translator: Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
            Arc::new(test_app.db_pool.clone())
        )),
        chronicle_event_listener: {
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
            let chronicle_ecs_translator = Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
                Arc::new(test_app.db_pool.clone())
            ));
            Arc::new(scribe_backend::services::ChronicleEventListener::new(
                Default::default(),
                feature_flags,
                chronicle_ecs_translator,
                entity_manager,
                chronicle_service,
            ))
        },
        // Agentic services for test
        world_model_service: {
            let (world_model_service, _, _) = create_agentic_services(&test_app);
            world_model_service
        },
        agentic_state_update_service: {
            let (_, _, agentic_state_update_service) = create_agentic_services(&test_app);
            agentic_state_update_service
        },
        agentic_orchestrator: {
            let (_, agentic_orchestrator, _) = create_agentic_services(&test_app);
            agentic_orchestrator
        },
        };
        let app_state = Arc::new(scribe_backend::state::AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            services,
        ));
        
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service.clone(),
            lorebook_service,
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            app_state,
            None, // Use default config
        );

        // Simulate a conversation that builds up to a revelation
        let context_building_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I've been having strange dreams about a castle I've never seen before.", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "The wise sage looks at you with knowing eyes. 'Tell me more about these dreams, child.'", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "In the dreams, I see myself as a child in royal robes, but I was raised as a peasant.", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "The sage nods slowly. 'The time has come for you to learn the truth about your birth.'", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "What truth? Who am I really?", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                "'You are the lost prince of Eldoria, hidden away to protect you from those who usurped the throne!'", "gemini-2.5-pro", &session_dek).unwrap(),
        ];

        // Run the agentic workflow on the revelation sequence
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, Some(chronicle.id), &context_building_messages, &session_dek, None)
            .await;

        // Verify the workflow succeeded
        assert!(result.is_ok(), "Real-time extraction should handle context-building conversations: {:?}", result.err());
        let workflow_result = result.unwrap();

        // Verify the plot revelation was detected
        let triage = workflow_result.get("triage").expect("Should have triage section");
        assert!(triage.get("is_significant").and_then(|v| v.as_bool()).unwrap_or(false), 
                "Should detect plot revelation as significant");
        let confidence = triage.get("confidence").and_then(|v| v.as_f64()).unwrap_or(0.0);
        assert!(confidence > 0.9, "Should have very high confidence for major revelation");

        // Verify execution occurred
        let execution = workflow_result.get("execution").expect("Should have execution section");
        assert!(execution.is_array() || execution.is_object(), "Should execute actions for major plot revelation");

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

        let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
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
            "confidence": 0.88,
            "reasoning": "Massive battlefield conflict with kingdom's fate at stake is a major turning point",
            "actions": [
                {
                    "tool_name": "create_chronicle_event",
                    "parameters": {
                        "event_category": "PLOT",
                        "event_type": "TURNING_POINT",
                        "event_subtype": "PLOT_DEVELOPMENT",
                        "subject": "Alliance Forces",
                        "summary": "Epic battle unfolds with alliance forces clashing against dark army in climactic confrontation",
                        "event_data": {
                            "location": "Massive Battlefield",
                            "action": "Epic battle",
                            "participants": ["Sir Gareth", "Lady Elara", "Captain Marcus", "Player"],
                            "enemies": ["Dark creatures", "Massive troll"],
                            "stakes": "Kingdom's fate"
                        }
                    },
                    "reasoning": "Record the climactic battle that determines the kingdom's fate"
                }
            ]
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(), 
            encryption_service.clone(),
            test_app.qdrant_service.clone()
        ));
        
        // Create AppState for the test
        let services = scribe_backend::state::AppStateServices {
            ai_client: test_app.ai_client.clone(),
            embedding_client: test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            qdrant_service: test_app.qdrant_service.clone(),
            embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone() as Arc<dyn scribe_backend::services::embeddings::EmbeddingPipelineServiceTrait + Send + Sync>,
            chat_override_service: Arc::new(scribe_backend::services::chat_override_service::ChatOverrideService::new(
                test_app.db_pool.clone(),
                encryption_service.clone()
            )),
            user_persona_service: Arc::new(scribe_backend::services::user_persona_service::UserPersonaService::new(
                test_app.db_pool.clone(),
                encryption_service.clone()
            )),
            token_counter: Arc::new(scribe_backend::services::hybrid_token_counter::HybridTokenCounter::new(
                scribe_backend::services::tokenizer_service::TokenizerService::new(&test_app.config.tokenizer_model_path).unwrap_or_else(|_| {
                    panic!("Failed to create tokenizer for test")
                }),
                None,
                "gemini-2.5-pro"
            )),
            encryption_service: encryption_service.clone(),
            lorebook_service: lorebook_service.clone(),
            auth_backend: Arc::new(scribe_backend::auth::user_store::Backend::new(test_app.db_pool.clone())),
            file_storage_service: Arc::new(scribe_backend::services::file_storage_service::FileStorageService::new("test_files").unwrap()),
            email_service: scribe_backend::services::email_service::create_email_service("development", "http://localhost:3000".to_string(), None).await.unwrap(),
        // ECS Services - minimal test instances
        redis_client: Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
        feature_flags: Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
        ecs_entity_manager: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ))
        },
        ecs_graceful_degradation: Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
            Default::default(),
            Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
            None,
            None,
        )),
        ecs_enhanced_rag_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                degradation,
                concrete_embedding_service,
            ))
        },
        hybrid_query_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            let rag_service = Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                concrete_embedding_service,
            ));
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                rag_service,
                degradation,
            ))
        },
        // Chronicle ECS services for test
        chronicle_service: Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone())),
        chronicle_ecs_translator: Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
            Arc::new(test_app.db_pool.clone())
        )),
        chronicle_event_listener: {
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
            let chronicle_ecs_translator = Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
                Arc::new(test_app.db_pool.clone())
            ));
            Arc::new(scribe_backend::services::ChronicleEventListener::new(
                Default::default(),
                feature_flags,
                chronicle_ecs_translator,
                entity_manager,
                chronicle_service,
            ))
        },
        // Agentic services for test
        world_model_service: {
            let (world_model_service, _, _) = create_agentic_services(&test_app);
            world_model_service
        },
        agentic_state_update_service: {
            let (_, _, agentic_state_update_service) = create_agentic_services(&test_app);
            agentic_state_update_service
        },
        agentic_orchestrator: {
            let (_, agentic_orchestrator, _) = create_agentic_services(&test_app);
            agentic_orchestrator
        },
        };
        let app_state = Arc::new(scribe_backend::state::AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            services,
        ));
        
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service.clone(),
            lorebook_service,
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            app_state,
            None, // Use default config
        );

        // Create long detailed messages (simulating verbose RP)
        let long_content = "The massive battlefield stretches before you, with thousands of warriors clashing in epic combat. Knights in shining armor clash with dark creatures emerging from shadow portals. Magic crackles through the air as wizards on both sides cast powerful spells. You see your allies fighting valiantly - Sir Gareth defending a group of villagers, Lady Elara weaving protective barriers around the wounded, and Captain Marcus leading a charge against a massive troll. The fate of the kingdom hangs in the balance as you prepare to make your move in this climactic battle.".repeat(3);

        let long_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User, 
                "I survey the battlefield and prepare for the final confrontation.", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant, 
                &long_content, "gemini-2.5-pro", &session_dek).unwrap(),
        ];

        // Measure extraction time
        let start_time = std::time::Instant::now();
        
        let result = agent_runner
            .process_narrative_event(user_id, chat_session_id, Some(chronicle.id), &long_messages, &session_dek, None)
            .await;
        
        let extraction_time = start_time.elapsed();

        // Verify the workflow succeeded and performed reasonably
        assert!(result.is_ok(), "Real-time extraction should handle long messages: {:?}", result.err());
        assert!(extraction_time.as_secs() < 30, "Extraction should complete within reasonable time: {:?}", extraction_time);

        let workflow_result = result.unwrap();

        // Verify the epic battle was detected despite length
        let triage = workflow_result.get("triage").expect("Should have triage section");
        assert!(triage.get("is_significant").and_then(|v| v.as_bool()).unwrap_or(false), "Should detect epic battle as significant");
        assert_eq!(triage.get("event_type").and_then(|v| v.as_str()).unwrap_or(""), "TURNING_POINT", "Should identify as turning point event");

        // Verify events were recorded
        let events = chronicle_service.get_chronicle_events(user_id, chronicle.id, Default::default()).await.unwrap();
        assert!(!events.is_empty(), "Should have recorded events despite long content");
    }
}