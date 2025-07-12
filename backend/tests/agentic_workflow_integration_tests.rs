// backend/tests/agentic_workflow_integration_tests.rs
//
// Integration tests for the complete agentic narrative workflow using mock AI responses.
// Tests the end-to-end flow from chat messages through AI analysis to tool execution.

use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;
use secrecy::SecretBox;

use scribe_backend::{
    config::{NarrativeFeatureFlags, ExtractionMode},
    llm::EmbeddingClient,
    models::chats::{ChatMessage, MessageRole},
    services::{
        agentic::AgenticNarrativeFactory,
        extraction_dispatcher::ExtractionDispatcher,
        ChronicleService, LorebookService, EncryptionService,
    },
    test_helpers::{spawn_app, MockAiClient, TestDataGuard, db::create_test_user},
    auth::session_dek::SessionDek,
};

#[tokio::test]
async fn test_complete_agentic_workflow_with_mock_responses() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    let user_id = user.id;
    let session_id = Uuid::new_v4();

    // Configure mock AI client with combined triage and planning response
    let combined_response = json!({
        "is_significant": true,
        "summary": "User introduces new character Alex and starts adventure",
        "event_category": "PLOT", 
        "event_type": "DEVELOPMENT",
        "narrative_action": "BEGAN",
        "primary_agent": "Alex",
        "primary_patient": "Adventure",
        "confidence": 0.85,
        "reasoning": "New adventure beginning with character introduction should be recorded in both chronicle and lorebook",
        "actions": [
            {
                "tool_name": "create_chronicle_event",
                "parameters": {
                    "event_category": "PLOT",
                    "event_type": "DEVELOPMENT",
                    "event_subtype": "QUEST_PROGRESS",
                    "subject": "Alex",
                    "summary": "Alex begins a new adventure at the magical academy",
                    "event_data": {
                        "location": "magical academy",
                        "action": "adventure start",
                        "character": "Alex"
                    }
                },
                "reasoning": "Record the beginning of Alex's adventure"
            },
            {
                "tool_name": "create_lorebook_entry", 
                "parameters": {
                    "name": "Alex the Wizard",
                    "content": "A young wizard starting their journey at the magical academy",
                    "keywords": "Alex wizard young academy",
                    "tags": ["character", "wizard", "main"]
                },
                "reasoning": "Create lorebook entry for the main character Alex"
            }
        ]
    });

    let mock_ai_client = Arc::new(MockAiClient::new_with_response(combined_response.to_string()));

    // Create agentic system with mock AI client using the same pattern as working tests
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let encryption_service = Arc::new(EncryptionService::new());
    let lorebook_service = Arc::new(LorebookService::new(
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
        world_model_service: Arc::new(scribe_backend::services::WorldModelService::new(
            Arc::new(test_app.db_pool.clone()),
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            )),
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                    None,
                )),
                Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                    Arc::new(test_app.db_pool.clone()),
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    Arc::new(scribe_backend::services::EcsEntityManager::new(
                        Arc::new(test_app.db_pool.clone()),
                        Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                        None,
                    )),
                    Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                        Default::default(),
                        Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                        None,
                        None,
                    )),
                    Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                        scribe_backend::text_processing::chunking::ChunkConfig {
                            metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                            max_size: 500,
                            overlap: 50,
                        }
                    )),
                )),
                Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    None,
                    None,
                )),
            )),
            Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone())),
        )),
        agentic_orchestrator: Arc::new(scribe_backend::services::AgenticOrchestrator::new(
            test_app.ai_client.clone(),
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                    None,
                )),
                Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                    Arc::new(test_app.db_pool.clone()),
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    Arc::new(scribe_backend::services::EcsEntityManager::new(
                        Arc::new(test_app.db_pool.clone()),
                        Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                        None,
                    )),
                    Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                        Default::default(),
                        Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                        None,
                        None,
                    )),
                    Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                        scribe_backend::text_processing::chunking::ChunkConfig {
                            metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                            max_size: 500,
                            overlap: 50,
                        }
                    )),
                )),
                Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    None,
                    None,
                )),
            )),
            Arc::new(test_app.db_pool.clone()),
            Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                    None,
                )),
            )),
        )),
        agentic_state_update_service: Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(
            test_app.ai_client.clone(),
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            )),
        )),
    };
    let app_state = Arc::new(scribe_backend::state::AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ));
    
    let agentic_runner = AgenticNarrativeFactory::create_system_with_deps(
        mock_ai_client.clone(),
        chronicle_service.clone(),
        lorebook_service,
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
        app_state,
        None, // Use default config
    );

    // Create test chat messages representing a new adventure
    let messages = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "Hello! I want to start a new adventure where I play as a young wizard named Alex.".as_bytes().to_vec(),
            content_nonce: Some(vec![1, 2, 3, 4]),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(20),
            completion_tokens: Some(0),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        },
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::Assistant,
            content: "Welcome, Alex! You find yourself at the entrance to an ancient magical academy...".as_bytes().to_vec(),
            content_nonce: Some(vec![5, 6, 7, 8]),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(0),
            completion_tokens: Some(25),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        },
    ];

    // Create session DEK for testing
    use secrecy::SecretBox;
    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

    // Run the agentic workflow
    let result = agentic_runner.process_narrative_content(
        &messages,
        &session_dek,
        user_id,
        None, // No existing chronicle
        None, // No persona context
        false, // Not re-chronicle
        "integration_test_context",
    ).await;

    // Verify the workflow completed successfully
    assert!(result.is_ok(), "Agentic workflow should complete successfully");
    let workflow_result = result.unwrap();

    // Verify triage detected significance
    let triage = workflow_result.get("triage").expect("Should have triage section");
    assert!(triage.get("is_significant").and_then(|v| v.as_bool()).unwrap_or(false), 
            "Triage should detect significant events");
    
    // Verify execution occurred
    let execution = workflow_result.get("execution").expect("Should have execution section");
    assert!(execution.is_array() || execution.is_object(), "Should have execution results");

    println!("✓ Complete agentic workflow test passed");
}

#[tokio::test]
async fn test_extraction_dispatcher_with_agentic_mode() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user2".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    let user_id = user.id;
    let session_id = Uuid::new_v4();

    // Create feature flags for agentic mode
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_agentic_extraction = true;
    feature_flags.agentic_rollout_percentage = 100; // Enable for all users
    feature_flags.enable_realtime_extraction = true;

    // Configure mock AI client
    let triage_response = json!({
        "is_significant": true,
        "summary": "Dialogue contains important character development",
        "event_category": "DIALOGUE",
        "event_type": "CHARACTER_DEVELOPMENT",
        "narrative_action": "SPOKE",
        "primary_agent": "Alex",
        "confidence": 0.9
    });

    let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

    // Create agentic system using the same pattern as working tests
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let encryption_service = Arc::new(EncryptionService::new());
    let lorebook_service = Arc::new(LorebookService::new(
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
        world_model_service: Arc::new(scribe_backend::services::WorldModelService::new(
            Arc::new(test_app.db_pool.clone()),
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            )),
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                    None,
                )),
                Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                    Arc::new(test_app.db_pool.clone()),
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    Arc::new(scribe_backend::services::EcsEntityManager::new(
                        Arc::new(test_app.db_pool.clone()),
                        Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                        None,
                    )),
                    Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                        Default::default(),
                        Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                        None,
                        None,
                    )),
                    Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                        scribe_backend::text_processing::chunking::ChunkConfig {
                            metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                            max_size: 500,
                            overlap: 50,
                        }
                    )),
                )),
                Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    None,
                    None,
                )),
            )),
            Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone())),
        )),
        agentic_orchestrator: Arc::new(scribe_backend::services::AgenticOrchestrator::new(
            test_app.ai_client.clone(),
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                    None,
                )),
                Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                    Arc::new(test_app.db_pool.clone()),
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    Arc::new(scribe_backend::services::EcsEntityManager::new(
                        Arc::new(test_app.db_pool.clone()),
                        Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                        None,
                    )),
                    Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                        Default::default(),
                        Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                        None,
                        None,
                    )),
                    Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                        scribe_backend::text_processing::chunking::ChunkConfig {
                            metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                            max_size: 500,
                            overlap: 50,
                        }
                    )),
                )),
                Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    None,
                    None,
                )),
            )),
            Arc::new(test_app.db_pool.clone()),
            Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                    None,
                )),
            )),
        )),
        agentic_state_update_service: Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(
            test_app.ai_client.clone(),
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            )),
        )),
    };
    let app_state = Arc::new(scribe_backend::state::AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ));
    
    let agentic_runner = AgenticNarrativeFactory::create_system_with_deps(
        mock_ai_client.clone(),
        chronicle_service.clone(),
        lorebook_service,
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
        app_state,
        None, // Use default config
    );

    // Create extraction dispatcher
    let dispatcher = ExtractionDispatcher::new(
        Arc::new(feature_flags),
        Some(Arc::new(agentic_runner)),
    );

    // Create test messages
    let messages = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "Alex looks around the magical academy courtyard nervously.".as_bytes().to_vec(),
            content_nonce: Some(vec![1, 2, 3, 4]),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(15),
            completion_tokens: Some(0),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        },
    ];

    // Create session DEK for testing
    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

    // Run extraction through dispatcher
    let result = dispatcher.extract_events_from_chat(
        user_id,
        session_id,
        None,
        &messages,
        &session_dek,
    ).await;

    // Verify extraction succeeded
    assert!(result.is_ok(), "Extraction should succeed through dispatcher");
    let extraction_result = result.unwrap();

    assert!(extraction_result.success, "Extraction should be successful");
    assert_eq!(extraction_result.mode_used, ExtractionMode::AgenticOnly);
    assert!(extraction_result.duration_ms > 0, "Should have measurable duration");
    assert!(extraction_result.ai_calls_made > 0, "Should have made AI calls");

    println!("✓ Extraction dispatcher agentic mode test passed");
}

#[tokio::test]
async fn test_dual_mode_extraction_comparison() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user3".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    let user_id = user.id;
    let session_id = Uuid::new_v4();

    // Create feature flags for dual mode
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_agentic_extraction = true;
    feature_flags.dual_extraction_mode = true;
    feature_flags.agentic_rollout_percentage = 100;
    feature_flags.enable_extraction_metrics = true;

    // Configure mock AI client for agentic extraction
    let triage_response = json!({
        "is_significant": false,
        "summary": "Just casual dialogue, no significant events",
        "event_category": "DIALOGUE",
        "event_type": "CASUAL_CONVERSATION",
        "narrative_action": "SPOKE",
        "confidence": 0.3
    });

    let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

    // Create agentic system using the same pattern as working tests
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let encryption_service = Arc::new(EncryptionService::new());
    let lorebook_service = Arc::new(LorebookService::new(
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
        world_model_service: Arc::new(scribe_backend::services::WorldModelService::new(
            Arc::new(test_app.db_pool.clone()),
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            )),
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                    None,
                )),
                Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                    Arc::new(test_app.db_pool.clone()),
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    Arc::new(scribe_backend::services::EcsEntityManager::new(
                        Arc::new(test_app.db_pool.clone()),
                        Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                        None,
                    )),
                    Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                        Default::default(),
                        Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                        None,
                        None,
                    )),
                    Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                        scribe_backend::text_processing::chunking::ChunkConfig {
                            metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                            max_size: 500,
                            overlap: 50,
                        }
                    )),
                )),
                Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    None,
                    None,
                )),
            )),
            Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone())),
        )),
        agentic_orchestrator: Arc::new(scribe_backend::services::AgenticOrchestrator::new(
            test_app.ai_client.clone(),
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                    None,
                )),
                Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                    Arc::new(test_app.db_pool.clone()),
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    Arc::new(scribe_backend::services::EcsEntityManager::new(
                        Arc::new(test_app.db_pool.clone()),
                        Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                        None,
                    )),
                    Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                        Default::default(),
                        Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                        None,
                        None,
                    )),
                    Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                        scribe_backend::text_processing::chunking::ChunkConfig {
                            metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                            max_size: 500,
                            overlap: 50,
                        }
                    )),
                )),
                Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    None,
                    None,
                )),
            )),
            Arc::new(test_app.db_pool.clone()),
            Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                    None,
                )),
            )),
        )),
        agentic_state_update_service: Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(
            test_app.ai_client.clone(),
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            )),
        )),
    };
    let app_state = Arc::new(scribe_backend::state::AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ));
    
    let agentic_runner = AgenticNarrativeFactory::create_system_with_deps(
        mock_ai_client.clone(),
        chronicle_service.clone(),
        lorebook_service,
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
        app_state,
        None, // Use default config
    );

    // Create extraction dispatcher with dual mode
    let dispatcher = ExtractionDispatcher::new(
        Arc::new(feature_flags),
        Some(Arc::new(agentic_runner)),
    );

    // Create test messages (mundane conversation)
    let messages = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
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
            session_id,
            message_type: MessageRole::Assistant,
            content: "I'm doing well, thank you for asking!".as_bytes().to_vec(),
            content_nonce: Some(vec![5, 6, 7, 8]),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(0),
            completion_tokens: Some(10),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        },
    ];

    // Create session DEK for testing
    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

    // Run dual mode extraction
    let result = dispatcher.extract_events_from_chat(
        user_id,
        session_id,
        None,
        &messages,
        &session_dek,
    ).await;

    // Verify dual mode ran (even though manual is placeholder)
    assert!(result.is_ok(), "Dual mode extraction should complete");
    let extraction_result = result.unwrap();

    // In dual mode, should return agentic result if it succeeded
    assert_eq!(extraction_result.mode_used, ExtractionMode::AgenticOnly);
    assert!(extraction_result.success, "Agentic extraction should succeed");

    println!("✓ Dual mode extraction comparison test passed");
}

#[tokio::test]
async fn test_agentic_workflow_with_json_parsing_failure() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user4".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    let user_id = user.id;
    let session_id = Uuid::new_v4();

    // Create feature flags with very short timeout
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_agentic_extraction = true;
    feature_flags.agentic_rollout_percentage = 100;
    feature_flags.agentic_extraction_timeout_secs = 1; // Very short timeout
    feature_flags.fallback_to_manual_on_error = true;

    // Configure mock AI client with default response that causes JSON parsing failure
    let mock_ai_client = Arc::new(MockAiClient::new()); // Returns "Mock AI response" - not valid JSON

    // Create agentic system using the same pattern as working tests
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let encryption_service = Arc::new(EncryptionService::new());
    let lorebook_service = Arc::new(LorebookService::new(
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
        world_model_service: Arc::new(scribe_backend::services::WorldModelService::new(
            Arc::new(test_app.db_pool.clone()),
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            )),
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                    None,
                )),
                Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                    Arc::new(test_app.db_pool.clone()),
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    Arc::new(scribe_backend::services::EcsEntityManager::new(
                        Arc::new(test_app.db_pool.clone()),
                        Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                        None,
                    )),
                    Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                        Default::default(),
                        Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                        None,
                        None,
                    )),
                    Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                        scribe_backend::text_processing::chunking::ChunkConfig {
                            metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                            max_size: 500,
                            overlap: 50,
                        }
                    )),
                )),
                Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    None,
                    None,
                )),
            )),
            Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone())),
        )),
        agentic_orchestrator: Arc::new(scribe_backend::services::AgenticOrchestrator::new(
            test_app.ai_client.clone(),
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                    None,
                )),
                Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                    Arc::new(test_app.db_pool.clone()),
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    Arc::new(scribe_backend::services::EcsEntityManager::new(
                        Arc::new(test_app.db_pool.clone()),
                        Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                        None,
                    )),
                    Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                        Default::default(),
                        Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                        None,
                        None,
                    )),
                    Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                        scribe_backend::text_processing::chunking::ChunkConfig {
                            metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                            max_size: 500,
                            overlap: 50,
                        }
                    )),
                )),
                Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                    Default::default(),
                    Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                    None,
                    None,
                )),
            )),
            Arc::new(test_app.db_pool.clone()),
            Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                    None,
                )),
            )),
        )),
        agentic_state_update_service: Arc::new(scribe_backend::services::agentic_state_update_service::AgenticStateUpdateService::new(
            test_app.ai_client.clone(),
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            )),
        )),
    };
    let app_state = Arc::new(scribe_backend::state::AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ));
    
    let agentic_runner = AgenticNarrativeFactory::create_system_with_deps(
        mock_ai_client.clone(),
        chronicle_service.clone(),
        lorebook_service,
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
        app_state,
        None, // Use default config
    );

    // Create extraction dispatcher
    let dispatcher = ExtractionDispatcher::new(
        Arc::new(feature_flags),
        Some(Arc::new(agentic_runner)),
    );

    // Create test messages
    let messages = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "This should cause JSON parsing failure".as_bytes().to_vec(),
            content_nonce: Some(vec![1, 2, 3, 4]),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(5),
            completion_tokens: Some(0),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        },
    ];

    // Create session DEK for testing
    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

    // Run extraction (should fail due to JSON parsing error in mock AI response)
    let result = dispatcher.extract_events_from_chat(
        user_id,
        session_id,
        None,
        &messages,
        &session_dek,
    ).await;

    // Currently, JSON parsing errors cause the entire extraction to fail
    // This demonstrates a limitation where only timeouts trigger fallback, not other errors
    assert!(result.is_err(), "Should fail due to JSON parsing error in mock AI response");
    let error = result.unwrap_err();
    assert!(error.to_string().contains("Failed to parse structured response"), "Error should mention JSON parsing failure");

    println!("✓ Agentic workflow JSON parsing failure test passed");
}

#[tokio::test]
async fn test_feature_flag_user_rollout() {
    let _test_app = spawn_app(false, false, false).await;

    // Test user not in rollout (0% rollout)
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_agentic_extraction = true;
    feature_flags.agentic_rollout_percentage = 0; // No users get agentic

    let dispatcher = ExtractionDispatcher::new(
        Arc::new(feature_flags.clone()),
        None, // No agentic runner needed for this test
    );

    assert!(!dispatcher.should_enable_realtime_extraction("test_user_1"));
    assert!(!dispatcher.should_enable_auto_lorebook_creation("test_user_1"));
    assert!(!dispatcher.should_enable_auto_chronicle_creation("test_user_1"));

    // Test user in 100% rollout
    feature_flags.agentic_rollout_percentage = 100;
    feature_flags.enable_realtime_extraction = true;
    feature_flags.enable_auto_lorebook_creation = true;
    feature_flags.enable_auto_chronicle_creation = true;

    let dispatcher = ExtractionDispatcher::new(
        Arc::new(feature_flags.clone()),
        None,
    );

    assert!(dispatcher.should_enable_realtime_extraction("test_user_1"));
    assert!(dispatcher.should_enable_auto_lorebook_creation("test_user_1"));
    assert!(dispatcher.should_enable_auto_chronicle_creation("test_user_1"));

    // Test force enable user
    feature_flags.agentic_rollout_percentage = 0;
    feature_flags.force_enable_users = vec!["special_user".to_string()];

    let dispatcher = ExtractionDispatcher::new(
        Arc::new(feature_flags),
        None,
    );

    assert!(!dispatcher.should_enable_realtime_extraction("regular_user"));
    assert!(dispatcher.should_enable_realtime_extraction("special_user"));

    println!("✓ Feature flag user rollout test passed");
}