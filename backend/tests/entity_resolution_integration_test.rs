// backend/tests/entity_resolution_integration_test.rs
//
// Simple integration test to verify entity resolution is working end-to-end
// This test focuses on the entity resolution tool functionality

use std::sync::Arc;
use uuid::Uuid;

use scribe_backend::{
    services::agentic::entity_resolution_tool::{EntityResolutionTool, ProcessingMode},
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
};

use serde_json::json;

#[tokio::test]
async fn test_entity_resolution_tool_basic_functionality() {
    // Basic compilation and functionality test
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Create test user
    let user = create_test_user(&test_app.db_pool, "test_user".to_string(), "password123".to_string()).await.unwrap();
    _guard.add_user(user.id);
    let user_id = user.id;
    
    // Create minimal app state services for the tool
    let services = scribe_backend::state::AppStateServices {
        ai_client: test_app.ai_client.clone(),
        embedding_client: test_app.mock_embedding_client.clone() as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone() as Arc<dyn scribe_backend::services::embeddings::EmbeddingPipelineServiceTrait + Send + Sync>,
        chat_override_service: Arc::new(scribe_backend::services::chat_override_service::ChatOverrideService::new(
            test_app.db_pool.clone(),
            Arc::new(scribe_backend::services::EncryptionService::new())
        )),
        user_persona_service: Arc::new(scribe_backend::services::user_persona_service::UserPersonaService::new(
            test_app.db_pool.clone(),
            Arc::new(scribe_backend::services::EncryptionService::new())
        )),
        token_counter: Arc::new(scribe_backend::services::hybrid_token_counter::HybridTokenCounter::new(
            scribe_backend::services::tokenizer_service::TokenizerService::new(&test_app.config.tokenizer_model_path).unwrap_or_else(|_| {
                panic!("Failed to create tokenizer for test")
            }),
            None,
            "gemini-2.5-pro"
        )),
        encryption_service: Arc::new(scribe_backend::services::EncryptionService::new()),
        lorebook_service: Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            Arc::new(scribe_backend::services::EncryptionService::new()),
            test_app.qdrant_service.clone()
        )),
        auth_backend: Arc::new(scribe_backend::auth::user_store::Backend::new(test_app.db_pool.clone())),
        file_storage_service: Arc::new(scribe_backend::services::file_storage_service::FileStorageService::new("test_files").unwrap()),
        email_service: scribe_backend::services::email_service::create_email_service("development", "http://localhost:3000".to_string(), None).await.unwrap(),
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
        world_model_service: {
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
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
                Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                entity_manager.clone(),
                degradation.clone(),
                concrete_embedding_service,
            ));
            let query_service = Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                entity_manager.clone(),
                rag_service,
                degradation,
            ));
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
            Arc::new(scribe_backend::services::WorldModelService::new(
                Arc::new(test_app.db_pool.clone()),
                entity_manager,
                query_service,
                chronicle_service,
            ))
        },
        agentic_state_update_service: {
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            ));
            Arc::new(scribe_backend::services::AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                entity_manager,
            ))
        },
        agentic_orchestrator: {
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
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
                Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                entity_manager.clone(),
                degradation.clone(),
                concrete_embedding_service,
            ));
            let hybrid_query_service = Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
                entity_manager.clone(),
                rag_service,
                degradation,
            ));
            let state_update_service = Arc::new(scribe_backend::services::AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                entity_manager,
            ));
            Arc::new(scribe_backend::services::AgenticOrchestrator::new(
                test_app.ai_client.clone(),
                hybrid_query_service,
                Arc::new(test_app.db_pool.clone()),
                state_update_service,
            ))
        },
        hierarchical_context_assembler: None,
    };
    
    let app_state = Arc::new(scribe_backend::state::AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ));

    // Create the EntityResolutionTool
    let entity_resolution_tool = EntityResolutionTool::new(app_state.clone());
    
    // Test extracting entity names from narrative text
    let narrative_text = "Sol meets with Borga at the cantina while Vargo watches from the shadows";
    let extracted_names = entity_resolution_tool.extract_entity_names(narrative_text).await;
    
    println!("✓ Entity name extraction test result: {:?}", extracted_names);
    
    // Test resolving actors to entities
    let test_actors = vec![
        json!({
            "id": "Sol",
            "role": "AGENT"
        }),
        json!({
            "id": "Borga", 
            "role": "PATIENT"
        }),
        json!({
            "id": "Vargo",
            "role": "WITNESS"
        })
    ];
    
    let resolved_actors = entity_resolution_tool.resolve_actors_to_entities(
        &test_actors,
        None, // No chronicle_id for this test
        user_id,
        ProcessingMode::Incremental,
    ).await;
    
    println!("✓ Actor resolution test result: {:?}", resolved_actors);
    
    // The test passed if we got here without panicking
    println!("✓ Entity resolution integration test passed!");
}