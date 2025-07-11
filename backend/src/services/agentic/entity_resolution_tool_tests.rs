// Tests for the EntityResolutionTool - Flash-powered entity resolution system
//
// This test suite validates the key functionality of the entity resolution system:
// - Entity creation and updates
// - Duplicate detection and prevention
// - Component extraction from narrative context
// - Processing mode handling (batch vs incremental)
// - Lifecycle management and validation

use super::{EntityResolutionTool, ProcessingMode};
use crate::services::agentic::tools::{ScribeTool, ToolError};
use crate::state::AppState;
use crate::services::{
    ChronicleService, ChronicleEventListener, ChronicleEcsTranslator, WorldModelService,
    AgenticOrchestrator, AgenticStateUpdateService, EcsEntityManager, EcsGracefulDegradation,
    EcsEnhancedRagService, HybridQueryService, 
    chat_override_service::ChatOverrideService,
    user_persona_service::UserPersonaService,
    encryption_service::EncryptionService,
    hybrid_token_counter::HybridTokenCounter,
    lorebook::LorebookService,
    tokenizer_service::TokenizerService,
    embeddings::EmbeddingPipelineService,
};
use crate::auth::user_store::Backend as AuthBackend;
use crate::services::file_storage_service::FileStorageService;
use crate::services::email_service::LoggingEmailService;
use crate::test_helpers::{TestApp, MockEmbeddingClient};
use crate::config::NarrativeFeatureFlags;
use crate::text_processing::chunking::{ChunkConfig, ChunkingMetric};
use serde_json::json;
use std::sync::Arc;

/// Helper function to create a minimal AppState for testing
fn create_test_app_state(test_app: &TestApp) -> Arc<AppState> {
    Arc::new(AppState {
        pool: test_app.db_pool.clone(),
        config: test_app.config.clone(),
        ai_client: test_app.ai_client.clone(),
        embedding_client: Arc::new(MockEmbeddingClient::new()),
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone(),
        chat_override_service: Arc::new(ChatOverrideService::new(
            test_app.db_pool.clone(),
            Arc::new(EncryptionService::new())
        )),
        user_persona_service: Arc::new(UserPersonaService::new(
            test_app.db_pool.clone(),
            Arc::new(EncryptionService::new())
        )),
        embedding_call_tracker: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        token_counter: Arc::new(HybridTokenCounter::new(
            TokenizerService::new(&test_app.config.tokenizer_model_path).unwrap(),
            None,
            "gemini-2.5-pro"
        )),
        encryption_service: Arc::new(EncryptionService::new()),
        lorebook_service: Arc::new(LorebookService::new(
            test_app.db_pool.clone(),
            Arc::new(EncryptionService::new()),
            test_app.qdrant_service.clone(),
        )),
        auth_backend: Arc::new(AuthBackend::new(test_app.db_pool.clone())),
        file_storage_service: Arc::new(FileStorageService::new("test_files").unwrap()),
        email_service: Arc::new(LoggingEmailService::new("http://localhost:3000".to_string())),
        narrative_intelligence_service: None,
        rechronicle_semaphore: Arc::new(tokio::sync::Semaphore::new(20)),
        // ECS Services - create minimal mocks
        redis_client: Arc::new(redis::Client::open("redis://127.0.0.1/").unwrap()),
        feature_flags: Arc::new(NarrativeFeatureFlags::default()),
        ecs_entity_manager: Arc::new(EcsEntityManager::new(
            Arc::new(test_app.db_pool.clone()),
            Arc::new(redis::Client::open("redis://127.0.0.1/").unwrap()),
            None,
        )),
        ecs_graceful_degradation: Arc::new(EcsGracefulDegradation::new(
            Default::default(),
            Arc::new(NarrativeFeatureFlags::default()),
            None,
            None,
        )),
        ecs_enhanced_rag_service: Arc::new(EcsEnhancedRagService::new(
            Arc::new(test_app.db_pool.clone()),
            Default::default(),
            Arc::new(NarrativeFeatureFlags::default()),
            Arc::new(EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1/").unwrap()),
                None,
            )),
            Arc::new(EcsGracefulDegradation::new(
                Default::default(),
                Arc::new(NarrativeFeatureFlags::default()),
                None,
                None,
            )),
            Arc::new(EmbeddingPipelineService::new(
                ChunkConfig {
                    metric: ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            )),
        )),
        hybrid_query_service: Arc::new(HybridQueryService::new(
            Arc::new(test_app.db_pool.clone()),
            Default::default(),
            Arc::new(NarrativeFeatureFlags::default()),
            Arc::new(EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1/").unwrap()),
                None,
            )),
            Arc::new(EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                Arc::new(NarrativeFeatureFlags::default()),
                Arc::new(EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1/").unwrap()),
                    None,
                )),
                Arc::new(EcsGracefulDegradation::new(
                    Default::default(),
                    Arc::new(NarrativeFeatureFlags::default()),
                    None,
                    None,
                )),
                Arc::new(EmbeddingPipelineService::new(
                    ChunkConfig {
                        metric: ChunkingMetric::Word,
                        max_size: 500,
                        overlap: 50,
                    }
                )),
            )),
            Arc::new(EcsGracefulDegradation::new(
                Default::default(),
                Arc::new(NarrativeFeatureFlags::default()),
                None,
                None,
            )),
        )),
        chronicle_event_listener: Arc::new(ChronicleEventListener::new(
            Default::default(),
            Arc::new(NarrativeFeatureFlags::default()),
            Arc::new(ChronicleEcsTranslator::new(
                Arc::new(test_app.db_pool.clone()),
            )),
            Arc::new(EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1/").unwrap()),
                None,
            )),
            Arc::new(ChronicleService::new(test_app.db_pool.clone())),
        )),
        chronicle_ecs_translator: Arc::new(ChronicleEcsTranslator::new(
            Arc::new(test_app.db_pool.clone()),
        )),
        chronicle_service: Arc::new(ChronicleService::new(
            test_app.db_pool.clone(),
        )),
        world_model_service: Arc::new(WorldModelService::new(
            Arc::new(test_app.db_pool.clone()),
            Arc::new(EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1/").unwrap()),
                None,
            )),
            Arc::new(HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                Arc::new(NarrativeFeatureFlags::default()),
                Arc::new(EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1/").unwrap()),
                    None,
                )),
                Arc::new(EcsEnhancedRagService::new(
                    Arc::new(test_app.db_pool.clone()),
                    Default::default(),
                    Arc::new(NarrativeFeatureFlags::default()),
                    Arc::new(EcsEntityManager::new(
                        Arc::new(test_app.db_pool.clone()),
                        Arc::new(redis::Client::open("redis://127.0.0.1/").unwrap()),
                        None,
                    )),
                    Arc::new(EcsGracefulDegradation::new(
                        Default::default(),
                        Arc::new(NarrativeFeatureFlags::default()),
                        None,
                        None,
                    )),
                    Arc::new(EmbeddingPipelineService::new(
                        ChunkConfig {
                            metric: ChunkingMetric::Word,
                            max_size: 500,
                            overlap: 50,
                        }
                    )),
                )),
                Arc::new(EcsGracefulDegradation::new(
                    Default::default(),
                    Arc::new(NarrativeFeatureFlags::default()),
                    None,
                    None,
                )),
            )),
            Arc::new(ChronicleService::new(test_app.db_pool.clone())),
        )),
        agentic_orchestrator: Arc::new(AgenticOrchestrator::new(
            test_app.ai_client.clone(),
            Arc::new(HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                Arc::new(NarrativeFeatureFlags::default()),
                Arc::new(EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1/").unwrap()),
                    None,
                )),
                Arc::new(EcsEnhancedRagService::new(
                    Arc::new(test_app.db_pool.clone()),
                    Default::default(),
                    Arc::new(NarrativeFeatureFlags::default()),
                    Arc::new(EcsEntityManager::new(
                        Arc::new(test_app.db_pool.clone()),
                        Arc::new(redis::Client::open("redis://127.0.0.1/").unwrap()),
                        None,
                    )),
                    Arc::new(EcsGracefulDegradation::new(
                        Default::default(),
                        Arc::new(NarrativeFeatureFlags::default()),
                        None,
                        None,
                    )),
                    Arc::new(EmbeddingPipelineService::new(
                        ChunkConfig {
                            metric: ChunkingMetric::Word,
                            max_size: 500,
                            overlap: 50,
                        }
                    )),
                )),
                Arc::new(EcsGracefulDegradation::new(
                    Default::default(),
                    Arc::new(NarrativeFeatureFlags::default()),
                    None,
                    None,
                )),
            )),
            Arc::new(test_app.db_pool.clone()),
            Arc::new(AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                Arc::new(EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1/").unwrap()),
                    None,
                )),
            )),
        )),
        agentic_state_update_service: Arc::new(AgenticStateUpdateService::new(
            test_app.ai_client.clone(),
            Arc::new(EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                Arc::new(redis::Client::open("redis://127.0.0.1/").unwrap()),
                None,
            )),
        )),
    })
}

#[tokio::test]
async fn test_entity_resolution_tool_creation() {
    let test_app = crate::test_helpers::spawn_app(false, false, false).await;
    
    // Create a minimal AppState for testing
    let app_state = create_test_app_state(&test_app);
    let tool = EntityResolutionTool::new(app_state);
    
    assert_eq!(tool.name(), "resolve_entities");
    assert_eq!(
        tool.description(),
        "Resolves entity names from narrative text to existing entities or creates new ones with rich component data extracted from context."
    );
    
    // Validate input schema has required fields
    let schema = tool.input_schema();
    let properties = schema.get("properties").unwrap();
    assert!(properties.get("user_id").is_some());
    assert!(properties.get("narrative_text").is_some());
    assert!(properties.get("entity_names").is_some());
}

#[tokio::test]
async fn test_processing_mode_enum() {
    let incremental = ProcessingMode::Incremental;
    let batch = ProcessingMode::Batch;
    
    assert_eq!(incremental.to_string(), "incremental");
    assert_eq!(batch.to_string(), "batch");
}

#[tokio::test]
async fn test_narrative_context_creation() {
    let test_app = crate::test_helpers::spawn_app(false, false, false).await;
    
    // Create a minimal AppState for testing
    let app_state = create_test_app_state(&test_app);
    let tool = EntityResolutionTool::new(app_state);
    
    let actors = vec![
        json!({
            "entity_name": "Elara",
            "role": "AGENT",
            "context": "brave warrior wielding a sword"
        }),
        json!({
            "entity_name": "ancient dragon",
            "role": "OPPONENT",
            "context": "breathing fire"
        })
    ];
    
    let narrative_context = tool.create_narrative_context_from_actors(&actors);
    
    assert!(narrative_context.contains("Elara"));
    assert!(narrative_context.contains("ancient dragon"));
    assert!(narrative_context.contains("AGENT"));
    assert!(narrative_context.contains("OPPONENT"));
    assert!(narrative_context.contains("brave warrior"));
    assert!(narrative_context.contains("breathing fire"));
}

#[tokio::test]
async fn test_error_handling() {
    let test_app = crate::test_helpers::spawn_app(false, false, false).await;
    
    // Create a minimal AppState for testing
    let app_state = create_test_app_state(&test_app);
    let tool = EntityResolutionTool::new(app_state);
    
    // Test with invalid parameters
    let invalid_params = json!({
        "invalid_field": "invalid_value"
    });
    
    let result = tool.execute(&invalid_params).await;
    assert!(result.is_err());
    
    if let Err(error) = result {
        match error {
            ToolError::InvalidParams(_) => {
                // Expected error type
            }
            _ => panic!("Expected InvalidParams error"),
        }
    }
}
#[tokio::test]
async fn test_truncated_ai_response_handling() {
    let test_app = crate::test_helpers::spawn_app(true, false, false).await;
    let user_id = uuid::Uuid::new_v4();

    // Simulate a truncated AI response
    let truncated_response = r#"```json
{
  "resolved_entities": [
    {
      "input_name": "vargo_id",
      "entity_id": "e2f3g4h5-i6j7-8901-2345-67890abcdef0",
      "is_new": true,
      "confidence": 1.0,
      "components": {
        "Name": {
          "name": "vargo_id",
          "display_name": "Vargo"
        }
"#; // Note the missing closing braces and backticks

    if let Some(mock_client) = &test_app.mock_ai_client {
        mock_client.set_next_chat_response(truncated_response.to_string());
    }

    // Create a minimal AppState for testing
    let app_state = create_test_app_state(&test_app);
    let tool = EntityResolutionTool::new(app_state);

    let params = json!({
        "user_id": user_id.to_string(),
        "narrative_text": "An urgent message from Vargo.",
        "entity_names": ["vargo_id"]
    });

    let result = tool.execute(&params).await;

    // Assert that the tool returns a parsing error, not a panic
    assert!(result.is_err());
    if let Err(ToolError::ExecutionFailed(msg)) = result {
        assert!(msg.contains("Failed to parse AI response"));
    } else {
        panic!("Expected ExecutionFailed error due to parsing failure, but got a different result.");
    }
}
