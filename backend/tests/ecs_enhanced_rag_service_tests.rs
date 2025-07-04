//! Tests for ECS-Enhanced RAG Service
//!
//! These tests verify Phase 4.2.1 implementation:
//! - Augment chronicle search with current entity state
//! - Provide entity relationship context for RAG
//! - Add "current state" information to chronicle events
//! - Maintain existing chronicle RAG as fallback

use scribe_backend::{
    config::NarrativeFeatureFlags,
    services::{
        ecs_enhanced_rag_service::{
            EcsEnhancedRagService, EcsEnhancedRagConfig, EnhancedRagQuery, EnhancedRagResult,
            EntityStateSnapshot, EntityStateContext, RelationshipContext
        },
        ecs_graceful_degradation::{EcsGracefulDegradation, GracefulDegradationConfig},
        ecs_entity_manager::{EcsEntityManager, EntityManagerConfig},
        embeddings::service::EmbeddingPipelineService,
    },
    test_helpers::{spawn_app_permissive_rate_limiting, TestApp, TestDataGuard},
    errors::AppError,
};
use std::sync::Arc;
use tokio::time::Duration;
use uuid::Uuid;
use serde_json::json;

/// Test creating ECS-enhanced RAG service with default configuration
#[tokio::test]
async fn test_create_ecs_enhanced_rag_service() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create required dependencies
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = create_test_entity_manager(&app).await;
    let degradation_service = create_test_degradation_service(&app, entity_manager.clone()).await;
    let embedding_service = create_test_embedding_service(&app).await;
    
    // Create the enhanced RAG service
    let config = EcsEnhancedRagConfig::default();
    let rag_service = EcsEnhancedRagService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        degradation_service,
        embedding_service,
    );
    
    // Verify service can be created without issues
    // This mainly tests that all dependencies are properly connected
    drop(rag_service);
}

/// Test enhanced RAG query with ECS enabled
#[tokio::test]
async fn test_enhanced_rag_query_with_ecs_enabled() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = create_test_entity_manager(&app).await;
    let degradation_service = create_test_degradation_service(&app, entity_manager.clone()).await;
    let embedding_service = create_test_embedding_service(&app).await;
    
    let config = EcsEnhancedRagConfig::default();
    let rag_service = EcsEnhancedRagService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        degradation_service,
        embedding_service,
    );
    
    // Create test query
    let query = EnhancedRagQuery {
        query: "What happened to the main character?".to_string(),
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        max_chronicle_results: 10,
        include_current_state: true,
        include_relationships: true,
        focus_entity_ids: None,
        similarity_threshold: 0.7,
    };
    
    // Execute enhanced RAG query
    let result = rag_service.query_enhanced_rag(query).await;
    assert!(result.is_ok());
    
    let rag_result = result.unwrap();
    assert_eq!(rag_result.query, "What happened to the main character?");
    // Note: With placeholder implementation, these will be empty
    // In real implementation, we'd have test data
}

/// Test enhanced RAG query fallback when ECS is disabled
#[tokio::test]
async fn test_enhanced_rag_query_with_ecs_disabled() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create feature flags with ECS disabled
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_ecs_system = false;
    let feature_flags = Arc::new(feature_flags);
    
    let entity_manager = create_test_entity_manager(&app).await;
    let degradation_service = create_test_degradation_service_with_flags(&app, entity_manager.clone(), feature_flags.clone()).await;
    let embedding_service = create_test_embedding_service(&app).await;
    
    let config = EcsEnhancedRagConfig::default();
    let rag_service = EcsEnhancedRagService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        degradation_service,
        embedding_service,
    );
    
    // Create test query
    let query = EnhancedRagQuery {
        query: "Show me character interactions".to_string(),
        user_id: Uuid::new_v4(),
        chronicle_id: None,
        max_chronicle_results: 5,
        include_current_state: true,
        include_relationships: true,
        focus_entity_ids: None,
        similarity_threshold: 0.6,
    };
    
    // Execute query - should fall back to chronicle-only
    let result = rag_service.query_enhanced_rag(query).await;
    assert!(result.is_ok());
    
    let rag_result = result.unwrap();
    assert!(!rag_result.ecs_enhanced);
    assert!(rag_result.fallback_used);
    assert!(!rag_result.warnings.is_empty());
    assert!(rag_result.warnings[0].contains("ECS unavailable"));
}

/// Test enhanced RAG query with specific entity focus
#[tokio::test]
async fn test_enhanced_rag_query_with_entity_focus() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = create_test_entity_manager(&app).await;
    let degradation_service = create_test_degradation_service(&app, entity_manager.clone()).await;
    let embedding_service = create_test_embedding_service(&app).await;
    
    let config = EcsEnhancedRagConfig::default();
    let rag_service = EcsEnhancedRagService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        degradation_service,
        embedding_service,
    );
    
    // Create focused entity IDs
    let focus_entities = vec![Uuid::new_v4(), Uuid::new_v4()];
    
    // Create test query with entity focus
    let query = EnhancedRagQuery {
        query: "What are these characters doing?".to_string(),
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        max_chronicle_results: 15,
        include_current_state: true,
        include_relationships: false,
        focus_entity_ids: Some(focus_entities.clone()),
        similarity_threshold: 0.8,
    };
    
    // Execute focused query
    let result = rag_service.query_enhanced_rag(query).await;
    assert!(result.is_ok());
    
    let rag_result = result.unwrap();
    // Test completed successfully - query structure validated
}

/// Test enhanced RAG configuration options
#[tokio::test]
async fn test_enhanced_rag_configuration_options() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = create_test_entity_manager(&app).await;
    let degradation_service = create_test_degradation_service(&app, entity_manager.clone()).await;
    let embedding_service = create_test_embedding_service(&app).await;
    
    // Test custom configuration
    let mut config = EcsEnhancedRagConfig::default();
    config.enable_ecs_context_enhancement = false;
    config.enable_current_state_overlay = false;
    config.enable_relationship_context = false;
    config.max_related_entities = 25;
    config.max_relationship_depth = 2;
    config.enable_entity_state_caching = false;
    config.entity_state_cache_ttl = 600;
    
    let rag_service = EcsEnhancedRagService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        degradation_service,
        embedding_service,
    );
    
    // Verify the service accepts custom configuration
    // This mainly tests that configuration is properly passed through
    drop(rag_service);
}

/// Test enhanced RAG query structure validation
#[tokio::test]
async fn test_enhanced_rag_query_structure() {
    // Test EnhancedRagQuery serialization and deserialization
    let query = EnhancedRagQuery {
        query: "Test query".to_string(),
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        max_chronicle_results: 10,
        include_current_state: true,
        include_relationships: true,
        focus_entity_ids: Some(vec![Uuid::new_v4()]),
        similarity_threshold: 0.75,
    };
    
    let json = serde_json::to_string(&query);
    assert!(json.is_ok());
    
    let deserialized: Result<EnhancedRagQuery, _> = serde_json::from_str(&json.unwrap());
    assert!(deserialized.is_ok());
    
    let restored = deserialized.unwrap();
    assert_eq!(restored.query, query.query);
    assert_eq!(restored.user_id, query.user_id);
    assert_eq!(restored.max_chronicle_results, query.max_chronicle_results);
    assert_eq!(restored.similarity_threshold, query.similarity_threshold);
}

/// Test enhanced RAG result structure
#[tokio::test]
async fn test_enhanced_rag_result_structure() {
    // Test EnhancedRagResult serialization
    let result = EnhancedRagResult {
        query: "Test query".to_string(),
        user_id: Uuid::new_v4(),
        chronicle_events: Vec::new(),
        current_entity_states: Vec::new(),
        relationship_context: Vec::new(),
        ecs_enhanced: true,
        fallback_used: false,
        query_duration_ms: 250,
        warnings: vec!["Test warning".to_string()],
    };
    
    let json = serde_json::to_string(&result);
    assert!(json.is_ok());
    
    let deserialized: Result<EnhancedRagResult, _> = serde_json::from_str(&json.unwrap());
    assert!(deserialized.is_ok());
    
    let restored = deserialized.unwrap();
    assert_eq!(restored.query, result.query);
    assert_eq!(restored.ecs_enhanced, result.ecs_enhanced);
    assert_eq!(restored.fallback_used, result.fallback_used);
    assert_eq!(restored.warnings.len(), 1);
}

/// Test entity state snapshot structure
#[tokio::test]
async fn test_entity_state_snapshot_structure() {
    let mut components = std::collections::HashMap::new();
    components.insert("health".to_string(), json!({"value": 100}));
    components.insert("position".to_string(), json!({"x": 10, "y": 20}));
    
    let snapshot = EntityStateSnapshot {
        entity_id: Uuid::new_v4(),
        archetype_signature: "character".to_string(),
        components,
        snapshot_time: chrono::Utc::now(),
        status_indicators: vec!["healthy".to_string(), "active".to_string()],
    };
    
    let json = serde_json::to_string(&snapshot);
    assert!(json.is_ok());
    
    let deserialized: Result<EntityStateSnapshot, _> = serde_json::from_str(&json.unwrap());
    assert!(deserialized.is_ok());
    
    let restored = deserialized.unwrap();
    assert_eq!(restored.entity_id, snapshot.entity_id);
    assert_eq!(restored.archetype_signature, snapshot.archetype_signature);
    assert_eq!(restored.components.len(), 2);
    assert_eq!(restored.status_indicators.len(), 2);
}

/// Test relationship context structure
#[tokio::test]
async fn test_relationship_context_structure() {
    let relationship = RelationshipContext {
        from_entity_id: Uuid::new_v4(),
        to_entity_id: Uuid::new_v4(),
        relationship_type: "friendship".to_string(),
        relationship_data: json!({"strength": 0.8, "duration": "long"}),
        established_at: Some(chrono::Utc::now()),
        last_updated: Some(chrono::Utc::now()),
    };
    
    let json = serde_json::to_string(&relationship);
    assert!(json.is_ok());
    
    let deserialized: Result<RelationshipContext, _> = serde_json::from_str(&json.unwrap());
    assert!(deserialized.is_ok());
    
    let restored = deserialized.unwrap();
    assert_eq!(restored.from_entity_id, relationship.from_entity_id);
    assert_eq!(restored.to_entity_id, relationship.to_entity_id);
    assert_eq!(restored.relationship_type, relationship.relationship_type);
    assert!(restored.established_at.is_some());
}

/// Test entity state context structure
#[tokio::test]
async fn test_entity_state_context_structure() {
    let mut key_attributes = std::collections::HashMap::new();
    key_attributes.insert("name".to_string(), json!("Test Character"));
    key_attributes.insert("level".to_string(), json!(5));
    
    let context = EntityStateContext {
        entity_id: Uuid::new_v4(),
        entity_name: Some("Test Character".to_string()),
        current_location: Some(json!({"area": "town_square", "coordinates": [100, 200]})),
        key_attributes,
        recent_changes: vec!["gained experience".to_string(), "moved location".to_string()],
        relevance_score: 0.9,
    };
    
    let json = serde_json::to_string(&context);
    assert!(json.is_ok());
    
    let deserialized: Result<EntityStateContext, _> = serde_json::from_str(&json.unwrap());
    assert!(deserialized.is_ok());
    
    let restored = deserialized.unwrap();
    assert_eq!(restored.entity_id, context.entity_id);
    assert_eq!(restored.entity_name, context.entity_name);
    assert!(restored.current_location.is_some());
    assert_eq!(restored.key_attributes.len(), 2);
    assert_eq!(restored.recent_changes.len(), 2);
    assert_eq!(restored.relevance_score, 0.9);
}

/// Test enhanced RAG configuration defaults
#[test]
fn test_enhanced_rag_config_defaults() {
    let config = EcsEnhancedRagConfig::default();
    
    assert!(config.enable_ecs_context_enhancement);
    assert!(config.enable_current_state_overlay);
    assert!(config.enable_relationship_context);
    assert_eq!(config.max_related_entities, 50);
    assert_eq!(config.max_relationship_depth, 3);
    assert!(config.enable_entity_state_caching);
    assert_eq!(config.entity_state_cache_ttl, 300);
}

/// Test that enhanced RAG preserves chronicle functionality
#[tokio::test]
async fn test_enhanced_rag_preserves_chronicle_functionality() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create degradation service with ECS disabled to simulate failure
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_ecs_system = false;
    let feature_flags = Arc::new(feature_flags);
    
    let entity_manager = create_test_entity_manager(&app).await;
    let degradation_service = create_test_degradation_service_with_flags(&app, entity_manager.clone(), feature_flags.clone()).await;
    let embedding_service = create_test_embedding_service(&app).await;
    
    let config = EcsEnhancedRagConfig::default();
    let rag_service = EcsEnhancedRagService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        degradation_service,
        embedding_service,
    );
    
    // Simulate chronicle operations that should continue working
    let chronicle_queries = vec![
        "What happened in the story?",
        "Show me character interactions",
        "Find emotional moments",
        "Search for plot developments",
    ];
    
    for query_text in chronicle_queries {
        let query = EnhancedRagQuery {
            query: query_text.to_string(),
            user_id: Uuid::new_v4(),
            chronicle_id: Some(Uuid::new_v4()),
            max_chronicle_results: 10,
            include_current_state: true,
            include_relationships: true,
            focus_entity_ids: None,
            similarity_threshold: 0.7,
        };
        
        let result = rag_service.query_enhanced_rag(query).await;
        
        // All operations should succeed via fallback
        assert!(result.is_ok());
        let rag_result = result.unwrap();
        assert!(!rag_result.ecs_enhanced);
        assert!(rag_result.fallback_used);
        assert_eq!(rag_result.query, query_text);
    }
}

// Helper functions for test setup

async fn create_test_entity_manager(app: &TestApp) -> Arc<EcsEntityManager> {
    let redis_client = Arc::new(
        redis::Client::open("redis://127.0.0.1:6379/")
            .expect("Failed to create Redis client for tests")
    );
    let config = EntityManagerConfig::default();
    Arc::new(EcsEntityManager::new(
        app.db_pool.clone().into(),
        redis_client,
        Some(config),
    ))
}

async fn create_test_degradation_service(app: &TestApp, entity_manager: Arc<EcsEntityManager>) -> Arc<EcsGracefulDegradation> {
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let config = GracefulDegradationConfig::default();
    Arc::new(EcsGracefulDegradation::new(
        config,
        feature_flags,
        Some(entity_manager),
        None,
    ))
}

async fn create_test_degradation_service_with_flags(app: &TestApp, entity_manager: Arc<EcsEntityManager>, feature_flags: Arc<NarrativeFeatureFlags>) -> Arc<EcsGracefulDegradation> {
    let config = GracefulDegradationConfig::default();
    Arc::new(EcsGracefulDegradation::new(
        config,
        feature_flags,
        Some(entity_manager),
        None,
    ))
}

async fn create_test_embedding_service(app: &TestApp) -> Arc<EmbeddingPipelineService> {
    use scribe_backend::text_processing::chunking::{ChunkConfig, ChunkingMetric};
    
    // Create a test chunking configuration for the embedding service
    let chunk_config = ChunkConfig {
        metric: ChunkingMetric::Word,
        max_size: 500,
        overlap: 50,
    };
    
    // Create embedding service with chunk configuration
    Arc::new(EmbeddingPipelineService::new(chunk_config))
}