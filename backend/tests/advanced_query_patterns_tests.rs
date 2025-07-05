//! Tests for Advanced Query Patterns
//!
//! This module tests the Phase 5.4a implementation of the ECS Architecture Plan.
//! It validates the specific production-ready query patterns:
//! - "Show me characters present at location X with trust >0.5"
//! - "What events affected the relationship between A and B?"
//! - "Which characters have interacted with this item?"

use std::sync::Arc;
use uuid::Uuid;
use chrono::Utc;

use scribe_backend::{
    config::NarrativeFeatureFlags,
    services::{
        HybridQueryService, HybridQueryConfig, HybridQuery, HybridQueryType, HybridQueryOptions,
        EcsEntityManager, EntityManagerConfig, EcsEnhancedRagService, EcsEnhancedRagConfig,
        EcsGracefulDegradation, GracefulDegradationConfig,
    },
    test_helpers::{spawn_app, TestDataGuard, TestApp},
    errors::AppError,
};

#[tokio::test]
async fn test_trusted_characters_at_location_query() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    // Create feature flags with ECS enabled
    let feature_flags = Arc::new(NarrativeFeatureFlags {
        enable_ecs_system: true,
        ..Default::default()
    });

    // Create mock Redis client
    let redis_client = Arc::new(redis::Client::open("redis://localhost:6379/1").unwrap());

    // Create entity manager
    let entity_manager = Arc::new(EcsEntityManager::new(
        Arc::new(app.db_pool.clone()),
        redis_client,
        Some(EntityManagerConfig::default()),
    ));

    // Create graceful degradation service
    let degradation_service = Arc::new(EcsGracefulDegradation::new(
        GracefulDegradationConfig::default(),
        feature_flags.clone(),
        Some(entity_manager.clone()),
        None, // No consistency monitor for this test
    ));

    // Create enhanced RAG service
    let rag_service = Arc::new(EcsEnhancedRagService::new(
        Arc::new(app.db_pool.clone()),
        EcsEnhancedRagConfig::default(),
        feature_flags.clone(),
        entity_manager.clone(),
        degradation_service.clone(),
        create_test_embedding_service(&app).await,
    ));

    // Create hybrid query service
    let hybrid_service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        HybridQueryConfig::default(),
        feature_flags,
        entity_manager,
        rag_service,
        degradation_service,
    );

    let user_id = Uuid::new_v4();
    let chronicle_id = Some(Uuid::new_v4());

    // Test the trusted characters at location query
    let result = hybrid_service.query_trusted_characters_at_location(
        user_id,
        chronicle_id,
        "Tavern",
        0.5, // Trust threshold
        Some(10), // Max results
    ).await;

    assert!(result.is_ok());
    let query_result = result.unwrap();

    // Verify the query type
    assert!(matches!(query_result.query_type, HybridQueryType::LocationQuery { .. }));
    assert_eq!(query_result.user_id, user_id);

    // Verify the summary includes trust filtering information
    assert!(query_result.summary.key_insights.iter().any(|insight| 
        insight.contains("trust ≥ 0.5")));

    // Verify narrative answer is provided
    assert!(query_result.summary.narrative_answer.is_some());
    let narrative = query_result.summary.narrative_answer.unwrap();
    assert!(narrative.contains("Tavern"));
    assert!(narrative.contains("trust"));

    println!("Trusted characters at location query test passed");
}

#[tokio::test]
async fn test_relationship_affecting_events_query() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    // Create feature flags with ECS enabled
    let feature_flags = Arc::new(NarrativeFeatureFlags {
        enable_ecs_system: true,
        ..Default::default()
    });

    // Create mock Redis client
    let redis_client = Arc::new(redis::Client::open("redis://localhost:6379/1").unwrap());

    // Create entity manager
    let entity_manager = Arc::new(EcsEntityManager::new(
        Arc::new(app.db_pool.clone()),
        redis_client,
        Some(EntityManagerConfig::default()),
    ));

    // Create graceful degradation service
    let degradation_service = Arc::new(EcsGracefulDegradation::new(
        GracefulDegradationConfig::default(),
        feature_flags.clone(),
        Some(entity_manager.clone()),
        None, // No consistency monitor for this test
    ));

    // Create enhanced RAG service
    let rag_service = Arc::new(EcsEnhancedRagService::new(
        Arc::new(app.db_pool.clone()),
        EcsEnhancedRagConfig::default(),
        feature_flags.clone(),
        entity_manager.clone(),
        degradation_service.clone(),
        create_test_embedding_service(&app).await,
    ));

    // Create hybrid query service
    let hybrid_service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        HybridQueryConfig::default(),
        feature_flags,
        entity_manager,
        rag_service,
        degradation_service,
    );

    let user_id = Uuid::new_v4();
    let chronicle_id = Some(Uuid::new_v4());
    let entity_a_id = Some(Uuid::new_v4());
    let entity_b_id = Some(Uuid::new_v4());

    // Test the relationship affecting events query
    let result = hybrid_service.query_relationship_affecting_events(
        user_id,
        chronicle_id,
        "Alice",
        "Bob",
        entity_a_id,
        entity_b_id,
        true, // Include indirect effects
        Some(25), // Max results
    ).await;

    assert!(result.is_ok());
    let query_result = result.unwrap();

    // Verify the query type
    assert!(matches!(query_result.query_type, HybridQueryType::RelationshipHistory { .. }));
    assert_eq!(query_result.user_id, user_id);

    // Verify the summary includes relationship analysis
    assert!(query_result.summary.key_insights.iter().any(|insight| 
        insight.contains("Alice") && insight.contains("Bob")));

    // Verify narrative answer is provided
    assert!(query_result.summary.narrative_answer.is_some());
    let narrative = query_result.summary.narrative_answer.unwrap();
    assert!(narrative.contains("Alice"));
    assert!(narrative.contains("Bob"));
    assert!(narrative.contains("relationship"));

    println!("Relationship affecting events query test passed");
}

#[tokio::test]
async fn test_item_interaction_history_query() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    // Create feature flags with ECS enabled
    let feature_flags = Arc::new(NarrativeFeatureFlags {
        enable_ecs_system: true,
        ..Default::default()
    });

    // Create mock Redis client
    let redis_client = Arc::new(redis::Client::open("redis://localhost:6379/1").unwrap());

    // Create entity manager
    let entity_manager = Arc::new(EcsEntityManager::new(
        Arc::new(app.db_pool.clone()),
        redis_client,
        Some(EntityManagerConfig::default()),
    ));

    // Create graceful degradation service
    let degradation_service = Arc::new(EcsGracefulDegradation::new(
        GracefulDegradationConfig::default(),
        feature_flags.clone(),
        Some(entity_manager.clone()),
        None, // No consistency monitor for this test
    ));

    // Create enhanced RAG service
    let rag_service = Arc::new(EcsEnhancedRagService::new(
        Arc::new(app.db_pool.clone()),
        EcsEnhancedRagConfig::default(),
        feature_flags.clone(),
        entity_manager.clone(),
        degradation_service.clone(),
        create_test_embedding_service(&app).await,
    ));

    // Create hybrid query service
    let hybrid_service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        HybridQueryConfig::default(),
        feature_flags,
        entity_manager,
        rag_service,
        degradation_service,
    );

    let user_id = Uuid::new_v4();
    let chronicle_id = Some(Uuid::new_v4());
    let item_id = Some(Uuid::new_v4());

    // Define interaction types to track
    let interaction_types = Some(vec![
        "use".to_string(),
        "transfer".to_string(),
        "acquire".to_string(),
        "lose".to_string(),
    ]);

    // Define time range for the query
    let time_range = Some((
        Utc::now() - chrono::Duration::days(30),
        Utc::now(),
    ));

    // Test the item interaction history query
    let result = hybrid_service.query_item_interaction_history(
        user_id,
        chronicle_id,
        "Sword of Power",
        item_id,
        interaction_types.clone(),
        time_range,
        Some(15), // Max results
    ).await;

    assert!(result.is_ok());
    let query_result = result.unwrap();

    // Verify the query type
    assert!(matches!(query_result.query_type, HybridQueryType::NarrativeQuery { .. }));
    assert_eq!(query_result.user_id, user_id);

    // Verify the summary includes item interaction information
    assert!(query_result.summary.key_insights.iter().any(|insight| 
        insight.contains("Sword of Power")));

    if let Some(types) = interaction_types {
        assert!(query_result.summary.key_insights.iter().any(|insight| 
            insight.contains("interaction types")));
    }

    // Verify narrative answer is provided
    assert!(query_result.summary.narrative_answer.is_some());
    let narrative = query_result.summary.narrative_answer.unwrap();
    assert!(narrative.contains("Sword of Power"));
    assert!(narrative.contains("characters"));

    println!("Item interaction history query test passed");
}

#[tokio::test]
async fn test_advanced_query_patterns_configuration() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    // Test custom hybrid query configuration
    let config = HybridQueryConfig {
        enable_entity_caching: true,
        entity_cache_ttl: 300, // 5 minutes
        max_entities_per_query: 15,
        enable_timeline_reconstruction: true,
        max_timeline_events: 75,
        enable_relationship_analysis: true,
        max_relationship_depth: 2,
    };

    // Verify configuration values
    assert!(config.enable_entity_caching);
    assert_eq!(config.entity_cache_ttl, 300);
    assert_eq!(config.max_entities_per_query, 15);
    assert!(config.enable_timeline_reconstruction);
    assert_eq!(config.max_timeline_events, 75);
    assert!(config.enable_relationship_analysis);
    assert_eq!(config.max_relationship_depth, 2);

    // Test hybrid query options for advanced patterns
    let options = HybridQueryOptions {
        use_cache: true,
        include_timelines: true,
        analyze_relationships: true,
        confidence_threshold: 0.7,
    };

    assert!(options.use_cache);
    assert!(options.include_timelines);
    assert!(options.analyze_relationships);
    assert_eq!(options.confidence_threshold, 0.7);

    println!("Advanced query patterns configuration test passed");
}

#[tokio::test]
async fn test_query_pattern_edge_cases() {
    let app = spawn_app(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());

    // Create feature flags with ECS enabled
    let feature_flags = Arc::new(NarrativeFeatureFlags {
        enable_ecs_system: true,
        ..Default::default()
    });

    // Create mock Redis client
    let redis_client = Arc::new(redis::Client::open("redis://localhost:6379/1").unwrap());

    // Create entity manager
    let entity_manager = Arc::new(EcsEntityManager::new(
        Arc::new(app.db_pool.clone()),
        redis_client,
        Some(EntityManagerConfig::default()),
    ));

    // Create graceful degradation service
    let degradation_service = Arc::new(EcsGracefulDegradation::new(
        GracefulDegradationConfig::default(),
        feature_flags.clone(),
        Some(entity_manager.clone()),
        None,
    ));

    // Create enhanced RAG service
    let rag_service = Arc::new(EcsEnhancedRagService::new(
        Arc::new(app.db_pool.clone()),
        EcsEnhancedRagConfig::default(),
        feature_flags.clone(),
        entity_manager.clone(),
        degradation_service.clone(),
        create_test_embedding_service(&app).await,
    ));

    // Create hybrid query service
    let hybrid_service = HybridQueryService::new(
        Arc::new(app.db_pool.clone()),
        HybridQueryConfig::default(),
        feature_flags,
        entity_manager,
        rag_service,
        degradation_service,
    );

    let user_id = Uuid::new_v4();

    // Test empty location name
    let result = hybrid_service.query_trusted_characters_at_location(
        user_id,
        None,
        "", // Empty location
        0.5,
        Some(10),
    ).await;

    assert!(result.is_ok());

    // Test very high trust threshold (should return fewer results)
    let result = hybrid_service.query_trusted_characters_at_location(
        user_id,
        None,
        "Test Location",
        0.99, // Very high trust threshold
        Some(10),
    ).await;

    assert!(result.is_ok());

    // Test relationship query with same entity names
    let result = hybrid_service.query_relationship_affecting_events(
        user_id,
        None,
        "Alice",
        "Alice", // Same entity
        None,
        None,
        false,
        Some(10),
    ).await;

    assert!(result.is_ok());

    // Test item query with special characters
    let result = hybrid_service.query_item_interaction_history(
        user_id,
        None,
        "Sword & Shield of +5", // Special characters
        None,
        None,
        None,
        Some(10),
    ).await;

    assert!(result.is_ok());

    println!("Query pattern edge cases test passed");
}

/// Create a test embedding service for testing purposes
async fn create_test_embedding_service(app: &TestApp) -> Arc<scribe_backend::services::embeddings::EmbeddingPipelineService> {
    use scribe_backend::text_processing::chunking::{ChunkConfig, ChunkingMetric};
    
    // Create a test chunking configuration for the embedding service
    let chunk_config = ChunkConfig {
        metric: ChunkingMetric::Word,
        max_size: 500,
        overlap: 50,
    };
    
    // Create embedding service with chunk configuration
    Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(chunk_config))
}