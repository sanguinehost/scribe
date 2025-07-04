//! Tests for Hybrid Query Service
//!
//! These tests verify Phase 4.2.2 implementation:
//! - Support queries spanning chronicle events and ECS state
//! - "What happened to X and where are they now?"
//! - "Who was present at Y event and what's their current relationship?"
//! - Cache frequently accessed entity states

use scribe_backend::{
    config::NarrativeFeatureFlags,
    services::{
        hybrid_query_service::{
            HybridQueryService, HybridQueryConfig, HybridQuery, HybridQueryType,
            HybridQueryOptions, EntityTimelineContext, RelationshipAnalysis,
            RelationshipMetrics, RelationshipTrend, HybridQuerySummary, QueryPerformanceMetrics
        },
        ecs_enhanced_rag_service::{EcsEnhancedRagService, EcsEnhancedRagConfig},
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
use chrono::Utc;

/// Test creating hybrid query service with default configuration
#[tokio::test]
async fn test_create_hybrid_query_service() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create required dependencies
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = create_test_entity_manager(&app).await;
    let degradation_service = create_test_degradation_service(&app, entity_manager.clone()).await;
    let rag_service = create_test_rag_service(&app, entity_manager.clone(), degradation_service.clone()).await;
    
    // Create the hybrid query service
    let config = HybridQueryConfig::default();
    let hybrid_service = HybridQueryService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        rag_service,
        degradation_service,
    );
    
    // Verify service can be created without issues
    drop(hybrid_service);
}

/// Test entity timeline query - "What happened to X and where are they now?"
#[tokio::test]
async fn test_entity_timeline_query() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = create_test_entity_manager(&app).await;
    let degradation_service = create_test_degradation_service(&app, entity_manager.clone()).await;
    let rag_service = create_test_rag_service(&app, entity_manager.clone(), degradation_service.clone()).await;
    
    let config = HybridQueryConfig::default();
    let hybrid_service = HybridQueryService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        rag_service,
        degradation_service,
    );
    
    // Create entity timeline query
    let query = HybridQuery {
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Alice".to_string(),
            entity_id: Some(Uuid::new_v4()),
            include_current_state: true,
        },
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        max_results: 20,
        include_current_state: true,
        include_relationships: true,
        options: HybridQueryOptions::default(),
    };
    
    // Execute query
    let result = hybrid_service.execute_hybrid_query(query).await;
    assert!(result.is_ok());
    
    let hybrid_result = result.unwrap();
    match hybrid_result.query_type {
        HybridQueryType::EntityTimeline { entity_name, .. } => {
            assert_eq!(entity_name, "Alice");
        }
        _ => panic!("Expected EntityTimeline query type"),
    }
}

/// Test event participants query - "Who was present at Y event and what's their current relationship?"
#[tokio::test]
async fn test_event_participants_query() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = create_test_entity_manager(&app).await;
    let degradation_service = create_test_degradation_service(&app, entity_manager.clone()).await;
    let rag_service = create_test_rag_service(&app, entity_manager.clone(), degradation_service.clone()).await;
    
    let config = HybridQueryConfig::default();
    let hybrid_service = HybridQueryService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        rag_service,
        degradation_service,
    );
    
    // Create event participants query
    let query = HybridQuery {
        query_type: HybridQueryType::EventParticipants {
            event_description: "The great battle at the castle".to_string(),
            event_id: Some(Uuid::new_v4()),
            include_relationships: true,
        },
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        max_results: 15,
        include_current_state: true,
        include_relationships: true,
        options: HybridQueryOptions::default(),
    };
    
    // Execute query
    let result = hybrid_service.execute_hybrid_query(query).await;
    assert!(result.is_ok());
    
    let hybrid_result = result.unwrap();
    match hybrid_result.query_type {
        HybridQueryType::EventParticipants { event_description, .. } => {
            assert_eq!(event_description, "The great battle at the castle");
        }
        _ => panic!("Expected EventParticipants query type"),
    }
}

/// Test relationship history query - "Show me the relationship history between A and B"
#[tokio::test]
async fn test_relationship_history_query() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = create_test_entity_manager(&app).await;
    let degradation_service = create_test_degradation_service(&app, entity_manager.clone()).await;
    let rag_service = create_test_rag_service(&app, entity_manager.clone(), degradation_service.clone()).await;
    
    let config = HybridQueryConfig::default();
    let hybrid_service = HybridQueryService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        rag_service,
        degradation_service,
    );
    
    // Create relationship history query
    let query = HybridQuery {
        query_type: HybridQueryType::RelationshipHistory {
            entity_a: "Alice".to_string(),
            entity_b: "Bob".to_string(),
            entity_a_id: Some(Uuid::new_v4()),
            entity_b_id: Some(Uuid::new_v4()),
        },
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        max_results: 25,
        include_current_state: true,
        include_relationships: true,
        options: HybridQueryOptions::default(),
    };
    
    // Execute query
    let result = hybrid_service.execute_hybrid_query(query).await;
    assert!(result.is_ok());
    
    let hybrid_result = result.unwrap();
    match hybrid_result.query_type {
        HybridQueryType::RelationshipHistory { entity_a, entity_b, .. } => {
            assert_eq!(entity_a, "Alice");
            assert_eq!(entity_b, "Bob");
        }
        _ => panic!("Expected RelationshipHistory query type"),
    }
}

/// Test location query - "What entities are currently in location X?"
#[tokio::test]
async fn test_location_query() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = create_test_entity_manager(&app).await;
    let degradation_service = create_test_degradation_service(&app, entity_manager.clone()).await;
    let rag_service = create_test_rag_service(&app, entity_manager.clone(), degradation_service.clone()).await;
    
    let config = HybridQueryConfig::default();
    let hybrid_service = HybridQueryService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        rag_service,
        degradation_service,
    );
    
    // Create location query
    let query = HybridQuery {
        query_type: HybridQueryType::LocationQuery {
            location_name: "Castle Courtyard".to_string(),
            location_data: Some(json!({"area": "courtyard", "coordinates": [100, 200]})),
            include_recent_activity: true,
        },
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        max_results: 30,
        include_current_state: true,
        include_relationships: false,
        options: HybridQueryOptions::default(),
    };
    
    // Execute query
    let result = hybrid_service.execute_hybrid_query(query).await;
    assert!(result.is_ok());
    
    let hybrid_result = result.unwrap();
    match hybrid_result.query_type {
        HybridQueryType::LocationQuery { location_name, .. } => {
            assert_eq!(location_name, "Castle Courtyard");
        }
        _ => panic!("Expected LocationQuery query type"),
    }
}

/// Test narrative query - "Custom narrative query"
#[tokio::test]
async fn test_narrative_query() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = create_test_entity_manager(&app).await;
    let degradation_service = create_test_degradation_service(&app, entity_manager.clone()).await;
    let rag_service = create_test_rag_service(&app, entity_manager.clone(), degradation_service.clone()).await;
    
    let config = HybridQueryConfig::default();
    let hybrid_service = HybridQueryService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        rag_service,
        degradation_service,
    );
    
    // Create narrative query
    let query = HybridQuery {
        query_type: HybridQueryType::NarrativeQuery {
            query_text: "What magical events have occurred recently?".to_string(),
            focus_entities: Some(vec!["Wizard".to_string(), "Spell".to_string()]),
            time_range: Some((Utc::now() - chrono::Duration::days(7), Utc::now())),
        },
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        max_results: 40,
        include_current_state: true,
        include_relationships: true,
        options: HybridQueryOptions::default(),
    };
    
    // Execute query
    let result = hybrid_service.execute_hybrid_query(query).await;
    assert!(result.is_ok());
    
    let hybrid_result = result.unwrap();
    match hybrid_result.query_type {
        HybridQueryType::NarrativeQuery { query_text, .. } => {
            assert_eq!(query_text, "What magical events have occurred recently?");
        }
        _ => panic!("Expected NarrativeQuery query type"),
    }
}

/// Test hybrid query with ECS disabled (fallback mode)
#[tokio::test]
async fn test_hybrid_query_fallback_mode() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create feature flags with ECS disabled
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_ecs_system = false;
    let feature_flags = Arc::new(feature_flags);
    
    let entity_manager = create_test_entity_manager(&app).await;
    let degradation_service = create_test_degradation_service_with_flags(&app, entity_manager.clone(), feature_flags.clone()).await;
    let rag_service = create_test_rag_service_with_flags(&app, entity_manager.clone(), degradation_service.clone(), feature_flags.clone()).await;
    
    let config = HybridQueryConfig::default();
    let hybrid_service = HybridQueryService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        rag_service,
        degradation_service,
    );
    
    // Create entity timeline query
    let query = HybridQuery {
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Alice".to_string(),
            entity_id: None,
            include_current_state: true,
        },
        user_id: Uuid::new_v4(),
        chronicle_id: None,
        max_results: 10,
        include_current_state: true,
        include_relationships: true,
        options: HybridQueryOptions::default(),
    };
    
    // Execute query - should fall back to chronicle-only
    let result = hybrid_service.execute_hybrid_query(query).await;
    assert!(result.is_ok());
    
    let hybrid_result = result.unwrap();
    assert!(!hybrid_result.warnings.is_empty());
    assert!(hybrid_result.warnings[0].contains("ECS unavailable"));
}

/// Test hybrid query configuration options
#[tokio::test]
async fn test_hybrid_query_configuration_options() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = create_test_entity_manager(&app).await;
    let degradation_service = create_test_degradation_service(&app, entity_manager.clone()).await;
    let rag_service = create_test_rag_service(&app, entity_manager.clone(), degradation_service.clone()).await;
    
    // Test custom configuration
    let mut config = HybridQueryConfig::default();
    config.enable_entity_caching = false;
    config.entity_cache_ttl = 300;
    config.max_entities_per_query = 10;
    config.enable_timeline_reconstruction = false;
    config.max_timeline_events = 50;
    config.enable_relationship_analysis = false;
    config.max_relationship_depth = 2;
    
    let hybrid_service = HybridQueryService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        rag_service,
        degradation_service,
    );
    
    // Verify the service accepts custom configuration
    drop(hybrid_service);
}

/// Test hybrid query options structure
#[test]
fn test_hybrid_query_options_structure() {
    let options = HybridQueryOptions {
        use_cache: false,
        include_timelines: false,
        analyze_relationships: false,
        confidence_threshold: 0.8,
    };
    
    let json = serde_json::to_string(&options);
    assert!(json.is_ok());
    
    let deserialized: Result<HybridQueryOptions, _> = serde_json::from_str(&json.unwrap());
    assert!(deserialized.is_ok());
    
    let restored = deserialized.unwrap();
    assert!(!restored.use_cache);
    assert!(!restored.include_timelines);
    assert!(!restored.analyze_relationships);
    assert_eq!(restored.confidence_threshold, 0.8);
}

/// Test hybrid query type serialization
#[test]
fn test_hybrid_query_type_serialization() {
    let query_types = vec![
        HybridQueryType::EntityTimeline {
            entity_name: "Alice".to_string(),
            entity_id: Some(Uuid::new_v4()),
            include_current_state: true,
        },
        HybridQueryType::EventParticipants {
            event_description: "Battle".to_string(),
            event_id: None,
            include_relationships: false,
        },
        HybridQueryType::RelationshipHistory {
            entity_a: "A".to_string(),
            entity_b: "B".to_string(),
            entity_a_id: None,
            entity_b_id: None,
        },
        HybridQueryType::LocationQuery {
            location_name: "Castle".to_string(),
            location_data: None,
            include_recent_activity: true,
        },
        HybridQueryType::NarrativeQuery {
            query_text: "Test query".to_string(),
            focus_entities: None,
            time_range: None,
        },
    ];
    
    for query_type in query_types {
        let json = serde_json::to_string(&query_type);
        assert!(json.is_ok());
        
        let deserialized: Result<HybridQueryType, _> = serde_json::from_str(&json.unwrap());
        assert!(deserialized.is_ok());
    }
}

/// Test relationship analysis structures
#[test]
fn test_relationship_analysis_structure() {
    let analysis = RelationshipAnalysis {
        from_entity_id: Uuid::new_v4(),
        to_entity_id: Uuid::new_v4(),
        current_relationship: None,
        relationship_history: Vec::new(),
        analysis: RelationshipMetrics {
            stability: 0.8,
            strength: 0.9,
            trend: RelationshipTrend::Improving,
            interaction_count: 15,
        },
    };
    
    let json = serde_json::to_string(&analysis);
    assert!(json.is_ok());
    
    let deserialized: Result<RelationshipAnalysis, _> = serde_json::from_str(&json.unwrap());
    assert!(deserialized.is_ok());
    
    let restored = deserialized.unwrap();
    assert_eq!(restored.analysis.stability, 0.8);
    assert_eq!(restored.analysis.strength, 0.9);
    assert!(matches!(restored.analysis.trend, RelationshipTrend::Improving));
    assert_eq!(restored.analysis.interaction_count, 15);
}

/// Test relationship trend enum
#[test]
fn test_relationship_trend_values() {
    let trends = vec![
        RelationshipTrend::Improving,
        RelationshipTrend::Declining,
        RelationshipTrend::Stable,
        RelationshipTrend::Volatile,
        RelationshipTrend::Unknown,
    ];
    
    for trend in trends {
        let json = serde_json::to_string(&trend);
        assert!(json.is_ok());
        
        let deserialized: Result<RelationshipTrend, _> = serde_json::from_str(&json.unwrap());
        assert!(deserialized.is_ok());
    }
}

/// Test hybrid query config defaults
#[test]
fn test_hybrid_query_config_defaults() {
    let config = HybridQueryConfig::default();
    
    assert!(config.enable_entity_caching);
    assert_eq!(config.entity_cache_ttl, 600);
    assert_eq!(config.max_entities_per_query, 20);
    assert!(config.enable_timeline_reconstruction);
    assert_eq!(config.max_timeline_events, 100);
    assert!(config.enable_relationship_analysis);
    assert_eq!(config.max_relationship_depth, 3);
}

/// Test query performance metrics structure
#[test]
fn test_query_performance_metrics_structure() {
    let metrics = QueryPerformanceMetrics {
        total_duration_ms: 1500,
        chronicle_query_ms: 800,
        ecs_query_ms: 400,
        relationship_analysis_ms: 300,
        cache_hit_rate: 0.75,
        db_queries_count: 12,
    };
    
    let json = serde_json::to_string(&metrics);
    assert!(json.is_ok());
    
    let deserialized: Result<QueryPerformanceMetrics, _> = serde_json::from_str(&json.unwrap());
    assert!(deserialized.is_ok());
    
    let restored = deserialized.unwrap();
    assert_eq!(restored.total_duration_ms, 1500);
    assert_eq!(restored.chronicle_query_ms, 800);
    assert_eq!(restored.ecs_query_ms, 400);
    assert_eq!(restored.relationship_analysis_ms, 300);
    assert_eq!(restored.cache_hit_rate, 0.75);
    assert_eq!(restored.db_queries_count, 12);
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

async fn create_test_rag_service(app: &TestApp, entity_manager: Arc<EcsEntityManager>, degradation_service: Arc<EcsGracefulDegradation>) -> Arc<EcsEnhancedRagService> {
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let embedding_service = create_test_embedding_service(&app).await;
    let config = EcsEnhancedRagConfig::default();
    
    Arc::new(EcsEnhancedRagService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        degradation_service,
        embedding_service,
    ))
}

async fn create_test_rag_service_with_flags(app: &TestApp, entity_manager: Arc<EcsEntityManager>, degradation_service: Arc<EcsGracefulDegradation>, feature_flags: Arc<NarrativeFeatureFlags>) -> Arc<EcsEnhancedRagService> {
    let embedding_service = create_test_embedding_service(&app).await;
    let config = EcsEnhancedRagConfig::default();
    
    Arc::new(EcsEnhancedRagService::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        entity_manager,
        degradation_service,
        embedding_service,
    ))
}

async fn create_test_embedding_service(app: &TestApp) -> Arc<EmbeddingPipelineService> {
    use scribe_backend::text_processing::chunking::{ChunkConfig, ChunkingMetric};
    
    let chunk_config = ChunkConfig {
        metric: ChunkingMetric::Word,
        max_size: 500,
        overlap: 50,
    };
    
    Arc::new(EmbeddingPipelineService::new(chunk_config))
}