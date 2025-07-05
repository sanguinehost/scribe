//! Tests for the Hybrid Query Router
//!
//! This module tests the Phase 5.4 implementation of the ECS Architecture Plan.
//! It validates the intelligent routing logic, failure contracts, and circuit breaker
//! patterns for hybrid query execution.

use std::sync::Arc;
use uuid::Uuid;

use scribe_backend::{
    config::NarrativeFeatureFlags,
    services::{
        HybridQueryRouter, HybridQueryRouterConfig, QueryRoutingStrategy, RoutingDecision,
        QueryComplexity, QueryPerformanceContract, FailureMode, DataVolume,
        EcsGracefulDegradation, EcsEntityManager, EntityManagerConfig,
        HybridQuery, HybridQueryType, HybridQueryOptions,
    },
    test_helpers::{spawn_app, TestDataGuard},
    errors::AppError,
};

#[tokio::test]
async fn test_hybrid_query_router_creation() {
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
        feature_flags,
        Some(entity_manager),
        Default::default(),
    ));

    // Create router configuration
    let router_config = HybridQueryRouterConfig {
        enable_intelligent_routing: true,
        health_check_interval_secs: 30,
        performance_window_secs: 300,
        circuit_breaker_config: Default::default(),
        default_performance_contract: QueryPerformanceContract::default(),
    };

    // Create router
    let router = HybridQueryRouter::new(router_config, degradation_service);

    // Basic test - router should be created successfully
    assert!(true); // This test just verifies compilation and creation
}

#[tokio::test]
async fn test_query_complexity_analysis() {
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
        feature_flags,
        Some(entity_manager),
        Default::default(),
    ));

    // Create router
    let router = HybridQueryRouter::new(
        HybridQueryRouterConfig::default(),
        degradation_service,
    );

    // Test entity timeline query (simple)
    let simple_query = HybridQuery {
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Test Character".to_string(),
            entity_id: Some(Uuid::new_v4()),
            include_current_state: true,
        },
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: HybridQueryOptions::default(),
    };

    let routing_decision = router.route_query(&simple_query).await;
    assert!(routing_decision.is_ok());
    
    let decision = routing_decision.unwrap();
    assert!(matches!(decision.strategy, QueryRoutingStrategy::FullEcsEnhanced));

    // Test complex narrative query
    let complex_query = HybridQuery {
        query_type: HybridQueryType::NarrativeQuery {
            query_text: "Show me all characters who have interacted with magical items".to_string(),
            focus_entities: None,
            time_range: None,
        },
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        max_results: 1000,
        include_current_state: true,
        include_relationships: true,
        options: HybridQueryOptions::default(),
    };

    let complex_routing_decision = router.route_query(&complex_query).await;
    assert!(complex_routing_decision.is_ok());
    
    let complex_decision = complex_routing_decision.unwrap();
    // Should still route to full ECS when healthy
    assert!(matches!(complex_decision.strategy, QueryRoutingStrategy::FullEcsEnhanced));
}

#[tokio::test]
async fn test_circuit_breaker_recording() {
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
        feature_flags,
        Some(entity_manager),
        Default::default(),
    ));

    // Create router
    let router = HybridQueryRouter::new(
        HybridQueryRouterConfig::default(),
        degradation_service,
    );

    // Test successful operation recording
    let success_result = router.record_operation_result("ecs", true, 100).await;
    assert!(success_result.is_ok());

    // Test failure operation recording
    let failure_result = router.record_operation_result("ecs", false, 5000).await;
    assert!(failure_result.is_ok());

    // Test unknown service recording (should not error)
    let unknown_result = router.record_operation_result("unknown", true, 100).await;
    assert!(unknown_result.is_ok());
}

#[tokio::test]
async fn test_failure_mode_classification() {
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
        feature_flags,
        Some(entity_manager),
        Default::default(),
    ));

    // Create router
    let router = HybridQueryRouter::new(
        HybridQueryRouterConfig::default(),
        degradation_service,
    );

    // Test database error classification
    let db_error = AppError::DatabaseQueryError("Connection timeout".to_string());
    let failure_mode = router.classify_failure_mode(&db_error, "test_service");
    assert!(matches!(failure_mode, FailureMode::ServiceUnavailable { .. }));

    // Test unauthorized error classification
    let auth_error = AppError::Unauthorized("Invalid token".to_string());
    let auth_failure_mode = router.classify_failure_mode(&auth_error, "test_service");
    assert!(matches!(auth_failure_mode, FailureMode::AuthorizationFailure { .. }));

    // Test validation error classification
    let validation_error = AppError::ValidationError(Default::default());
    let validation_failure_mode = router.classify_failure_mode(&validation_error, "test_service");
    assert!(matches!(validation_failure_mode, FailureMode::QueryTooComplex { .. }));

    // Test timeout error classification
    let timeout_error = AppError::InternalServerErrorGeneric("Operation timeout exceeded".to_string());
    let timeout_failure_mode = router.classify_failure_mode(&timeout_error, "test_service");
    assert!(matches!(timeout_failure_mode, FailureMode::ServiceDegraded { .. }));

    // Test unknown error classification
    let unknown_error = AppError::ConfigError("Unknown config issue".to_string());
    let unknown_failure_mode = router.classify_failure_mode(&unknown_error, "test_service");
    assert!(matches!(unknown_failure_mode, FailureMode::UnknownError { .. }));
}

#[tokio::test]
async fn test_routing_metrics() {
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
        feature_flags,
        Some(entity_manager),
        Default::default(),
    ));

    // Create router
    let router = HybridQueryRouter::new(
        HybridQueryRouterConfig::default(),
        degradation_service,
    );

    // Get initial metrics
    let metrics_result = router.get_routing_metrics().await;
    assert!(metrics_result.is_ok());
    
    let metrics = metrics_result.unwrap();
    assert_eq!(metrics.total_queries, 0);
    assert!(metrics.strategy_counts.is_empty());
    assert!(metrics.avg_response_times.is_empty());

    // Test query to update metrics
    let test_query = HybridQuery {
        query_type: HybridQueryType::EntityTimeline {
            entity_name: "Test Character".to_string(),
            entity_id: Some(Uuid::new_v4()),
            include_current_state: true,
        },
        user_id: Uuid::new_v4(),
        chronicle_id: Some(Uuid::new_v4()),
        max_results: 10,
        include_current_state: true,
        include_relationships: false,
        options: HybridQueryOptions::default(),
    };

    let routing_result = router.route_query(&test_query).await;
    assert!(routing_result.is_ok());

    // Get updated metrics
    let updated_metrics_result = router.get_routing_metrics().await;
    assert!(updated_metrics_result.is_ok());
    
    let updated_metrics = updated_metrics_result.unwrap();
    assert_eq!(updated_metrics.total_queries, 1);
    assert!(!updated_metrics.strategy_counts.is_empty());
}

#[tokio::test]
async fn test_router_configuration() {
    // Test default configuration
    let default_config = HybridQueryRouterConfig::default();
    
    assert!(default_config.enable_intelligent_routing);
    assert_eq!(default_config.health_check_interval_secs, 30);
    assert_eq!(default_config.performance_window_secs, 300);
    assert_eq!(default_config.default_performance_contract.max_response_time_ms, 5000);
    assert_eq!(default_config.default_performance_contract.min_quality_score, 0.7);
    assert!(default_config.default_performance_contract.allow_fallback);
    assert!(default_config.default_performance_contract.allow_partial_results);

    // Test custom configuration
    let custom_config = HybridQueryRouterConfig {
        enable_intelligent_routing: false,
        health_check_interval_secs: 60,
        performance_window_secs: 600,
        circuit_breaker_config: Default::default(),
        default_performance_contract: QueryPerformanceContract {
            max_response_time_ms: 10000,
            min_quality_score: 0.8,
            allow_fallback: false,
            allow_partial_results: false,
        },
    };
    
    assert!(!custom_config.enable_intelligent_routing);
    assert_eq!(custom_config.health_check_interval_secs, 60);
    assert_eq!(custom_config.performance_window_secs, 600);
    assert_eq!(custom_config.default_performance_contract.max_response_time_ms, 10000);
    assert_eq!(custom_config.default_performance_contract.min_quality_score, 0.8);
    assert!(!custom_config.default_performance_contract.allow_fallback);
    assert!(!custom_config.default_performance_contract.allow_partial_results);
}

#[tokio::test]
async fn test_data_volume_classification() {
    // Test DataVolume enum comparison
    assert_eq!(DataVolume::Small, DataVolume::Small);
    assert_ne!(DataVolume::Small, DataVolume::Medium);
    assert_ne!(DataVolume::Medium, DataVolume::Large);
    
    // Test that different volumes are properly differentiated
    let small_volume = DataVolume::Small;
    let medium_volume = DataVolume::Medium;
    let large_volume = DataVolume::Large;
    
    assert!(small_volume == DataVolume::Small);
    assert!(medium_volume == DataVolume::Medium);
    assert!(large_volume == DataVolume::Large);
}