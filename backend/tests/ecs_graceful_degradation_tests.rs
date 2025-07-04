//! Tests for ECS Graceful Degradation Service
//!
//! These tests verify Phase 4.1.3 implementation:
//! - Chronicle system continues working if ECS fails
//! - RAG falls back to chronicle-only mode
//! - ECS state rebuilds automatically on recovery
//! - Chronicle functionality unaffected by ECS issues

use scribe_backend::{
    config::NarrativeFeatureFlags,
    services::{
        ecs_graceful_degradation::{
            EcsGracefulDegradation, GracefulDegradationConfig, CircuitState,
            EcsHealthStatus, FallbackOperationResult
        },
        chronicle_ecs_consistency_monitor::{
            ChronicleEcsConsistencyMonitor, ConsistencyMonitorConfig
        },
        chronicle_ecs_translator::ChronicleEcsTranslator,
        ecs_entity_manager::{EcsEntityManager, EntityManagerConfig},
    },
    test_helpers::{spawn_app_permissive_rate_limiting, TestApp, TestDataGuard},
    errors::AppError,
};
use std::sync::Arc;
use tokio::time::Duration;
use uuid::Uuid;

/// Test creating graceful degradation service with ECS enabled
#[tokio::test]
async fn test_create_graceful_degradation_with_ecs_enabled() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create feature flags with ECS enabled
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = Some(create_test_entity_manager(&app).await);
    let consistency_monitor = Some(create_test_consistency_monitor(&app).await);
    
    // Create the graceful degradation service
    let config = GracefulDegradationConfig::default();
    let degradation = EcsGracefulDegradation::new(
        config,
        feature_flags,
        entity_manager,
        consistency_monitor,
    );
    
    // Verify initial state
    assert!(degradation.is_ecs_available().await);
    
    let health = degradation.get_health_status().await;
    assert_eq!(health.circuit_state, CircuitState::Closed);
    assert!(health.ecs_available);
    assert!(!health.fallback_mode_active);
    assert!(health.operational_mode.contains("ECS Active"));
}

/// Test creating graceful degradation service with ECS disabled
#[tokio::test]
async fn test_create_graceful_degradation_with_ecs_disabled() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create feature flags with ECS disabled
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_ecs_system = false;
    let feature_flags = Arc::new(feature_flags);
    
    // Create the graceful degradation service (no entity manager when disabled)
    let config = GracefulDegradationConfig::default();
    let degradation = EcsGracefulDegradation::new(
        config,
        feature_flags,
        None,
        None,
    );
    
    // Verify ECS is unavailable
    assert!(!degradation.is_ecs_available().await);
    
    let health = degradation.get_health_status().await;
    assert_eq!(health.circuit_state, CircuitState::Open);
    assert!(!health.ecs_available);
    assert!(health.fallback_mode_active);
    assert!(health.operational_mode.contains("Chronicle-Only"));
}

/// Test fallback operation when ECS is available
#[tokio::test]
async fn test_fallback_operation_with_ecs_available() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = Some(create_test_entity_manager(&app).await);
    
    let config = GracefulDegradationConfig::default();
    let degradation = EcsGracefulDegradation::new(
        config,
        feature_flags,
        entity_manager,
        None,
    );
    
    // Test successful ECS operation
    let result = degradation.execute_with_fallback(
        "test_operation",
        async { Ok("ecs_result".to_string()) },
        async { Ok("fallback_result".to_string()) },
    ).await;
    
    assert!(result.result.is_ok());
    assert_eq!(result.result.unwrap(), "ecs_result");
    assert!(result.served_from_ecs);
    assert!(!result.fallback_occurred);
    assert!(result.warnings.is_empty());
}

/// Test fallback operation when ECS is unavailable
#[tokio::test]
async fn test_fallback_operation_with_ecs_unavailable() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create feature flags with ECS disabled
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_ecs_system = false;
    let feature_flags = Arc::new(feature_flags);
    
    let config = GracefulDegradationConfig::default();
    let degradation = EcsGracefulDegradation::new(
        config,
        feature_flags,
        None,
        None,
    );
    
    // Test operation with ECS unavailable
    let result = degradation.execute_with_fallback(
        "test_operation",
        async { Ok("ecs_result".to_string()) },
        async { Ok("fallback_result".to_string()) },
    ).await;
    
    assert!(result.result.is_ok());
    assert_eq!(result.result.unwrap(), "fallback_result");
    assert!(!result.served_from_ecs);
    assert!(result.fallback_occurred);
    assert!(!result.warnings.is_empty());
    assert!(result.warnings[0].contains("ECS unavailable"));
}

/// Test fallback when ECS operation fails
#[tokio::test]
async fn test_fallback_operation_when_ecs_fails() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = Some(create_test_entity_manager(&app).await);
    
    let config = GracefulDegradationConfig::default();
    let degradation = EcsGracefulDegradation::new(
        config,
        feature_flags,
        entity_manager,
        None,
    );
    
    // Test ECS operation that fails
    let result = degradation.execute_with_fallback(
        "test_operation",
        async { Err(AppError::InternalServerErrorGeneric("ECS failed".to_string())) },
        async { Ok("fallback_result".to_string()) },
    ).await;
    
    assert!(result.result.is_ok());
    assert_eq!(result.result.unwrap(), "fallback_result");
    assert!(!result.served_from_ecs);
    assert!(result.fallback_occurred);
    assert!(!result.warnings.is_empty());
    assert!(result.warnings[0].contains("ECS operation failed"));
}

/// Test circuit breaker behavior with repeated failures
#[tokio::test]
async fn test_circuit_breaker_opens_on_repeated_failures() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = Some(create_test_entity_manager(&app).await);
    
    let mut config = GracefulDegradationConfig::default();
    config.failure_threshold = 3; // Open circuit after 3 failures
    
    let degradation = EcsGracefulDegradation::new(
        config,
        feature_flags,
        entity_manager,
        None,
    );
    
    // Verify initially closed
    assert_eq!(degradation.get_health_status().await.circuit_state, CircuitState::Closed);
    
    // Cause multiple failures
    for i in 1..=3 {
        let result = degradation.execute_with_fallback(
            "failing_operation",
            async { Err(AppError::InternalServerErrorGeneric("Simulated failure".to_string())) },
            async { Ok(format!("fallback_{}", i)) },
        ).await;
        
        assert!(result.result.is_ok());
        assert!(result.fallback_occurred);
    }
    
    // Circuit should now be open
    let health = degradation.get_health_status().await;
    assert_eq!(health.circuit_state, CircuitState::Open);
    assert!(health.fallback_mode_active);
    assert!(health.operational_mode.contains("Chronicle-Only"));
    assert_eq!(health.recent_failures, 3);
}

/// Test manual recovery attempt when ECS is available
#[tokio::test]
async fn test_manual_recovery_attempt_success() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = Some(create_test_entity_manager(&app).await);
    
    let config = GracefulDegradationConfig::default();
    let degradation = EcsGracefulDegradation::new(
        config,
        feature_flags,
        entity_manager,
        None,
    );
    
    // Attempt manual recovery
    let recovery_result = degradation.attempt_recovery().await;
    assert!(recovery_result.is_ok());
    
    let result = recovery_result.unwrap();
    assert!(result.success);
    assert!(result.error_message.is_none());
    assert_eq!(result.reconstruction_attempted, false); // No consistency monitor
}

/// Test manual recovery attempt when ECS is disabled
#[tokio::test]
async fn test_manual_recovery_attempt_ecs_disabled() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create feature flags with ECS disabled
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_ecs_system = false;
    let feature_flags = Arc::new(feature_flags);
    
    let config = GracefulDegradationConfig::default();
    let degradation = EcsGracefulDegradation::new(
        config,
        feature_flags,
        None,
        None,
    );
    
    // Attempt manual recovery
    let recovery_result = degradation.attempt_recovery().await;
    assert!(recovery_result.is_ok());
    
    let result = recovery_result.unwrap();
    assert!(!result.success);
    assert!(result.error_message.is_some());
    assert!(result.error_message.unwrap().contains("ECS system disabled"));
}

/// Test health status reporting
#[tokio::test]
async fn test_health_status_reporting() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = Some(create_test_entity_manager(&app).await);
    
    let mut config = GracefulDegradationConfig::default();
    config.enable_auto_recovery = true;
    
    let degradation = EcsGracefulDegradation::new(
        config,
        feature_flags,
        entity_manager,
        None,
    );
    
    let health = degradation.get_health_status().await;
    
    // Verify health status fields
    assert_eq!(health.circuit_state, CircuitState::Closed);
    assert!(health.ecs_available);
    assert!(!health.fallback_mode_active);
    assert_eq!(health.recent_failures, 0);
    assert!(health.last_failure_time.is_none());
    assert!(health.last_success_time.is_none());
    assert!(health.circuit_opened_time.is_none());
    assert!(health.auto_recovery_enabled);
    assert!(health.last_recovery_attempt.is_none());
    assert!(health.operational_mode.contains("ECS Active"));
}

/// Test configuration options
#[tokio::test]
async fn test_configuration_options() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = Some(create_test_entity_manager(&app).await);
    
    // Test custom configuration
    let mut config = GracefulDegradationConfig::default();
    config.failure_threshold = 10;
    config.failure_window_secs = 120;
    config.circuit_timeout_secs = 600;
    config.enable_auto_recovery = false;
    config.recovery_check_interval_secs = 60;
    config.enable_auto_reconstruction = false;
    config.reconstruction_timeout_secs = 3600;
    
    let degradation = EcsGracefulDegradation::new(
        config,
        feature_flags,
        entity_manager,
        None,
    );
    
    // Verify the service accepts custom configuration
    let health = degradation.get_health_status().await;
    assert!(!health.auto_recovery_enabled);
}

/// Test service start functionality
#[tokio::test]
async fn test_service_start() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let entity_manager = Some(create_test_entity_manager(&app).await);
    
    let mut config = GracefulDegradationConfig::default();
    config.enable_auto_recovery = false; // Disable to avoid background tasks in test
    
    let degradation = EcsGracefulDegradation::new(
        config,
        feature_flags,
        entity_manager,
        None,
    );
    
    // Start the service
    let start_result = degradation.start().await;
    assert!(start_result.is_ok());
}

/// Test CircuitState enum values
#[test]
fn test_circuit_state_values() {
    let closed = CircuitState::Closed;
    let open = CircuitState::Open;
    let half_open = CircuitState::HalfOpen;
    
    assert_eq!(closed, CircuitState::Closed);
    assert_ne!(closed, open);
    assert_ne!(open, half_open);
    assert_ne!(half_open, closed);
    
    // Test that all states are different
    let states = vec![closed, open, half_open];
    for (i, state1) in states.iter().enumerate() {
        for (j, state2) in states.iter().enumerate() {
            if i != j {
                assert_ne!(state1, state2);
            }
        }
    }
}

/// Test FallbackOperationResult structure
#[tokio::test]
async fn test_fallback_operation_result_structure() {
    // Test successful ECS result
    let ecs_success = FallbackOperationResult {
        result: Ok("test_result".to_string()),
        served_from_ecs: true,
        fallback_occurred: false,
        warnings: Vec::new(),
    };
    
    assert!(ecs_success.result.is_ok());
    assert!(ecs_success.served_from_ecs);
    assert!(!ecs_success.fallback_occurred);
    assert!(ecs_success.warnings.is_empty());
    
    // Test fallback result
    let fallback_result = FallbackOperationResult {
        result: Ok("fallback_result".to_string()),
        served_from_ecs: false,
        fallback_occurred: true,
        warnings: vec!["ECS unavailable".to_string()],
    };
    
    assert!(fallback_result.result.is_ok());
    assert!(!fallback_result.served_from_ecs);
    assert!(fallback_result.fallback_occurred);
    assert_eq!(fallback_result.warnings.len(), 1);
    assert!(fallback_result.warnings[0].contains("ECS unavailable"));
}

/// Test that fallback preserves chronicle functionality
#[tokio::test]
async fn test_chronicle_functionality_preserved() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create degradation service with ECS disabled to simulate failure
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_ecs_system = false;
    let feature_flags = Arc::new(feature_flags);
    
    let config = GracefulDegradationConfig::default();
    let degradation = EcsGracefulDegradation::new(
        config,
        feature_flags,
        None,
        None,
    );
    
    // Simulate chronicle operations that should continue working
    let chronicle_operations = vec![
        "chronicle_query",
        "event_creation", 
        "narrative_search",
        "rag_retrieval",
    ];
    
    for operation in chronicle_operations {
        let result = degradation.execute_with_fallback(
            operation,
            async { Ok(format!("ecs_{}", operation)) },
            async { Ok(format!("chronicle_{}", operation)) },
        ).await;
        
        // All operations should succeed via fallback
        assert!(result.result.is_ok());
        assert!(result.result.unwrap().starts_with("chronicle_"));
        assert!(!result.served_from_ecs);
        assert!(result.fallback_occurred);
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

async fn create_test_consistency_monitor(app: &TestApp) -> Arc<ChronicleEcsConsistencyMonitor> {
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let translator = Arc::new(create_test_translator(&app).await);
    let entity_manager = create_test_entity_manager(&app).await;
    
    let config = ConsistencyMonitorConfig::default();
    Arc::new(ChronicleEcsConsistencyMonitor::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        translator,
        entity_manager,
    ))
}

async fn create_test_translator(app: &TestApp) -> ChronicleEcsTranslator {
    ChronicleEcsTranslator::new(
        app.db_pool.clone().into(),
    )
}