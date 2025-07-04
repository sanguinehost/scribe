//! Tests for Chronicle-ECS Consistency Monitor Service
//!
//! These tests verify Phase 4.1.2 implementation:
//! - Consistency checking between chronicle events and ECS state
//! - State reconstruction from chronicle events
//! - Health monitoring and reporting
//! - Inconsistency detection and classification

use scribe_backend::{
    config::NarrativeFeatureFlags,
    services::{
        chronicle_ecs_consistency_monitor::{
            ChronicleEcsConsistencyMonitor, ConsistencyMonitorConfig, ConsistencyCheckResult,
            InconsistencyType, InconsistencySeverity, StateReconstructionResult, HealthStatus
        },
        chronicle_ecs_translator::ChronicleEcsTranslator,
        ecs_entity_manager::{EcsEntityManager, EntityManagerConfig},
    },
    test_helpers::{spawn_app_permissive_rate_limiting, TestApp, TestDataGuard},
};
use std::sync::Arc;
use tokio::time::Duration;
use uuid::Uuid;

/// Test creating a consistency monitor with default configuration
#[tokio::test]
async fn test_create_consistency_monitor() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create required dependencies
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let translator = create_test_translator(&app).await;
    let entity_manager = create_test_entity_manager(&app).await;
    
    // Create the monitor
    let config = ConsistencyMonitorConfig::default();
    let monitor = ChronicleEcsConsistencyMonitor::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        translator,
        entity_manager,
    );
    
    // Verify basic functionality
    let user_id = Uuid::new_v4();
    let health_status = monitor.get_consistency_health_status(Some(user_id)).await;
    assert!(health_status.is_ok());
    
    let health = health_status.unwrap();
    assert_eq!(health.overall_health, HealthStatus::Healthy);
}

/// Test consistency checking when ECS system is disabled
#[tokio::test] 
async fn test_consistency_check_with_ecs_disabled() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create feature flags with ECS disabled
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_ecs_system = false;
    let feature_flags = Arc::new(feature_flags);
    
    let translator = create_test_translator(&app).await;
    let entity_manager = create_test_entity_manager(&app).await;
    
    // Create the monitor
    let config = ConsistencyMonitorConfig::default();
    let monitor = ChronicleEcsConsistencyMonitor::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        translator,
        entity_manager,
    );
    
    // Run consistency check
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    let result = monitor.check_chronicle_consistency(user_id, chronicle_id).await;
    assert!(result.is_ok());
    
    let check_result = result.unwrap();
    assert!(check_result.is_consistent);
    assert_eq!(check_result.total_events_processed, 0);
    assert!(check_result.summary.contains("ECS system disabled"));
}

/// Test consistency checking with ECS enabled but no events
#[tokio::test]
async fn test_consistency_check_with_no_events() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create feature flags with ECS enabled
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let translator = create_test_translator(&app).await;
    let entity_manager = create_test_entity_manager(&app).await;
    
    // Create the monitor
    let config = ConsistencyMonitorConfig::default();
    let monitor = ChronicleEcsConsistencyMonitor::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        translator,
        entity_manager,
    );
    
    // Run consistency check on non-existent chronicle
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    let result = monitor.check_chronicle_consistency(user_id, chronicle_id).await;
    assert!(result.is_ok());
    
    let check_result = result.unwrap();
    assert!(check_result.is_consistent);
    assert_eq!(check_result.total_events_processed, 0);
    assert_eq!(check_result.inconsistencies_detected, 0);
}

/// Test state reconstruction when ECS system is disabled
#[tokio::test]
async fn test_state_reconstruction_with_ecs_disabled() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create feature flags with ECS disabled
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_ecs_system = false;
    let feature_flags = Arc::new(feature_flags);
    
    let translator = create_test_translator(&app).await;
    let entity_manager = create_test_entity_manager(&app).await;
    
    // Create the monitor
    let config = ConsistencyMonitorConfig::default();
    let monitor = ChronicleEcsConsistencyMonitor::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        translator,
        entity_manager,
    );
    
    // Attempt state reconstruction - should fail
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    let result = monitor.reconstruct_ecs_state_from_chronicle(user_id, chronicle_id, false).await;
    assert!(result.is_err());
    
    if let Err(error) = result {
        assert!(error.to_string().contains("ECS system disabled"));
    }
}

/// Test state reconstruction with ECS enabled but no events
#[tokio::test]
async fn test_state_reconstruction_with_no_events() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create feature flags with ECS enabled
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let translator = create_test_translator(&app).await;
    let entity_manager = create_test_entity_manager(&app).await;
    
    // Create the monitor
    let config = ConsistencyMonitorConfig::default();
    let monitor = ChronicleEcsConsistencyMonitor::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        translator,
        entity_manager,
    );
    
    // Run state reconstruction on non-existent chronicle
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    let result = monitor.reconstruct_ecs_state_from_chronicle(user_id, chronicle_id, false).await;
    assert!(result.is_ok());
    
    let reconstruction_result = result.unwrap();
    assert!(reconstruction_result.success);
    assert_eq!(reconstruction_result.events_processed, 0);
    assert_eq!(reconstruction_result.entities_created, 0);
}

/// Test health status reporting
#[tokio::test]
async fn test_consistency_health_status() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let translator = create_test_translator(&app).await;
    let entity_manager = create_test_entity_manager(&app).await;
    
    // Create the monitor
    let config = ConsistencyMonitorConfig::default();
    let monitor = ChronicleEcsConsistencyMonitor::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        translator,
        entity_manager,
    );
    
    // Test health status with no user filter
    let health_status = monitor.get_consistency_health_status(None).await;
    assert!(health_status.is_ok());
    
    let health = health_status.unwrap();
    assert_eq!(health.overall_health, HealthStatus::Healthy);
    assert_eq!(health.total_chronicles_checked, 0);
    assert_eq!(health.consistent_chronicles, 0);
    assert_eq!(health.inconsistent_chronicles, 0);
    assert_eq!(health.critical_inconsistencies, 0);
    assert_eq!(health.auto_repairs_performed, 0);
    
    // Test health status with specific user
    let user_id = Uuid::new_v4();
    let health_status_user = monitor.get_consistency_health_status(Some(user_id)).await;
    assert!(health_status_user.is_ok());
    
    let health_user = health_status_user.unwrap();
    assert_eq!(health_user.overall_health, HealthStatus::Healthy);
}

/// Test monitor configuration options
#[tokio::test]
async fn test_monitor_configuration_options() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let translator = create_test_translator(&app).await;
    let entity_manager = create_test_entity_manager(&app).await;
    
    // Test with custom configuration
    let mut config = ConsistencyMonitorConfig::default();
    config.enable_component_validation = false;
    config.enable_relationship_validation = false;
    config.enable_auto_repair = true;
    config.max_inconsistencies_reported = 50;
    config.check_timeout_secs = 600;
    config.enable_parallel_processing = false;
    
    let monitor = ChronicleEcsConsistencyMonitor::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        translator,
        entity_manager,
    );
    
    // Verify monitor accepts custom configuration
    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    
    let result = monitor.check_chronicle_consistency(user_id, chronicle_id).await;
    assert!(result.is_ok());
}

/// Test inconsistency type and severity classifications
#[test]
fn test_inconsistency_classifications() {
    // Test InconsistencyType variants
    let missing_entity = InconsistencyType::MissingEntity;
    let orphaned_entity = InconsistencyType::OrphanedEntity;
    let missing_component = InconsistencyType::MissingComponent;
    let component_mismatch = InconsistencyType::ComponentDataMismatch;
    
    assert_eq!(missing_entity, InconsistencyType::MissingEntity);
    assert_ne!(missing_entity, orphaned_entity);
    
    // Test InconsistencySeverity variants
    let critical = InconsistencySeverity::Critical;
    let high = InconsistencySeverity::High;
    let medium = InconsistencySeverity::Medium;
    let low = InconsistencySeverity::Low;
    
    assert_eq!(critical, InconsistencySeverity::Critical);
    assert_ne!(critical, high);
    
    // Verify all combinations can be created
    assert!(matches!(missing_entity, InconsistencyType::MissingEntity));
    assert!(matches!(critical, InconsistencySeverity::Critical));
}

/// Test HealthStatus values
#[test]
fn test_health_status_values() {
    let healthy = HealthStatus::Healthy;
    let warning = HealthStatus::Warning;
    let critical = HealthStatus::Critical;
    let unknown = HealthStatus::Unknown;
    
    assert_eq!(healthy, HealthStatus::Healthy);
    assert_ne!(healthy, warning);
    assert_ne!(warning, critical);
    assert_ne!(critical, unknown);
    
    // Test that all health statuses are different
    let statuses = vec![healthy, warning, critical, unknown];
    for (i, status1) in statuses.iter().enumerate() {
        for (j, status2) in statuses.iter().enumerate() {
            if i != j {
                assert_ne!(status1, status2);
            }
        }
    }
}

/// Test serialization and deserialization of result types
#[tokio::test]
async fn test_result_serialization() {
    use serde_json;
    
    // Test ConsistencyCheckResult serialization
    let check_result = ConsistencyCheckResult {
        check_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        chronicle_id: Uuid::new_v4(),
        total_events_processed: 10,
        ecs_entities_found: 5,
        expected_entities_count: 5,
        inconsistencies_detected: 0,
        inconsistencies: Vec::new(),
        is_consistent: true,
        check_duration_ms: 250,
        checked_at: chrono::Utc::now(),
        summary: "Test consistency check".to_string(),
    };
    
    let json = serde_json::to_string(&check_result);
    assert!(json.is_ok());
    
    let deserialized: Result<ConsistencyCheckResult, _> = serde_json::from_str(&json.unwrap());
    assert!(deserialized.is_ok());
    
    let restored = deserialized.unwrap();
    assert_eq!(restored.check_id, check_result.check_id);
    assert_eq!(restored.is_consistent, check_result.is_consistent);
    assert_eq!(restored.total_events_processed, check_result.total_events_processed);
}

/// Test concurrent consistency checks
#[tokio::test]
async fn test_concurrent_consistency_checks() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let translator = create_test_translator(&app).await;
    let entity_manager = create_test_entity_manager(&app).await;
    
    // Create the monitor
    let config = ConsistencyMonitorConfig::default();
    let monitor = Arc::new(ChronicleEcsConsistencyMonitor::new(
        app.db_pool.clone().into(),
        config,
        feature_flags,
        translator,
        entity_manager,
    ));
    
    // Run multiple consistency checks concurrently
    let mut handles = Vec::new();
    
    for i in 0..5 {
        let monitor = Arc::clone(&monitor);
        let user_id = Uuid::new_v4();
        let chronicle_id = Uuid::new_v4();
        
        let handle = tokio::spawn(async move {
            let result = monitor.check_chronicle_consistency(user_id, chronicle_id).await;
            (i, result)
        });
        
        handles.push(handle);
    }
    
    // Wait for all checks to complete
    for handle in handles {
        let (index, result) = handle.await.unwrap();
        assert!(result.is_ok(), "Check {} failed: {:?}", index, result);
        
        let check_result = result.unwrap();
        assert!(check_result.is_consistent);
    }
}

// Helper functions for test setup

async fn create_test_translator(app: &TestApp) -> Arc<ChronicleEcsTranslator> {
    Arc::new(ChronicleEcsTranslator::new(
        app.db_pool.clone().into(),
    ))
}

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