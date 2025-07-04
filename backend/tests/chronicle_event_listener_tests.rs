//! Tests for Chronicle Event Listener Service
//!
//! These tests verify Phase 4.1.1 implementation:
//! - Chronicle event listening with toggle capability
//! - Feature flag respecting behavior
//! - Graceful degradation when ECS is disabled
//! - User-scoped processing

use scribe_backend::{
    config::NarrativeFeatureFlags,
    services::{
        chronicle_event_listener::{
            ChronicleEventListener, ChronicleEventListenerConfig, 
            ChronicleEventNotification, ChronicleNotificationType
        },
        chronicle_ecs_translator::ChronicleEcsTranslator,
        ecs_entity_manager::{EcsEntityManager, EntityManagerConfig},
    },
    test_helpers::{spawn_app_permissive_rate_limiting, TestApp, TestDataGuard},
};
use std::sync::Arc;
use tokio::time::Duration;
use uuid::Uuid;

/// Test creating a chronicle event listener with default configuration
#[tokio::test]
async fn test_create_chronicle_event_listener() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create required dependencies
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let translator = create_test_translator(&app).await;
    let entity_manager = create_test_entity_manager(&app).await;
    
    // Create the listener
    let config = ChronicleEventListenerConfig::default();
    let listener = ChronicleEventListener::new(
        config,
        feature_flags,
        translator,
        entity_manager,
    );
    
    // Verify we can get a sender handle
    let sender = listener.get_event_sender();
    assert!(!sender.is_closed());
}

/// Test that listener respects ECS system feature flag
#[tokio::test]
async fn test_listener_respects_ecs_disabled_flag() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create feature flags with ECS disabled
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_ecs_system = false; // ECS disabled
    let feature_flags = Arc::new(feature_flags);
    
    let translator = create_test_translator(&app).await;
    let entity_manager = create_test_entity_manager(&app).await;
    
    // Create and start the listener
    let config = ChronicleEventListenerConfig::default();
    let mut listener = ChronicleEventListener::new(
        config,
        feature_flags,
        translator,
        entity_manager,
    );
    
    // Starting should succeed but do nothing
    let result = listener.start().await;
    assert!(result.is_ok());
    
    // Sending events should still work (they'll just be ignored)
    let notification = create_test_notification();
    let result = listener.notify_chronicle_event(notification).await;
    assert!(result.is_ok());
}

/// Test that listener respects user-specific ECS rollout
#[tokio::test]
async fn test_listener_respects_user_rollout() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create feature flags with partial rollout
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_ecs_system = true;
    feature_flags.enable_chronicle_to_ecs_sync = true;
    feature_flags.ecs_rollout_percentage = 0; // No users get ECS
    let feature_flags = Arc::new(feature_flags);
    
    let user_id = "test_user_123";
    
    // Verify user is not in rollout
    assert!(!feature_flags.should_sync_chronicle_to_ecs(user_id));
    
    // Update rollout to 100%
    let mut feature_flags_full = NarrativeFeatureFlags::default();
    feature_flags_full.enable_ecs_system = true;
    feature_flags_full.enable_chronicle_to_ecs_sync = true;
    feature_flags_full.ecs_rollout_percentage = 100; // All users get ECS
    let feature_flags_full = Arc::new(feature_flags_full);
    
    // Verify user is now in rollout
    assert!(feature_flags_full.should_sync_chronicle_to_ecs(user_id));
}

/// Test processing different types of chronicle event notifications
#[tokio::test]
async fn test_chronicle_event_notification_types() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create listener with ECS enabled
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let translator = create_test_translator(&app).await;
    let entity_manager = create_test_entity_manager(&app).await;
    
    let config = ChronicleEventListenerConfig::default();
    let mut listener = ChronicleEventListener::new(
        config,
        feature_flags,
        translator,
        entity_manager,
    );
    
    // Start the listener
    let start_result = listener.start().await;
    assert!(start_result.is_ok());
    
    // Test different notification types
    let base_notification = create_test_notification();
    
    // Test Created notification
    let created_notification = ChronicleEventNotification {
        notification_type: ChronicleNotificationType::Created,
        ..base_notification.clone()
    };
    
    let result = listener.notify_chronicle_event(created_notification).await;
    assert!(result.is_ok());
    
    // Test Updated notification
    let updated_notification = ChronicleEventNotification {
        notification_type: ChronicleNotificationType::Updated,
        ..base_notification.clone()
    };
    
    let result = listener.notify_chronicle_event(updated_notification).await;
    assert!(result.is_ok());
    
    // Test Deleted notification
    let deleted_notification = ChronicleEventNotification {
        notification_type: ChronicleNotificationType::Deleted,
        ..base_notification.clone()
    };
    
    let result = listener.notify_chronicle_event(deleted_notification).await;
    assert!(result.is_ok());
    
    // Test BulkUpdate notification
    let bulk_notification = ChronicleEventNotification {
        notification_type: ChronicleNotificationType::BulkUpdate { event_count: 50 },
        ..base_notification
    };
    
    let result = listener.notify_chronicle_event(bulk_notification).await;
    assert!(result.is_ok());
    
    // Give time for processing (in real implementation, we'd have better synchronization)
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Test listener metrics collection
#[tokio::test]
async fn test_listener_metrics() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create listener with metrics enabled
    let feature_flags = Arc::new(NarrativeFeatureFlags::development());
    let translator = create_test_translator(&app).await;
    let entity_manager = create_test_entity_manager(&app).await;
    
    let mut config = ChronicleEventListenerConfig::default();
    config.enable_metrics = true;
    
    let listener = ChronicleEventListener::new(
        config,
        feature_flags,
        translator,
        entity_manager,
    );
    
    // Get initial metrics
    let initial_metrics = listener.get_metrics();
    assert_eq!(initial_metrics.events_processed, 0);
    assert_eq!(initial_metrics.events_skipped, 0);
    assert_eq!(initial_metrics.events_failed, 0);
}

/// Test chronicle notification type string conversion
#[test]
fn test_chronicle_notification_type_conversion() {
    use scribe_backend::services::chronicle_event_listener::ChronicleNotificationType;
    
    // Test string representation
    assert_eq!(
        format!("{:?}", ChronicleNotificationType::Created),
        "Created"
    );
    assert_eq!(
        format!("{:?}", ChronicleNotificationType::Updated), 
        "Updated"
    );
    assert_eq!(
        format!("{:?}", ChronicleNotificationType::Deleted),
        "Deleted"
    );
    assert_eq!(
        format!("{:?}", ChronicleNotificationType::BulkUpdate { event_count: 10 }),
        "BulkUpdate { event_count: 10 }"
    );
}

/// Test feature flag validation for ECS features
#[test]
fn test_ecs_feature_flag_validation() {
    let mut flags = NarrativeFeatureFlags::default();
    
    // Valid configuration should pass
    assert!(flags.validate().is_ok());
    
    // Invalid ECS rollout percentage
    flags.ecs_rollout_percentage = 150;
    assert!(flags.validate().is_err());
    
    // Reset to valid state
    flags.ecs_rollout_percentage = 50;
    assert!(flags.validate().is_ok());
    
    // Chronicle-to-ECS sync without ECS system
    flags.enable_chronicle_to_ecs_sync = true;
    flags.enable_ecs_system = false;
    assert!(flags.validate().is_err());
    
    // ECS-to-chronicle sync without ECS system
    flags.enable_chronicle_to_ecs_sync = false;
    flags.enable_ecs_to_chronicle_sync = true;
    flags.enable_ecs_system = false;
    assert!(flags.validate().is_err());
    
    // ECS enhanced RAG without ECS system
    flags.enable_ecs_to_chronicle_sync = false;
    flags.enable_ecs_enhanced_rag = true;
    flags.enable_ecs_system = false;
    assert!(flags.validate().is_err());
}

/// Test that compatibility mode can be enabled/disabled
#[test]
fn test_ecs_compatibility_mode() {
    let mut flags = NarrativeFeatureFlags::default();
    
    // Default should have compatibility mode enabled
    assert!(flags.is_ecs_compatibility_mode());
    
    // Disable compatibility mode
    flags.enable_ecs_compatibility_mode = false;
    assert!(!flags.is_ecs_compatibility_mode());
    
    // Development flags should have compatibility mode enabled
    let dev_flags = NarrativeFeatureFlags::development();
    assert!(dev_flags.is_ecs_compatibility_mode());
    
    // Production flags should have compatibility mode enabled
    let prod_flags = NarrativeFeatureFlags::production_rollout(50);
    assert!(prod_flags.is_ecs_compatibility_mode());
}

/// Test ECS user determination with different rollout percentages
#[test]
fn test_ecs_user_determination_rollout() {
    let mut flags = NarrativeFeatureFlags::default();
    flags.enable_ecs_system = true;
    
    // Test 0% rollout
    flags.ecs_rollout_percentage = 0;
    assert!(!flags.should_use_ecs_for_user("any_user"));
    
    // Test 100% rollout
    flags.ecs_rollout_percentage = 100;
    assert!(flags.should_use_ecs_for_user("any_user"));
    
    // Test consistent hashing (same user should always get same result)
    flags.ecs_rollout_percentage = 50;
    let user_id = "consistent_test_user";
    let result1 = flags.should_use_ecs_for_user(user_id);
    let result2 = flags.should_use_ecs_for_user(user_id);
    assert_eq!(result1, result2);
}

// Helper functions for test setup

async fn create_test_translator(app: &TestApp) -> Arc<ChronicleEcsTranslator> {
    // In a real implementation, this would create a properly configured translator
    // For now, we'll create a minimal one for testing
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

fn create_test_notification() -> ChronicleEventNotification {
    ChronicleEventNotification {
        event_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        chronicle_id: Uuid::new_v4(),
        event_type: "CHARACTER".to_string(),
        notification_type: ChronicleNotificationType::Created,
    }
}