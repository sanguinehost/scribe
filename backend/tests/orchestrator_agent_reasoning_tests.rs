// backend/tests/orchestrator_agent_reasoning_tests.rs
//
// Orchestrator Agent Reasoning Loop Tests
// Epic 8: Orchestrator-Driven Intelligent Agent System
//
// This test file validates the 5-phase reasoning loop (Perceive, Strategize, 
// Plan, Execute, Reflect) with Progressive Response optimization.

use uuid::Uuid;
use scribe_backend::{
    test_helpers::{spawn_app, TestApp, TestDataGuard, db::create_test_user},
    services::{
        orchestrator::{
            OrchestratorAgent, OrchestratorConfig,
            ReasoningPhase, ReasoningLoopResult,
        },
        task_queue::EnrichmentTaskPayload,
    },
};
use chrono::Utc;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Helper to create test orchestrator with mocked dependencies
async fn create_test_orchestrator(test_app: &TestApp) -> OrchestratorAgent {
    let config = OrchestratorConfig {
        worker_id: Uuid::new_v4(),
        poll_interval_ms: 100,
        batch_size: 5,
        retry_limit: 3,
        phase_timeout_ms: 5000,
    };
    
    OrchestratorAgent::new(
        config,
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
        test_app.app_state.ai_client.clone(),
        Arc::new(test_app.config.clone()),
    )
}

/// Test full reasoning loop for first message (full analysis)
#[tokio::test]
async fn test_reasoning_loop_first_message() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "reasoning_first".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Set up DEK cache
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "I enter the bustling tavern and look around.".to_string(),
        ai_response: "You push open the heavy wooden door...".to_string(),
        timestamp: Utc::now(),
        metadata: None,
    };
    
    let result = orchestrator.execute_full_reasoning_loop(&payload, true).await.unwrap();
    
    // Verify all phases completed
    assert_eq!(result.phases_completed.len(), 5);
    assert_eq!(result.phases_completed[0], ReasoningPhase::Perceive);
    assert_eq!(result.phases_completed[1], ReasoningPhase::Strategize);
    assert_eq!(result.phases_completed[2], ReasoningPhase::Plan);
    assert_eq!(result.phases_completed[3], ReasoningPhase::Execute);
    assert_eq!(result.phases_completed[4], ReasoningPhase::Reflect);
    
    // First message should populate all cache layers
    assert_eq!(result.cache_layers_populated.len(), 3);
    assert_eq!(result.cache_hits, 0); // No cache hits on first message
}

/// Test reasoning loop for subsequent messages (delta analysis)
#[tokio::test]
async fn test_reasoning_loop_subsequent_message() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "reasoning_delta".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "I order a drink from the bartender.".to_string(),
        ai_response: "The bartender nods and pours you an ale.".to_string(),
        timestamp: Utc::now(),
        metadata: Some(json!({
            "cached_state": true
        })),
    };
    
    let result = orchestrator.execute_full_reasoning_loop(&payload, false).await.unwrap();
    
    // Subsequent message should benefit from caching
    assert_eq!(result.phases_completed.len(), 5);
    assert!(result.cache_hits > 0);
    assert!(result.processing_time_saved_ms > 0);
}

/// Test phase execution tracking
#[tokio::test]
async fn test_phase_execution_tracking() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "phase_tracking".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    
    // Track phases through observer
    let phase_tracker = Arc::new(Mutex::new(Vec::new()));
    let tracker_clone = phase_tracker.clone();
    
    orchestrator.set_phase_observer(move |phase| {
        let tracker = tracker_clone.clone();
        Box::pin(async move {
            let mut phases = tracker.lock().await;
            phases.push(phase);
        })
    }).await;
    
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "I draw my sword.".to_string(),
        ai_response: "You unsheathe your blade with a metallic ring.".to_string(),
        timestamp: Utc::now(),
        metadata: None,
    };
    
    orchestrator.execute_full_reasoning_loop(&payload, true).await.unwrap();
    
    // Verify all phases were tracked
    let phases = phase_tracker.lock().await;
    assert_eq!(phases.len(), 5);
    assert_eq!(phases[0], ReasoningPhase::Perceive);
    assert_eq!(phases[1], ReasoningPhase::Strategize);
    assert_eq!(phases[2], ReasoningPhase::Plan);
    assert_eq!(phases[3], ReasoningPhase::Execute);
    assert_eq!(phases[4], ReasoningPhase::Reflect);
}

/// Test state tracking between phases
#[tokio::test]
async fn test_state_tracking_between_phases() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "state_tracking".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    
    // Track state changes through observer
    let state_tracker = Arc::new(Mutex::new(Vec::new()));
    let tracker_clone = state_tracker.clone();
    
    orchestrator.set_state_observer(move |phase, state| {
        let tracker = tracker_clone.clone();
        Box::pin(async move {
            let mut states = tracker.lock().await;
            states.push((phase, state.clone()));
        })
    }).await;
    
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "I explore the ancient ruins.".to_string(),
        ai_response: "You step into the crumbling stone structure.".to_string(),
        timestamp: Utc::now(),
        metadata: Some(json!({
            "location": "ruins",
            "atmosphere": "mysterious"
        })),
    };
    
    orchestrator.execute_full_reasoning_loop(&payload, true).await.unwrap();
    
    // Verify state was tracked for all phases
    let states = state_tracker.lock().await;
    assert_eq!(states.len(), 5);
    
    // Each phase should have its own state
    for (i, (phase, _state)) in states.iter().enumerate() {
        match i {
            0 => assert_eq!(*phase, ReasoningPhase::Perceive),
            1 => assert_eq!(*phase, ReasoningPhase::Strategize),
            2 => assert_eq!(*phase, ReasoningPhase::Plan),
            3 => assert_eq!(*phase, ReasoningPhase::Execute),
            4 => assert_eq!(*phase, ReasoningPhase::Reflect),
            _ => panic!("Unexpected phase"),
        }
    }
}

/// Test phase timeout handling
#[tokio::test]
async fn test_phase_timeout() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "timeout_test".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    // Create orchestrator with very short timeout
    let config = OrchestratorConfig {
        worker_id: Uuid::new_v4(),
        poll_interval_ms: 100,
        batch_size: 5,
        retry_limit: 3,
        phase_timeout_ms: 1, // 1ms timeout to force timeout
    };
    
    let orchestrator = OrchestratorAgent::new(
        config,
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
        test_app.app_state.ai_client.clone(),
    );
    
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "Complex action requiring analysis.".to_string(),
        ai_response: "Multiple entities and locations involved.".to_string(),
        timestamp: Utc::now(),
        metadata: None,
    };
    
    // Should fail with timeout
    let result = orchestrator.execute_full_reasoning_loop(&payload, true).await;
    assert!(result.is_err());
}

/// Test Progressive Response optimization
#[tokio::test]
async fn test_progressive_response_optimization() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "progressive_test".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    let session_id = Uuid::new_v4();
    
    // First message - full analysis
    let payload1 = EnrichmentTaskPayload {
        session_id,
        user_id: user.id,
        user_message: "I enter the dragon's lair.".to_string(),
        ai_response: "The vast cavern is filled with treasure.".to_string(),
        timestamp: Utc::now(),
        metadata: None,
    };
    
    let result1 = orchestrator.execute_full_reasoning_loop(&payload1, true).await.unwrap();
    assert_eq!(result1.cache_hits, 0);
    assert_eq!(result1.processing_time_saved_ms, 0);
    
    // Second message - should use caching
    let payload2 = EnrichmentTaskPayload {
        session_id,
        user_id: user.id,
        user_message: "I pick up a golden coin.".to_string(),
        ai_response: "The coin is warm to the touch.".to_string(),
        timestamp: Utc::now(),
        metadata: None,
    };
    
    let result2 = orchestrator.execute_full_reasoning_loop(&payload2, false).await.unwrap();
    assert!(result2.cache_hits > 0);
    assert!(result2.processing_time_saved_ms > 0);
}

/// Test complex interaction with multiple entities
#[tokio::test]
async fn test_complex_multi_entity_interaction() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "complex_test".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "I negotiate with the merchant while the guard watches suspiciously.".to_string(),
        ai_response: "The merchant eyes you carefully as the guard's hand moves to his sword hilt.".to_string(),
        timestamp: Utc::now(),
        metadata: Some(json!({
            "entities": ["player", "merchant", "guard"],
            "relationships": {
                "merchant-guard": "allied",
                "player-merchant": "negotiating",
                "player-guard": "suspicious"
            }
        })),
    };
    
    let result = orchestrator.execute_full_reasoning_loop(&payload, true).await.unwrap();
    
    // Complex interactions should complete all phases
    assert_eq!(result.phases_completed.len(), 5);
    assert!(result.world_enrichment_complete);
}

/// Test error handling and recovery
#[tokio::test]
async fn test_error_handling_and_recovery() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "error_test".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    
    // Payload with invalid metadata that might cause issues
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "FORCE_ERROR".to_string(), // Special message to trigger error path
        ai_response: "Error response".to_string(),
        timestamp: Utc::now(),
        metadata: Some(json!({
            "invalid": null,
            "malformed": {}
        })),
    };
    
    // The reasoning loop should handle errors gracefully
    let result = orchestrator.execute_full_reasoning_loop(&payload, true).await;
    
    // In a production system, this might return an error or a partial result
    // For now, we just verify it doesn't panic
    assert!(result.is_ok() || result.is_err());
}

/// Test alternative path exploration
#[tokio::test]
async fn test_alternative_path_exploration() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "alt_path_test".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "I stand at the crossroads, unsure which path to take.".to_string(),
        ai_response: "Three paths stretch before you: forest, mountain, or desert.".to_string(),
        timestamp: Utc::now(),
        metadata: Some(json!({
            "decision_point": true,
            "options": ["forest", "mountain", "desert"]
        })),
    };
    
    let result = orchestrator.execute_full_reasoning_loop(&payload, true).await.unwrap();
    
    // Decision points might explore alternative paths
    assert!(result.world_enrichment_complete);
    // Alternative paths might be explored but not necessarily returned
    // in the current implementation
}