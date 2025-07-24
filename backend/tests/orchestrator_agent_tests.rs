// backend/tests/orchestrator_agent_tests.rs
//
// Orchestrator Agent Core Functionality Tests
// Epic 8: Orchestrator-Driven Intelligent Agent System
//
// This test file validates the core functionality of the Orchestrator Agent,
// which processes tasks from the durable queue with dynamic reasoning and
// coordinates all agents based on context and needs.

use uuid::Uuid;
use scribe_backend::{
    test_helpers::{spawn_app, TestApp, TestDataGuard, db::create_test_user},
    services::{
        orchestrator::{
            OrchestratorAgent, OrchestratorConfig,
            ReasoningPhase,
        },
        task_queue::{
            TaskQueueService, EnrichmentTaskPayload, CreateTaskRequest,
            TaskStatus, TaskPriority,
        },
    },
};
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Helper to create test orchestrator with mocked dependencies
async fn create_test_orchestrator(test_app: &TestApp) -> OrchestratorAgent {
    let config = OrchestratorConfig {
        worker_id: Uuid::new_v4(),
        poll_interval_ms: 100, // Fast polling for tests
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
        test_app.app_state.config.clone(),
    )
}

/// Test that orchestrator can be created with required dependencies
#[tokio::test]
async fn test_orchestrator_creation() {
    let test_app = spawn_app(true, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    assert_eq!(orchestrator.config().batch_size, 5);
    assert_eq!(orchestrator.config().retry_limit, 3);
}

/// Test basic task processing workflow
#[tokio::test]
async fn test_process_single_task() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "orchestrator_user".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Populate DEK cache for background processing
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    // Create task queue service
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Enqueue a test task
    let session_id = Uuid::new_v4();
    let payload = EnrichmentTaskPayload {
        session_id,
        user_id: user.id,
        user_message: "Hello, I'm in the tavern. What do I see?".to_string(),
        ai_response: "You find yourself in a bustling tavern...".to_string(),
        timestamp: Utc::now(),
        metadata: None,
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id,
        payload,
        priority: TaskPriority::Normal,
    };
    
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    // Create orchestrator and process single task
    let orchestrator = create_test_orchestrator(&test_app).await;
    let processed = orchestrator.process_single_task().await.unwrap();
    
    assert!(processed);
    
    // Verify task was completed
    let updated_task = task_queue.get_task(task.id).await.unwrap().unwrap();
    assert_eq!(updated_task.status(), TaskStatus::Completed);
}

/// Test orchestrator handles empty queue gracefully
#[tokio::test]
async fn test_process_empty_queue() {
    let test_app = spawn_app(true, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    let processed = orchestrator.process_single_task().await.unwrap();
    
    assert!(!processed, "Should return false when no tasks available");
}

/// Test orchestrator properly tracks reasoning phases
#[tokio::test]
async fn test_reasoning_phase_tracking() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "phase_user".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Set up DEK cache
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create test task
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "Test message".to_string(),
        ai_response: "Test response".to_string(),
        timestamp: Utc::now(),
        metadata: None,
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id: payload.session_id,
        payload,
        priority: TaskPriority::High,
    };
    
    task_queue.enqueue_task(request).await.unwrap();
    
    // Track phases through mock observer
    let phase_tracker = Arc::new(Mutex::new(Vec::new()));
    let tracker_clone = phase_tracker.clone();
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    orchestrator.set_phase_observer(move |phase| {
        let tracker = tracker_clone.clone();
        Box::pin(async move {
            let mut phases = tracker.lock().await;
            phases.push(phase);
        })
    }).await;
    
    orchestrator.process_single_task().await.unwrap();
    
    // Verify all phases were executed
    let phases = phase_tracker.lock().await;
    assert_eq!(phases.len(), 5);
    assert_eq!(phases[0], ReasoningPhase::Perceive);
    assert_eq!(phases[1], ReasoningPhase::Strategize);
    assert_eq!(phases[2], ReasoningPhase::Plan);
    assert_eq!(phases[3], ReasoningPhase::Execute);
    assert_eq!(phases[4], ReasoningPhase::Reflect);
}

/// Test orchestrator handles task failures gracefully
#[tokio::test]
async fn test_handle_task_failure() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "failure_user".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create task with invalid data that will cause failure
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "FORCE_FAILURE".to_string(), // Special marker for test
        ai_response: "This will fail".to_string(),
        timestamp: Utc::now(),
        metadata: Some(serde_json::json!({"force_error": true})),
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id: payload.session_id,
        payload,
        priority: TaskPriority::Normal,
    };
    
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    let processed = orchestrator.process_single_task().await.unwrap();
    
    assert!(processed);
    
    // Verify task was marked as failed
    let updated_task = task_queue.get_task(task.id).await.unwrap().unwrap();
    assert_eq!(updated_task.status(), TaskStatus::Failed);
    
    // Verify error was encrypted and stored
    assert!(updated_task.encrypted_error.is_some());
    assert!(updated_task.error_nonce.is_some());
}

/// Test batch processing of multiple tasks
#[tokio::test]
async fn test_batch_processing() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "batch_user".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create multiple tasks
    let session_id = Uuid::new_v4();
    let mut task_ids = Vec::new();
    
    for i in 0..3 {
        let payload = EnrichmentTaskPayload {
            session_id,
            user_id: user.id,
            user_message: format!("Message {}", i),
            ai_response: format!("Response {}", i),
            timestamp: Utc::now(),
            metadata: None,
        };
        
        let request = CreateTaskRequest {
            user_id: user.id,
            session_id,
            payload,
            priority: TaskPriority::Normal,
        };
        
        let task = task_queue.enqueue_task(request).await.unwrap();
        task_ids.push(task.id);
    }
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    let processed_count = orchestrator.process_batch().await.unwrap();
    
    assert_eq!(processed_count, 3);
    
    // Verify all tasks were completed
    for task_id in task_ids {
        let task = task_queue.get_task(task_id).await.unwrap().unwrap();
        assert_eq!(task.status(), TaskStatus::Completed);
    }
}

/// Test priority-based task processing
#[tokio::test]
async fn test_priority_processing() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "priority_orchestrator".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create tasks with different priorities
    let priorities = vec![
        (TaskPriority::Low, "Low priority task"),
        (TaskPriority::Critical, "Critical priority task"),
        (TaskPriority::Normal, "Normal priority task"),
    ];
    
    let mut expected_order = Vec::new();
    for (priority, message) in priorities {
        let payload = EnrichmentTaskPayload {
            session_id: Uuid::new_v4(),
            user_id: user.id,
            user_message: message.to_string(),
            ai_response: "Response".to_string(),
            timestamp: Utc::now(),
            metadata: None,
        };
        
        let request = CreateTaskRequest {
            user_id: user.id,
            session_id: payload.session_id,
            payload,
            priority,
        };
        
        let task = task_queue.enqueue_task(request).await.unwrap();
        if priority == TaskPriority::Critical {
            expected_order.insert(0, message);
        } else {
            expected_order.push(message);
        }
    }
    
    // Track processed order
    let processed_order = Arc::new(Mutex::new(Vec::new()));
    let order_clone = processed_order.clone();
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    orchestrator.set_task_observer(move |task_context| {
        let order = order_clone.clone();
        Box::pin(async move {
            let mut vec = order.lock().await;
            vec.push(task_context.payload.user_message.clone());
        })
    }).await;
    
    // Process all tasks
    while orchestrator.process_single_task().await.unwrap() {}
    
    // Verify critical task was processed first
    let order = processed_order.lock().await;
    assert_eq!(order[0], "Critical priority task");
}

/// Test graceful shutdown handling
#[tokio::test]
async fn test_graceful_shutdown() {
    let test_app = spawn_app(true, false, false).await;
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    
    // Start worker in background
    let worker_handle = tokio::spawn(async move {
        orchestrator.run_worker().await
    });
    
    // Give worker time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    
    // Send shutdown signal
    worker_handle.abort();
    
    // Verify worker shuts down gracefully
    let result = worker_handle.await;
    assert!(result.is_err()); // Should be aborted
}

/// Test concurrent worker safety
#[tokio::test]
async fn test_concurrent_workers() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "concurrent_orchestrator".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create a single task
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "Concurrent test".to_string(),
        ai_response: "Response".to_string(),
        timestamp: Utc::now(),
        metadata: None,
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id: payload.session_id,
        payload,
        priority: TaskPriority::Normal,
    };
    
    task_queue.enqueue_task(request).await.unwrap();
    
    // Create two orchestrators with different worker IDs
    let orchestrator1 = create_test_orchestrator(&test_app).await;
    let orchestrator2 = create_test_orchestrator(&test_app).await;
    
    // Try to process concurrently
    let (result1, result2) = tokio::join!(
        orchestrator1.process_single_task(),
        orchestrator2.process_single_task()
    );
    
    // Only one should process the task
    let processed1 = result1.unwrap();
    let processed2 = result2.unwrap();
    
    assert!(processed1 ^ processed2, "Exactly one worker should process the task");
}

/// Test state persistence between phases
#[tokio::test]
async fn test_state_persistence() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "state_user".to_string(), "password123".to_string())
        .await
        .unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create task with metadata that requires state tracking
    let session_id = Uuid::new_v4();
    let payload = EnrichmentTaskPayload {
        session_id,
        user_id: user.id,
        user_message: "I pick up the sword and shield".to_string(),
        ai_response: "You equip the ancient sword and shield".to_string(),
        timestamp: Utc::now(),
        metadata: Some(serde_json::json!({
            "entities": ["sword", "shield"],
            "action": "equip"
        })),
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id,
        payload,
        priority: TaskPriority::Normal,
    };
    
    task_queue.enqueue_task(request).await.unwrap();
    
    // Track state between phases
    let state_tracker = Arc::new(Mutex::new(Vec::new()));
    let tracker_clone = state_tracker.clone();
    
    let orchestrator = create_test_orchestrator(&test_app).await;
    orchestrator.set_state_observer(move |phase, state| {
        let tracker = tracker_clone.clone();
        Box::pin(async move {
            let mut states = tracker.lock().await;
            states.push((phase, state.clone()));
        })
    }).await;
    
    orchestrator.process_single_task().await.unwrap();
    
    // Verify state was maintained across phases
    let states = state_tracker.lock().await;
    assert!(states.len() >= 5); // One for each phase
    
    // Verify entities were tracked through all phases
    for (_, state) in states.iter() {
        if let Some(entities) = state.get("entities").and_then(|v| v.as_array()) {
            assert!(entities.iter().any(|e| e.as_str() == Some("sword")));
            assert!(entities.iter().any(|e| e.as_str() == Some("shield")));
        }
    }
}