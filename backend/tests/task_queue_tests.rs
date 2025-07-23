// backend/tests/task_queue_tests.rs
//
// Task Queue Basic Functionality Tests
// Epic 8: Orchestrator-Driven Intelligent Agent System
//
// This test file validates the core functionality of the durable task queue
// that enables the Orchestrator to process background enrichment tasks.

use uuid::Uuid;
use chrono::Utc;
use secrecy::ExposeSecret;
use scribe_backend::{
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user, TestApp},
    services::task_queue::{
        TaskQueueService, TaskStatus, TaskPriority,
        EnrichmentTaskPayload, CreateTaskRequest,
    },
    models::users::User,
};

/// Helper function to create a test user and populate the auth backend DEK cache
async fn create_test_user_with_dek_cache(test_app: &TestApp, username: &str, password: &str) -> User {
    let user = create_test_user(&test_app.db_pool, username.to_string(), password.to_string())
        .await
        .unwrap();
    
    // Populate auth backend DEK cache for test user
    if let Some(user_dek) = &user.dek {
        let mut cache = test_app.app_state.auth_backend.dek_cache.write().await;
        cache.insert(user.id, user_dek.clone());
    }
    
    user
}

/// Test that we can create and retrieve a basic task
#[tokio::test]
async fn test_create_and_retrieve_task() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user_with_dek_cache(&test_app, "queue_user", "password123").await;
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create test payload
    let session_id = Uuid::new_v4();
    let payload = EnrichmentTaskPayload {
        session_id,
        user_id: user.id,
        user_message: "Hello world".to_string(),
        ai_response: "Hi there!".to_string(),
        timestamp: Utc::now(),
        metadata: None,
    };
    
    // Create task request
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id,
        payload,
        priority: TaskPriority::Normal,
    };
    
    // Create task
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    assert_eq!(task.user_id, user.id);
    assert_eq!(task.session_id, session_id);
    assert_eq!(task.status(), TaskStatus::Pending);
    assert_eq!(task.priority, TaskPriority::Normal as i32);
    assert_eq!(task.retry_count, 0);
}

/// Test atomic task dequeuing with locking
#[tokio::test]
async fn test_atomic_dequeue_with_locking() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user_with_dek_cache(&test_app, "dequeue_user", "password123").await;
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create multiple tasks
    let mut task_ids = Vec::new();
    for i in 0..3 {
        let payload = EnrichmentTaskPayload {
            session_id: Uuid::new_v4(),
            user_id: user.id,
            user_message: format!("Message {}", i),
            ai_response: format!("Response {}", i),
            timestamp: Utc::now(),
            metadata: None,
        };
        
        let request = CreateTaskRequest {
            user_id: user.id,
            session_id: payload.session_id,
            payload,
            priority: TaskPriority::Normal,
        };
        
        let task = task_queue.enqueue_task(request).await.unwrap();
        task_ids.push(task.id);
    }
    
    // Dequeue tasks - should get them in order
    let worker_id = Uuid::new_v4();
    
    let task1 = task_queue.dequeue_task(worker_id).await.unwrap();
    assert!(task1.is_some());
    let task1 = task1.unwrap();
    assert_eq!(task1.task.status(), TaskStatus::InProgress);
    assert_eq!(task1.task.id, task_ids[0]);
    
    // Verify payload was decrypted correctly
    assert_eq!(task1.payload.user_message, "Message 0");
    assert_eq!(task1.payload.ai_response, "Response 0");
}

/// Test task status updates
#[tokio::test]
async fn test_update_task_status() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user_with_dek_cache(&test_app, "status_user", "password123").await;
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create a task
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
    
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    // Update to in progress
    task_queue.update_task_status(task.id, TaskStatus::InProgress, None).await.unwrap();
    
    // Verify status changed
    let updated_task = task_queue.get_task(task.id).await.unwrap().unwrap();
    assert_eq!(updated_task.status(), TaskStatus::InProgress);
    
    // Update to completed
    task_queue.update_task_status(task.id, TaskStatus::Completed, None).await.unwrap();
    
    let completed_task = task_queue.get_task(task.id).await.unwrap().unwrap();
    assert_eq!(completed_task.status(), TaskStatus::Completed);
}

/// Test task failure handling with encrypted errors
#[tokio::test]
async fn test_task_failure_with_encrypted_error() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user_with_dek_cache(&test_app, "error_user", "password123").await;
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create a task
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "Failing message".to_string(),
        ai_response: "Will fail".to_string(),
        timestamp: Utc::now(),
        metadata: None,
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id: payload.session_id,
        payload,
        priority: TaskPriority::Normal,
    };
    
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    // Fail the task with an error
    let error_message = "Agent processing failed: timeout";
    task_queue.update_task_status(
        task.id, 
        TaskStatus::Failed, 
        Some(error_message.to_string())
    ).await.unwrap();
    
    // Retrieve and verify error is encrypted
    let failed_task = task_queue.get_task(task.id).await.unwrap().unwrap();
    assert_eq!(failed_task.status(), TaskStatus::Failed);
    assert!(failed_task.encrypted_error.is_some());
    assert!(failed_task.error_nonce.is_some());
    
    // Decrypt and verify error message
    let decrypted_error = task_queue.decrypt_error(&failed_task).await.unwrap();
    assert_eq!(decrypted_error.unwrap(), error_message);
}

/// Test priority-based dequeuing
#[tokio::test]
async fn test_priority_dequeuing() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user_with_dek_cache(&test_app, "priority_user", "password123").await;
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create tasks with different priorities
    let priorities = vec![
        (TaskPriority::Low, "Low priority"),
        (TaskPriority::High, "High priority"),
        (TaskPriority::Normal, "Normal priority"),
        (TaskPriority::Critical, "Critical priority"),
    ];
    
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
        
        task_queue.enqueue_task(request).await.unwrap();
    }
    
    // Dequeue - should get critical first
    let worker_id = Uuid::new_v4();
    let task = task_queue.dequeue_task(worker_id).await.unwrap().unwrap();
    assert_eq!(task.payload.user_message, "Critical priority");
    
    // Then high
    let task = task_queue.dequeue_task(worker_id).await.unwrap().unwrap();
    assert_eq!(task.payload.user_message, "High priority");
    
    // Then normal
    let task = task_queue.dequeue_task(worker_id).await.unwrap().unwrap();
    assert_eq!(task.payload.user_message, "Normal priority");
    
    // Finally low
    let task = task_queue.dequeue_task(worker_id).await.unwrap().unwrap();
    assert_eq!(task.payload.user_message, "Low priority");
}

/// Test task retry mechanism
#[tokio::test]
async fn test_task_retry_mechanism() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user_with_dek_cache(&test_app, "retry_user", "password123").await;
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create a task
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "Retry message".to_string(),
        ai_response: "Will retry".to_string(),
        timestamp: Utc::now(),
        metadata: None,
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id: payload.session_id,
        payload,
        priority: TaskPriority::Normal,
    };
    
    let task = task_queue.enqueue_task(request).await.unwrap();
    let worker_id = Uuid::new_v4();
    
    // Dequeue and fail the task
    let _dequeued = task_queue.dequeue_task(worker_id).await.unwrap();
    task_queue.update_task_status(task.id, TaskStatus::Failed, Some("Temporary failure".to_string())).await.unwrap();
    
    // Retry the task
    task_queue.retry_task(task.id).await.unwrap();
    
    // Verify retry count increased and status is pending
    let retried_task = task_queue.get_task(task.id).await.unwrap().unwrap();
    assert_eq!(retried_task.status(), TaskStatus::Pending);
    assert_eq!(retried_task.retry_count, 1);
}

/// Test concurrent dequeue doesn't give same task to multiple workers
#[tokio::test]
async fn test_concurrent_dequeue_safety() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user_with_dek_cache(&test_app, "concurrent_user", "password123").await;
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create a single task
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "Single task".to_string(),
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
    
    // Try to dequeue from multiple workers concurrently
    let worker1 = Uuid::new_v4();
    let worker2 = Uuid::new_v4();
    
    let queue1 = task_queue.clone();
    let queue2 = task_queue.clone();
    
    let (result1, result2) = tokio::join!(
        queue1.dequeue_task(worker1),
        queue2.dequeue_task(worker2)
    );
    
    // Only one should get the task
    let got_task1 = result1.unwrap().is_some();
    let got_task2 = result2.unwrap().is_some();
    
    assert!(got_task1 ^ got_task2, "Exactly one worker should get the task");
}

/// Test getting task history for a session
#[tokio::test]
async fn test_get_session_task_history() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user_with_dek_cache(&test_app, "history_user", "password123").await;
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    let session_id = Uuid::new_v4();
    
    // Create multiple tasks for the same session
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
        
        task_queue.enqueue_task(request).await.unwrap();
    }
    
    // Get task history for session
    let history = task_queue.get_session_tasks(session_id).await.unwrap();
    
    assert_eq!(history.len(), 3);
    assert!(history.iter().all(|t| t.session_id == session_id));
}

/// Test task expiration and cleanup
#[tokio::test]
async fn test_task_expiration() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user_with_dek_cache(&test_app, "expire_user", "password123").await;
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create a manually old task using raw SQL to bypass any triggers
    let old_timestamp = Utc::now() - chrono::Duration::days(8);
    let old_task_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    
    {
        use diesel::prelude::*;
        
        let pool = test_app.db_pool.clone();
        let user_id = user.id;
        
        // Create payload for the old task
        let payload = EnrichmentTaskPayload {
            session_id,
            user_id: user.id,
            user_message: "Old task".to_string(),
            ai_response: "Old response".to_string(),
            timestamp: Utc::now() - chrono::Duration::days(8), // 8 days old
            metadata: None,
        };
        let payload_json = serde_json::to_string(&payload).unwrap();
        
        // Get user DEK for encryption directly from cache
        let cache = test_app.app_state.auth_backend.dek_cache.read().await;
        let session_dek = cache.get(&user_id).unwrap();
            
        let (encrypted_payload, payload_nonce) = test_app.app_state.encryption_service
            .encrypt(&payload_json, session_dek.0.expose_secret())
            .unwrap();
        
        // Insert directly with old timestamps  
        pool.get().await.unwrap()
            .interact(move |conn| {
                diesel::sql_query(
                    "INSERT INTO world_enrichment_tasks 
                     (id, session_id, user_id, status, priority, encrypted_payload, payload_nonce, 
                      retry_count, worker_id, created_at, updated_at) 
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
                )
                .bind::<diesel::sql_types::Uuid, _>(old_task_id)
                .bind::<diesel::sql_types::Uuid, _>(session_id)
                .bind::<diesel::sql_types::Uuid, _>(user_id)
                .bind::<diesel::sql_types::Int4, _>(TaskStatus::Completed as i32)
                .bind::<diesel::sql_types::Int4, _>(TaskPriority::Normal as i32)
                .bind::<diesel::sql_types::Bytea, _>(&encrypted_payload)
                .bind::<diesel::sql_types::Bytea, _>(&payload_nonce)
                .bind::<diesel::sql_types::Int4, _>(0)
                .bind::<diesel::sql_types::Nullable<diesel::sql_types::Uuid>, _>(None::<Uuid>)
                .bind::<diesel::sql_types::Timestamptz, _>(old_timestamp)
                .bind::<diesel::sql_types::Timestamptz, _>(old_timestamp)
                .execute(conn)
            })
            .await
            .unwrap()
            .unwrap();
    }
    
    // Run cleanup (tasks older than 7 days)
    let deleted_count = task_queue.cleanup_old_tasks(chrono::Duration::days(7)).await.unwrap();
    
    assert_eq!(deleted_count, 1);
    
    // Verify old task is gone
    let result = task_queue.get_task(old_task_id).await.unwrap();
    assert!(result.is_none());
}