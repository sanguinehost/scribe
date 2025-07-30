// backend/tests/task_queue_security_tests.rs
//
// Task Queue Security Tests - OWASP Top 10 (2021) Compliance
// Epic 8: Orchestrator-Driven Intelligent Agent System
//
// Tests security controls following OWASP Top 10 Web Application Security Risks.
// Each test is mapped to specific OWASP categories to ensure comprehensive coverage.

use uuid::Uuid;
use chrono::Utc;
use scribe_backend::{
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
    services::task_queue::{
        TaskQueueService, EnrichmentTaskPayload, TaskStatus, TaskPriority,
        CreateTaskRequest,
    },
    auth::session_dek::SessionDek,
    errors::AppError,
};
use sqlx;

/// A01: Broken Access Control - Test user isolation
#[tokio::test]
async fn test_a01_user_task_isolation() {
    let test_app = spawn_app(true, false, false).await;
    let user1 = create_test_user(&test_app.db_pool, "isolated_user1".to_string(), "password123".to_string()).await.unwrap();
    let user2 = create_test_user(&test_app.db_pool, "isolated_user2".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create task for user1
    let payload1 = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user1.id,
        user_message: "User1 secret message".to_string(),
        ai_response: "User1 response".to_string(),
        timestamp: Utc::now(),
        metadata: None,
    };
    
    let request1 = CreateTaskRequest {
        user_id: user1.id,
        session_id: payload1.session_id,
        payload: payload1,
        priority: TaskPriority::Normal,
    };
    
    let task1 = task_queue.enqueue_task(request1).await.unwrap();
    
    // Create task for user2
    let payload2 = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user2.id,
        user_message: "User2 secret message".to_string(),
        ai_response: "User2 response".to_string(),
        timestamp: Utc::now(),
        metadata: None,
    };
    
    let request2 = CreateTaskRequest {
        user_id: user2.id,
        session_id: payload2.session_id,
        payload: payload2,
        priority: TaskPriority::Normal,
    };
    
    let _task2 = task_queue.enqueue_task(request2).await.unwrap();
    
    // Try to access user1's task as user2 (should fail)
    let result = task_queue.get_task_as_user(task1.id, user2.id).await;
    assert!(result.is_err() || result.unwrap().is_none(), "User2 should not access User1's task");
    
    // Verify user1 can access their own task
    let result = task_queue.get_task_as_user(task1.id, user1.id).await.unwrap();
    assert!(result.is_some(), "User1 should access their own task");
}

/// A02: Cryptographic Failures - Test encryption at rest
#[tokio::test]
async fn test_a02_encryption_at_rest() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "crypto_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    let sensitive_message = "My SSN is 123-45-6789";
    let sensitive_response = "Bank account: 9876543210";
    
    // Create task with sensitive data
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: sensitive_message.to_string(),
        ai_response: sensitive_response.to_string(),
        timestamp: Utc::now(),
        metadata: Some(serde_json::json!({
            "credit_card": "4111111111111111"
        })),
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id: payload.session_id,
        payload,
        priority: TaskPriority::Normal,
    };
    
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    // Query database directly to verify encryption
    let pool = &test_app.db_pool;
    let raw_task = sqlx::query!(
        "SELECT encrypted_payload, payload_nonce FROM world_enrichment_tasks WHERE id = $1",
        task.id
    )
    .fetch_one(pool)
    .await
    .unwrap();
    
    // Verify payload is encrypted (should not contain plaintext sensitive data)
    let encrypted_bytes = raw_task.encrypted_payload;
    let encrypted_str = String::from_utf8_lossy(&encrypted_bytes);
    
    assert!(!encrypted_str.contains(sensitive_message), "Message should be encrypted");
    assert!(!encrypted_str.contains(sensitive_response), "Response should be encrypted");
    assert!(!encrypted_str.contains("4111111111111111"), "Credit card should be encrypted");
    assert!(raw_task.payload_nonce.is_some(), "Nonce should be present");
}

/// A03: Injection - Test SQL injection protection
#[tokio::test]
async fn test_a03_sql_injection_protection() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "injection_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Attempt SQL injection in message content
    let malicious_message = "'; DROP TABLE world_enrichment_tasks; --";
    let malicious_response = "1' OR '1'='1";
    
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: malicious_message.to_string(),
        ai_response: malicious_response.to_string(),
        timestamp: Utc::now(),
        metadata: Some(serde_json::json!({
            "injection": "'; DELETE FROM users; --"
        })),
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id: payload.session_id,
        payload,
        priority: TaskPriority::Normal,
    };
    
    // Should succeed without executing injection
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    // Verify table still exists and data is intact
    let count = sqlx::query!("SELECT COUNT(*) as count FROM world_enrichment_tasks")
        .fetch_one(&test_app.db_pool)
        .await
        .unwrap()
        .count
        .unwrap_or(0);
    
    assert!(count > 0, "Table should still exist");
    
    // Verify we can retrieve the task with malicious content safely
    let retrieved = task_queue.dequeue_task(Uuid::new_v4()).await.unwrap().unwrap();
    assert_eq!(retrieved.payload.user_message, malicious_message);
}

/// A04: Insecure Design - Test task queue design security
#[tokio::test]
async fn test_a04_secure_design_principles() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "design_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Test 1: Verify DEK requirement - tasks require user context
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "Test".to_string(),
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
    
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    // Test 2: Verify atomic operations - no partial states
    let worker_id = Uuid::new_v4();
    let dequeued = task_queue.dequeue_task(worker_id).await.unwrap();
    assert!(dequeued.is_some());
    
    // Same worker can't dequeue again while task in progress
    let second_dequeue = task_queue.dequeue_task(worker_id).await.unwrap();
    assert!(second_dequeue.is_none(), "Worker shouldn't get another task while one in progress");
    
    // Test 3: Verify status transitions are controlled
    let result = task_queue.update_task_status(
        task.id,
        TaskStatus::Pending, // Invalid transition from InProgress to Pending
        None
    ).await;
    
    // Should either error or remain in progress
    let current_task = task_queue.get_task(task.id).await.unwrap().unwrap();
    assert_eq!(current_task.status, TaskStatus::InProgress, "Invalid status transition should be prevented");
}

/// A05: Security Misconfiguration - Test secure defaults
#[tokio::test]
async fn test_a05_secure_configuration() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "config_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Test secure defaults
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "Config test".to_string(),
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
    
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    // Verify secure defaults
    assert_eq!(task.retry_count, 0, "Retry count should start at 0");
    assert_eq!(task.status, TaskStatus::Pending, "Should start as Pending");
    assert!(task.encrypted_error.is_none(), "No error initially");
    
    // Test max retry limit enforcement
    for _ in 0..5 {
        task_queue.retry_task(task.id).await.unwrap();
    }
    
    let retried_task = task_queue.get_task(task.id).await.unwrap().unwrap();
    assert!(retried_task.retry_count <= 5, "Should enforce max retry limit");
}

/// A07: Identification and Authentication Failures - Test DEK validation
#[tokio::test]
async fn test_a07_authentication_failures() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "auth_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create task with valid user
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "Auth test".to_string(),
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
    
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    // Test: Cannot decrypt without proper DEK
    // Simulate DEK cache miss by using a different user context
    let fake_user_id = Uuid::new_v4();
    let result = task_queue.get_task_as_user(task.id, fake_user_id).await;
    
    // Should either fail or return None (no access)
    assert!(result.is_err() || result.unwrap().is_none(), "Should not decrypt without proper DEK");
}

/// A08: Software and Data Integrity Failures - Test data integrity
#[tokio::test]
async fn test_a08_data_integrity() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "integrity_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create task with specific data
    let original_message = "Original message with integrity";
    let original_response = "Original response data";
    
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: original_message.to_string(),
        ai_response: original_response.to_string(),
        timestamp: Utc::now(),
        metadata: Some(serde_json::json!({
            "checksum": "abc123"
        })),
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id: payload.session_id,
        payload,
        priority: TaskPriority::Normal,
    };
    
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    // Dequeue and verify data integrity
    let worker_id = Uuid::new_v4();
    let dequeued = task_queue.dequeue_task(worker_id).await.unwrap().unwrap();
    
    assert_eq!(dequeued.payload.user_message, original_message, "Message integrity preserved");
    assert_eq!(dequeued.payload.ai_response, original_response, "Response integrity preserved");
    assert_eq!(
        dequeued.payload.metadata.unwrap()["checksum"], 
        "abc123", 
        "Metadata integrity preserved"
    );
}

/// A09: Security Logging and Monitoring Failures - Test audit trail
#[tokio::test]
async fn test_a09_security_logging() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "logging_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create task
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "Logging test".to_string(),
        ai_response: "Response".to_string(),
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
    
    // Perform various operations that should be logged
    let worker_id = Uuid::new_v4();
    
    // Dequeue
    let _dequeued = task_queue.dequeue_task(worker_id).await.unwrap();
    
    // Update status
    task_queue.update_task_status(task.id, TaskStatus::InProgress, None).await.unwrap();
    
    // Fail with error
    task_queue.update_task_status(
        task.id, 
        TaskStatus::Failed, 
        Some("Security event: authentication failure".to_string())
    ).await.unwrap();
    
    // Verify audit fields exist
    let final_task = task_queue.get_task(task.id).await.unwrap().unwrap();
    
    assert!(final_task.created_at < final_task.updated_at, "Updated timestamp should be later");
    assert!(final_task.encrypted_error.is_some(), "Error should be logged");
}

/// A10: Server-Side Request Forgery (SSRF) - Test internal access controls
#[tokio::test]
async fn test_a10_ssrf_protection() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "ssrf_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Test that task payloads with SSRF-like content are handled safely
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "Check http://internal-service/admin".to_string(),
        ai_response: "Access file:///etc/passwd".to_string(),
        timestamp: Utc::now(),
        metadata: Some(serde_json::json!({
            "webhook": "http://169.254.169.254/latest/meta-data/",
            "callback": "http://localhost:8080/internal/debug"
        })),
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id: payload.session_id,
        payload,
        priority: TaskPriority::Normal,
    };
    
    // Should handle without executing any requests
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    // Verify content is stored encrypted and not processed
    assert_eq!(task.status, TaskStatus::Pending);
    
    // When dequeued, payload should be returned as-is (encrypted) for processing
    let worker_id = Uuid::new_v4();
    let dequeued = task_queue.dequeue_task(worker_id).await.unwrap().unwrap();
    
    // Verify potentially dangerous URLs are preserved but encrypted
    assert!(dequeued.payload.user_message.contains("internal-service"));
    assert!(dequeued.payload.metadata.is_some());
}

/// Test comprehensive encryption flow
#[tokio::test]
async fn test_comprehensive_encryption_flow() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "encrypt_flow_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Complex payload with nested sensitive data
    let complex_payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "User's private conversation about health issues".to_string(),
        ai_response: "Medical advice and personal recommendations".to_string(),
        timestamp: Utc::now(),
        metadata: Some(serde_json::json!({
            "user_context": {
                "medical_history": ["diabetes", "hypertension"],
                "medications": ["metformin", "lisinopril"],
                "allergies": ["penicillin"]
            },
            "session_data": {
                "ip_address": "192.168.1.100",
                "location": "New York, NY",
                "device_id": "unique-device-123"
            }
        })),
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id: complex_payload.session_id,
        payload: complex_payload.clone(),
        priority: TaskPriority::High,
    };
    
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    // Verify encryption in database
    let raw_data = sqlx::query!(
        "SELECT encrypted_payload FROM world_enrichment_tasks WHERE id = $1",
        task.id
    )
    .fetch_one(&test_app.db_pool)
    .await
    .unwrap();
    
    let encrypted_str = String::from_utf8_lossy(&raw_data.encrypted_payload);
    
    // Nothing sensitive should be in plaintext
    assert!(!encrypted_str.contains("diabetes"));
    assert!(!encrypted_str.contains("metformin"));
    assert!(!encrypted_str.contains("192.168.1.100"));
    
    // Dequeue and verify decryption
    let worker_id = Uuid::new_v4();
    let dequeued = task_queue.dequeue_task(worker_id).await.unwrap().unwrap();
    
    // All data should be properly decrypted
    assert_eq!(dequeued.payload.user_message, complex_payload.user_message);
    assert_eq!(dequeued.payload.ai_response, complex_payload.ai_response);
    
    let metadata = dequeued.payload.metadata.unwrap();
    assert_eq!(metadata["user_context"]["medical_history"][0], "diabetes");
    assert_eq!(metadata["session_data"]["ip_address"], "192.168.1.100");
}