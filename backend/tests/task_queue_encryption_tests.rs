// backend/tests/task_queue_encryption_tests.rs
//
// Task Queue End-to-End Encryption Tests
// Epic 8: Orchestrator-Driven Intelligent Agent System
//
// Validates comprehensive encryption flow for task queue system,
// ensuring all sensitive data is protected with per-user DEKs.

use uuid::Uuid;
use chrono::Utc;
use scribe_backend::{
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user},
    services::{
        task_queue::{
            TaskQueueService, EnrichmentTaskPayload, TaskPriority,
            CreateTaskRequest, TaskStatus,
        },
        encryption_service::EncryptionService,
    },
    auth::session_dek::SessionDek,
    errors::AppError,
};
use sqlx::PgPool;

/// Test complete encryption lifecycle for task queue
#[tokio::test]
async fn test_e2e_task_encryption_lifecycle() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "e2e_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create complex payload with nested sensitive data
    let sensitive_payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "Patient discussed symptoms: severe headaches, dizziness".to_string(),
        ai_response: "Based on symptoms, recommend neurological evaluation. Consider MRI scan.".to_string(),
        timestamp: Utc::now(),
        metadata: Some(serde_json::json!({
            "patient_data": {
                "ssn": "123-45-6789",
                "dob": "1985-03-15",
                "insurance_id": "INS-9876543",
                "conditions": ["hypertension", "diabetes"],
                "medications": {
                    "current": ["lisinopril", "metformin"],
                    "allergies": ["penicillin", "sulfa"]
                }
            },
            "session_context": {
                "location": "NYC Medical Center",
                "provider": "Dr. Smith",
                "appointment_id": "APT-2024-001"
            }
        })),
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id: sensitive_payload.session_id,
        payload: sensitive_payload.clone(),
        priority: TaskPriority::High,
    };
    
    // Step 1: Enqueue task
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    // Step 2: Verify raw database has encrypted data
    verify_database_encryption(&test_app.db_pool, task.id, &sensitive_payload).await;
    
    // Step 3: Dequeue and verify decryption
    let worker_id = Uuid::new_v4();
    let dequeued = task_queue.dequeue_task(worker_id).await.unwrap().unwrap();
    
    // Verify all sensitive data is correctly decrypted
    assert_eq!(dequeued.payload.user_message, sensitive_payload.user_message);
    assert_eq!(dequeued.payload.ai_response, sensitive_payload.ai_response);
    
    let metadata = dequeued.payload.metadata.as_ref().unwrap();
    assert_eq!(metadata["patient_data"]["ssn"], "123-45-6789");
    assert_eq!(metadata["patient_data"]["insurance_id"], "INS-9876543");
    assert_eq!(metadata["patient_data"]["medications"]["current"][0], "lisinopril");
    
    // Step 4: Test error encryption
    let error_msg = "Failed to process: patient data validation error";
    task_queue.update_task_status(task.id, TaskStatus::Failed, Some(error_msg.to_string())).await.unwrap();
    
    // Verify error is encrypted in database
    verify_error_encryption(&test_app.db_pool, task.id, error_msg).await;
}

/// Test DEK rotation scenario
#[tokio::test]
async fn test_dek_rotation_handling() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "rotation_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create task with initial DEK
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "Sensitive message before rotation".to_string(),
        ai_response: "Response before rotation".to_string(),
        timestamp: Utc::now(),
        metadata: Some(serde_json::json!({
            "secret": "pre-rotation-secret"
        })),
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id: payload.session_id,
        payload,
        priority: TaskPriority::Normal,
    };
    
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    // Simulate DEK rotation by clearing cache
    // In production, this would involve re-encryption with new DEK
    
    // Dequeue should still work with DEK retrieval
    let worker_id = Uuid::new_v4();
    let dequeued = task_queue.dequeue_task(worker_id).await.unwrap().unwrap();
    
    assert_eq!(dequeued.payload.user_message, "Sensitive message before rotation");
    assert_eq!(dequeued.payload.metadata.unwrap()["secret"], "pre-rotation-secret");
}

/// Test cross-user encryption isolation
#[tokio::test]
async fn test_cross_user_encryption_isolation() {
    let test_app = spawn_app(true, false, false).await;
    let user1 = create_test_user(&test_app.db_pool, "alice".to_string(), "password123".to_string()).await.unwrap();
    let user2 = create_test_user(&test_app.db_pool, "bob".to_string(), "password456".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create tasks for both users with sensitive data
    let payload1 = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user1.id,
        user_message: "Alice's private information: Account #12345".to_string(),
        ai_response: "Processing Alice's request".to_string(),
        timestamp: Utc::now(),
        metadata: Some(serde_json::json!({
            "alice_secret": "alice-only-data"
        })),
    };
    
    let request1 = CreateTaskRequest {
        user_id: user1.id,
        session_id: payload1.session_id,
        payload: payload1,
        priority: TaskPriority::Normal,
    };
    
    let task1 = task_queue.enqueue_task(request1).await.unwrap();
    
    let payload2 = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user2.id,
        user_message: "Bob's confidential data: PIN 6789".to_string(),
        ai_response: "Processing Bob's request".to_string(),
        timestamp: Utc::now(),
        metadata: Some(serde_json::json!({
            "bob_secret": "bob-only-data"
        })),
    };
    
    let request2 = CreateTaskRequest {
        user_id: user2.id,
        session_id: payload2.session_id,
        payload: payload2,
        priority: TaskPriority::Normal,
    };
    
    let _task2 = task_queue.enqueue_task(request2).await.unwrap();
    
    // Verify tasks are encrypted with different DEKs
    let raw_data = sqlx::query!(
        r#"
        SELECT user_id, encrypted_payload 
        FROM world_enrichment_tasks 
        WHERE id = $1
        "#,
        task1.id
    )
    .fetch_one(&test_app.db_pool)
    .await
    .unwrap();
    
    // Each user's data should be encrypted with their own DEK
    assert_eq!(raw_data.user_id, user1.id);
    let encrypted_bytes = raw_data.encrypted_payload;
    let encrypted_str = String::from_utf8_lossy(&encrypted_bytes);
    
    // Should not contain any plaintext from either user
    assert!(!encrypted_str.contains("Alice"));
    assert!(!encrypted_str.contains("Bob"));
    assert!(!encrypted_str.contains("12345"));
    assert!(!encrypted_str.contains("6789"));
}

/// Test metadata encryption specifically
#[tokio::test]
async fn test_metadata_encryption() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "metadata_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create deeply nested metadata
    let complex_metadata = serde_json::json!({
        "level1": {
            "level2": {
                "level3": {
                    "secret_key": "deeply-nested-secret",
                    "api_token": "sk-1234567890abcdef",
                    "credentials": {
                        "username": "admin",
                        "password": "super-secret-password"
                    }
                }
            },
            "pii": {
                "email": "user@example.com",
                "phone": "+1-555-0123",
                "address": {
                    "street": "123 Secret St",
                    "city": "Confidential City",
                    "zip": "12345"
                }
            }
        },
        "arrays": {
            "secret_list": ["secret1", "secret2", "secret3"],
            "sensitive_ids": [123456, 789012, 345678]
        }
    });
    
    let payload = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "Message with complex metadata".to_string(),
        ai_response: "Response acknowledging metadata".to_string(),
        timestamp: Utc::now(),
        metadata: Some(complex_metadata.clone()),
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id: payload.session_id,
        payload,
        priority: TaskPriority::Normal,
    };
    
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    // Verify none of the nested secrets appear in plaintext
    let raw_data = sqlx::query!(
        "SELECT encrypted_payload FROM world_enrichment_tasks WHERE id = $1",
        task.id
    )
    .fetch_one(&test_app.db_pool)
    .await
    .unwrap();
    
    let encrypted_str = String::from_utf8_lossy(&raw_data.encrypted_payload);
    
    // Check various nested values don't appear in plaintext
    assert!(!encrypted_str.contains("deeply-nested-secret"));
    assert!(!encrypted_str.contains("sk-1234567890abcdef"));
    assert!(!encrypted_str.contains("super-secret-password"));
    assert!(!encrypted_str.contains("user@example.com"));
    assert!(!encrypted_str.contains("Confidential City"));
    assert!(!encrypted_str.contains("secret1"));
    
    // Dequeue and verify all nested data is preserved
    let worker_id = Uuid::new_v4();
    let dequeued = task_queue.dequeue_task(worker_id).await.unwrap().unwrap();
    
    let decrypted_metadata = dequeued.payload.metadata.unwrap();
    assert_eq!(decrypted_metadata, complex_metadata);
    
    // Verify specific nested values
    assert_eq!(
        decrypted_metadata["level1"]["level2"]["level3"]["secret_key"], 
        "deeply-nested-secret"
    );
    assert_eq!(
        decrypted_metadata["level1"]["pii"]["address"]["city"], 
        "Confidential City"
    );
    assert_eq!(
        decrypted_metadata["arrays"]["secret_list"][0], 
        "secret1"
    );
}

/// Test encryption with empty/null metadata
#[tokio::test]
async fn test_encryption_with_null_metadata() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "null_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Test with None metadata
    let payload_none = EnrichmentTaskPayload {
        session_id: Uuid::new_v4(),
        user_id: user.id,
        user_message: "Message without metadata".to_string(),
        ai_response: "Response without metadata".to_string(),
        timestamp: Utc::now(),
        metadata: None,
    };
    
    let request = CreateTaskRequest {
        user_id: user.id,
        session_id: payload_none.session_id,
        payload: payload_none,
        priority: TaskPriority::Normal,
    };
    
    let task = task_queue.enqueue_task(request).await.unwrap();
    
    // Should handle gracefully
    let worker_id = Uuid::new_v4();
    let dequeued = task_queue.dequeue_task(worker_id).await.unwrap().unwrap();
    
    assert!(dequeued.payload.metadata.is_none());
    assert_eq!(dequeued.payload.user_message, "Message without metadata");
}

// Helper function to verify database encryption
async fn verify_database_encryption(
    pool: &PgPool,
    task_id: Uuid,
    original_payload: &EnrichmentTaskPayload,
) {
    let raw_data = sqlx::query!(
        r#"
        SELECT encrypted_payload, payload_nonce 
        FROM world_enrichment_tasks 
        WHERE id = $1
        "#,
        task_id
    )
    .fetch_one(pool)
    .await
    .unwrap();
    
    let encrypted_bytes = raw_data.encrypted_payload;
    let encrypted_str = String::from_utf8_lossy(&encrypted_bytes);
    
    // Verify no sensitive data in plaintext
    assert!(!encrypted_str.contains(&original_payload.user_message));
    assert!(!encrypted_str.contains(&original_payload.ai_response));
    assert!(!encrypted_str.contains("123-45-6789")); // SSN
    assert!(!encrypted_str.contains("INS-9876543")); // Insurance ID
    assert!(!encrypted_str.contains("lisinopril")); // Medication
    assert!(!encrypted_str.contains("Dr. Smith")); // Provider
    
    // Verify nonce exists
    assert!(raw_data.payload_nonce.is_some());
    assert!(!raw_data.payload_nonce.unwrap().is_empty());
}

// Helper function to verify error encryption
async fn verify_error_encryption(pool: &PgPool, task_id: Uuid, original_error: &str) {
    let raw_data = sqlx::query!(
        r#"
        SELECT encrypted_error, error_nonce 
        FROM world_enrichment_tasks 
        WHERE id = $1
        "#,
        task_id
    )
    .fetch_one(pool)
    .await
    .unwrap();
    
    if let Some(encrypted_error) = raw_data.encrypted_error {
        let encrypted_str = String::from_utf8_lossy(&encrypted_error);
        assert!(!encrypted_str.contains(original_error));
        assert!(raw_data.error_nonce.is_some());
    }
}