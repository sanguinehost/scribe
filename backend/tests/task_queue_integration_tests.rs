// backend/tests/task_queue_integration_tests.rs
//
// Task Queue Integration Tests with Chat Service
// Epic 8: Orchestrator-Driven Intelligent Agent System
//
// Tests the integration between task queue and chat service,
// validating the transition from tokio::spawn to durable task queue.
//
// TODO: This test file references ChatService which no longer exists in the codebase.
// It needs to be updated to work with the current chat implementation or removed.
// Temporarily disabled until migration is complete.

/*

use uuid::Uuid;
use chrono::Utc;
use scribe_backend::{
    test_helpers::{spawn_app, TestDataGuard, db::create_test_user, login_user_via_api},
    services::{
        task_queue::{TaskQueueService, TaskStatus, TaskPriority},
        chat_service::ChatService,
    },
    models::chats::{ApiChatMessage, ChatMode},
    errors::AppError,
};
use std::time::Duration;
use tokio::time::sleep;

/// Test chat service creates tasks instead of using tokio::spawn
#[tokio::test]
async fn test_chat_service_creates_background_tasks() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "chat_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    // Login to get authenticated client
    let (_client, session_id) = login_user_via_api(&test_app, "chat_user", "password123").await;
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    // Create chat session
    let chat_service = &test_app.app_state.chat_service;
    let character_id = Uuid::new_v4(); // Mock character
    let chat_session = chat_service.create_chat_session(
        user.id,
        session_id,
        character_id,
        None,
        ChatMode::Character,
    ).await.unwrap();
    
    // Send a message through chat service
    let history = vec![
        ApiChatMessage {
            role: "user".to_string(),
            content: "Hello, tell me about the enchanted forest.".to_string(),
        },
    ];
    
    // This should create a background task instead of using tokio::spawn
    let _response = chat_service.generate_chat_response(
        chat_session.id,
        user.id,
        session_id,
        history,
        None,
        None,
        true, // enable_progressive_response
    ).await.unwrap();
    
    // Wait a moment for task to be created
    sleep(Duration::from_millis(100)).await;
    
    // Verify task was created in queue
    let tasks = task_queue.get_session_tasks(chat_session.id).await.unwrap();
    
    assert!(!tasks.is_empty(), "Chat service should create background enrichment task");
    
    let task = &tasks[0];
    assert_eq!(task.session_id, chat_session.id);
    assert_eq!(task.user_id, user.id);
    assert_eq!(task.status, TaskStatus::Pending);
}

/// Test progressive response with task queue
#[tokio::test]
async fn test_progressive_response_with_task_queue() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "progressive_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let (_client, session_id) = login_user_via_api(&test_app, "progressive_user", "password123").await;
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    let chat_service = &test_app.app_state.chat_service;
    let character_id = Uuid::new_v4();
    let chat_session = chat_service.create_chat_session(
        user.id,
        session_id,
        character_id,
        None,
        ChatMode::Character,
    ).await.unwrap();
    
    // First message - Lightning Agent with minimal cache
    let history1 = vec![
        ApiChatMessage {
            role: "user".to_string(),
            content: "What's happening in the Dragon's Crown Peaks?".to_string(),
        },
    ];
    
    let response1 = chat_service.generate_chat_response(
        chat_session.id,
        user.id,
        session_id,
        history1,
        None,
        None,
        true, // Progressive response enabled
    ).await.unwrap();
    
    // Should get immediate response from Lightning Agent
    assert!(!response1.is_empty(), "Should get immediate Lightning response");
    
    // Background task should be created
    let tasks1 = task_queue.get_session_tasks(chat_session.id).await.unwrap();
    assert_eq!(tasks1.len(), 1, "First message should create one background task");
    
    // Simulate background processing by a worker
    let worker_id = Uuid::new_v4();
    if let Some(dequeued) = task_queue.dequeue_task(worker_id).await.unwrap() {
        // Simulate enrichment processing
        sleep(Duration::from_millis(100)).await;
        
        // Mark as completed
        task_queue.update_task_status(
            dequeued.task.id,
            TaskStatus::Completed,
            None
        ).await.unwrap();
    }
    
    // Second message - Lightning Agent with enriched cache
    let history2 = vec![
        ApiChatMessage {
            role: "user".to_string(),
            content: "What's happening in the Dragon's Crown Peaks?".to_string(),
        },
        ApiChatMessage {
            role: "assistant".to_string(),
            content: response1.clone(),
        },
        ApiChatMessage {
            role: "user".to_string(),
            content: "Tell me more about the ancient ruins there.".to_string(),
        },
    ];
    
    let response2 = chat_service.generate_chat_response(
        chat_session.id,
        user.id,
        session_id,
        history2,
        None,
        None,
        true,
    ).await.unwrap();
    
    assert!(!response2.is_empty(), "Should get enriched Lightning response");
    
    // Another background task for continued enrichment
    let tasks2 = task_queue.get_session_tasks(chat_session.id).await.unwrap();
    assert_eq!(tasks2.len(), 2, "Second message should create another task");
}

/// Test task priority based on chat context
#[tokio::test]
async fn test_task_priority_assignment() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "priority_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let (_client, session_id) = login_user_via_api(&test_app, "priority_user", "password123").await;
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    let chat_service = &test_app.app_state.chat_service;
    let character_id = Uuid::new_v4();
    
    // Test 1: Normal priority for regular chat
    let chat_session1 = chat_service.create_chat_session(
        user.id,
        session_id,
        character_id,
        None,
        ChatMode::Character,
    ).await.unwrap();
    
    let normal_history = vec![
        ApiChatMessage {
            role: "user".to_string(),
            content: "Tell me a story about a knight.".to_string(),
        },
    ];
    
    let _response1 = chat_service.generate_chat_response(
        chat_session1.id,
        user.id,
        session_id,
        normal_history,
        None,
        None,
        true,
    ).await.unwrap();
    
    sleep(Duration::from_millis(100)).await;
    
    let tasks1 = task_queue.get_session_tasks(chat_session1.id).await.unwrap();
    assert_eq!(tasks1[0].priority, TaskPriority::Normal as i32);
    
    // Test 2: High priority for complex world interactions
    let chat_session2 = chat_service.create_chat_session(
        user.id,
        session_id,
        character_id,
        None,
        ChatMode::Character,
    ).await.unwrap();
    
    let complex_history = vec![
        ApiChatMessage {
            role: "user".to_string(),
            content: "I cast a powerful spell that changes the landscape of the entire valley!".to_string(),
        },
    ];
    
    let _response2 = chat_service.generate_chat_response(
        chat_session2.id,
        user.id,
        session_id,
        complex_history,
        None,
        None,
        true,
    ).await.unwrap();
    
    sleep(Duration::from_millis(100)).await;
    
    let tasks2 = task_queue.get_session_tasks(chat_session2.id).await.unwrap();
    // Chat service should assign higher priority for world-changing events
    // This is a placeholder - actual implementation would analyze content
    assert!(tasks2[0].priority >= TaskPriority::Normal as i32);
}

/// Test task creation failure handling
#[tokio::test]
async fn test_task_creation_failure_handling() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "failure_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let (_client, session_id) = login_user_via_api(&test_app, "failure_user", "password123").await;
    
    let chat_service = &test_app.app_state.chat_service;
    let character_id = Uuid::new_v4();
    let chat_session = chat_service.create_chat_session(
        user.id,
        session_id,
        character_id,
        None,
        ChatMode::Character,
    ).await.unwrap();
    
    // Even if task creation fails, chat should still return response
    let history = vec![
        ApiChatMessage {
            role: "user".to_string(),
            content: "Hello world".to_string(),
        },
    ];
    
    let response = chat_service.generate_chat_response(
        chat_session.id,
        user.id,
        session_id,
        history,
        None,
        None,
        true,
    ).await;
    
    // Chat should not fail even if background task creation fails
    assert!(response.is_ok(), "Chat should succeed even if task queue fails");
}

/// Test concurrent chat sessions with task queue
#[tokio::test]
async fn test_concurrent_chat_sessions() {
    let test_app = spawn_app(true, false, false).await;
    let user1 = create_test_user(&test_app.db_pool, "concurrent1".to_string(), "password123".to_string()).await.unwrap();
    let user2 = create_test_user(&test_app.db_pool, "concurrent2".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let (_client1, session_id1) = login_user_via_api(&test_app, "concurrent1", "password123").await;
    let (_client2, session_id2) = login_user_via_api(&test_app, "concurrent2", "password123").await;
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    let chat_service = &test_app.app_state.chat_service;
    let character_id = Uuid::new_v4();
    
    // Create concurrent chat sessions
    let chat_session1 = chat_service.create_chat_session(
        user1.id,
        session_id1,
        character_id,
        None,
        ChatMode::Character,
    ).await.unwrap();
    
    let chat_session2 = chat_service.create_chat_session(
        user2.id,
        session_id2,
        character_id,
        None,
        ChatMode::Character,
    ).await.unwrap();
    
    // Send messages concurrently
    let history1 = vec![
        ApiChatMessage {
            role: "user".to_string(),
            content: "User 1 exploring the northern mountains".to_string(),
        },
    ];
    
    let history2 = vec![
        ApiChatMessage {
            role: "user".to_string(),
            content: "User 2 sailing the southern seas".to_string(),
        },
    ];
    
    let service1 = chat_service.clone();
    let service2 = chat_service.clone();
    
    let (result1, result2) = tokio::join!(
        service1.generate_chat_response(
            chat_session1.id,
            user1.id,
            session_id1,
            history1,
            None,
            None,
            true,
        ),
        service2.generate_chat_response(
            chat_session2.id,
            user2.id,
            session_id2,
            history2,
            None,
            None,
            true,
        )
    );
    
    assert!(result1.is_ok(), "User 1 chat should succeed");
    assert!(result2.is_ok(), "User 2 chat should succeed");
    
    sleep(Duration::from_millis(200)).await;
    
    // Verify both created separate tasks
    let tasks1 = task_queue.get_session_tasks(chat_session1.id).await.unwrap();
    let tasks2 = task_queue.get_session_tasks(chat_session2.id).await.unwrap();
    
    assert_eq!(tasks1.len(), 1, "User 1 should have one task");
    assert_eq!(tasks2.len(), 1, "User 2 should have one task");
    assert_ne!(tasks1[0].id, tasks2[0].id, "Tasks should be different");
}

/// Test task processing doesn't block chat response
#[tokio::test]
async fn test_non_blocking_background_enrichment() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "nonblock_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let (_client, session_id) = login_user_via_api(&test_app, "nonblock_user", "password123").await;
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    let chat_service = &test_app.app_state.chat_service;
    let character_id = Uuid::new_v4();
    let chat_session = chat_service.create_chat_session(
        user.id,
        session_id,
        character_id,
        None,
        ChatMode::Character,
    ).await.unwrap();
    
    let history = vec![
        ApiChatMessage {
            role: "user".to_string(),
            content: "Quick response test".to_string(),
        },
    ];
    
    let start = std::time::Instant::now();
    
    let response = chat_service.generate_chat_response(
        chat_session.id,
        user.id,
        session_id,
        history,
        None,
        None,
        true,
    ).await.unwrap();
    
    let duration = start.elapsed();
    
    // Response should be fast (not waiting for background processing)
    assert!(duration < Duration::from_secs(10), "Chat response should not wait for background task");
    assert!(!response.is_empty(), "Should get response");
    
    // Task should still be created
    let tasks = task_queue.get_session_tasks(chat_session.id).await.unwrap();
    assert_eq!(tasks.len(), 1, "Background task should be created");
    assert_eq!(tasks[0].status, TaskStatus::Pending, "Task should be pending");
}

/// Test task contains correct encrypted payload
#[tokio::test]
async fn test_task_payload_correctness() {
    let test_app = spawn_app(true, false, false).await;
    let user = create_test_user(&test_app.db_pool, "payload_user".to_string(), "password123".to_string()).await.unwrap();
    
    let _guard = TestDataGuard::new(test_app.db_pool.clone());
    
    let (_client, session_id) = login_user_via_api(&test_app, "payload_user", "password123").await;
    
    let task_queue = TaskQueueService::new(
        test_app.db_pool.clone(),
        test_app.app_state.encryption_service.clone(),
        test_app.app_state.auth_backend.clone(),
    );
    
    let chat_service = &test_app.app_state.chat_service;
    let character_id = Uuid::new_v4();
    let chat_session = chat_service.create_chat_session(
        user.id,
        session_id,
        character_id,
        None,
        ChatMode::Character,
    ).await.unwrap();
    
    let user_message = "I found a mysterious artifact in the ancient temple.";
    let history = vec![
        ApiChatMessage {
            role: "user".to_string(),
            content: user_message.to_string(),
        },
    ];
    
    let ai_response = chat_service.generate_chat_response(
        chat_session.id,
        user.id,
        session_id,
        history,
        None,
        None,
        true,
    ).await.unwrap();
    
    sleep(Duration::from_millis(100)).await;
    
    // Dequeue and check payload
    let worker_id = Uuid::new_v4();
    let dequeued = task_queue.dequeue_task(worker_id).await.unwrap();
    
    assert!(dequeued.is_some(), "Should have task to process");
    let task_data = dequeued.unwrap();
    
    // Verify payload contains correct data
    assert_eq!(task_data.payload.user_id, user.id);
    assert_eq!(task_data.payload.session_id, chat_session.id);
    assert_eq!(task_data.payload.user_message, user_message);
    assert_eq!(task_data.payload.ai_response, ai_response);
    assert!(task_data.payload.timestamp < Utc::now());
}*/
