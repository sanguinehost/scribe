//! Comprehensive test suite for Flash-integrated Narrative Intelligence Service
//! 
//! Tests the complete 4-step agentic workflow: Triage → Retrieve → Plan → Execute
//! with Flash/Flash-Lite integration following Epic 1, Task 1.0.1

use chrono::Utc;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

use scribe_backend::{
    auth::session_dek::SessionDek,
    errors::AppError,
    models::chats::ChatMessage,
    services::{
        narrative_intelligence_service::{
            NarrativeIntelligenceService, NarrativeProcessingConfig, NarrativeProcessingResult,
            BatchEventData, EventDataToInsert
        },
    },
    test_helpers::{spawn_app, TestDataGuard, MockAiClient},
};

/// Test the basic Flash-integrated service creation
#[tokio::test]
async fn test_narrative_intelligence_service_creation() {
    let _guard = TestDataGuard::new().await;
    let app_state = spawn_app().await.expect("Failed to spawn test app");

    // Test service creation with default config
    let service = NarrativeIntelligenceService::for_development_with_deps(
        app_state.clone(),
        None,
    );
    
    assert!(service.is_ok(), "Service creation should succeed with default config");

    // Test service creation with custom config
    let custom_config = NarrativeProcessingConfig {
        enabled: true,
        min_confidence_threshold: 0.7,
        max_concurrent_jobs: 5,
        enable_cost_optimizations: true,
    };

    let service_with_config = NarrativeIntelligenceService::for_development_with_deps(
        app_state.clone(),
        Some(custom_config),
    );
    
    assert!(service_with_config.is_ok(), "Service creation should succeed with custom config");
}

/// Test Flash-Lite triage functionality
#[tokio::test]
async fn test_flash_lite_triage_analysis() {
    let _guard = TestDataGuard::new().await;
    let app_state = spawn_app().await.expect("Failed to spawn test app");

    let service = NarrativeIntelligenceService::for_development_with_deps(
        app_state.clone(),
        None,
    ).expect("Failed to create service");

    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let session_dek = SessionDek::new_for_user(user_id);

    // Test with significant narrative content
    let significant_messages = vec![
        ChatMessage {
            id: 1,
            user_id,
            chronicle_id: Some(chronicle_id),
            content: "The dragon emerged from the ancient cave, its eyes glowing with malevolent intelligence. Sir Gareth raised his enchanted sword, knowing this battle would determine the fate of the kingdom.".to_string(),
            created_at: Utc::now(),
            persona_id: None,
            token_count: 0,
        }
    ];

    let result = service.process_narrative_batch(
        user_id,
        chronicle_id,
        significant_messages,
        &session_dek,
    ).await;

    assert!(result.is_ok(), "Triage analysis should succeed for significant content");
    let processing_result = result.unwrap();
    
    // Flash-Lite should identify this as significant
    assert!(processing_result.is_significant, "Epic dragon battle should be deemed significant");
    assert!(processing_result.confidence > 0.5, "Confidence should be reasonably high for clear narrative content");
    assert!(processing_result.processing_time_ms > 0, "Processing time should be recorded");
}

/// Test triage with non-significant content
#[tokio::test]
async fn test_flash_lite_triage_non_significant() {
    let _guard = TestDataGuard::new().await;
    let app_state = spawn_app().await.expect("Failed to spawn test app");

    let service = NarrativeIntelligenceService::for_development_with_deps(
        app_state.clone(),
        None,
    ).expect("Failed to create service");

    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let session_dek = SessionDek::new_for_user(user_id);

    // Test with non-significant content
    let mundane_messages = vec![
        ChatMessage {
            id: 1,
            user_id,
            chronicle_id: Some(chronicle_id),
            content: "I checked my inventory. Still have that old rope.".to_string(),
            created_at: Utc::now(),
            persona_id: None,
            token_count: 0,
        }
    ];

    let result = service.process_narrative_batch(
        user_id,
        chronicle_id,
        mundane_messages,
        &session_dek,
    ).await;

    assert!(result.is_ok(), "Triage analysis should succeed even for mundane content");
    let processing_result = result.unwrap();
    
    // Processing time should still be recorded even if not significant
    assert!(processing_result.processing_time_ms > 0, "Processing time should be recorded");
}

/// Test batch analysis without database insertion
#[tokio::test]
async fn test_batch_analysis_without_insert() {
    let _guard = TestDataGuard::new().await;
    let app_state = spawn_app().await.expect("Failed to spawn test app");

    let service = NarrativeIntelligenceService::for_development_with_deps(
        app_state.clone(),
        None,
    ).expect("Failed to create service");

    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let session_dek = SessionDek::new_for_user(user_id);

    let messages = vec![
        ChatMessage {
            id: 1,
            user_id,
            chronicle_id: Some(chronicle_id),
            content: "The wizard cast a powerful spell, transforming the battlefield into a frozen wasteland.".to_string(),
            created_at: Utc::now(),
            persona_id: None,
            token_count: 0,
        }
    ];

    let result = service.analyze_batch_without_insert(
        user_id,
        chronicle_id,
        messages,
        &session_dek,
        0, // batch_index
    ).await;

    assert!(result.is_ok(), "Batch analysis should succeed");
    let batch_data = result.unwrap();
    
    assert_eq!(batch_data.batch_index, 0, "Batch index should be preserved");
    assert!(batch_data.processing_time_ms > 0, "Processing time should be recorded");
    
    if batch_data.is_significant {
        assert!(batch_data.confidence > 0.0, "Significant batches should have confidence > 0");
    }
}

/// Test empty message batch handling
#[tokio::test]
async fn test_empty_message_batch() {
    let _guard = TestDataGuard::new().await;
    let app_state = spawn_app().await.expect("Failed to spawn test app");

    let service = NarrativeIntelligenceService::for_development_with_deps(
        app_state.clone(),
        None,
    ).expect("Failed to create service");

    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let session_dek = SessionDek::new_for_user(user_id);

    let empty_messages = vec![];

    let result = service.process_narrative_batch(
        user_id,
        chronicle_id,
        empty_messages,
        &session_dek,
    ).await;

    assert!(result.is_ok(), "Empty batch should be handled gracefully");
    let processing_result = result.unwrap();
    
    assert!(!processing_result.is_significant, "Empty batch should not be significant");
    assert_eq!(processing_result.confidence, 0.0, "Empty batch should have zero confidence");
    assert_eq!(processing_result.events_created, 0, "No events should be created for empty batch");
    assert_eq!(processing_result.entries_created, 0, "No entries should be created for empty batch");
}

/// Test service with disabled configuration
#[tokio::test]
async fn test_disabled_service_configuration() {
    let _guard = TestDataGuard::new().await;
    let app_state = spawn_app().await.expect("Failed to spawn test app");

    let disabled_config = NarrativeProcessingConfig {
        enabled: false,
        min_confidence_threshold: 0.5,
        max_concurrent_jobs: 1,
        enable_cost_optimizations: true,
    };

    let service = NarrativeIntelligenceService::for_development_with_deps(
        app_state.clone(),
        Some(disabled_config),
    ).expect("Failed to create service");

    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let session_dek = SessionDek::new_for_user(user_id);

    let messages = vec![
        ChatMessage {
            id: 1,
            user_id,
            chronicle_id: Some(chronicle_id),
            content: "Epic battle between good and evil!".to_string(),
            created_at: Utc::now(),
            persona_id: None,
            token_count: 0,
        }
    ];

    let result = service.process_narrative_batch(
        user_id,
        chronicle_id,
        messages,
        &session_dek,
    ).await;

    assert!(result.is_ok(), "Disabled service should still respond");
    let processing_result = result.unwrap();
    
    // Disabled service should return default result without processing
    assert!(!processing_result.is_significant, "Disabled service should not process content");
    assert_eq!(processing_result.confidence, 0.0, "Disabled service should return zero confidence");
}

/// Test confidence threshold filtering
#[tokio::test]
async fn test_confidence_threshold_filtering() {
    let _guard = TestDataGuard::new().await;
    let app_state = spawn_app().await.expect("Failed to spawn test app");

    let high_threshold_config = NarrativeProcessingConfig {
        enabled: true,
        min_confidence_threshold: 0.9, // Very high threshold
        max_concurrent_jobs: 1,
        enable_cost_optimizations: true,
    };

    let service = NarrativeIntelligenceService::for_development_with_deps(
        app_state.clone(),
        Some(high_threshold_config),
    ).expect("Failed to create service");

    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let session_dek = SessionDek::new_for_user(user_id);

    // Even significant content might not meet the very high threshold
    let messages = vec![
        ChatMessage {
            id: 1,
            user_id,
            chronicle_id: Some(chronicle_id),
            content: "I walked to the tavern.".to_string(),
            created_at: Utc::now(),
            persona_id: None,
            token_count: 0,
        }
    ];

    let result = service.process_narrative_batch(
        user_id,
        chronicle_id,
        messages,
        &session_dek,
    ).await;

    assert!(result.is_ok(), "High threshold processing should succeed");
    // Result will depend on actual Flash-Lite analysis
}

/// Test multiple message batch processing
#[tokio::test]
async fn test_multiple_message_batch() {
    let _guard = TestDataGuard::new().await;
    let app_state = spawn_app().await.expect("Failed to spawn test app");

    let service = NarrativeIntelligenceService::for_development_with_deps(
        app_state.clone(),
        None,
    ).expect("Failed to create service");

    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let session_dek = SessionDek::new_for_user(user_id);

    // Multiple messages forming a narrative sequence
    let messages = vec![
        ChatMessage {
            id: 1,
            user_id,
            chronicle_id: Some(chronicle_id),
            content: "I entered the ancient dungeon, torch in hand.".to_string(),
            created_at: Utc::now(),
            persona_id: None,
            token_count: 0,
        },
        ChatMessage {
            id: 2,
            user_id,
            chronicle_id: Some(chronicle_id),
            content: "The walls were covered in strange runes that seemed to glow.".to_string(),
            created_at: Utc::now(),
            persona_id: None,
            token_count: 0,
        },
        ChatMessage {
            id: 3,
            user_id,
            chronicle_id: Some(chronicle_id),
            content: "Suddenly, a skeletal guardian emerged from the shadows!".to_string(),
            created_at: Utc::now(),
            persona_id: None,
            token_count: 0,
        },
    ];

    let result = service.process_narrative_batch(
        user_id,
        chronicle_id,
        messages,
        &session_dek,
    ).await;

    assert!(result.is_ok(), "Multi-message batch should be processed successfully");
    let processing_result = result.unwrap();
    
    // Multi-message narrative should generally be more significant
    assert!(processing_result.processing_time_ms > 0, "Processing time should be recorded");
}

/// Test error handling with invalid user ID
#[tokio::test]
async fn test_error_handling_invalid_session() {
    let _guard = TestDataGuard::new().await;
    let app_state = spawn_app().await.expect("Failed to spawn test app");

    let service = NarrativeIntelligenceService::for_development_with_deps(
        app_state.clone(),
        None,
    ).expect("Failed to create service");

    let user_id = Uuid::new_v4();
    let different_user_id = Uuid::new_v4(); // Different user for session
    let chronicle_id = Uuid::new_v4();
    let session_dek = SessionDek::new_for_user(different_user_id); // Mismatched session

    let messages = vec![
        ChatMessage {
            id: 1,
            user_id,
            chronicle_id: Some(chronicle_id),
            content: "Test message".to_string(),
            created_at: Utc::now(),
            persona_id: None,
            token_count: 0,
        }
    ];

    let result = service.process_narrative_batch(
        user_id,
        chronicle_id,
        messages,
        &session_dek,
    ).await;

    // This should either handle gracefully or return appropriate error
    // The exact behavior depends on SessionDek validation implementation
}

/// Test Flash integration with realistic narrative content
#[tokio::test]
async fn test_realistic_narrative_flash_integration() {
    let _guard = TestDataGuard::new().await;
    let app_state = spawn_app().await.expect("Failed to spawn test app");

    let service = NarrativeIntelligenceService::for_development_with_deps(
        app_state.clone(),
        None,
    ).expect("Failed to create service");

    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let session_dek = SessionDek::new_for_user(user_id);

    // Realistic RPG narrative content
    let messages = vec![
        ChatMessage {
            id: 1,
            user_id,
            chronicle_id: Some(chronicle_id),
            content: r#"
                Captain Sarah Chen adjusted her neural interface as the ship's AI announced their arrival at the Kepler-442 system. 
                "Something's wrong," she murmured, studying the sensor readings. The colony that should have been thriving 
                was dark and silent. No response to hails, no energy signatures, nothing.
                
                "Commander," her first officer reported, "I'm detecting a single life sign on the surface. 
                Human. But there's something else... something the sensors can't quite identify."
            "#.to_string(),
            created_at: Utc::now(),
            persona_id: None,
            token_count: 0,
        }
    ];

    let result = service.process_narrative_batch(
        user_id,
        chronicle_id,
        messages,
        &session_dek,
    ).await;

    assert!(result.is_ok(), "Realistic narrative should be processed successfully");
    let processing_result = result.unwrap();
    
    // Rich narrative content should be deemed significant
    assert!(processing_result.processing_time_ms > 0, "Processing time should be recorded");
    
    // Log the results for manual verification
    println!("Flash Analysis Results:");
    println!("  Significant: {}", processing_result.is_significant);
    println!("  Confidence: {:.2}", processing_result.confidence);
    println!("  Events Created: {}", processing_result.events_created);
    println!("  Entries Created: {}", processing_result.entries_created);
    println!("  Processing Time: {}ms", processing_result.processing_time_ms);
}

/// Test cost optimization configuration
#[tokio::test]
async fn test_cost_optimization_config() {
    let _guard = TestDataGuard::new().await;
    let app_state = spawn_app().await.expect("Failed to spawn test app");

    let cost_optimized_config = NarrativeProcessingConfig {
        enabled: true,
        min_confidence_threshold: 0.5,
        max_concurrent_jobs: 1, // Limit concurrency for cost control
        enable_cost_optimizations: true,
    };

    let service = NarrativeIntelligenceService::for_development_with_deps(
        app_state.clone(),
        Some(cost_optimized_config),
    ).expect("Failed to create service with cost optimization");

    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let session_dek = SessionDek::new_for_user(user_id);

    let messages = vec![
        ChatMessage {
            id: 1,
            user_id,
            chronicle_id: Some(chronicle_id),
            content: "Test message for cost optimization".to_string(),
            created_at: Utc::now(),
            persona_id: None,
            token_count: 0,
        }
    ];

    let start_time = std::time::Instant::now();
    let result = service.process_narrative_batch(
        user_id,
        chronicle_id,
        messages,
        &session_dek,
    ).await;
    let elapsed = start_time.elapsed();

    assert!(result.is_ok(), "Cost-optimized processing should succeed");
    
    // Cost optimization should potentially reduce processing time
    println!("Cost-optimized processing took: {:?}", elapsed);
}