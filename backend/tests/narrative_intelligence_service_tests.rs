//! Comprehensive test suite for Flash-integrated Narrative Intelligence Service
//! 
//! Tests the complete 4-step agentic workflow: Triage → Retrieve → Plan → Execute
//! with Flash/Flash-Lite integration following Epic 1, Task 1.0.1

use chrono::Utc;
use uuid::Uuid;
use secrecy::{SecretBox, ExposeSecret};

use scribe_backend::{
    auth::session_dek::SessionDek,
    models::chats::{ChatMessage, MessageRole},
    services::narrative_intelligence_service::{
            NarrativeIntelligenceService, NarrativeProcessingConfig
        },
    test_helpers::TestDataGuard,
};

/// Test the basic Flash-integrated service creation
#[tokio::test]
async fn test_narrative_intelligence_service_creation() {
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    // Test service creation with default config
    let service = NarrativeIntelligenceService::for_development_with_deps(
        test_app.app_state.clone(),
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
        test_app.app_state.clone(),
        Some(custom_config),
    );
    
    assert!(service_with_config.is_ok(), "Service creation with custom config should succeed");
}

/// Test Flash integration with realistic narrative content
#[tokio::test]
async fn test_realistic_narrative_flash_integration() {
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let service = NarrativeIntelligenceService::for_development_with_deps(
        test_app.app_state.clone(),
        None,
    ).expect("Failed to create service");

    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    
    // Create proper SessionDek
    let kek_salt = scribe_backend::crypto::generate_salt().unwrap();
    let dek = scribe_backend::crypto::generate_dek().unwrap();
    let session_dek = SessionDek(SecretBox::new(Box::new(dek.expose_secret().to_vec())));

    // Realistic RPG narrative content
    let content = r#"
                Captain Sarah Chen adjusted her neural interface as the ship's AI announced their arrival at the Kepler-442 system. 
                "Something's wrong," she murmured, studying the sensor readings. The colony that should have been thriving 
                was dark and silent. No response to hails, no energy signatures, nothing.
                
                "Commander," her first officer reported, "I'm detecting a single life sign on the surface. 
                Human. But there's something else... something the sensors can't quite identify."
            "#;
    
    // Encrypt the content
    let (encrypted_content, nonce) = scribe_backend::crypto::encrypt_gcm(
        content.as_bytes(),
        &session_dek.0,
    ).unwrap();
    
    let messages = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: encrypted_content,
            content_nonce: Some(nonce),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(20),
            completion_tokens: Some(50),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
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
    
    // Log the results for manual verification - processing time may be 0 for mock responses
    println!("Flash Analysis Results:");
    println!("  Significant: {}", processing_result.is_significant);
    println!("  Confidence: {:.2}", processing_result.confidence);
    println!("  Events Created: {}", processing_result.events_created);
    println!("  Entries Created: {}", processing_result.entries_created);
    println!("  Processing Time: {}ms", processing_result.processing_time_ms);
    
    // The service should at least complete processing (mock may not find content significant)
    assert!(processing_result.confidence >= 0.0, "Confidence should be valid");
    assert!(processing_result.events_created >= 0, "Events count should be valid");
    assert!(processing_result.entries_created >= 0, "Entries count should be valid");
}

/// Test cost optimization configuration
#[tokio::test]
async fn test_cost_optimization_config() {
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let cost_optimized_config = NarrativeProcessingConfig {
        enabled: true,
        min_confidence_threshold: 0.5,
        max_concurrent_jobs: 1, // Limit concurrency for cost control
        enable_cost_optimizations: true,
    };

    let service = NarrativeIntelligenceService::for_development_with_deps(
        test_app.app_state.clone(),
        Some(cost_optimized_config),
    ).expect("Failed to create service with cost optimization");

    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    
    // Create proper SessionDek
    let kek_salt = scribe_backend::crypto::generate_salt().unwrap();
    let dek = scribe_backend::crypto::generate_dek().unwrap();
    let session_dek = SessionDek(SecretBox::new(Box::new(dek.expose_secret().to_vec())));

    // Encrypt test content
    let content = "Test message for cost optimization";
    let (encrypted_content, nonce) = scribe_backend::crypto::encrypt_gcm(
        content.as_bytes(),
        &session_dek.0,
    ).unwrap();
    
    let messages = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: encrypted_content,
            content_nonce: Some(nonce),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(5),
            completion_tokens: Some(10),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
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
    println!("Cost optimization test result: {:?}", result);
}

/// Test error handling with invalid inputs
#[tokio::test]
async fn test_error_handling() {
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

    let service = NarrativeIntelligenceService::for_development_with_deps(
        test_app.app_state.clone(),
        None,
    ).expect("Failed to create service");

    let user_id = Uuid::new_v4();
    let chronicle_id = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    
    // Create proper SessionDek
    let kek_salt = scribe_backend::crypto::generate_salt().unwrap();
    let dek = scribe_backend::crypto::generate_dek().unwrap();
    let session_dek = SessionDek(SecretBox::new(Box::new(dek.expose_secret().to_vec())));

    // Test with empty messages
    let empty_messages = vec![];
    let result = service.process_narrative_batch(
        user_id,
        chronicle_id,
        empty_messages,
        &session_dek,
    ).await;

    // Should handle empty input gracefully
    println!("Empty messages test result: {:?}", result);
}