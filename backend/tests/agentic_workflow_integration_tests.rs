// backend/tests/agentic_workflow_integration_tests.rs
//
// Integration tests for the complete agentic narrative workflow using mock AI responses.
// Tests the end-to-end flow from chat messages through AI analysis to tool execution.

use chrono::Utc;
use reqwest::StatusCode;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use scribe_backend::{
    config::{NarrativeFeatureFlags, ExtractionMode},
    llm::{AiClient, EmbeddingClient},
    models::{
        chats::{ChatMessage, MessageRole},
        chronicle_dtos::CreateChroniclePayload,
        lorebook_dtos::CreateLorebookEntryPayload,
    },
    services::{
        agentic::{
            AgenticNarrativeFactory, NarrativeAgentRunner, 
            NarrativeWorkflowConfig, NarrativeWorkflowResult
        },
        extraction_dispatcher::{ExtractionDispatcher, ExtractionResult},
        ChronicleService, LorebookService, EncryptionService,
    },
    test_helpers::{spawn_app, MockAiClient, TestDataGuard},
    auth::session_dek::SessionDek,
};

#[tokio::test]
async fn test_complete_agentic_workflow_with_mock_responses() {
    let test_app = spawn_app().await;
    let user_id = test_app.test_user.id;
    let session_id = Uuid::new_v4();

    // Configure mock AI client with realistic triage response
    let triage_response = json!({
        "is_significant": true,
        "summary": "User introduces new character Alex and starts adventure",
        "event_category": "PLOT", 
        "event_type": "ADVENTURE_START",
        "narrative_action": "BEGAN",
        "primary_agent": "Alex",
        "primary_patient": "Adventure",
        "confidence": 0.85
    });

    // For simplicity, use only the triage response in this test
    // In a full implementation, we'd need a more sophisticated mock that can handle multiple calls
    let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

    // Create agentic system with mock AI client using the same pattern as working tests
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let lorebook_service = Arc::new(LorebookService::new(
        test_app.db_pool.clone(), 
        Arc::new(EncryptionService::new()),
        test_app.qdrant_service.clone()
    ));
    
    let agentic_runner = AgenticNarrativeFactory::create_system_with_deps(
        mock_ai_client.clone(),
        chronicle_service.clone(),
        lorebook_service,
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
        None, // Use default config
    );

    // Create test chat messages representing a new adventure
    let messages = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "Hello! I want to start a new adventure where I play as a young wizard named Alex.".as_bytes().to_vec(),
            content_nonce: Some(vec![1, 2, 3, 4]),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(20),
            completion_tokens: Some(0),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        },
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::Assistant,
            content: "Welcome, Alex! You find yourself at the entrance to an ancient magical academy...".as_bytes().to_vec(),
            content_nonce: Some(vec![5, 6, 7, 8]),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(0),
            completion_tokens: Some(25),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        },
    ];

    // Create session DEK for testing
    use secrecy::SecretBox;
    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

    // Run the agentic workflow
    let result = agentic_runner.process_narrative_event(
        user_id,
        session_id,
        None, // No existing chronicle
        &messages,
        &session_dek,
    ).await;

    // Verify the workflow completed successfully
    assert!(result.is_ok(), "Agentic workflow should complete successfully");
    let workflow_result = result.unwrap();

    // Verify triage and planning steps were executed
    assert!(!workflow_result.execution_results.is_empty(), "Should have execution results");
    assert!(!workflow_result.actions_taken.is_empty(), "Should have taken actions");

    // Verify actions were planned correctly
    let actions = &workflow_result.actions_taken;
    assert!(
        actions.iter().any(|action| action.tool_name == "create_chronicle"),
        "Should have planned chronicle creation"
    );
    assert!(
        actions.iter().any(|action| action.tool_name == "create_lorebook_entry"),
        "Should have planned lorebook entry creation"
    );

    println!("✓ Complete agentic workflow test passed");
}

#[tokio::test]
async fn test_extraction_dispatcher_with_agentic_mode() {
    let test_app = spawn_app().await;
    let user_id = test_app.test_user.id;
    let session_id = Uuid::new_v4();

    // Create feature flags for agentic mode
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_agentic_extraction = true;
    feature_flags.agentic_rollout_percentage = 100; // Enable for all users
    feature_flags.enable_realtime_extraction = true;

    // Configure mock AI client
    let triage_response = json!({
        "is_significant": true,
        "summary": "Dialogue contains important character development",
        "event_category": "DIALOGUE",
        "event_type": "CHARACTER_DEVELOPMENT",
        "narrative_action": "SPOKE",
        "primary_agent": "Alex",
        "confidence": 0.9
    });

    let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

    // Create agentic system using the same pattern as working tests
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let lorebook_service = Arc::new(LorebookService::new(
        test_app.db_pool.clone(), 
        Arc::new(EncryptionService::new()),
        test_app.qdrant_service.clone()
    ));
    
    let agentic_runner = AgenticNarrativeFactory::create_system_with_deps(
        mock_ai_client.clone(),
        chronicle_service.clone(),
        lorebook_service,
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
        None, // Use default config
    );

    // Create extraction dispatcher
    let dispatcher = ExtractionDispatcher::new(
        Arc::new(feature_flags),
        Some(agentic_runner),
    );

    // Create test messages
    let messages = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "Alex looks around the magical academy courtyard nervously.".as_bytes().to_vec(),
            content_nonce: Some(vec![1, 2, 3, 4]),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(15),
            completion_tokens: Some(0),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        },
    ];

    // Create session DEK for testing
    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

    // Run extraction through dispatcher
    let result = dispatcher.extract_events_from_chat(
        user_id,
        session_id,
        None,
        &messages,
        &session_dek,
    ).await;

    // Verify extraction succeeded
    assert!(result.is_ok(), "Extraction should succeed through dispatcher");
    let extraction_result = result.unwrap();

    assert!(extraction_result.success, "Extraction should be successful");
    assert_eq!(extraction_result.mode_used, ExtractionMode::AgenticOnly);
    assert!(extraction_result.duration_ms > 0, "Should have measurable duration");
    assert!(extraction_result.ai_calls_made > 0, "Should have made AI calls");

    println!("✓ Extraction dispatcher agentic mode test passed");
}

#[tokio::test]
async fn test_dual_mode_extraction_comparison() {
    let test_app = spawn_app().await;
    let user_id = test_app.test_user.id;
    let session_id = Uuid::new_v4();

    // Create feature flags for dual mode
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_agentic_extraction = true;
    feature_flags.dual_extraction_mode = true;
    feature_flags.agentic_rollout_percentage = 100;
    feature_flags.enable_extraction_metrics = true;

    // Configure mock AI client for agentic extraction
    let triage_response = json!({
        "is_significant": false,
        "summary": "Just casual dialogue, no significant events",
        "event_category": "DIALOGUE",
        "event_type": "CASUAL_CONVERSATION",
        "narrative_action": "SPOKE",
        "confidence": 0.3
    });

    let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

    // Create agentic system using the same pattern as working tests
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let lorebook_service = Arc::new(LorebookService::new(
        test_app.db_pool.clone(), 
        Arc::new(EncryptionService::new()),
        test_app.qdrant_service.clone()
    ));
    
    let agentic_runner = AgenticNarrativeFactory::create_system_with_deps(
        mock_ai_client.clone(),
        chronicle_service.clone(),
        lorebook_service,
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
        None, // Use default config
    );

    // Create extraction dispatcher with dual mode
    let dispatcher = ExtractionDispatcher::new(
        Arc::new(feature_flags),
        Some(agentic_runner),
    );

    // Create test messages (mundane conversation)
    let messages = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "How are you today?".as_bytes().to_vec(),
            content_nonce: Some(vec![1, 2, 3, 4]),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(5),
            completion_tokens: Some(0),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        },
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::Assistant,
            content: "I'm doing well, thank you for asking!".as_bytes().to_vec(),
            content_nonce: Some(vec![5, 6, 7, 8]),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(0),
            completion_tokens: Some(10),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        },
    ];

    // Create session DEK for testing
    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

    // Run dual mode extraction
    let result = dispatcher.extract_events_from_chat(
        user_id,
        session_id,
        None,
        &messages,
        &session_dek,
    ).await;

    // Verify dual mode ran (even though manual is placeholder)
    assert!(result.is_ok(), "Dual mode extraction should complete");
    let extraction_result = result.unwrap();

    // In dual mode, should return agentic result if it succeeded
    assert_eq!(extraction_result.mode_used, ExtractionMode::AgenticOnly);
    assert!(extraction_result.success, "Agentic extraction should succeed");

    println!("✓ Dual mode extraction comparison test passed");
}

#[tokio::test]
async fn test_agentic_workflow_with_timeout() {
    let test_app = spawn_app().await;
    let user_id = test_app.test_user.id;
    let session_id = Uuid::new_v4();

    // Create feature flags with very short timeout
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_agentic_extraction = true;
    feature_flags.agentic_rollout_percentage = 100;
    feature_flags.agentic_extraction_timeout_secs = 1; // Very short timeout
    feature_flags.fallback_to_manual_on_error = true;

    // Configure mock AI client with default response (will hang/timeout in real scenario)
    let mock_ai_client = Arc::new(MockAiClient::new()); // Default response

    // Create agentic system using the same pattern as working tests
    let chronicle_service = Arc::new(ChronicleService::new(test_app.db_pool.clone()));
    let lorebook_service = Arc::new(LorebookService::new(
        test_app.db_pool.clone(), 
        Arc::new(EncryptionService::new()),
        test_app.qdrant_service.clone()
    ));
    
    let agentic_runner = AgenticNarrativeFactory::create_system_with_deps(
        mock_ai_client.clone(),
        chronicle_service.clone(),
        lorebook_service,
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
        None, // Use default config
    );

    // Create extraction dispatcher
    let dispatcher = ExtractionDispatcher::new(
        Arc::new(feature_flags),
        Some(agentic_runner),
    );

    // Create test messages
    let messages = vec![
        ChatMessage {
            id: Uuid::new_v4(),
            session_id,
            message_type: MessageRole::User,
            content: "This should timeout".as_bytes().to_vec(),
            content_nonce: Some(vec![1, 2, 3, 4]),
            created_at: Utc::now(),
            user_id,
            prompt_tokens: Some(5),
            completion_tokens: Some(0),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        },
    ];

    // Create session DEK for testing
    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

    // Run extraction (should timeout and fall back to manual)
    let result = dispatcher.extract_events_from_chat(
        user_id,
        session_id,
        None,
        &messages,
        &session_dek,
    ).await;

    // Should succeed due to fallback to manual (which returns placeholder)
    assert!(result.is_ok(), "Should fall back to manual on timeout");
    let extraction_result = result.unwrap();

    // Should have fallen back to manual mode
    assert_eq!(extraction_result.mode_used, ExtractionMode::ManualOnly);
    assert!(!extraction_result.success, "Manual extraction is placeholder and fails");
    assert!(extraction_result.error_message.is_some(), "Should have error message explaining manual extraction not implemented");

    println!("✓ Agentic workflow timeout and fallback test passed");
}

#[tokio::test]
async fn test_feature_flag_user_rollout() {
    let test_app = spawn_app().await;

    // Test user not in rollout (0% rollout)
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_agentic_extraction = true;
    feature_flags.agentic_rollout_percentage = 0; // No users get agentic

    let dispatcher = ExtractionDispatcher::new(
        Arc::new(feature_flags.clone()),
        None, // No agentic runner needed for this test
    );

    assert!(!dispatcher.should_enable_realtime_extraction("test_user_1"));
    assert!(!dispatcher.should_enable_auto_lorebook_creation("test_user_1"));
    assert!(!dispatcher.should_enable_auto_chronicle_creation("test_user_1"));

    // Test user in 100% rollout
    feature_flags.agentic_rollout_percentage = 100;
    feature_flags.enable_realtime_extraction = true;
    feature_flags.enable_auto_lorebook_creation = true;
    feature_flags.enable_auto_chronicle_creation = true;

    let dispatcher = ExtractionDispatcher::new(
        Arc::new(feature_flags.clone()),
        None,
    );

    assert!(dispatcher.should_enable_realtime_extraction("test_user_1"));
    assert!(dispatcher.should_enable_auto_lorebook_creation("test_user_1"));
    assert!(dispatcher.should_enable_auto_chronicle_creation("test_user_1"));

    // Test force enable user
    feature_flags.agentic_rollout_percentage = 0;
    feature_flags.force_enable_users = vec!["special_user".to_string()];

    let dispatcher = ExtractionDispatcher::new(
        Arc::new(feature_flags),
        None,
    );

    assert!(!dispatcher.should_enable_realtime_extraction("regular_user"));
    assert!(dispatcher.should_enable_realtime_extraction("special_user"));

    println!("✓ Feature flag user rollout test passed");
}