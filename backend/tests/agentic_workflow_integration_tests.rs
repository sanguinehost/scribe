#![cfg(feature = "postgres-backend")]
// backend/tests/agentic_workflow_integration_tests.rs
//
// Integration tests for the complete agentic narrative workflow using mock AI responses.
// Tests the end-to-end flow from chat messages through AI analysis to tool execution.

use chrono::Utc;
use diesel::{ExpressionMethods, RunQueryDsl};
use secrecy::SecretBox;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use scribe_backend::{
    auth::session_dek::SessionDek,
    config::{ExtractionMode, NarrativeFeatureFlags},
    llm::EmbeddingClient,
    models::chats::{ChatMessage, MessageRole},
    schema::chat_sessions,
    services::{
        agentic::AgenticNarrativeFactory, extraction_dispatcher::ExtractionDispatcher,
        ChronicleService, EncryptionService, LorebookService,
    },
    test_helpers::{db::create_test_user, spawn_app, MockAiClient, TestDataGuard},
};

/// Helper to create a chat session in the database (required for foreign key constraint)
async fn create_test_chat_session(
    db_pool: &deadpool_diesel::Pool<deadpool_diesel::Manager<diesel::PgConnection>>,
    user_id: scribe_backend::db::DbId,
    session_id: scribe_backend::db::DbId,
) -> anyhow::Result<()> {
    let conn = db_pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get DB connection: {}", e))?;

    conn.interact(move |conn| {
        diesel::insert_into(chat_sessions::table)
            .values((
                chat_sessions::id.eq(session_id),
                chat_sessions::user_id.eq(user_id),
                chat_sessions::model_name.eq("gemini-2.5-pro"),
                chat_sessions::history_management_strategy.eq("sliding_window"),
                chat_sessions::history_management_limit.eq(50),
                chat_sessions::created_at.eq(diesel::dsl::now),
                chat_sessions::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to interact with database: {}", e))?
    .map_err(|e| anyhow::anyhow!("Failed to insert chat session: {}", e))?;

    Ok(())
}

#[tokio::test]
async fn test_complete_agentic_workflow_with_mock_responses() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

    // Create test user
    let user = create_test_user(
        &test_app.db_pool,
        "test_user".to_string(),
        "password123".to_string(),
    )
    .await
    .unwrap();
    _guard.add_user(user.id);
    let user_id = user.id;
    let session_id = Uuid::new_v4();

    // Create chat session (required for foreign key constraint)
    create_test_chat_session(&test_app.db_pool, (*user_id).into(), session_id.into())
        .await
        .unwrap();

    // Configure mock AI client with combined triage and planning response
    let combined_response = json!({
        "should_create_event": true,
        "summary": "User introduces new character Alex and starts adventure",
        "reasoning": "New adventure beginning with character introduction should be recorded in both chronicle and lorebook",
        "keywords": ["Alex", "wizard", "adventure", "academy"],
        "facts": [
            {
                "who": "Alex",
                "what": "begins a new adventure at the magical academy",
                "where": "magical academy",
                "when": "current day",
                "why": "to start their magical journey",
                "fact_type": "Experience",
                "confidence": 0.9,
                "significance": 0.85
            }
        ],
        "surprise_score": 0.5,
        "significance_score": 0.85,
        "opinions": [],
        "observations": []
    });

    let mock_ai_client = Arc::new(MockAiClient::new_with_response(
        combined_response.to_string(),
    ));

    // Create agentic system with mock AI client using the same pattern as working tests
    let chronicle_service = Arc::new(ChronicleService::new(
        test_app.db_pool.clone(),
        test_app.ai_client.clone(),
    ));
    let lorebook_service = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        Arc::new(EncryptionService::new()),
        test_app.qdrant_service.clone(),
    ));

    let agentic_runner = AgenticNarrativeFactory::create_system_with_deps(
        mock_ai_client.clone(),
        chronicle_service.clone(),
        lorebook_service,
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
        test_app.create_app_state().await,
        None, // Use default config
    );

    // Create test chat messages representing a new adventure
    let messages = vec![
        ChatMessage {
            id: Uuid::new_v4().into(),
            session_id: session_id.into(),
            message_type: MessageRole::User,
            content:
                "Hello! I want to start a new adventure where I play as a young wizard named Alex."
                    .as_bytes()
                    .to_vec(),
            content_nonce: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            created_at: Utc::now().into(),
            user_id: user_id.into(),
            prompt_tokens: Some(scribe_backend::db::DbBigInt(20)),
            completion_tokens: Some(scribe_backend::db::DbBigInt(0)),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
            status: "completed".to_string(),
            error_message: None,
            superseded_at: None,
            variant_count: 1,
            current_variant_index: 0,
            ..Default::default()
        },
        ChatMessage {
            id: Uuid::new_v4().into(),
            session_id: session_id.into(),
            message_type: MessageRole::Assistant,
            content:
                "Welcome, Alex! You find yourself at the entrance to an ancient magical academy..."
                    .as_bytes()
                    .to_vec(),
            content_nonce: Some(vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            created_at: Utc::now().into(),
            user_id,
            prompt_tokens: Some(scribe_backend::db::DbBigInt(0)),
            completion_tokens: Some(scribe_backend::db::DbBigInt(25)),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
            status: "completed".to_string(),
            error_message: None,
            superseded_at: None,
            variant_count: 1,
            current_variant_index: 0,
            ..Default::default()
        },
    ];

    // Create session DEK for testing
    use secrecy::SecretBox;
    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

    // Run the agentic workflow
    let result = agentic_runner
        .process_narrative_event(
            user_id.into(),
            session_id.into(),
            None, // chronicle_id
            None, // message_variant_id
            &messages,
            &session_dek,
            None, // persona_context
            None, // game_state
            None, // character_context
        )
        .await;

    // Verify the workflow completed successfully
    assert!(
        result.is_ok(),
        "Agentic workflow should complete successfully"
    );
    let workflow_result = result.unwrap();

    // Verify cognitive payload was generated
    assert!(
        workflow_result.cognitive_payload.is_some(),
        "Should have cognitive payload"
    );
    let payload = workflow_result.cognitive_payload.unwrap();
    assert!(payload.should_create_event);
    assert!(payload.summary.contains("Alex"));
    assert_eq!(payload.significance_score, 0.85);

    println!("✓ Complete agentic workflow test passed");

    println!("✓ Complete agentic workflow test passed");
}

#[tokio::test]
async fn test_extraction_dispatcher_with_agentic_mode() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

    // Create test user
    let user = create_test_user(
        &test_app.db_pool,
        "test_user2".to_string(),
        "password123".to_string(),
    )
    .await
    .unwrap();
    _guard.add_user(user.id);
    let user_id = user.id;
    let session_id = Uuid::new_v4().into();

    // Create chat session (required for foreign key constraint)
    create_test_chat_session(&test_app.db_pool, user_id, session_id)
        .await
        .unwrap();

    // Create feature flags for agentic mode
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_agentic_extraction = true;
    feature_flags.agentic_rollout_percentage = 100; // Enable for all users
    feature_flags.enable_realtime_extraction = true;

    // Configure mock AI client
    let triage_response = json!({
        "should_create_event": true,
        "summary": "Dialogue contains important character development",
        "reasoning": "Character development is significant",
        "keywords": ["Alex", "expression"],
        "facts": [
            {
                "who": "Alex",
                "what": "looks around the magical academy courtyard nervously",
                "where": "magical academy courtyard",
                "when": "current day",
                "why": "nervousness",
                "fact_type": "Experience",
                "confidence": 0.9,
                "significance": 0.7
            }
        ],
        "surprise_score": 0.3,
        "significance_score": 0.9,
        "opinions": [],
        "observations": []
    });

    let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

    // Create agentic system using the same pattern as working tests
    let chronicle_service = Arc::new(ChronicleService::new(
        test_app.db_pool.clone(),
        test_app.ai_client.clone(),
    ));
    let lorebook_service = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        Arc::new(EncryptionService::new()),
        test_app.qdrant_service.clone(),
    ));

    let agentic_runner = AgenticNarrativeFactory::create_system_with_deps(
        mock_ai_client.clone(),
        chronicle_service.clone(),
        lorebook_service,
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
        test_app.create_app_state().await,
        None, // Use default config
    );

    // Create extraction dispatcher
    let dispatcher =
        ExtractionDispatcher::new(Arc::new(feature_flags), Some(Arc::new(agentic_runner)));

    // Create test messages
    let messages = vec![ChatMessage {
        id: Uuid::new_v4().into(),
        session_id: session_id.into(),
        message_type: MessageRole::User,
        content: "Alex looks around the magical academy courtyard nervously."
            .as_bytes()
            .to_vec(),
        content_nonce: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
        created_at: Utc::now().into(),
        user_id: user_id.into(),
        prompt_tokens: Some(scribe_backend::db::DbBigInt(15)),
        completion_tokens: Some(scribe_backend::db::DbBigInt(0)),
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: "gemini-2.5-pro".to_string(),
        status: "completed".to_string(),
        error_message: None,
        superseded_at: None,
        variant_count: 1,
        current_variant_index: 0,
        ..Default::default()
    }];

    // Create session DEK for testing
    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

    // Run extraction through dispatcher
    let result = dispatcher
        .extract_events_from_chat(user_id, session_id, None, &messages, &session_dek, None)
        .await;

    // Verify extraction succeeded
    assert!(
        result.is_ok(),
        "Extraction should succeed through dispatcher"
    );
    let extraction_result = result.unwrap();

    assert!(extraction_result.success, "Extraction should be successful");
    assert_eq!(extraction_result.mode_used, ExtractionMode::AgenticOnly);
    // Note: duration_ms can be 0 with mocked AI calls that complete in microseconds
    assert!(
        extraction_result.ai_calls_made > 0,
        "Should have made AI calls"
    );

    println!("✓ Extraction dispatcher agentic mode test passed");
}

#[tokio::test]
async fn test_dual_mode_extraction_comparison() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

    // Create test user
    let user = create_test_user(
        &test_app.db_pool,
        "test_user3".to_string(),
        "password123".to_string(),
    )
    .await
    .unwrap();
    _guard.add_user(user.id);
    let user_id = user.id;
    let session_id = Uuid::new_v4().into();

    // Create chat session (required for foreign key constraint)
    create_test_chat_session(&test_app.db_pool, user_id, session_id)
        .await
        .unwrap();

    // Create feature flags for dual mode
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_agentic_extraction = true;
    feature_flags.dual_extraction_mode = true;
    feature_flags.agentic_rollout_percentage = 100;
    feature_flags.enable_extraction_metrics = true;

    // Configure mock AI client for agentic extraction
    let triage_response = json!({
        "should_create_event": false,
        "summary": "Just casual dialogue, no significant events",
        "reasoning": "Mundane conversation",
        "keywords": ["casual", "dialogue"],
        "facts": [],
        "surprise_score": 0.1,
        "significance_score": 0.2,
        "opinions": [],
        "observations": []
    });

    let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

    // Create agentic system using the same pattern as working tests
    let chronicle_service = Arc::new(ChronicleService::new(
        test_app.db_pool.clone(),
        test_app.ai_client.clone(),
    ));
    let lorebook_service = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        Arc::new(EncryptionService::new()),
        test_app.qdrant_service.clone(),
    ));

    let agentic_runner = AgenticNarrativeFactory::create_system_with_deps(
        mock_ai_client.clone(),
        chronicle_service.clone(),
        lorebook_service,
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
        test_app.create_app_state().await,
        None, // Use default config
    );

    // Create extraction dispatcher with dual mode
    let dispatcher =
        ExtractionDispatcher::new(Arc::new(feature_flags), Some(Arc::new(agentic_runner)));

    // Create test messages (mundane conversation)
    let messages = vec![
        ChatMessage {
            id: Uuid::new_v4().into(),
            session_id,
            message_type: MessageRole::User,
            content_nonce: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            created_at: Utc::now().into(),
            user_id,
            prompt_tokens: Some(scribe_backend::db::DbBigInt(5)),
            completion_tokens: Some(scribe_backend::db::DbBigInt(0)),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
            status: "completed".to_string(),
            error_message: None,
            superseded_at: None,
            variant_count: 1,
            current_variant_index: 0,
            ..Default::default()
        },
        ChatMessage {
            id: Uuid::new_v4().into(),
            session_id: session_id.into(),
            message_type: MessageRole::Assistant,
            content: "I'm doing well, thank you for asking!".as_bytes().to_vec(),
            content_nonce: Some(vec![5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]),
            created_at: Utc::now().into(),
            user_id: user_id.into(),
            prompt_tokens: Some(scribe_backend::db::DbBigInt(0)),
            completion_tokens: Some(scribe_backend::db::DbBigInt(10)),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
            status: "completed".to_string(),
            error_message: None,
            superseded_at: None,
            variant_count: 1,
            current_variant_index: 0,
            ..Default::default()
        },
    ];

    // Create session DEK for testing
    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

    // Run dual mode extraction
    let result = dispatcher
        .extract_events_from_chat(user_id, session_id, None, &messages, &session_dek, None)
        .await;

    // Verify dual mode ran (even though manual is placeholder)
    assert!(result.is_ok(), "Dual mode extraction should complete");
    let extraction_result = result.unwrap();

    // In dual mode, should return agentic result if it succeeded
    assert_eq!(extraction_result.mode_used, ExtractionMode::AgenticOnly);
    assert!(
        extraction_result.success,
        "Agentic extraction should succeed"
    );

    println!("✓ Dual mode extraction comparison test passed");
}

#[tokio::test]
async fn test_agentic_workflow_with_json_parsing_failure() {
    let test_app = spawn_app(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

    // Create test user
    let user = create_test_user(
        &test_app.db_pool,
        "test_user4".to_string(),
        "password123".to_string(),
    )
    .await
    .unwrap();
    _guard.add_user(user.id);
    let user_id = user.id;
    let session_id = Uuid::new_v4().into();

    // Create chat session (required for foreign key constraint)
    create_test_chat_session(&test_app.db_pool, user_id, session_id)
        .await
        .unwrap();

    // Create feature flags with very short timeout
    let mut feature_flags = NarrativeFeatureFlags::default();
    feature_flags.enable_agentic_extraction = true;
    feature_flags.agentic_rollout_percentage = 100;
    feature_flags.agentic_extraction_timeout_secs = 1; // Very short timeout
    feature_flags.fallback_to_manual_on_error = true;

    // Configure mock AI client with default response that causes JSON parsing failure
    let mock_ai_client = Arc::new(MockAiClient::new()); // Returns "Mock AI response" - not valid JSON

    // Create agentic system using the same pattern as working tests
    let chronicle_service = Arc::new(ChronicleService::new(
        test_app.db_pool.clone(),
        test_app.ai_client.clone(),
    ));
    let lorebook_service = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        Arc::new(EncryptionService::new()),
        test_app.qdrant_service.clone(),
    ));

    let agentic_runner = AgenticNarrativeFactory::create_system_with_deps(
        mock_ai_client.clone(),
        chronicle_service.clone(),
        lorebook_service,
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
        test_app.create_app_state().await,
        None, // Use default config
    );

    // Create extraction dispatcher
    let dispatcher =
        ExtractionDispatcher::new(Arc::new(feature_flags), Some(Arc::new(agentic_runner)));

    // Create test messages
    let messages = vec![ChatMessage {
        id: Uuid::new_v4().into(),
        session_id,
        message_type: MessageRole::User,
        content: "This should cause JSON parsing failure".as_bytes().to_vec(),
        content_nonce: Some(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
        created_at: Utc::now().into(),
        user_id,
        prompt_tokens: Some(scribe_backend::db::DbBigInt(5)),
        completion_tokens: Some(scribe_backend::db::DbBigInt(0)),
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: "gemini-2.5-pro".to_string(),
        status: "completed".to_string(),
        error_message: None,
        superseded_at: None,
        variant_count: 1,
        current_variant_index: 0,
        ..Default::default()
    }];

    // Create session DEK for testing
    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

    // Run extraction (should fail due to JSON parsing error in mock AI response)
    let result = dispatcher
        .extract_events_from_chat(user_id, session_id, None, &messages, &session_dek, None)
        .await;

    // Currently, JSON parsing errors cause the entire extraction to fail
    // This demonstrates a limitation where only timeouts trigger fallback, not other errors
    assert!(
        result.is_err(),
        "Should fail due to JSON parsing error in mock AI response"
    );
    let error = result.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Failed to parse cognitive payload"),
        "Error should mention JSON parsing failure"
    );

    println!("✓ Agentic workflow JSON parsing failure test passed");
}

#[tokio::test]
async fn test_feature_flag_user_rollout() {
    let _test_app = spawn_app(false, false, false).await;

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

    let dispatcher = ExtractionDispatcher::new(Arc::new(feature_flags.clone()), None);

    assert!(dispatcher.should_enable_realtime_extraction("test_user_1"));
    assert!(dispatcher.should_enable_auto_lorebook_creation("test_user_1"));
    assert!(dispatcher.should_enable_auto_chronicle_creation("test_user_1"));

    // Test force enable user
    feature_flags.agentic_rollout_percentage = 0;
    feature_flags.force_enable_users = vec!["special_user".to_string()];

    let dispatcher = ExtractionDispatcher::new(Arc::new(feature_flags), None);

    assert!(!dispatcher.should_enable_realtime_extraction("regular_user"));
    assert!(dispatcher.should_enable_realtime_extraction("special_user"));

    println!("✓ Feature flag user rollout test passed");
}
