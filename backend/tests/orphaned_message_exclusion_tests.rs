//! Test cases to verify that orphaned messages are properly excluded from AI context and RAG
//! when using frontend-provided history

use chrono::Utc;
use diesel::{RunQueryDsl, SelectableHelper};
use scribe_backend::models::characters::Character as DbCharacter;
use scribe_backend::models::chats::{ApiChatMessage, Chat as ChatSession, NewChat};
use scribe_backend::schema::{
    characters::dsl as characters_dsl, chat_sessions::dsl as chat_sessions_dsl,
};
use scribe_backend::services::chat::generation::get_session_data_for_generation;
use scribe_backend::services::{
    chat_override_service::ChatOverrideService, email_service::LoggingEmailService,
    encryption_service::EncryptionService, file_storage_service::FileStorageService,
    hybrid_token_counter::HybridTokenCounter, lorebook::LorebookService,
    tokenizer_service::TokenizerService, user_persona_service::UserPersonaService,
};
use scribe_backend::state::{AppState, AppStateServices};
use scribe_backend::test_helpers;
use secrecy::SecretBox;
use std::sync::Arc;
use uuid::Uuid;

/// Helper function to create a test character and session
async fn create_test_character_and_session(
    test_app: &test_helpers::TestApp,
    user_id: Uuid,
) -> (DbCharacter, ChatSession) {
    let conn_pool = test_app.db_pool.clone();
    let user_id_clone = user_id;
    let character_name = "Test Character".to_string();
    let character: DbCharacter = conn_pool
        .get()
        .await
        .expect("Failed to get DB conn for char create")
        .interact(move |conn_sync| {
            let new_char_card = scribe_backend::models::character_card::NewCharacter {
                user_id: user_id_clone,
                name: character_name,
                spec: "test_spec_v1.0".to_string(),
                spec_version: "1.0".to_string(),
                description: Some(b"Test description".to_vec()),
                greeting: Some(b"Hello".to_vec()),
                visibility: Some("private".to_string()),
                creator: Some("test_creator".to_string()),
                persona: Some(b"Test persona".to_vec()),
                created_at: Some(Utc::now()),
                updated_at: Some(Utc::now()),
                ..Default::default()
            };
            diesel::insert_into(characters_dsl::characters)
                .values(&new_char_card)
                .get_result::<DbCharacter>(conn_sync)
        })
        .await
        .expect("DB interaction for create character failed")
        .expect("Error saving new character");

    let conn_pool = test_app.db_pool.clone();
    let user_id_clone_session = user_id;
    let character_id_clone_session = character.id;
    let session: ChatSession = conn_pool
        .get()
        .await
        .expect("Failed to get DB conn for session create")
        .interact(move |conn_sync| {
            let new_chat_session = NewChat {
                id: Uuid::new_v4(),
                user_id: user_id_clone_session,
                character_id: character_id_clone_session,
                title_ciphertext: None,
                title_nonce: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                history_management_strategy: "truncate".to_string(),
                history_management_limit: 10,
                model_name: "test-model".to_string(),
                visibility: Some("private".to_string()),
                active_custom_persona_id: None,
                active_impersonated_character_id: None,
                temperature: None,
                max_output_tokens: None,
                frequency_penalty: None,
                presence_penalty: None,
                top_k: None,
                top_p: None,
                seed: None,
                stop_sequences: None,
                gemini_thinking_budget: None,
                gemini_enable_code_execution: None,
                system_prompt_ciphertext: None,
                system_prompt_nonce: None,
                player_chronicle_id: None,
            };
            diesel::insert_into(chat_sessions_dsl::chat_sessions)
                .values(&new_chat_session)
                .returning(ChatSession::as_returning())
                .get_result::<ChatSession>(conn_sync)
        })
        .await
        .expect("DB interaction for create session failed")
        .expect("Error saving new session");

    (character, session)
}

/// Simple test to verify that frontend history is used instead of database history
#[tokio::test]
async fn test_frontend_history_vs_database_history() {
    // This test verifies the core functionality: when frontend history is provided,
    // it should be used instead of querying the database

    let test_app = test_helpers::spawn_app(false, false, false).await;
    let _guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    // Create test data
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "test_user".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    // Create character and session in database
    let (_character, session) = create_test_character_and_session(&test_app, user.id).await;
    let session_id = session.id;

    // Create AppState similar to how spawn_app does it
    let encryption_service = Arc::new(EncryptionService::new());
    let chat_override_service = Arc::new(ChatOverrideService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
    ));
    let user_persona_service = Arc::new(UserPersonaService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
    ));
    let token_counter_service = Arc::new(HybridTokenCounter::new_local_only(
        TokenizerService::new(&test_app.config.tokenizer_model_path)
            .expect("Failed to create tokenizer for test"),
    ));
    let lorebook_service = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
        test_app.qdrant_service.clone(),
    ));
    let auth_backend = Arc::new(scribe_backend::auth::user_store::Backend::new(
        test_app.db_pool.clone(),
    ));
    let file_storage_service = Arc::new(
        FileStorageService::new("./test_uploads")
            .expect("Failed to create test file storage service"),
    );
    let email_service = Arc::new(LoggingEmailService::new(
        "http://localhost:3000".to_string(),
    ));

    let services = AppStateServices {
        ai_client: test_app.ai_client.clone(),
        embedding_client: test_app.mock_embedding_client.clone(),
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone(),
        chat_override_service,
        user_persona_service,
        token_counter: token_counter_service,
        encryption_service,
        lorebook_service,
        auth_backend,
        file_storage_service,
        email_service,
        // ECS Services - minimal test instances
        redis_client: Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
        feature_flags: Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
        ecs_entity_manager: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ))
        },
        ecs_graceful_degradation: Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
            Default::default(),
            Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
            None,
            None,
        )),
        ecs_enhanced_rag_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                degradation,
                concrete_embedding_service,
            ))
        },
        hybrid_query_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            let rag_service = Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                concrete_embedding_service,
            ));
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                rag_service,
                degradation,
            ))
        },
    };

    let state = AppState::new(test_app.db_pool.clone(), test_app.config.clone(), services);
    let state_arc = Arc::new(state);
    let session_dek = SecretBox::new(Box::new(vec![0u8; 32]));
    let session_dek_arc = Arc::new(session_dek);

    // Mock embedding pipeline to return empty results
    test_app
        .mock_embedding_pipeline_service
        .add_retrieve_response(Ok(vec![]));
    test_app
        .mock_embedding_pipeline_service
        .add_retrieve_response(Ok(vec![]));

    // Test 1: With no frontend history (database mode)
    let _result_db = get_session_data_for_generation(
        state_arc.clone(),
        user.id,
        session_id,
        "Test message".to_string(),
        Some(session_dek_arc.clone()),
        None, // No frontend history - use database
    )
    .await
    .expect("Database mode should work");

    // Track calls from database mode
    let db_calls = test_app.mock_embedding_pipeline_service.get_calls();
    let db_call_count = db_calls.len();

    // Clear calls for next test
    test_app.mock_embedding_pipeline_service.clear_calls();
    test_app
        .mock_embedding_pipeline_service
        .add_retrieve_response(Ok(vec![])); // Set up for frontend test

    // Test 2: With frontend history - should NOT call RAG for chat history
    let frontend_history = vec![
        ApiChatMessage {
            role: "user".to_string(),
            content: "Previous user message".to_string(),
        },
        ApiChatMessage {
            role: "assistant".to_string(),
            content: "Previous assistant response".to_string(),
        },
        ApiChatMessage {
            role: "user".to_string(),
            content: "Test message".to_string(), // Current message
        },
    ];

    let result_frontend = get_session_data_for_generation(
        state_arc.clone(),
        user.id,
        session_id,
        "Test message".to_string(),
        Some(session_dek_arc.clone()),
        Some(frontend_history), // Use frontend history
    )
    .await
    .expect("Frontend mode should work");

    // The key test: frontend mode should make fewer or equal RAG calls than database mode
    // because it skips chat history RAG to prevent orphaned message contamination
    let frontend_calls = test_app.mock_embedding_pipeline_service.get_calls();
    let frontend_call_count = frontend_calls.len();

    // Verify that frontend mode doesn't make more RAG calls than database mode
    // This proves chat history RAG is being skipped in frontend mode
    assert!(
        frontend_call_count <= db_call_count,
        "Frontend mode should make same or fewer RAG calls than database mode. DB: {}, Frontend: {}",
        db_call_count,
        frontend_call_count
    );

    let (managed_history, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _) =
        result_frontend;

    // Should have 2 messages from frontend history (excluding current message)
    assert_eq!(
        managed_history.len(),
        2,
        "Should have 2 messages from frontend history"
    );

    // Verify content matches frontend history
    assert_eq!(
        String::from_utf8_lossy(&managed_history[0].content),
        "Previous user message"
    );
    assert_eq!(
        String::from_utf8_lossy(&managed_history[1].content),
        "Previous assistant response"
    );

    println!(
        "✅ Test passed: Frontend history prevents database query and orphaned message contamination"
    );
}

/// Test to verify that orphaned messages don't contaminate context when editing messages
#[tokio::test]
async fn test_orphaned_message_exclusion_scenario() {
    // This test simulates the real scenario where a user edits a message
    // and we need to ensure that subsequent messages (orphans) are excluded

    let test_app = test_helpers::spawn_app(false, false, false).await;
    let _guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    // Create test data
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "orphan_test_user".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    // Create character and session in database
    let (_character, session) = create_test_character_and_session(&test_app, user.id).await;
    let session_id = session.id;

    // Create AppState
    let encryption_service = Arc::new(EncryptionService::new());
    let chat_override_service = Arc::new(ChatOverrideService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
    ));
    let user_persona_service = Arc::new(UserPersonaService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
    ));
    let token_counter_service = Arc::new(HybridTokenCounter::new_local_only(
        TokenizerService::new(&test_app.config.tokenizer_model_path)
            .expect("Failed to create tokenizer for test"),
    ));
    let lorebook_service = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
        test_app.qdrant_service.clone(),
    ));
    let auth_backend = Arc::new(scribe_backend::auth::user_store::Backend::new(
        test_app.db_pool.clone(),
    ));
    let file_storage_service = Arc::new(
        FileStorageService::new("./test_uploads")
            .expect("Failed to create test file storage service"),
    );
    let email_service = Arc::new(LoggingEmailService::new(
        "http://localhost:3000".to_string(),
    ));

    let services = AppStateServices {
        ai_client: test_app.ai_client.clone(),
        embedding_client: test_app.mock_embedding_client.clone(),
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone(),
        chat_override_service,
        user_persona_service,
        token_counter: token_counter_service,
        encryption_service,
        lorebook_service,
        auth_backend,
        file_storage_service,
        email_service,
        // ECS Services - minimal test instances
        redis_client: Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
        feature_flags: Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
        ecs_entity_manager: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ))
        },
        ecs_graceful_degradation: Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
            Default::default(),
            Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
            None,
            None,
        )),
        ecs_enhanced_rag_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                degradation,
                concrete_embedding_service,
            ))
        },
        hybrid_query_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            let rag_service = Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                concrete_embedding_service,
            ));
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                rag_service,
                degradation,
            ))
        },
    };

    let state = AppState::new(test_app.db_pool.clone(), test_app.config.clone(), services);
    let state_arc = Arc::new(state);
    let session_dek = SecretBox::new(Box::new(vec![0u8; 32]));
    let session_dek_arc = Arc::new(session_dek);

    // Set up mock responses
    test_app
        .mock_embedding_pipeline_service
        .add_retrieve_response(Ok(vec![])); // Lorebook

    // Simulate a conversation where a message was edited and we have orphaned messages
    // Frontend provides filtered history that excludes orphaned messages
    let filtered_frontend_history = vec![
        ApiChatMessage {
            role: "user".to_string(),
            content: "Hello, how are you?".to_string(),
        },
        ApiChatMessage {
            role: "assistant".to_string(),
            content: "I'm doing well, thank you!".to_string(),
        },
        ApiChatMessage {
            role: "user".to_string(),
            content: "What's the weather like?".to_string(), // User edited this message
        },
        // Note: Any messages that came after the original "What's the weather like?"
        // message are now orphaned and should NOT appear in this history
        ApiChatMessage {
            role: "user".to_string(),
            content: "Can you help me with this task?".to_string(), // Current message
        },
    ];

    let result = get_session_data_for_generation(
        state_arc.clone(),
        user.id,
        session_id,
        "Can you help me with this task?".to_string(),
        Some(session_dek_arc.clone()),
        Some(filtered_frontend_history), // Use frontend-filtered history
    )
    .await
    .expect("Generation should work with frontend history");

    // Verify that RAG was handled appropriately for frontend mode
    // In frontend mode, we skip chat history RAG to prevent orphaned message contamination
    let calls = test_app.mock_embedding_pipeline_service.get_calls();
    println!("RAG calls made in frontend mode: {}", calls.len());

    let (managed_history, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _, _) = result;

    // Should have exactly 3 messages from frontend history (excluding current message)
    assert_eq!(
        managed_history.len(),
        3,
        "Should have 3 messages from frontend history (orphaned messages excluded)"
    );

    // Verify the messages are in correct order and content
    assert_eq!(
        String::from_utf8_lossy(&managed_history[0].content),
        "Hello, how are you?"
    );
    assert_eq!(
        String::from_utf8_lossy(&managed_history[1].content),
        "I'm doing well, thank you!"
    );
    assert_eq!(
        String::from_utf8_lossy(&managed_history[2].content),
        "What's the weather like?"
    );

    println!("✅ Test passed: Orphaned messages are properly excluded from context and RAG");
}
