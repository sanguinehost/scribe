#![cfg(feature = "postgres-backend")]
#![cfg(test)]
// backend/tests/agentic_lorebook_creation_tests.rs
//
// Tests that verify the agentic narrative system automatically creates lorebook entries
// when new characters, locations, items, or lore concepts are introduced during chat.

use chrono::Utc;
use scribe_backend::{
    auth::session_dek::SessionDek,
    models::{
        chats::{ChatMessage, MessageRole},
        lorebook_dtos::CreateLorebookPayload,
    },
    services::agentic::factory::AgenticNarrativeFactory,
    test_helpers::{MockAiClient, TestDataGuard},
};
use secrecy::SecretBox;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

// Note: AuthSession mock removed - using test-specific service method instead

/// Helper function to create a chat session in the database for testing
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
        use diesel::{ExpressionMethods, RunQueryDsl};
        use scribe_backend::schema::chat_sessions;

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

// Helper to create AppState for tests
async fn create_test_app_state(
    test_app: &scribe_backend::test_helpers::TestApp,
    lorebook_service: Arc<scribe_backend::services::LorebookService>,
) -> Arc<scribe_backend::state::AppState> {
    let services = scribe_backend::state::AppStateServices {
        ai_client: test_app.ai_client.clone(),
        embedding_client: test_app.mock_embedding_client.clone()
            as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone()
            as Arc<
                dyn scribe_backend::services::embeddings::EmbeddingPipelineServiceTrait
                    + Send
                    + Sync,
            >,
        chat_override_service: Arc::new(
            scribe_backend::services::chat_override_service::ChatOverrideService::new(
                test_app.db_pool.clone(),
                Arc::new(scribe_backend::services::EncryptionService::new()),
            ),
        ),
        user_persona_service: Arc::new(
            scribe_backend::services::user_persona_service::UserPersonaService::new(
                test_app.db_pool.clone(),
                Arc::new(scribe_backend::services::EncryptionService::new()),
            ),
        ),
        token_counter: Arc::new(
            scribe_backend::services::hybrid_token_counter::HybridTokenCounter::new(
                scribe_backend::services::tokenizer_service::TokenizerService::new(
                    &test_app.config.tokenizer_model_path,
                )
                .unwrap_or_else(|_| panic!("Failed to create tokenizer for test")),
                None,
                "gemini-2.5-pro",
            ),
        ),
        encryption_service: Arc::new(scribe_backend::services::EncryptionService::new()),
        lorebook_service: lorebook_service.clone(),
        auth_backend: Arc::new(scribe_backend::auth::user_store::Backend::new(
            test_app.db_pool.clone(),
        )),
        email_service: scribe_backend::services::email_service::create_email_service(
            "development",
            "http://localhost:3000".to_string(),
            None,
        )
        .await
        .unwrap(),
        ai_client_factory: Arc::new(
            scribe_backend::services::ai_client_factory::AiClientFactory::new(
                test_app.db_pool.clone(),
                test_app.config.clone(),
                test_app.ai_client.clone(),
            ),
        ),
        rate_limiter: Arc::new(
            scribe_backend::middleware::llm_security::LlmRateLimiter::new(10, 100),
        ),
        recall_pipeline: Arc::new(scribe_backend::services::cognitive::RecallPipeline::new(
            test_app.db_pool.clone(),
        )),
        token_service: None,
        character_service: Arc::new(
            scribe_backend::services::character_service::CharacterService::new(
                test_app.db_pool.clone(),
                Arc::new(scribe_backend::services::EncryptionService::new()),
            ),
        ),
        #[cfg(feature = "local-llm")]
        llamacpp_server_manager: None,
        #[cfg(feature = "local-llm")]
        security_audit_logger: None,
        #[cfg(feature = "local-llm")]
        model_integrity_verifier: None,
    };
    Arc::new(scribe_backend::state::AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ))
}

// Helper to create a chat message with proper encryption
fn create_chat_message(
    user_id: scribe_backend::db::DbId,
    session_id: scribe_backend::db::DbId,
    role: MessageRole,
    content: &str,
    model_name: &str,
    session_dek: &SessionDek,
) -> ChatMessage {
    // Properly encrypt the content
    let (encrypted_content, content_nonce) =
        scribe_backend::crypto::encrypt_gcm(content.as_bytes(), &session_dek.0)
            .expect("Failed to encrypt test content");

    ChatMessage {
        id: Uuid::new_v4().into(),
        session_id,
        message_type: role,
        content: encrypted_content,
        content_nonce: Some(content_nonce),
        created_at: Utc::now().into(),
        user_id,
        prompt_tokens: Some(content.len() as i64 / 4), // Rough estimate
        completion_tokens: if matches!(role, MessageRole::Assistant) {
            Some(20)
        } else {
            Some(0)
        },
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: model_name.to_string(),
        status: "completed".to_string(),
        error_message: None,
        superseded_at: None,
        variant_count: 1,
        current_variant_index: 0,
        ..Default::default()
    }
}

mod lorebook_creation_tests {
    use super::*;

    // NOTE: 5 obsolete tests were removed that tested automatic lorebook creation.
    // The chronicle system was simplified to only create NARRATIVE.EVENT chronicle events
    // with summary/keywords. Automatic lorebook creation via the agentic system was removed.

    #[tokio::test]
    async fn test_agentic_system_ignores_existing_well_documented_concepts() {
        let test_app =
            scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false)
                .await;
        let mut _guard =
            TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

        // Create a real user in the database
        let user = scribe_backend::test_helpers::db::create_test_user(
            &test_app.db_pool,
            "agentic_documented_test_user".to_string(),
            "password".to_string(),
        )
        .await
        .expect("Failed to create test user");
        let user_id = user.id;
        let chat_session_id = Uuid::new_v4();

        // Create chat session in database (required for foreign key constraint)
        create_test_chat_session(&test_app.db_pool, user_id.into(), chat_session_id.into())
            .await
            .expect("Failed to create test chat session");

        // Create a lorebook with existing entries
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            encryption_service.clone(),
            test_app.qdrant_service.clone(),
        ));

        let create_lorebook_request = CreateLorebookPayload {
            name: "Established Lore".to_string(),
            description: Some("Well-documented world information".to_string()),
        };
        let lorebook = lorebook_service
            .create_lorebook_for_test(user_id, create_lorebook_request)
            .await
            .unwrap();

        // Mock AI response for already-known information
        let triage_response = json!({
            "is_significant": false,
            "summary": "Discussion of well-established lore already documented",
            "event_category": "CONVERSATION",
            "event_type": "CASUAL_DISCUSSION",
            "narrative_action": "DISCUSSED",
            "primary_agent": "Characters",
            "primary_patient": "Known Information",
            "confidence": 0.3
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
            test_app.db_pool.clone(),
            mock_ai_client.clone(),
        ));

        let app_state = create_test_app_state(&test_app, lorebook_service.clone()).await;

        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service,
            lorebook_service.clone(),
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone()
                as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            app_state,
            None, // Use default config
        );

        let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

        // Simulate casual discussion of common knowledge
        let common_knowledge_messages = vec![
            create_chat_message(
                user_id.into(),
                chat_session_id.into(),
                MessageRole::User,
                "The sun is setting, casting long shadows.",
                "gemini-2.5-pro",
                &session_dek,
            ),
            create_chat_message(
                user_id.into(),
                chat_session_id.into(),
                MessageRole::Assistant,
                "Indeed, the golden hour bathes everything in warm light. It's a peaceful end to the day.",
                "gemini-2.5-pro",
                &session_dek,
            ),
            create_chat_message(
                user_id.into(),
                chat_session_id.into(),
                MessageRole::User,
                "I enjoy watching the sunset from this hill.",
                "gemini-2.5-pro",
                &session_dek,
            ),
            create_chat_message(
                user_id.into(),
                chat_session_id.into(),
                MessageRole::Assistant,
                "This is certainly a beautiful vantage point for watching the day's end.",
                "gemini-2.5-pro",
                &session_dek,
            ),
        ];

        // Get initial entry count
        let initial_entries = lorebook_service
            .list_lorebook_entries_for_test(user_id, lorebook.id)
            .await
            .unwrap();
        let initial_count = initial_entries.len();

        // Run the agentic workflow - should not create new entries
        let result = agent_runner
            .process_narrative_event(
                user_id.into(),
                chat_session_id.into(),
                None, // chronicle_id
                None, // message_variant_id
                &common_knowledge_messages,
                &session_dek,
                None, // persona_context
                None, // game_state
                None, // character_context
            )
            .await;

        // Verify the workflow succeeded but took no action
        assert!(
            result.is_ok(),
            "Agentic system should handle common knowledge gracefully"
        );
        let workflow_result = result.unwrap();

        // Verify the workflow handled common knowledge appropriately
        // Note: The AI may sometimes mark simple conversations as significant, so we check that either:
        // 1. It's not significant, OR 2. If significant, no lorebook actions were taken
        let handled_appropriately = !workflow_result.triage_result.is_significant
            || !workflow_result
                .actions_taken
                .iter()
                .any(|action| action.tool_name == "create_lorebook_entry");
        assert!(
            handled_appropriately,
            "Should handle common knowledge appropriately by either marking as insignificant or not creating lorebook entries"
        );

        // Verify no new entries were created
        let final_entries = lorebook_service
            .list_lorebook_entries_for_test(user_id, lorebook.id)
            .await
            .unwrap();
        assert_eq!(
            final_entries.len(),
            initial_count,
            "Should not create entries for common knowledge"
        );
    }
}
