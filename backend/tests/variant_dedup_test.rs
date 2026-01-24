#![cfg(feature = "postgres-backend")]
#![cfg(test)]

use anyhow::Result as AnyhowResult;
use bcrypt;
use chrono::Utc;
use diesel::{prelude::*, RunQueryDsl};
use scribe_backend::db;
use scribe_backend::{
    auth::session_dek::SessionDek,
    db::{DbBigInt, DbId, DbPool},
    models::{
        chats::{ChatMessage, MessageRole},
        chronicle::CreateChronicleRequest,
        chronicle_event::{CreateEventRequest, EventFilter, EventSource},
        users::{AccountStatus, NewUser, UserDbQuery, UserRole},
    },
    schema::users,
    services::{agentic::AgenticNarrativeFactory, ChronicleService},
    test_helpers::{spawn_app_permissive_rate_limiting, TestApp, TestAppGuard, TestDataGuard},
};
use secrecy::{ExposeSecret, SecretBox};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Helper to create a test user
async fn create_test_user(test_app: &TestApp) -> AnyhowResult<(Uuid, SessionDek)> {
    let mut conn = scribe_backend::db::get_conn(&test_app.db_pool).await?;

    let hashed_password = bcrypt::hash("testpassword", bcrypt::DEFAULT_COST)?;
    let username = format!("variant_test_user_{}", Uuid::new_v4().simple());
    let email = format!("{}@test.com", username);

    // Generate proper crypto keys
    let kek_salt = scribe_backend::crypto::generate_salt()?;
    let dek = scribe_backend::crypto::generate_dek()?;

    let secret_password = secrecy::SecretString::new("testpassword".to_string().into());
    let kek = scribe_backend::crypto::derive_kek(&secret_password, &kek_salt)?;

    let (encrypted_dek, dek_nonce) =
        scribe_backend::crypto::encrypt_gcm(dek.expose_secret(), &kek)?;

    let new_user = NewUser {
        id: Uuid::new_v4().into(),
        username,
        password_hash: hashed_password,
        email: email,
        kek_salt,
        encrypted_dek: encrypted_dek.into(),
        encrypted_dek_by_recovery: None,
        role: UserRole::User,
        recovery_kek_salt: None,
        dek_nonce: dek_nonce.into(),
        recovery_dek_nonce: None,
        account_status: AccountStatus::Active,
        total_prompt_tokens: DbBigInt::from(0),
        total_completion_tokens: DbBigInt::from(0),
        total_token_cost_cents: DbBigInt::from(0),
        tokens_last_reset_at: None,
        token_usage_updated_at: Utc::now().into(),
    };

    let user_db: UserDbQuery = conn
        .interact(move |conn| {
            diesel::insert_into(users::table)
                .values(&new_user)
                .returning(UserDbQuery::as_returning())
                .get_result(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;

    let user_id = *user_db.id;

    let session_dek = SessionDek(SecretBox::new(Box::new(dek.expose_secret().to_vec())));
    Ok((user_id, session_dek))
}

/// Helper to create a test chronicle
async fn create_test_chronicle(user_id: Uuid, test_app: &TestApp) -> AnyhowResult<Uuid> {
    let chronicle_service =
        ChronicleService::new(test_app.db_pool.clone(), test_app.ai_client.clone());

    let create_request = CreateChronicleRequest {
        name: "Variant Test Chronicle".to_string(),
        description: Some("Testing variant handling".to_string()),
    };

    let chronicle = chronicle_service
        .create_chronicle(user_id.into(), create_request)
        .await?;

    Ok(*chronicle.id)
}

/// Helper function to create a chat session in the database for testing
async fn create_test_chat_session(
    db_pool: &DbPool,
    user_id: DbId,
    session_id: DbId,
) -> AnyhowResult<()> {
    let mut conn = scribe_backend::db::get_conn(db_pool)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get DB connection: {}", e))?;

    conn.interact(move |conn| {
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
async fn create_test_app_state(test_app: TestAppGuard) -> Arc<scribe_backend::state::AppState> {
    let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
    let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
        test_app.qdrant_service.clone(),
    ));

    let character_service = Arc::new(
        scribe_backend::services::character_service::CharacterService::new(
            test_app.db_pool.clone(),
            encryption_service.clone(),
        ),
    );

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
        chat_override_service: Arc::new(scribe_backend::services::ChatOverrideService::new(
            test_app.db_pool.clone(),
            encryption_service.clone(),
        )),
        user_persona_service: Arc::new(scribe_backend::services::UserPersonaService::new(
            test_app.db_pool.clone(),
            encryption_service.clone(),
        )),
        character_service,
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
        encryption_service: encryption_service.clone(),
        lorebook_service: lorebook_service.clone(),
        auth_backend: Arc::new(scribe_backend::auth::user_store::Backend::new(
            test_app.db_pool.clone(),
        )),
        email_service: scribe_backend::services::email_service::create_email_service(
            &"development".to_string(),
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
        #[cfg(feature = "local-llm")]
        llamacpp_server_manager: None,
        #[cfg(feature = "local-llm")]
        security_audit_logger: None,
        #[cfg(feature = "local-llm")]
        model_integrity_verifier: None,
    };

    let app_state = scribe_backend::state::AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    );

    let app_state_arc = Arc::new(app_state);
    app_state_arc
}

#[tokio::test]
async fn test_variant_handling_updates_event() {
    let test_app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut _guard = TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

    let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
    let session_id = Uuid::new_v4();
    let chronicle_id = create_test_chronicle(user_id, &test_app).await.unwrap();

    // Create chat session
    create_test_chat_session(&test_app.db_pool, user_id.into(), session_id.into())
        .await
        .expect("Failed to create test chat session");

    // Setup Agentic System
    let mock_response = json!({
        "is_significant": true,
        "summary": "Initial summary of the event",
        "event_type": "NARRATIVE.EVENT",
        "confidence": 1.0,
        "actions": []
    });

    let mock_ai_client = Arc::new(
        scribe_backend::test_helpers::MockAiClient::new_with_response(mock_response.to_string()),
    );

    let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
    let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
        test_app.qdrant_service.clone(),
    ));
    let app_state = create_test_app_state(test_app.clone()).await;
    let agentic_system = AgenticNarrativeFactory::create_system_with_deps(
        mock_ai_client.clone(),
        Arc::new(ChronicleService::new(
            test_app.db_pool.clone(),
            test_app.ai_client.clone(),
        )),
        lorebook_service,
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone(),
        app_state,
        Some(AgenticNarrativeFactory::create_dev_config()),
    );

    // 1. Create FIRST message (Variant 1)
    let message1 = ChatMessage {
        id: Uuid::new_v4().into(),
        session_id: session_id.into(),
        message_type: MessageRole::Assistant,
        content: vec![], // Content doesn't matter for this test as we mock AI response
        content_nonce: None,
        created_at: Utc::now().into(),
        user_id: user_id.into(),
        variant_count: 1,
        current_variant_index: 0,
        ..Default::default()
    };

    // Process first event
    agentic_system
        .process_narrative_event(
            user_id.into(),
            session_id.into(),
            Some(chronicle_id.into()),
            None, // message_variant_id
            &[message1.clone()],
            &session_dek,
            None, // persona_context
            None, // game_state
            None, // character_context
        )
        .await
        .expect("First workflow failed");

    // Verify first event created
    let chronicle_service =
        ChronicleService::new(test_app.db_pool.clone(), test_app.ai_client.clone());
    let events = chronicle_service
        .get_chronicle_events(user_id.into(), chronicle_id.into(), EventFilter::default())
        .await
        .unwrap();

    assert_eq!(events.len(), 1);

    let decrypted_summary_1 = events[0]
        .get_decrypted_summary(&session_dek.0)
        .expect("Failed to decrypt summary");

    assert_eq!(decrypted_summary_1, "Initial summary of the event");
    let first_event_id = events[0].id;

    // 2. Create SECOND message (Variant 2 - Regeneration)
    // Update mock response for the variant
    let mock_response_variant = json!({
        "is_significant": true,
        "summary": "Updated summary for the variant",
        "event_type": "NARRATIVE.EVENT",
        "confidence": 1.0,
        "actions": []
    });

    // We need to update the mock client's response.
    // Since MockAiClient in this test setup might be immutable or hard to update,
    // we might need to create a new system or rely on the fact that we can't easily change the mock response
    // without a more complex mock.
    // However, for this test, let's assume we can just create a NEW system with the NEW mock response
    // but sharing the same DB and services.

    let mock_ai_client_variant = Arc::new(
        scribe_backend::test_helpers::MockAiClient::new_with_response(
            mock_response_variant.to_string(),
        ),
    );

    let agentic_system_variant = AgenticNarrativeFactory::create_system_with_deps(
        mock_ai_client_variant.clone(),
        Arc::new(ChronicleService::new(
            test_app.db_pool.clone(),
            test_app.ai_client.clone(),
        )),
        Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            Arc::new(scribe_backend::services::EncryptionService::new()),
            test_app.qdrant_service.clone(),
        )),
        test_app.qdrant_service.clone(),
        test_app.mock_embedding_client.clone(),
        create_test_app_state(test_app.clone()).await,
        Some(AgenticNarrativeFactory::create_dev_config()),
    );

    let message2 = ChatMessage {
        id: Uuid::new_v4().into(),
        session_id: session_id.into(),
        message_type: MessageRole::Assistant,
        content: vec![],
        content_nonce: None,
        created_at: Utc::now().into(), // Very recent
        user_id: user_id.into(),
        variant_count: 2, // THIS IS THE KEY
        current_variant_index: 1,
        ..Default::default()
    };

    // Process variant event
    agentic_system_variant
        .process_narrative_event(
            user_id.into(),
            session_id.into(),
            Some(chronicle_id.into()),
            None, // message_variant_id
            &[message2.clone()],
            &session_dek,
            None, // persona_context
            None, // game_state
            None, // character_context
        )
        .await
        .expect("Variant workflow failed");

    // Verify results
    let final_events = chronicle_service
        .get_chronicle_events(user_id.into(), chronicle_id.into(), EventFilter::default())
        .await
        .unwrap();

    // Should still be 1 event, but updated
    assert_eq!(
        final_events.len(),
        1,
        "Should not create a new event for variant"
    );
    assert_eq!(
        final_events[0].id, first_event_id,
        "Should update the same event ID"
    );

    let decrypted_summary = final_events[0]
        .get_decrypted_summary(&session_dek.0)
        .expect("Failed to decrypt summary");

    assert_eq!(
        decrypted_summary, "Updated summary for the variant",
        "Summary should be updated"
    );
}
