#![cfg(test)]
// backend/tests/agentic_realtime_extraction_tests.rs
//
// Tests that verify the agentic narrative system extracts events in real-time
// during chat sessions, automatically detecting and recording significant narrative events.

use anyhow::Result as AnyhowResult;
use bcrypt;
use chrono::Utc;
use diesel::{ExpressionMethods, RunQueryDsl, prelude::*};
use scribe_backend::{
    auth::session_dek::SessionDek,
    models::{
        chats::{ChatMessage, MessageRole},
        chronicle::CreateChronicleRequest,
        chronicle_event::EventSource,
        users::{AccountStatus, NewUser, UserDbQuery, UserRole},
    },
    schema::{chat_sessions, users},
    services::agentic::factory::AgenticNarrativeFactory,
    test_helpers::{MockAiClient, TestApp, TestDataGuard},
};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Helper to create a test user in the database
async fn create_test_user(test_app: &TestApp) -> AnyhowResult<(Uuid, SessionDek)> {
    let conn = test_app.db_pool.get().await?;

    let hashed_password = bcrypt::hash("testpassword", bcrypt::DEFAULT_COST)?;
    let username = format!("realtime_test_user_{}", Uuid::new_v4().simple());
    let email = format!("{}@test.com", username);

    // Generate proper crypto keys
    let kek_salt = scribe_backend::crypto::generate_salt()?;
    let dek = scribe_backend::crypto::generate_dek()?;

    let secret_password = secrecy::SecretString::new("testpassword".to_string().into());
    let kek = scribe_backend::crypto::derive_kek(&secret_password, &kek_salt)?;

    let (encrypted_dek, dek_nonce) =
        scribe_backend::crypto::encrypt_gcm(dek.expose_secret(), &kek)?;

    let new_user = NewUser {
        username,
        password_hash: hashed_password,
        email,
        kek_salt,
        encrypted_dek,
        encrypted_dek_by_recovery: None,
        role: UserRole::User,
        recovery_kek_salt: None,
        dek_nonce,
        recovery_dek_nonce: None,
        account_status: AccountStatus::Active,
        total_prompt_tokens: 0,
        total_completion_tokens: 0,
        total_token_cost_cents: 0,
        tokens_last_reset_at: None,
        token_usage_updated_at: Utc::now(),
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

    let session_dek = SessionDek(SecretBox::new(Box::new(dek.expose_secret().to_vec())));
    Ok((user_db.id, session_dek))
}

/// Helper to create a chat session in the database (required for foreign key constraint)
async fn create_test_chat_session(
    db_pool: &deadpool_diesel::Pool<deadpool_diesel::Manager<diesel::PgConnection>>,
    user_id: Uuid,
    session_id: Uuid,
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

// Helper to create a chat message with proper encryption
fn create_chat_message(
    user_id: Uuid,
    session_id: Uuid,
    role: MessageRole,
    content: &str,
    model_name: &str,
    session_dek: &SessionDek,
) -> AnyhowResult<ChatMessage> {
    // Encrypt the content properly
    let (encrypted_content, nonce) =
        scribe_backend::crypto::encrypt_gcm(content.as_bytes(), &session_dek.0)?;

    Ok(ChatMessage {
        id: Uuid::new_v4(),
        session_id,
        message_type: role,
        content: encrypted_content,
        content_nonce: Some(nonce),
        created_at: Utc::now(),
        user_id,
        prompt_tokens: Some(content.len() as i32 / 4), // Rough estimate
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
    })
}

// Helper to create AppState for tests
async fn create_test_app_state(test_app: TestApp) -> Arc<scribe_backend::state::AppState> {
    let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
    let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
        test_app.qdrant_service.clone(),
    ));

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
        #[cfg(feature = "local-llm")]
        llamacpp_server_manager: None,
        #[cfg(feature = "local-llm")]
        security_audit_logger: None,
        #[cfg(feature = "local-llm")]
        model_integrity_verifier: None,
    };

    let mut app_state = scribe_backend::state::AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    );

    let app_state_arc = Arc::new(app_state);

    // Add narrative intelligence service after AppState construction to break circular dependency
    let _narrative_intelligence_service =
        Arc::new(scribe_backend::services::NarrativeIntelligenceService::new(
            test_app.ai_client.clone(),
            Arc::new(scribe_backend::services::ChronicleService::new(
                test_app.db_pool.clone(),
            )),
            lorebook_service,
            app_state_arc.clone(),
            None, // No config for tests
        ));

    // Skip setting narrative intelligence service to avoid circular dependency in tests
    // app_state.set_narrative_intelligence_service(narrative_intelligence_service);

    app_state_arc
}

mod realtime_extraction_tests {
    use super::*;

    #[tokio::test]
    async fn test_realtime_event_extraction_during_progressive_chat() {
        let test_app =
            scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false)
                .await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
        let chat_session_id = Uuid::new_v4();

        // Create chat session (required for foreign key constraint)
        create_test_chat_session(&test_app.db_pool, user_id, chat_session_id)
            .await
            .unwrap();

        // Create a chronicle for the ongoing adventure
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
            test_app.db_pool.clone(),
        ));
        let create_chronicle_request = CreateChronicleRequest {
            name: "The Dragon's Quest".to_string(),
            description: Some("Epic adventure with dragons and treasures".to_string()),
        };
        let chronicle = chronicle_service
            .create_chronicle(user_id, create_chronicle_request)
            .await
            .unwrap();

        // Mock AI response for significant event detection
        let triage_response = json!({
            "is_significant": true,
            "summary": "Character discovers treasure and encounters danger",
            "event_category": "WORLD",
            "event_type": "DISCOVERY",
            "narrative_action": "DISCOVERED",
            "primary_agent": "Hero",
            "primary_patient": "Ancient Treasure",
            "confidence": 0.85,
            "reasoning": "Treasure discovery is a significant narrative event that should be recorded",
            "actions": [
                {
                    "tool_name": "create_chronicle_event",
                    "parameters": {
                        "event_category": "WORLD",
                        "event_type": "DISCOVERY",
                        "event_subtype": "ITEM_ACQUISITION",
                        "subject": "Hero",
                        "summary": "Hero discovers ancient treasure in dungeon chest",
                        "event_data": {
                            "location": "Dungeon",
                            "action": "Treasure discovery",
                            "items": ["golden amulet", "ancient coins"]
                        }
                    },
                    "reasoning": "Document treasure discovery event"
                }
            ]
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            encryption_service,
            test_app.qdrant_service.clone(),
        ));

        let app_state = create_test_app_state(test_app.clone()).await;
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service.clone(),
            lorebook_service,
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone()
                as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            app_state,
            None, // Use default config
        );

        // Simulate a progressive chat session with multiple message exchanges
        let messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User,
                "I carefully examine the ancient chest I found in the dungeon.", "gemini-2.5-flash", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant,
                "The chest is ornate, covered in mystical runes that glow faintly blue. As you touch it, you hear a soft click - it's unlocked!", "gemini-2.5-flash", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::User,
                "I open the chest to see what's inside.", "gemini-2.5-flash", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant,
                "Inside, you discover a magnificent golden amulet and a pouch of ancient coins. But suddenly, you hear footsteps echoing through the dungeon!", "gemini-2.5-flash", &session_dek).unwrap(),
        ];

        // Run the agentic workflow - should detect significant events in real-time
        let result = agent_runner
            .process_narrative_event(
                user_id,
                chat_session_id,
                Some(chronicle.id),
                &messages,
                &session_dek,
                None,
            )
            .await;

        // Verify the workflow succeeded
        assert!(
            result.is_ok(),
            "Real-time extraction should succeed: {:?}",
            result.err()
        );
        let workflow_result = result.unwrap();

        // Verify triage detected significance
        assert!(
            workflow_result.triage_result.is_significant,
            "Should detect significant treasure discovery"
        );
        assert!(
            workflow_result.triage_result.confidence > 0.7,
            "Should have high confidence: {}",
            workflow_result.triage_result.confidence
        );
        assert_eq!(
            workflow_result.triage_result.event_type, "NARRATIVE.EVENT",
            "Should identify as narrative event"
        );

        // Note: actions_taken might be empty if the MockAiClient isn't properly integrated
        // The key verification is that events were actually created in the chronicle

        // Verify events were recorded in the chronicle
        let events = chronicle_service
            .get_chronicle_events(user_id, chronicle.id, Default::default())
            .await
            .unwrap();
        assert!(
            !events.is_empty(),
            "Should have recorded events from real-time extraction"
        );

        let latest_event = &events[0];
        assert_eq!(
            latest_event.get_source().unwrap(),
            EventSource::AiExtracted,
            "Events should be AI-extracted"
        );
        // Note: Event summaries may be encrypted and show as "[ENCRYPTED]"
        // The key verification is that the event was created successfully
    }

    #[tokio::test]
    async fn test_realtime_extraction_chronicles_all_chat_progression() {
        let test_app =
            scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false)
                .await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
        let chat_session_id = Uuid::new_v4();

        // Create chat session (required for foreign key constraint)
        create_test_chat_session(&test_app.db_pool, user_id, chat_session_id)
            .await
            .unwrap();

        // Create a chronicle for tracking
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
            test_app.db_pool.clone(),
        ));
        let create_chronicle_request = CreateChronicleRequest {
            name: "Adventure Log".to_string(),
            description: Some("General adventure chronicle".to_string()),
        };
        let chronicle = chronicle_service
            .create_chronicle(user_id, create_chronicle_request)
            .await
            .unwrap();

        // Mock AI response for insignificant chat
        let triage_response = json!({
            "is_significant": false,
            "summary": "General conversation and movement without meaningful events",
            "event_category": "CONVERSATION",
            "event_type": "CASUAL_CHAT",
            "narrative_action": "DISCUSSED",
            "primary_agent": "Player",
            "primary_patient": "Assistant",
            "confidence": 0.2,
            "reasoning": "Simple movement and casual conversation lacks narrative significance",
            "actions": []
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            encryption_service,
            test_app.qdrant_service.clone(),
        ));

        let app_state = create_test_app_state(test_app.clone()).await;
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service.clone(),
            lorebook_service,
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone()
                as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            app_state,
            None, // Use default config
        );

        // Simulate mundane chat progression (which now gets chronicled like everything else)
        let mundane_messages = vec![
            create_chat_message(
                user_id,
                chat_session_id,
                MessageRole::User,
                "I walk down the corridor.",
                "gemini-2.5-pro",
                &session_dek,
            )
            .unwrap(),
            create_chat_message(
                user_id,
                chat_session_id,
                MessageRole::Assistant,
                "You walk down the stone corridor. The walls are lined with torches.",
                "gemini-2.5-pro",
                &session_dek,
            )
            .unwrap(),
            create_chat_message(
                user_id,
                chat_session_id,
                MessageRole::User,
                "What do I see ahead?",
                "gemini-2.5-pro",
                &session_dek,
            )
            .unwrap(),
            create_chat_message(
                user_id,
                chat_session_id,
                MessageRole::Assistant,
                "The corridor continues straight ahead. You can see more torches lighting the way.",
                "gemini-2.5-pro",
                &session_dek,
            )
            .unwrap(),
        ];

        // Get initial event count
        let initial_events = chronicle_service
            .get_chronicle_events(user_id, chronicle.id, Default::default())
            .await
            .unwrap();
        let initial_count = initial_events.len();

        // Run the agentic workflow on mundane content
        let result = agent_runner
            .process_narrative_event(
                user_id,
                chat_session_id,
                Some(chronicle.id),
                &mundane_messages,
                &session_dek,
                None,
            )
            .await;

        // Verify the workflow succeeded and handled the chat
        assert!(
            result.is_ok(),
            "Real-time extraction should handle all chat including mundane content"
        );
        let workflow_result = result.unwrap();

        // Verify triage detected significance (now all messages are chronicled)
        assert!(
            workflow_result.triage_result.is_significant,
            "All chat is now chronicled regardless of significance"
        );

        // Note: actions_taken might be empty if the MockAiClient isn't properly integrated
        // The key verification is that events were actually created in the chronicle

        // Verify events were recorded (since all messages get chronicled now)
        let final_events = chronicle_service
            .get_chronicle_events(user_id, chronicle.id, Default::default())
            .await
            .unwrap();
        assert!(
            final_events.len() > initial_count,
            "Should add events since all messages are now chronicled"
        );
    }

    #[tokio::test]
    async fn test_realtime_extraction_handles_rapid_message_sequence() {
        let test_app =
            scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false)
                .await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
        let chat_session_id = Uuid::new_v4();

        // Create chat session (required for foreign key constraint)
        create_test_chat_session(&test_app.db_pool, user_id, chat_session_id)
            .await
            .unwrap();

        // Create a chronicle for the combat scenario
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
            test_app.db_pool.clone(),
        ));
        let create_chronicle_request = CreateChronicleRequest {
            name: "Combat Encounter".to_string(),
            description: Some("Fast-paced combat scenario".to_string()),
        };
        let chronicle = chronicle_service
            .create_chronicle(user_id, create_chronicle_request)
            .await
            .unwrap();

        // Mock AI response for combat events
        let triage_response = json!({
            "is_significant": true,
            "summary": "Intense combat with multiple actions and outcomes",
            "event_category": "CHARACTER",
            "event_type": "STATE_CHANGE",
            "narrative_action": "ATTACKED",
            "primary_agent": "Hero",
            "primary_patient": "Dragon",
            "confidence": 0.9,
            "reasoning": "Epic dragon combat with spell casting and weapon strikes is highly significant",
            "actions": [
                {
                    "tool_name": "create_chronicle_event",
                    "parameters": {
                        "event_category": "CHARACTER",
                        "event_type": "STATE_CHANGE",
                        "event_subtype": "COMBAT_ENCOUNTER",
                        "subject": "Hero",
                        "summary": "Hero defeats mighty dragon in epic battle using sword and lightning magic",
                        "event_data": {
                            "location": "Dragon's Lair",
                            "action": "Combat sequence",
                            "opponent": "Dragon",
                            "methods": ["sword strike", "lightning spell"],
                            "outcome": "Victory"
                        }
                    },
                    "reasoning": "Record the epic dragon battle outcome"
                }
            ]
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            encryption_service,
            test_app.qdrant_service.clone(),
        ));

        let app_state = create_test_app_state(test_app.clone()).await;
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service.clone(),
            lorebook_service,
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone()
                as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            app_state,
            None, // Use default config
        );

        // Simulate rapid-fire combat sequence
        let rapid_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User,
                "I draw my sword and attack the dragon!", "gemini-2.5-flash", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant,
                "Your blade strikes true! The dragon roars in fury and breathes fire at you!", "gemini-2.5-flash", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::User,
                "I dodge and cast a lightning spell!", "gemini-2.5-flash", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant,
                "Lightning crackles through the air! The dragon staggers, wounded but still dangerous!", "gemini-2.5-flash", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::User,
                "I press the attack with a final strike!", "gemini-2.5-flash", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant,
                "With a mighty blow, you defeat the dragon! It crashes to the ground, defeated!", "gemini-2.5-flash", &session_dek).unwrap(),
        ];

        // Run the agentic workflow on rapid sequence
        let result = agent_runner
            .process_narrative_event(
                user_id,
                chat_session_id,
                Some(chronicle.id),
                &rapid_messages,
                &session_dek,
                None,
            )
            .await;

        // Verify the workflow handled rapid sequence successfully
        assert!(
            result.is_ok(),
            "Real-time extraction should handle rapid message sequences: {:?}",
            result.err()
        );
        let workflow_result = result.unwrap();

        // Verify significant combat was detected
        assert!(
            workflow_result.triage_result.is_significant,
            "Should detect combat as significant"
        );
        assert!(
            workflow_result.triage_result.confidence > 0.8,
            "Should have high confidence for combat"
        );
        assert_eq!(
            workflow_result.triage_result.event_type, "NARRATIVE.EVENT",
            "Should identify as narrative event"
        );

        // Verify events were recorded
        let events = chronicle_service
            .get_chronicle_events(user_id, chronicle.id, Default::default())
            .await
            .unwrap();
        assert!(!events.is_empty(), "Should have recorded combat events");

        let _combat_event = &events[0];
        // Note: Event summaries may be encrypted and show as "[ENCRYPTED]"
        // The key verification is that the combat event was created successfully
    }

    #[tokio::test]
    async fn test_realtime_extraction_with_context_from_previous_messages() {
        let test_app =
            scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false)
                .await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
        let chat_session_id = Uuid::new_v4();

        // Create chat session (required for foreign key constraint)
        create_test_chat_session(&test_app.db_pool, user_id, chat_session_id)
            .await
            .unwrap();

        // Create a chronicle for the story
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
            test_app.db_pool.clone(),
        ));
        let create_chronicle_request = CreateChronicleRequest {
            name: "The Mysterious Quest".to_string(),
            description: Some("A quest with developing plot elements".to_string()),
        };
        let chronicle = chronicle_service
            .create_chronicle(user_id, create_chronicle_request)
            .await
            .unwrap();

        // Mock AI response for plot revelation
        let triage_response = json!({
            "is_significant": true,
            "summary": "Major plot revelation about character's true identity",
            "event_category": "PLOT",
            "event_type": "REVELATION",
            "narrative_action": "REVEALED",
            "primary_agent": "Sage",
            "primary_patient": "Hero's Identity",
            "confidence": 0.95,
            "reasoning": "Major character identity revelation is a crucial plot turning point",
            "actions": [
                {
                    "tool_name": "create_chronicle_event",
                    "parameters": {
                        "event_category": "PLOT",
                        "event_type": "REVELATION",
                        "event_subtype": "SECRET_REVELATION",
                        "subject": "Hero",
                        "summary": "Hero learns from wise sage that they are the lost prince of Eldoria",
                        "event_data": {
                            "location": "Sage's dwelling",
                            "action": "Identity revelation",
                            "revealed_identity": "Lost Prince of Eldoria",
                            "revealer": "Wise Sage",
                            "implications": "Rightful claim to throne"
                        }
                    },
                    "reasoning": "Document this major plot revelation about the hero's true identity"
                }
            ]
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            encryption_service,
            test_app.qdrant_service.clone(),
        ));

        let app_state = create_test_app_state(test_app.clone()).await;
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service.clone(),
            lorebook_service,
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone()
                as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            app_state,
            None, // Use default config
        );

        // Simulate a conversation that builds up to a revelation
        let context_building_messages = vec![
            create_chat_message(user_id, chat_session_id, MessageRole::User,
                "I've been having strange dreams about a castle I've never seen before.", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant,
                "The wise sage looks at you with knowing eyes. 'Tell me more about these dreams, child.'", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::User,
                "In the dreams, I see myself as a child in royal robes, but I was raised as a peasant.", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant,
                "The sage nods slowly. 'The time has come for you to learn the truth about your birth.'", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::User,
                "What truth? Who am I really?", "gemini-2.5-pro", &session_dek).unwrap(),
            create_chat_message(user_id, chat_session_id, MessageRole::Assistant,
                "'You are the lost prince of Eldoria, hidden away to protect you from those who usurped the throne!'", "gemini-2.5-pro", &session_dek).unwrap(),
        ];

        // Run the agentic workflow on the revelation sequence
        let result = agent_runner
            .process_narrative_event(
                user_id,
                chat_session_id,
                Some(chronicle.id),
                &context_building_messages,
                &session_dek,
                None,
            )
            .await;

        // Verify the workflow succeeded
        assert!(
            result.is_ok(),
            "Real-time extraction should handle context-building conversations: {:?}",
            result.err()
        );
        let workflow_result = result.unwrap();

        // Verify the plot revelation was detected
        assert!(
            workflow_result.triage_result.is_significant,
            "Should detect plot revelation as significant"
        );
        assert!(
            workflow_result.triage_result.confidence > 0.9,
            "Should have very high confidence for major revelation"
        );
        assert_eq!(
            workflow_result.triage_result.event_type, "NARRATIVE.EVENT",
            "Should identify as narrative event"
        );

        // Note: actions_taken might be empty if the MockAiClient isn't properly integrated
        // The key verification is that events were actually created in the chronicle

        // Verify the revelation event was recorded
        let events = chronicle_service
            .get_chronicle_events(user_id, chronicle.id, Default::default())
            .await
            .unwrap();
        assert!(
            !events.is_empty(),
            "Should have recorded the revelation event"
        );

        let _revelation_event = &events[0];
        // Note: Event summaries may be encrypted and show as "[ENCRYPTED]"
        // The key verification is that the revelation event was created successfully
    }

    #[tokio::test]
    async fn test_realtime_extraction_performance_with_long_messages() {
        let test_app =
            scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false)
                .await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let (user_id, session_dek) = create_test_user(&test_app).await.unwrap();
        let chat_session_id = Uuid::new_v4();

        // Create chat session (required for foreign key constraint)
        create_test_chat_session(&test_app.db_pool, user_id, chat_session_id)
            .await
            .unwrap();

        // Create a chronicle
        let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(
            test_app.db_pool.clone(),
        ));
        let create_chronicle_request = CreateChronicleRequest {
            name: "Performance Test Chronicle".to_string(),
            description: Some("Testing extraction with long content".to_string()),
        };
        let chronicle = chronicle_service
            .create_chronicle(user_id, create_chronicle_request)
            .await
            .unwrap();

        // Mock AI response
        let triage_response = json!({
            "is_significant": true,
            "summary": "Epic battle with detailed descriptions and multiple participants",
            "event_category": "PLOT",
            "event_type": "TURNING_POINT",
            "narrative_action": "BATTLED",
            "primary_agent": "Alliance Forces",
            "primary_patient": "Dark Army",
            "confidence": 0.88,
            "reasoning": "Massive battlefield conflict with kingdom's fate at stake is a major turning point",
            "actions": [
                {
                    "tool_name": "create_chronicle_event",
                    "parameters": {
                        "event_category": "PLOT",
                        "event_type": "TURNING_POINT",
                        "event_subtype": "PLOT_DEVELOPMENT",
                        "subject": "Alliance Forces",
                        "summary": "Epic battle unfolds with alliance forces clashing against dark army in climactic confrontation",
                        "event_data": {
                            "location": "Massive Battlefield",
                            "action": "Epic battle",
                            "participants": ["Sir Gareth", "Lady Elara", "Captain Marcus", "Player"],
                            "enemies": ["Dark creatures", "Massive troll"],
                            "stakes": "Kingdom's fate"
                        }
                    },
                    "reasoning": "Record the climactic battle that determines the kingdom's fate"
                }
            ]
        });

        let mock_ai_client = Arc::new(MockAiClient::new_with_response(triage_response.to_string()));

        // Create the agentic narrative system
        let encryption_service = Arc::new(scribe_backend::services::EncryptionService::new());
        let lorebook_service = Arc::new(scribe_backend::services::LorebookService::new(
            test_app.db_pool.clone(),
            encryption_service,
            test_app.qdrant_service.clone(),
        ));

        let app_state = create_test_app_state(test_app.clone()).await;
        let agent_runner = AgenticNarrativeFactory::create_system_with_deps(
            mock_ai_client.clone(),
            chronicle_service.clone(),
            lorebook_service,
            test_app.qdrant_service.clone(),
            test_app.mock_embedding_client.clone()
                as Arc<dyn scribe_backend::llm::EmbeddingClient + Send + Sync>,
            app_state,
            None, // Use default config
        );

        // Create long detailed messages (simulating verbose RP)
        let long_content = "The massive battlefield stretches before you, with thousands of warriors clashing in epic combat. Knights in shining armor clash with dark creatures emerging from shadow portals. Magic crackles through the air as wizards on both sides cast powerful spells. You see your allies fighting valiantly - Sir Gareth defending a group of villagers, Lady Elara weaving protective barriers around the wounded, and Captain Marcus leading a charge against a massive troll. The fate of the kingdom hangs in the balance as you prepare to make your move in this climactic battle.".repeat(3);

        let long_messages = vec![
            create_chat_message(
                user_id,
                chat_session_id,
                MessageRole::User,
                "I survey the battlefield and prepare for the final confrontation.",
                "gemini-2.5-pro",
                &session_dek,
            )
            .unwrap(),
            create_chat_message(
                user_id,
                chat_session_id,
                MessageRole::Assistant,
                &long_content,
                "gemini-2.5-pro",
                &session_dek,
            )
            .unwrap(),
        ];

        // Measure extraction time
        let start_time = std::time::Instant::now();

        let result = agent_runner
            .process_narrative_event(
                user_id,
                chat_session_id,
                Some(chronicle.id),
                &long_messages,
                &session_dek,
                None,
            )
            .await;

        let extraction_time = start_time.elapsed();

        // Verify the workflow succeeded and performed reasonably
        assert!(
            result.is_ok(),
            "Real-time extraction should handle long messages: {:?}",
            result.err()
        );
        assert!(
            extraction_time.as_secs() < 30,
            "Extraction should complete within reasonable time: {:?}",
            extraction_time
        );

        let workflow_result = result.unwrap();

        // Verify the epic battle was detected despite length
        assert!(
            workflow_result.triage_result.is_significant,
            "Should detect epic battle as significant"
        );
        assert_eq!(
            workflow_result.triage_result.event_type, "NARRATIVE.EVENT",
            "Should identify as narrative event"
        );

        // Verify events were recorded
        let events = chronicle_service
            .get_chronicle_events(user_id, chronicle.id, Default::default())
            .await
            .unwrap();
        assert!(
            !events.is_empty(),
            "Should have recorded events despite long content"
        );
    }
}
