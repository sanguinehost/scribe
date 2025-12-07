use diesel::prelude::*;
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::db::DbId;
use scribe_backend::models::chats::{Chat, NewChat};
use scribe_backend::models::chats::{DbInsertableChatMessage, MessageRole, NewMessageVariant};
use scribe_backend::models::chronicle::{CreateChronicleRequest, PlayerChronicle};
use scribe_backend::models::chronicle_event::{CreateEventRequest, EventSource};
use scribe_backend::models::users::User;
use scribe_backend::services::ChronicleService;
use scribe_backend::test_helpers::{spawn_app_permissive_rate_limiting, TestApp, TestAppGuard};
use secrecy::ExposeSecret;
use uuid;

#[async_trait::async_trait]
trait TestAppExt {
    async fn create_test_chronicle(
        &self,
        user_id: DbId,
        name: &str,
    ) -> Result<PlayerChronicle, scribe_backend::errors::AppError>;
    async fn create_chat_session(&self, user_id: DbId) -> Chat;
    async fn create_user_and_session(&self) -> (User, Chat, SessionDek);
}

#[async_trait::async_trait]
impl TestAppExt for TestAppGuard {
    async fn create_test_chronicle(
        &self,
        user_id: DbId,
        name: &str,
    ) -> Result<PlayerChronicle, scribe_backend::errors::AppError> {
        let chronicle_service =
            scribe_backend::services::ChronicleService::new(self.db_pool.clone());
        let request = CreateChronicleRequest {
            name: name.to_string(),
            description: None,
        };
        chronicle_service.create_chronicle(user_id, request).await
    }

    async fn create_chat_session(&self, user_id: DbId) -> Chat {
        let pool = self.db_pool.clone();
        scribe_backend::db::with_conn(&pool, move |conn| {
            use scribe_backend::schema::chat_sessions;
            let new_chat = NewChat {
                id: uuid::Uuid::new_v4().into(),
                user_id,
                character_id: uuid::Uuid::nil().into(), // Dummy character ID
                title_ciphertext: None,
                title_nonce: None,
                created_at: chrono::Utc::now().into(),
                updated_at: chrono::Utc::now().into(),
                history_management_strategy: "default".to_string(),
                history_management_limit: 10,
                model_name: Some("gpt-4".to_string()),
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
                stop_sequences: scribe_backend::models::OptionalStringArray(None),
                gemini_thinking_budget: None,
                gemini_enable_code_execution: None,
                system_prompt_ciphertext: None,
                system_prompt_nonce: None,
                player_chronicle_id: None,
                total_prompt_tokens: 0,
                total_completion_tokens: 0,
                estimated_cost_cents: 0,
                tokens_counted_at: chrono::Utc::now().into(),
                total_credits_used: 0.into(),
                prompt_template_id: "default".to_string(),
                narrative_style_override_ciphertext: None,
                narrative_style_override_nonce: None,
            };

            #[cfg(feature = "postgres-backend")]
            {
                diesel::insert_into(chat_sessions::table)
                    .values(&new_chat)
                    .execute(conn)?;
                chat_sessions::table
                    .find(new_chat.id)
                    .select(Chat::as_select())
                    .first(conn)
                    .map_err(scribe_backend::errors::AppError::from)
            }

            #[cfg(feature = "sqlite-backend")]
            {
                diesel::insert_into(chat_sessions::table)
                    .values(&new_chat)
                    .execute(conn)?;
                chat_sessions::table
                    .order(chat_sessions::created_at.desc())
                    .first(conn)
                    .map_err(scribe_backend::errors::AppError::from)
            }
        })
        .await
        .unwrap()
    }

    async fn create_user_and_session(&self) -> (User, Chat, SessionDek) {
        let user = scribe_backend::test_helpers::db::create_test_user(
            &self.db_pool,
            format!("user_{}", uuid::Uuid::new_v4()),
            "password123".to_string(),
        )
        .await
        .unwrap();

        let chat_session = self.create_chat_session(user.id).await;
        let session_dek = SessionDek::new(user.dek.as_ref().unwrap().0.expose_secret().clone());

        (user, chat_session, session_dek)
    }
}

#[tokio::test]
async fn test_variant_switching_chronicle_filtering() {
    // 1. Setup
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let (user, _session, session_dek) = app.create_user_and_session().await;
    let chronicle_service = scribe_backend::services::ChronicleService::new(app.db_pool.clone());

    // Create a chronicle
    let chronicle = app
        .create_test_chronicle(user.id, "Test Chronicle")
        .await
        .unwrap();

    // Create a chat session
    let chat_session = app.create_chat_session(user.id).await;

    // 2. Create a message with two variants
    let _message_id = DbId::new();
    let _variant0_id = DbId::new();
    let _variant1_id = DbId::new();

    // Helper to insert message and variants
    let (inserted_message_id, v0_id, v1_id) =
        scribe_backend::db::with_conn(&app.db_pool, move |conn| {
            use scribe_backend::schema::{chat_messages, message_variants};

            // Insert Message
            let new_message = DbInsertableChatMessage::new(
                #[cfg(feature = "sqlite-backend")]
                _message_id.clone(),
                chat_session.id,
                user.id,
                MessageRole::Assistant,
                vec![1, 2, 3], // Dummy content
                None,
                "gpt-4".to_string(),
            );

            // We need to set the ID for Postgres manually if it's not auto-generated or if we want to control it.
            // DbInsertableChatMessage doesn't have ID field for Postgres (it relies on DB generation usually).
            // But for this test we want to know the ID.
            // Let's use `insert_into` with `values` and `returning`.

            #[cfg(feature = "postgres-backend")]
            let inserted_message_id: DbId = diesel::insert_into(chat_messages::table)
                .values(&new_message)
                .returning(chat_messages::id)
                .get_result(conn)?;

            #[cfg(feature = "sqlite-backend")]
            let inserted_message_id = {
                diesel::insert_into(chat_messages::table)
                    .values(&new_message)
                    .execute(conn)?;
                _message_id.clone()
            };

            // Insert Variant 0
            let variant0 = NewMessageVariant {
                #[cfg(feature = "sqlite-backend")]
                id: DbId::new(),
                parent_message_id: inserted_message_id.clone(),
                variant_index: 0,
                content: vec![10, 20],
                content_nonce: None,
                user_id: user.id,
                prompt_tokens: None,
                completion_tokens: None,
                model_name: None,
                raw_prompt_ciphertext: None,
                raw_prompt_nonce: None,
            };

            #[cfg(feature = "postgres-backend")]
            let v0_id: DbId = diesel::insert_into(message_variants::table)
                .values(&variant0)
                .returning(message_variants::id)
                .get_result(conn)?;

            #[cfg(feature = "sqlite-backend")]
            let v0_id = {
                // For SQLite, NewMessageVariant might not have ID field to set?
                // Actually NewMessageVariant usually doesn't have ID.
                // But we need the ID.
                // We can insert and then query back.
                diesel::insert_into(message_variants::table)
                    .values(&variant0)
                    .execute(conn)?;

                message_variants::table
                    .filter(message_variants::parent_message_id.eq(inserted_message_id.clone()))
                    .filter(message_variants::variant_index.eq(0))
                    .select(message_variants::id)
                    .first::<DbId>(conn)?
            };

            // Insert Variant 1
            let variant1 = NewMessageVariant {
                #[cfg(feature = "sqlite-backend")]
                id: DbId::new(),
                parent_message_id: inserted_message_id.clone(),
                variant_index: 1,
                content: vec![30, 40],
                content_nonce: None,
                user_id: user.id,
                prompt_tokens: None,
                completion_tokens: None,
                model_name: None,
                raw_prompt_ciphertext: None,
                raw_prompt_nonce: None,
            };

            #[cfg(feature = "postgres-backend")]
            let v1_id: DbId = diesel::insert_into(message_variants::table)
                .values(&variant1)
                .returning(message_variants::id)
                .get_result(conn)?;

            #[cfg(feature = "sqlite-backend")]
            let v1_id = {
                diesel::insert_into(message_variants::table)
                    .values(&variant1)
                    .execute(conn)?;

                message_variants::table
                    .filter(message_variants::parent_message_id.eq(inserted_message_id.clone()))
                    .filter(message_variants::variant_index.eq(1))
                    .select(message_variants::id)
                    .first::<DbId>(conn)?
            };

            Ok::<_, scribe_backend::errors::AppError>((inserted_message_id, v0_id, v1_id))
        })
        .await
        .unwrap();

    // 3. Create Chronicle Events linked to variants
    let event_req_0 = CreateEventRequest {
        event_type: "NARRATIVE.EVENT".to_string(),
        summary: "Event for Variant 0".to_string(),
        source: EventSource::AiExtracted,
        keywords: Some(vec!["v0".to_string()]),
        timestamp_iso8601: Some(chrono::Utc::now().into()),
        chat_session_id: Some(chat_session.id),
        message_variant_id: Some(v0_id),
    };

    let event0 = chronicle_service
        .create_event(user.id, chronicle.id, event_req_0, Some(&session_dek))
        .await
        .unwrap();

    let event_req_1 = CreateEventRequest {
        event_type: "NARRATIVE.EVENT".to_string(),
        summary: "Event for Variant 1".to_string(),
        source: EventSource::AiExtracted,
        keywords: Some(vec!["v1".to_string()]),
        timestamp_iso8601: Some(chrono::Utc::now().into()),
        chat_session_id: Some(chat_session.id),
        message_variant_id: Some(v1_id),
    };

    let event1 = chronicle_service
        .create_event(user.id, chronicle.id, event_req_1, Some(&session_dek))
        .await
        .unwrap();

    // 4. Verify Filtering

    // Helper to update current_variant_index
    let pool = app.db_pool.clone();
    let update_variant_index = |index: i32| {
        let pool = pool.clone();
        async move {
            scribe_backend::db::with_conn(&pool, move |conn| {
                use scribe_backend::schema::chat_messages;
                diesel::update(
                    chat_messages::table.filter(chat_messages::session_id.eq(chat_session.id)),
                )
                .set(chat_messages::current_variant_index.eq(index))
                .execute(conn)
                .map_err(scribe_backend::errors::AppError::from)
            })
            .await
            .unwrap();
        }
    };

    // Case A: Variant Index 0
    update_variant_index(0).await;
    let events_v0 = chronicle_service
        .get_chronicle_events(
            user.id,
            chronicle.id,
            scribe_backend::models::chronicle_event::EventFilter::default(),
        )
        .await
        .unwrap();

    // Should contain event0, NOT event1
    assert!(
        events_v0.iter().any(|e| e.id == event0.id),
        "Event 0 should be present for variant 0"
    );
    assert!(
        !events_v0.iter().any(|e| e.id == event1.id),
        "Event 1 should NOT be present for variant 0"
    );

    // Case B: Variant Index 1
    update_variant_index(1).await;
    let events_v1 = chronicle_service
        .get_chronicle_events(
            user.id,
            chronicle.id,
            scribe_backend::models::chronicle_event::EventFilter::default(),
        )
        .await
        .unwrap();

    // Should contain event1, NOT event0
    assert!(
        events_v1.iter().any(|e| e.id == event1.id),
        "Event 1 should be present for variant 1"
    );
    assert!(
        !events_v1.iter().any(|e| e.id == event0.id),
        "Event 0 should NOT be present for variant 1"
    );

    // Case C: User added event (no variant ID)
    let event_req_user = CreateEventRequest {
        event_type: "USER.NOTE".to_string(),
        summary: "User note".to_string(),
        source: EventSource::UserAdded,
        keywords: Some(vec![]),
        timestamp_iso8601: Some(chrono::Utc::now().into()),
        chat_session_id: Some(chat_session.id),
        message_variant_id: None,
    };

    let event_user = chronicle_service
        .create_event(user.id, chronicle.id, event_req_user, Some(&session_dek))
        .await
        .unwrap();

    // Should be present in BOTH variants
    update_variant_index(0).await;
    let events_v0_user = chronicle_service
        .get_chronicle_events(user.id, chronicle.id, Default::default())
        .await
        .unwrap();
    assert!(
        events_v0_user.iter().any(|e| e.id == event_user.id),
        "User event should be present for variant 0"
    );

    update_variant_index(1).await;
    let events_v1_user = chronicle_service
        .get_chronicle_events(user.id, chronicle.id, Default::default())
        .await
        .unwrap();
    assert!(
        events_v1_user.iter().any(|e| e.id == event_user.id),
        "User event should be present for variant 1"
    );
}
