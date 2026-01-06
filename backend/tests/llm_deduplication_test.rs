#![cfg(feature = "postgres-backend")]
use diesel::prelude::*;
use genai::adapter::AdapterKind;
use genai::chat::{ChatResponse, MessageContent, Usage};
use genai::ModelIden;
#[cfg(feature = "sqlite-backend")]
use scribe_backend::db::SqliteInteractExt;
use scribe_backend::db::{get_conn, DbBigInt, DbBlob, DbId, DbTimestamp};
use scribe_backend::models::chronicle::{CreateChronicleRequest, NewPlayerChronicle};
use scribe_backend::models::chronicle_event::{CreateEventRequest, EventFilter, EventSource};
use scribe_backend::models::users::{AccountStatus, NewUser, User, UserDbQuery, UserRole};
use scribe_backend::schema::{player_chronicles, users};
use scribe_backend::services::chronicle_service::ChronicleService;
use scribe_backend::test_helpers::{spawn_app, TestApp};
use std::sync::Arc;

#[tokio::test]
async fn test_llm_deduplication_solomon_example() {
    // 1. Spawn app
    let app = spawn_app(false, false, false).await;

    // 2. Manually create User
    let new_user = NewUser {
        username: "testuser".to_string(),
        password_hash: "hash".to_string(),
        email: "test@example.com".to_string(),
        kek_salt: "salt".to_string(),
        encrypted_dek: DbBlob::from(vec![1, 2, 3]),
        encrypted_dek_by_recovery: None,
        recovery_kek_salt: None,
        dek_nonce: DbBlob::from(vec![4, 5, 6]),
        recovery_dek_nonce: None,
        role: UserRole::User,
        account_status: AccountStatus::Active,
        total_prompt_tokens: DbBigInt::from(0),
        total_completion_tokens: DbBigInt::from(0),
        total_token_cost_cents: DbBigInt::from(0),
        tokens_last_reset_at: None,
        token_usage_updated_at: chrono::Utc::now().into(),
    };

    let mut conn = get_conn(&app.db_pool)
        .await
        .expect("Failed to get DB connection");

    let user_db: UserDbQuery = conn
        .interact(move |conn| {
            diesel::insert_into(users::table)
                .values(&new_user)
                .returning(UserDbQuery::as_returning())
                .get_result(conn)
        })
        .await
        .expect("Failed to interact with DB")
        .expect("Failed to create user");

    let user = User::from(user_db);
    let user_id = user.id;

    // 3. Manually create Chronicle
    let chronicle_id = DbId::new();
    let new_chronicle = NewPlayerChronicle {
        id: Some(chronicle_id),
        user_id,
        name: "Test Chronicle".to_string(),
        description: None,
    };

    conn.interact(move |conn| {
        diesel::insert_into(player_chronicles::table)
            .values(&new_chronicle)
            .execute(conn)
    })
    .await
    .expect("Failed to interact with DB")
    .expect("Failed to create chronicle");

    // 4. Instantiate ChronicleService
    let chronicle_service = ChronicleService::new(app.db_pool.clone(), app.ai_client.clone());

    // 5. Create Event A (The "Existing" event)
    let event_a_summary =
        "Solomon secures a carton of water, carefully transferring its contents into his backpack.";
    let event_a_req = CreateEventRequest {
        event_type: "NARRATIVE".to_string(),
        summary: event_a_summary.to_string(),
        source: EventSource::AiExtracted,
        keywords: Some(vec!["water".to_string(), "backpack".to_string()]),
        message_variant_id: Some(DbId::new()), // Distinct Variant ID
        chat_session_id: None,
        timestamp_iso8601: None,
    };

    let event_a = chronicle_service
        .create_event(user_id, chronicle_id, event_a_req, None)
        .await
        .expect("Failed to create Event A");

    // 6. Prepare Event B (The "Duplicate" event)
    let event_b_summary = "Solomon transfers water bottles from a carton into his backpack.";
    let event_b_req = CreateEventRequest {
        event_type: "NARRATIVE".to_string(),
        summary: event_b_summary.to_string(),
        source: EventSource::AiExtracted,
        keywords: Some(vec!["water".to_string(), "backpack".to_string()]),
        message_variant_id: Some(DbId::new()), // Different Variant ID
        chat_session_id: None,
        timestamp_iso8601: None,
    };

    // 7. Configure Mock LLM to detect duplicate
    if let Some(mock_client) = &app.mock_ai_client {
        let json_response = serde_json::json!({
            "is_duplicate": true,
            "confidence": 0.95,
            "reasoning": "Both events describe Solomon transferring water to his backpack."
        });

        let chat_response = ChatResponse {
            content: MessageContent::from(json_response.to_string()),
            reasoning_content: None,
            model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-2.5-flash-lite"),
            provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-2.5-flash-lite"),
            usage: Usage::default(),
            captured_raw_body: None,
        };

        mock_client.set_response(Ok(chat_response));
    } else {
        panic!("Mock AI client not available");
    }

    // 8. Create Event B - Should be detected as duplicate
    let event_b = chronicle_service
        .create_event(user_id, chronicle_id, event_b_req, None)
        .await
        .expect("Failed to create Event B");

    // 9. Verify Event B was NOT persisted
    let events = chronicle_service
        .get_chronicle_events(user_id, chronicle_id, EventFilter::default())
        .await
        .expect("Failed to list events");

    assert_eq!(
        events.len(),
        1,
        "Should only be 1 event in the DB (Event A)"
    );
    assert_eq!(
        events[0].id, event_a.id,
        "The persisted event should be Event A"
    );

    // 10. Verify the returned event_b is indeed the one we tried to create (but wasn't saved)
    assert_eq!(event_b.summary, event_b_summary);
    assert_ne!(event_b.id, event_a.id);
}

#[tokio::test]
async fn test_llm_deduplication_elara_example() {
    // 1. Setup
    let app = spawn_app(false, false, false).await; // Use the same spawn_app signature as other tests
    let pool = app.db_pool.clone();

    // 2. Create User
    let mut user_id = DbId::new();
    {
        let mut conn = get_conn(&pool).await.expect("Failed to get connection");
        let new_user = NewUser {
            username: "test_elara".to_string(),
            email: "test_elara@example.com".to_string(),
            password_hash: "hash".to_string(),
            kek_salt: "salt".to_string(),
            encrypted_dek: DbBlob::from(vec![1, 2, 3]),
            encrypted_dek_by_recovery: None,
            recovery_kek_salt: None,
            dek_nonce: DbBlob::from(vec![4, 5, 6]),
            recovery_dek_nonce: None,
            role: UserRole::User,
            account_status: AccountStatus::Active,
            total_prompt_tokens: DbBigInt::from(0),
            total_completion_tokens: DbBigInt::from(0),
            total_token_cost_cents: DbBigInt::from(0),
            tokens_last_reset_at: None,
            token_usage_updated_at: chrono::Utc::now().into(),
        };

        let user_db: UserDbQuery = conn
            .interact(move |conn| {
                diesel::insert_into(users::table)
                    .values(&new_user)
                    .returning(UserDbQuery::as_returning())
                    .get_result(conn)
            })
            .await
            .expect("Failed to interact with DB")
            .expect("Failed to create user");
        user_id = user_db.id;
    }

    // 3. Create Chronicle
    let chronicle_service = ChronicleService::new(pool.clone(), app.ai_client.clone()); // Use app.ai_client.clone()
    let new_chronicle = NewPlayerChronicle {
        // Create NewPlayerChronicle
        id: Some(DbId::new()),
        user_id,
        name: "Elara Arc".to_string(),
        description: None,
    };
    let chronicle = chronicle_service
        .create_chronicle(
            user_id,
            CreateChronicleRequest {
                name: new_chronicle.name,
                description: new_chronicle.description,
            },
        ) // Adjust create_chronicle call
        .await
        .expect("Failed to create chronicle");
    let chronicle_id = chronicle.id;

    // 4. Create Event A (Detailed)
    let event_a_summary = "Solomon, intrigued by Elara, a half-elf girl, approaches her and asks for her name and guidance on local herbs, deliberately thwarting Mastema's own plans to claim the girl. Mastema, observing from a distance, grows increasingly furious over the next three days as Solomon remains constantly by Elara's side.";
    let event_a_req = CreateEventRequest {
        event_type: "NARRATIVE".to_string(),
        summary: event_a_summary.to_string(),
        source: EventSource::AiExtracted,
        keywords: Some(vec!["Elara".to_string(), "Mastema".to_string()]),
        message_variant_id: Some(DbId::new()),
        chat_session_id: None,
        timestamp_iso8601: None,
    };

    let event_a = chronicle_service
        .create_event(user_id, chronicle_id, event_a_req, None)
        .await
        .expect("Failed to create Event A");

    // 5. Create Event B (Summary/Alternative)
    let event_b_summary = "Solomon, drawn by a potent mana signature, encounters a gifted half-elf girl named Elara in a village. Mastema, observing from afar, sees Elara as a valuable resource. Solomon decides to protect Elara, approaching her to ask for her name.";
    let event_b_req = CreateEventRequest {
        event_type: "NARRATIVE".to_string(),
        summary: event_b_summary.to_string(),
        source: EventSource::AiExtracted,
        keywords: Some(vec!["Elara".to_string(), "Mastema".to_string()]),
        message_variant_id: Some(DbId::new()),
        chat_session_id: None,
        timestamp_iso8601: None,
    };

    // Configure Mock LLM to detect duplicate
    if let Some(mock_client) = &app.mock_ai_client {
        let json_response = serde_json::json!({
            "is_duplicate": true,
            "confidence": 0.90,
            "reasoning": "Both events describe Solomon interacting with Elara and Mastema observing."
        });

        let chat_response = ChatResponse {
            content: MessageContent::from(json_response.to_string()),
            reasoning_content: None,
            model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-2.5-flash-lite"),
            provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini-2.5-flash-lite"),
            usage: Usage::default(),
            captured_raw_body: None,
        };

        mock_client.set_response(Ok(chat_response));
    } else {
        panic!("Mock AI client not available");
    }

    // 6. Attempt to create Event B - SHOULD BE DETECTED AS DUPLICATE
    let event_b = chronicle_service
        .create_event(user_id, chronicle_id, event_b_req, None)
        .await
        .expect("Failed to process Event B");

    // 7. Verify
    // Use direct DB query to avoid complex filtering in get_chronicle_events which requires message_variants table
    let mut conn = get_conn(&pool).await.expect("Failed to get connection");
    let events: Vec<scribe_backend::models::chronicle_event::ChronicleEvent> = conn
        .interact(move |conn| {
            use scribe_backend::schema::chronicle_events;
            chronicle_events::table
                .filter(chronicle_events::chronicle_id.eq(chronicle_id))
                .load::<scribe_backend::models::chronicle_event::ChronicleEvent>(conn)
        })
        .await
        .expect("Failed to interact with DB")
        .expect("Failed to load events");

    assert_eq!(
        events.len(),
        1,
        "Should only be 1 event in the DB (Event A)"
    );
    assert_eq!(
        events[0].id, event_a.id,
        "The persisted event should be Event A"
    );

    // Verify the returned event_b is indeed the one we tried to create (but wasn't saved)
    assert_eq!(event_b.summary, event_b_summary);
    assert_ne!(event_b.id, event_a.id);
}
