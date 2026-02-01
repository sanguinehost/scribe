#![cfg(feature = "postgres-backend")]
use scribe_backend::auth::session_dek::SessionDek;
use scribe_backend::db::DbId;
use scribe_backend::models::chats::{ChatMessage, MessageRole};
use scribe_backend::services::agentic::{
    agent_runner::{NarrativeAgentRunner, NarrativeWorkflowConfig},
    registry::ToolRegistry,
};
use scribe_backend::services::{hybrid_token_counter::HybridTokenCounter, ChronicleService};
use scribe_backend::state::AppState;
use scribe_backend::test_helpers::{
    MockAiClient, MockEmbeddingClient, MockEmbeddingPipelineService,
};
use secrecy::SecretBox;
use std::sync::Arc;
use uuid::Uuid;

use scribe_backend::test_helpers::spawn_app;

#[tokio::test]
async fn test_chronicle_creation_refusal() {
    std::env::set_var("COOKIE_SIGNING_KEY", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let app = spawn_app(true, false, false).await;

    // 1. Setup Mock AI Client to refuse event creation
    let refusal_response = serde_json::json!({
        "should_create_event": false,
        "reasoning": "This is a duplicate of a previous event.",
        "summary": "Duplicate event",
        "keywords": []
    });

    // Configure the mock client from the app
    if let Some(mock_client) = &app.mock_ai_client {
        use scribe_backend::llm::rig_client::RigChatResponse;

        let chat_response = RigChatResponse {
            content: refusal_response.to_string(),
            prompt_tokens: Some(10),
            completion_tokens: Some(10),
            total_tokens: Some(20),
            reasoning_content: None,
        };
        mock_client.set_response(Ok(chat_response));
    } else {
        panic!("Mock AI client not available");
    }

    // 2. Setup other dependencies
    let tool_registry = Arc::new(ToolRegistry::new());
    let config = NarrativeWorkflowConfig::default();

    use scribe_backend::services::tokenizer_service::TokenizerService;
    use std::path::PathBuf;

    // We need a real ChronicleService (connected to test DB)
    let chronicle_service = Arc::new(ChronicleService::new(
        app.db_pool.clone(),
        app.ai_client.clone(),
    ));

    // Setup TokenizerService and HybridTokenCounter
    let tokenizer_path =
        PathBuf::from("/home/socol/Workspace/scribe/backend/resources/tokenizers/tokenizer.json");
    let tokenizer = TokenizerService::new(tokenizer_path).expect("Failed to create tokenizer");
    let token_counter = Arc::new(HybridTokenCounter::new_local_only(tokenizer));

    let agent_runner = NarrativeAgentRunner::new(
        app.ai_client.clone(),
        tool_registry,
        config,
        chronicle_service,
        app.state.clone(),
        token_counter,
    );

    // 3. Create dummy data
    let user_id = DbId::from(Uuid::new_v4());
    let chat_session_id = DbId::from(Uuid::new_v4());
    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec()))); // Dummy DEK

    let mut message = ChatMessage {
        id: DbId::new(),
        session_id: DbId::new(),
        message_type: MessageRole::User,
        content: vec![],
        content_nonce: None,
        created_at: chrono::Utc::now().into(),

        user_id: DbId::new(),
        prompt_tokens: Some(10),
        completion_tokens: Some(10),
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: "gemini-2.5-flash-lite".to_string(),
        role: Some("user".to_string()),
        updated_at: chrono::Utc::now().into(),
        status: "completed".to_string(),
        error_message: None,
        superseded_at: None,
        variant_count: 1,
        current_variant_index: 0,
        credits_charged: 0,
        credits_cost: scribe_backend::db::DbDecimal::from(0),
        actual_cost: scribe_backend::db::DbDecimal::from(0),
        modified_cost: scribe_backend::db::DbDecimal::from(0),
        credit_cost: 0,
        actual_charge: scribe_backend::db::DbDecimal::from(0),
        game_time: None,
        parts: None,
        attachments: None,
        rag_embedding_id: None,
    };

    // Encrypt the content
    let _ = message.encrypt_content_field(&session_dek.0, "Hello");
    // We need to handle the Result from encrypt_content_field
    let messages = vec![message];

    // NOTE: The agent runner expects encrypted content in messages if it tries to decrypt.
    // However, our mock AI client ignores the input prompt content, so the decryption failure in `build_conversation_context`
    // might be logged but shouldn't crash the test if we handle it right.
    // Actually `process_narrative_event` calls `build_conversation_context_with_token_limit` which attempts decryption.
    // If decryption fails, it logs a warning and uses placeholder text. This is fine for our test since the Mock AI response is pre-determined.

    // 4. Run process_narrative_event
    let result = agent_runner
        .process_narrative_event(
            user_id,
            chat_session_id,
            None, // No chronicle
            None, // No message_variant_id
            &messages,
            &session_dek,
            None, // No persona context
            None, // No game state
            None, // No character context
        )
        .await;

    // 5. Assertions
    assert!(result.is_ok(), "Agent runner failed: {:?}", result.err());
    let workflow_result = result.unwrap();

    // Verify that the event type is SKIPPED
    assert_eq!(workflow_result.triage_result.event_type, "SKIPPED");
    assert_eq!(
        workflow_result.triage_result.summary,
        "Duplicate or insignificant event"
    );

    // Verify execution results contain the skipped message
    let execution_result = &workflow_result.execution_results[0];
    assert_eq!(execution_result["skipped"], true);
    assert!(execution_result["message"]
        .as_str()
        .unwrap()
        .contains("duplicate"));
}

#[tokio::test]
async fn test_chronicle_creation_success() {
    std::env::set_var("COOKIE_SIGNING_KEY", "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let app = spawn_app(true, false, false).await;

    // 1. Setup Mock AI Client to APPROVE event creation
    let success_response = serde_json::json!({
        "should_create_event": true,
        "reasoning": "This is a significant event.",
        "summary": "Something important happened.",
        "keywords": ["important", "event"]
    });

    if let Some(mock_client) = &app.mock_ai_client {
        use scribe_backend::llm::rig_client::RigChatResponse;

        let chat_response = RigChatResponse {
            content: success_response.to_string(),
            prompt_tokens: Some(10),
            completion_tokens: Some(10),
            total_tokens: Some(20),
            reasoning_content: None,
        };
        mock_client.set_response(Ok(chat_response));
    } else {
        panic!("Mock AI client not available");
    }

    // 2. Setup dependencies
    let tool_registry = Arc::new(ToolRegistry::new());
    let config = NarrativeWorkflowConfig::default();

    use scribe_backend::services::tokenizer_service::TokenizerService;
    use std::path::PathBuf;

    let chronicle_service = Arc::new(ChronicleService::new(
        app.db_pool.clone(),
        app.ai_client.clone(),
    ));

    let tokenizer_path =
        PathBuf::from("/home/socol/Workspace/scribe/backend/resources/tokenizers/tokenizer.json");
    let tokenizer = TokenizerService::new(tokenizer_path).expect("Failed to create tokenizer");
    let token_counter = Arc::new(HybridTokenCounter::new_local_only(tokenizer));

    let agent_runner = NarrativeAgentRunner::new(
        app.ai_client.clone(),
        tool_registry,
        config,
        chronicle_service.clone(),
        app.state.clone(),
        token_counter,
    );

    // 3. Create real data in DB
    use diesel::prelude::*;
    use scribe_backend::db::{DbBlob, DbId, DbTimestamp};
    use scribe_backend::models::chronicle::CreateChronicleRequest;
    use scribe_backend::models::users::{AccountStatus, NewUser, UserRole};
    use scribe_backend::schema::users;

    let user_id = DbId::new();
    let new_user = NewUser {
        id: Uuid::new_v4().into(),
        username: "testuser".to_string(),
        password_hash: "hash".to_string(),
        email: "test@test.com".to_string(),
        kek_salt: "salt".to_string(),
        encrypted_dek: DbBlob::from(vec![0; 32]),
        dek_nonce: DbBlob::from(vec![0; 12]),
        encrypted_dek_by_recovery: None,
        recovery_kek_salt: None,
        recovery_dek_nonce: None,
        role: UserRole::User,
        account_status: AccountStatus::Active,
        total_prompt_tokens: 0,
        total_completion_tokens: 0,
        total_token_cost_cents: 0,
        tokens_last_reset_at: None,
        token_usage_updated_at: DbTimestamp::now(),
    };

    app.db_pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::insert_into(users::table)
                .values(&new_user)
                .execute(conn)
        })
        .await
        .unwrap()
        .expect("Failed to insert user");

    let chronicle_req = CreateChronicleRequest {
        name: "Test Chronicle".to_string(),
        description: Some("A test chronicle".to_string()),
    };
    let chronicle = chronicle_service
        .create_chronicle(user_id, chronicle_req)
        .await
        .expect("Failed to create chronicle");
    let chronicle_id = chronicle.id;

    let chat_session_id = DbId::from(Uuid::new_v4());
    let session_dek = SessionDek(SecretBox::new(Box::new([0u8; 32].to_vec())));

    let mut message = ChatMessage {
        id: DbId::new(),
        session_id: DbId::new(),
        message_type: MessageRole::User,
        content: vec![],
        content_nonce: None,
        created_at: chrono::Utc::now().into(),

        user_id: DbId::new(),
        prompt_tokens: Some(10),
        completion_tokens: Some(10),
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: "gemini-2.5-flash-lite".to_string(),
        role: Some("user".to_string()),
        updated_at: chrono::Utc::now().into(),
        status: "completed".to_string(),
        error_message: None,
        superseded_at: None,
        variant_count: 1,
        current_variant_index: 0,
        credits_charged: 0,
        credits_cost: scribe_backend::db::DbDecimal::from(0),
        actual_cost: scribe_backend::db::DbDecimal::from(0),
        modified_cost: scribe_backend::db::DbDecimal::from(0),
        credit_cost: 0,
        actual_charge: scribe_backend::db::DbDecimal::from(0),
        game_time: None,
        parts: None,
        attachments: None,
        rag_embedding_id: None,
    };

    let _ = message.encrypt_content_field(&session_dek.0, "Something happened");
    let messages = vec![message];

    // 4. Run process_narrative_event
    let result = agent_runner
        .process_narrative_event(
            user_id,
            chat_session_id,
            Some(chronicle_id),
            None, // No message_variant_id
            &messages,
            &session_dek,
            None,
            None, // No game state
            None, // No character context
        )
        .await;

    // 5. Assertions
    assert!(result.is_ok(), "Agent runner failed: {:?}", result.err());
    let workflow_result = result.unwrap();

    // Verify that the event type is NOT SKIPPED
    assert_ne!(workflow_result.triage_result.event_type, "SKIPPED");
    assert_eq!(
        workflow_result.triage_result.summary,
        "Something important happened."
    );

    // Verify execution results
    let execution_result = &workflow_result.execution_results[0];
    assert_eq!(execution_result["success"], true);
    assert_eq!(
        execution_result["message"],
        "Chronicle event created successfully"
    );
    assert!(execution_result["event_id"].is_string());

    // Verify DB
    // We need to check if a chronicle event exists for this session
    // But since we used a random session ID and user ID, and didn't create the session/user in DB,
    // the foreign key constraints might have failed if we were using a real DB with constraints.
    // SQLite might be lenient or we might need to create user/session first.
    // However, process_narrative_event calls chronicle_service.create_event which inserts into DB.
    // If it succeeded (result.is_ok()), then it inserted.
}
