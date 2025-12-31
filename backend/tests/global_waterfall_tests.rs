#![cfg(feature = "sqlite-backend")]
#![cfg(test)]

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use bigdecimal::BigDecimal;
use chrono::Utc;
use genai::{
    adapter::AdapterKind,
    chat::{ChatResponse, MessageContent, Usage},
    ModelIden,
};
use serde_json::json;
use tower::ServiceExt;

// Diesel imports
use diesel::prelude::*;

// Crate imports
use scribe_backend::{
    db::{with_conn, DbId, DbTimestamp},
    models::chats::{
        ApiChatMessage, Chat as DbChat, GenerateChatRequest, MessageRole, NewChat, NewChatMessage,
    },
    schema,
    test_helpers::{self},
};

#[tokio::test]
async fn test_global_waterfall_fills_context() -> anyhow::Result<()> {
    // 1. Spawn app with mock services
    let test_app = test_helpers::spawn_app(false, false, false).await;

    // 2. Create user
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "waterfall_user".to_string(),
        "password".to_string(),
    )
    .await?;

    // 3. Login
    let client = reqwest::Client::builder().cookie_store(true).build()?;
    let login_payload = json!({
        "identifier": user.username,
        "password": "password",
    });
    let login_response = client
        .post(format!("{}/api/auth/login", &test_app.address))
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .json(&login_payload)
        .send()
        .await?;
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response
        .cookies()
        .find(|c| c.name() == "id")
        .map(|c| format!("{}={}", c.name(), c.value()))
        .unwrap();

    // 4. Create character
    let character = test_helpers::db::create_test_character(
        &test_app.db_pool,
        user.id,
        "Waterfall Char".to_string(),
    )
    .await?;

    // 5. Create chat session
    let session = with_conn(&test_app.db_pool, move |conn| {
        let now = Utc::now();
        let new_chat = NewChat {
            id: DbId::new(),
            user_id: user.id,
            character_id: character.id,
            title_ciphertext: None,
            title_nonce: None,
            created_at: DbTimestamp::now(),
            updated_at: DbTimestamp::now(),
            history_management_strategy: "message_window".to_string(),
            history_management_limit: 100,
            model_name: Some("test-model".to_string()),
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
            stop_sequences: scribe_backend::models::OptionalStringArray::default(),
            gemini_thinking_budget: None,
            gemini_enable_code_execution: None,
            system_prompt_ciphertext: None,
            system_prompt_nonce: None,
            player_chronicle_id: None,
            total_prompt_tokens: 0,
            total_completion_tokens: 0,
            estimated_cost_cents: 0,
            tokens_counted_at: DbTimestamp::now(),
            total_credits_used: BigDecimal::from(0).into(),
            prompt_template_id: "default".to_string(),
            narrative_style_override_ciphertext: None,
            narrative_style_override_nonce: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            logit_bias: None,
            agent_mode: None,
            model_provider: None,
            total_actual_cost: 0.0,
            total_modified_cost: 0.0,
            total_credit_cost: 0,
            total_actual_charge: 0.0,
            game_state: None,
            game_master_mode_enabled: false,
            gemini_thinking_level: None,
            rag_chronicles_limit: None,
            rag_lorebooks_limit: None,
            rag_older_chat_limit: None,
        };

        #[cfg(feature = "postgres-backend")]
        {
            diesel::insert_into(schema::chat_sessions::table)
                .values(&new_chat)
                .get_result::<DbChat>(conn)
                .map_err(|e| scribe_backend::errors::AppError::DatabaseQueryError(e.to_string()))
        }

        #[cfg(feature = "sqlite-backend")]
        {
            diesel::insert_into(schema::chat_sessions::table)
                .values(&new_chat)
                .execute(conn)
                .map_err(|e| scribe_backend::errors::AppError::DatabaseQueryError(e.to_string()))?;

            schema::chat_sessions::table
                .find(new_chat.id)
                .first::<DbChat>(conn)
                .map_err(|e| scribe_backend::errors::AppError::DatabaseQueryError(e.to_string()))
        }
    })
    .await?;

    // 6. Add many messages to the session
    // Each message will be ~100 tokens
    let num_messages = 50;
    let session_id = session.id;
    let user_id = user.id;
    with_conn(&test_app.db_pool, move |conn| {
        for i in 0..num_messages {
            let now = Utc::now() - chrono::Duration::minutes(num_messages - i);
            let content = format!("This is message number {} in the conversation. It contains some text to consume tokens. ", i).repeat(5);
            let new_message = NewChatMessage {
                id: DbId::new(),
                session_id,
                user_id,
                message_type: if i % 2 == 0 { MessageRole::User } else { MessageRole::Assistant },
                content: content.into_bytes(),
                content_nonce: None,
                created_at: now.into(),
                updated_at: now.into(),
                role: None,
                parts: None,
                attachments: None,
                prompt_tokens: Some(100),
                completion_tokens: None,
                raw_prompt_ciphertext: None,
                raw_prompt_nonce: None,
                model_name: "test-model".to_string(),
                status: "completed".to_string(),
                variant_count: 0,
                current_variant_index: 0,
                credits_charged: 0,
                credits_cost: 0,
                actual_cost: 0.0,
                modified_cost: 0.0,
                credit_cost: 0,
                actual_charge: 0.0,
                game_time: None,
            };
            diesel::insert_into(schema::chat_messages::table)
                .values(&new_message)
                .execute(conn)
                .map_err(|e| scribe_backend::errors::AppError::DatabaseQueryError(e.to_string()))?;
        }
        Ok(())
    }).await?;

    // 7. Set up user settings with large context limit and small history budget
    // This forces the Global Waterfall to kick in if RAG is empty
    with_conn(&test_app.db_pool, move |conn| {
        diesel::update(
            schema::user_settings::table.filter(schema::user_settings::user_id.eq(user_id)),
        )
        .set((
            schema::user_settings::default_context_total_token_limit.eq(Some(100000)),
            schema::user_settings::default_context_recent_history_budget.eq(Some(2000)), // Small budget (~20 messages)
            schema::user_settings::default_context_rag_budget.eq(Some(90000)),
        ))
        .execute(conn)
        .map_err(|e| scribe_backend::errors::AppError::DatabaseQueryError(e.to_string()))
    })
    .await?;

    // 8. Ensure RAG returns no results
    test_app
        .mock_embedding_pipeline_service
        .set_retrieve_responses_sequence(vec![
            Ok(vec![]), // Lorebooks
            Ok(vec![]), // Chronicles
            Ok(vec![]), // Older Chat
        ]);

    // 9. Mock AI response
    test_app
        .mock_ai_client
        .as_ref()
        .unwrap()
        .set_response(Ok(ChatResponse {
            model_iden: ModelIden::new(AdapterKind::Gemini, "test-model"),
            provider_model_iden: ModelIden::new(AdapterKind::Gemini, "test-model"),
            content: MessageContent::from("Waterfall response"),
            reasoning_content: None,
            usage: Usage::default(),
            captured_raw_body: None,
        }));

    // 10. Call generate endpoint
    let payload = GenerateChatRequest {
        history: vec![ApiChatMessage {
            role: "user".to_string(),
            content: "Trigger waterfall".to_string(),
        }],
        model: None,
        query_text_for_rag: None,
        analysis_mode: None,
        guidance: None,
        variant_of: None,
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chat/{}/generate", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload)?))?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);

    // 11. Verify that the AI request contains many messages
    // The initial budget was 2000 tokens (~20 messages).
    // The total limit is 100000 tokens.
    // The Global Waterfall should have added almost all 50 messages.
    let last_request = test_app
        .mock_ai_client
        .as_ref()
        .unwrap()
        .get_last_request()
        .unwrap();

    // messages include the system prompt (if any) and the history
    println!(
        "Number of messages in AI request: {}",
        last_request.messages.len()
    );

    // We expect more than 20 messages (which would be the ~2000 token limit)
    // Plus the current user message and potentially a system prompt.
    assert!(
        last_request.messages.len() > 30,
        "Global Waterfall should have added more messages than the initial budget allowed. Got {}",
        last_request.messages.len()
    );

    Ok(())
}
