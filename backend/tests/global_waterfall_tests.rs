#![cfg(feature = "sqlite-backend")]
#![cfg(test)]

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use bigdecimal::BigDecimal;
use chrono::Utc;
use scribe_backend::llm::RigChatResponse;
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
            created_at: DbTimestamp::now(),
            updated_at: DbTimestamp::now(),
            history_management_strategy: "message_window".to_string(),
            history_management_limit: 100,
            model_name: Some("test-model".to_string()),
            visibility: Some("private".to_string()),
            tokens_counted_at: DbTimestamp::now(),
            total_credits_used: scribe_backend::db::DbDecimal(BigDecimal::from(0)),
            prompt_template_id: "default".to_string(),
            ..Default::default()
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
                created_at: now.into(),
                updated_at: now.into(),
                prompt_tokens: Some(100),
                model_name: "test-model".to_string(),
                status: "completed".to_string(),
                ..Default::default()
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
        .set_response(Ok(RigChatResponse {
            content: "Waterfall response".to_string(),
            prompt_tokens: Some(15),
            completion_tokens: Some(10),
            total_tokens: Some(25),
            reasoning_content: None,
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
        parent_message_id: None,
        game_master_mode_enabled: None,
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

    // history include the system prompt (if any) and the history
    println!(
        "Number of messages in AI request: {}",
        last_request.history.len()
    );

    // We expect more than 20 messages (which would be the ~2000 token limit)
    // Plus the current user message and potentially a system prompt.
    assert!(
        last_request.history.len() > 30,
        "Global Waterfall should have added more messages than the initial budget allowed. Got {}",
        last_request.history.len()
    );

    Ok(())
}
