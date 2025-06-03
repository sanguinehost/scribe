#![cfg(test)]

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use chrono::Utc;
use diesel::RunQueryDsl as _;
use diesel::prelude::*;
use std::time::Duration;
use tower::ServiceExt;
use uuid::Uuid;

use scribe_backend::{
    models::{
        characters::Character as DbCharacter,
        chats::{
            ApiChatMessage, Chat as ChatSession, GenerateChatRequest, MessageRole, NewChat,
            NewChatMessage,
        },
    },
    schema::{
        characters::dsl as characters_dsl, chat_messages::dsl as chat_messages_dsl,
        chat_sessions::dsl as chat_sessions_dsl,
    },
    test_helpers::{self},
};

// Helper struct for common test setup
struct TestContext {
    test_app: test_helpers::TestApp,
    auth_cookie: String,
    #[allow(dead_code)]
    user: scribe_backend::models::users::User,
    #[allow(dead_code)]
    character: DbCharacter,
    session: ChatSession,
    document_content: String,
}


#[allow(clippy::too_many_lines)]
async fn setup_rag_test_context() -> TestContext {
    let test_app = test_helpers::spawn_app(false, true, true).await;

    let username = "rag_real_user";
    let password = "password";
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await
    .expect("Failed to create test user");

    let auth_cookie = test_helpers::login_user_via_router(&test_app.router, username, password).await;

    let conn_pool = test_app.db_pool.clone();
    let user_id_clone = user.id;
    let char_name_rag = "RAG Real AI Char".to_string();
    let character: DbCharacter = conn_pool
        .get()
        .await
        .expect("Failed to get DB conn for char create")
        .interact(move |conn_sync| {
            let new_char_card = scribe_backend::models::character_card::NewCharacter {
                user_id: user_id_clone,
                name: char_name_rag,
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
    let user_id_clone_session = user.id;
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
            };
            diesel::insert_into(chat_sessions_dsl::chat_sessions)
                .values(&new_chat_session)
                .returning(ChatSession::as_returning())
                .get_result::<ChatSession>(conn_sync)
        })
        .await
        .expect("DB interaction for create session failed")
        .expect("Error saving new chat session");

    let document_content = "Ouroboros is the secret handshake.".to_string();

    let conn_pool = test_app.db_pool.clone();
    let session_id_clone_msg = session.id;
    let user_id_clone_msg = user.id;
    let document_content_clone = document_content.clone();
    conn_pool
        .get()
        .await
        .expect("Failed to get DB conn for msg save")
        .interact(move |conn_sync| {
            let new_message = NewChatMessage {
                id: Uuid::new_v4(),
                session_id: session_id_clone_msg,
                user_id: user_id_clone_msg,
                message_type: MessageRole::Assistant,
                content: document_content_clone.as_bytes().to_vec(),
                content_nonce: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                role: Some("assistant".to_string()),
                prompt_tokens: None,
                completion_tokens: None,
                parts: None,
                attachments: None,
            };
            diesel::insert_into(chat_messages_dsl::chat_messages)
                .values(&new_message)
                .execute(conn_sync)
        })
        .await
        .expect("DB interaction for save message failed")
        .expect("Error saving document message");

    tokio::time::sleep(Duration::from_secs(1)).await;

    TestContext {
        test_app,
        auth_cookie,
        user,
        character,
        session,
        document_content,
    }
}

async fn assert_rag_response(
    test_context: &TestContext,
    query_text: &str,
    expected_content_substring: &str,
) {
    let history = vec![
        ApiChatMessage {
            role: "assistant".to_string(),
            content: test_context.document_content.clone(),
        },
        ApiChatMessage {
            role: "user".to_string(),
            content: query_text.to_string(),
        },
    ];
    let payload = GenerateChatRequest {
        history,
        model: None,
        query_text_for_rag: None,
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chat/{}/generate", test_context.session.id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, &test_context.auth_cookie)
        .header(header::ACCEPT, "text/event-stream")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_context.test_app.router.clone().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let sse_data = test_helpers::collect_full_sse_events(response.into_body()).await;
    let combined_response = sse_data
        .iter()
        .filter_map(|e| {
            if e.event.is_none() && e.data != "[DONE]" {
                serde_json::from_str::<serde_json::Value>(&e.data)
                    .ok()
                    .and_then(|v| v.get("text").and_then(|t| t.as_str().map(String::from)))
            } else {
                None
            }
        })
        .collect::<String>(); // Changed from Vec<String>().join("")

    println!(
        "\n--- REAL AI Response Received ---\n{combined_response}\n---------------------------------\n"
    );
    assert!(
        combined_response.to_lowercase().contains(expected_content_substring),
        "Real AI response should mention '{expected_content_substring}', but got: {combined_response}"
    );
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB and real AI are guaranteed
async fn test_rag_context_injection_real_ai() {
    if std::env::var("RUN_INTEGRATION_TESTS").is_err() {
        println!("Skipping RAG integration test: RUN_INTEGRATION_TESTS not set");
        return;
    }

    let test_context = setup_rag_test_context().await;

    let query_text = "What is Ouroboros in Greek mythology?";
    assert_rag_response(&test_context, query_text, "serpent").await;
    assert_rag_response(&test_context, query_text, "dragon").await;
    assert_rag_response(&test_context, query_text, "tail").await;
}
