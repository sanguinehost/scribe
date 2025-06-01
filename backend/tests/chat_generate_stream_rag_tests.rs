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
    test_helpers::{self, collect_full_sse_events},
};

#[tokio::test]
#[ignore] // Ignore for CI unless DB and real AI are guaranteed
async fn test_rag_context_injection_real_ai() {
    let test_app = test_helpers::spawn_app(false, true, true).await; // Use the helper, ensure all args present

    if std::env::var("RUN_INTEGRATION_TESTS").is_err() {
        println!("Skipping RAG integration test: RUN_INTEGRATION_TESTS not set");
        return;
    }

    let username = "rag_real_user";
    let password = "password";
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await
    .expect("Failed to create test user");

    let login_payload = serde_json::json!({
        "identifier": username,
        "password": password,
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
        .unwrap();

    let login_response = test_app
        .router
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();
    assert_eq!(
        login_response.status(),
        StatusCode::OK,
        "Login request failed"
    );

    let auth_cookie_header = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present on login")
        .to_str()
        .unwrap();
    let parsed_cookie =
        cookie::Cookie::parse(auth_cookie_header).expect("Failed to parse Set-Cookie header");
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());

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
                description: Some("Test description".to_string().into_bytes()),
                greeting: Some("Hello".to_string().into_bytes()),
                visibility: Some("private".to_string()),
                creator: Some("test_creator".to_string()),
                persona: Some("Test persona".to_string().into_bytes()),
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
                .returning(ChatSession::as_returning()) // Ensure returning or select is used
                .get_result::<ChatSession>(conn_sync)
        })
        .await
        .expect("DB interaction for create session failed")
        .expect("Error saving new chat session");

    // Message containing info the AI shouldn't know without RAG
    let document_content = "Ouroboros is the secret handshake.";

    // Create the message using interact pattern
    let conn_pool = test_app.db_pool.clone();
    let session_id_clone_msg = session.id;
    let user_id_clone_msg = user.id;
    conn_pool
        .get()
        .await
        .expect("Failed to get DB conn for msg save")
        .interact(move |conn_sync| {
            let new_message = NewChatMessage {
                id: Uuid::new_v4(),
                session_id: session_id_clone_msg,
                user_id: user_id_clone_msg,
                message_type: MessageRole::Assistant, // Or User, depending on how RAG docs are stored
                content: document_content.as_bytes().to_vec(),
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

    // Allow time for potential Qdrant indexing
    tokio::time::sleep(Duration::from_secs(1)).await;

    let query_text = "What is Ouroboros in Greek mythology?";
    let history = vec![
        ApiChatMessage {
            role: "assistant".to_string(),
            content: document_content.to_string(),
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
        .uri(format!("/api/chat/{}/generate", session.id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, &auth_cookie)
        .header(header::ACCEPT, "text/event-stream")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let sse_data = collect_full_sse_events(response.into_body()).await;
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
        .collect::<Vec<String>>()
        .join("");

    println!(
        "\n--- REAL AI Response Received ---\n{combined_response}\n---------------------------------\n"
    );
    assert!(
        combined_response.to_lowercase().contains("serpent")
            || combined_response.to_lowercase().contains("dragon")
            || combined_response.to_lowercase().contains("tail"),
        "Real AI response should mention serpent/dragon/tail for Ouroboros, but got: {combined_response}"
    );
}
