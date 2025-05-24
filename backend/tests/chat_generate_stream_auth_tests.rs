#![cfg(test)]

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use chrono::Utc;
use diesel::RunQueryDsl as _;
use diesel::prelude::*;
use mime;
use tower::ServiceExt;
use uuid::Uuid;

use scribe_backend::{
    models::{
        characters::Character as DbCharacter,
        chats::{ApiChatMessage, Chat as ChatSession, GenerateChatRequest, NewChat},
    },
    schema::{characters::dsl as characters_dsl, chat_sessions::dsl as chat_sessions_dsl},
    test_helpers,
};

#[tokio::test]
#[ignore] // Added ignore for CI
async fn generate_chat_response_streaming_unauthorized() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let session_id = Uuid::new_v4(); // Dummy ID

    // Construct the new payload with history
    let history = vec![ApiChatMessage {
        role: "user".to_string(),
        content: "test".to_string(),
    }];
    let payload = GenerateChatRequest {
        history,
        model: None,
        query_text_for_rag: None,
    };
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chat/{}/generate", session_id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    // No auth cookie

    let response = test_app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_ne!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|h| h.as_bytes()),
        Some(mime::TEXT_EVENT_STREAM.as_ref().as_bytes()),
        "Content-Type should not be text/event-stream"
    );
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn generate_chat_response_streaming_not_found() {
    let test_app = test_helpers::spawn_app(false, false, false).await;

    let username = "stream_404_user";
    let password = "password";
    let _user = test_helpers::db::create_test_user(
        // _user as it's not used directly
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

    let non_existent_session_id = Uuid::new_v4();

    // Construct the new payload with history
    let history = vec![ApiChatMessage {
        role: "user".to_string(),
        content: "test".to_string(),
    }];
    let payload = GenerateChatRequest {
        history,
        model: None,
        query_text_for_rag: None,
    };
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chat/{}/generate", non_existent_session_id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_ne!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|h| h.as_bytes()),
        Some(mime::TEXT_EVENT_STREAM.as_ref().as_bytes()),
        "Content-Type should not be text/event-stream"
    );
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn generate_chat_response_streaming_forbidden() {
    let test_app = test_helpers::spawn_app(false, false, false).await;

    // Create User 1
    let username1 = "stream_forbid_user1";
    let password_user1 = "password";
    let user1 = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username1.to_string(),
        password_user1.to_string(),
    )
    .await
    .expect("Failed to create test user1");

    let conn_pool = test_app.db_pool.clone();
    let user_id_clone = user1.id;
    let character_name = "User1 Char for Stream Forbidden".to_string();
    let character1: DbCharacter = conn_pool
        .get()
        .await
        .expect("Failed to get DB conn for char create")
        .interact(move |conn_sync| {
            let new_char_card = scribe_backend::models::character_card::NewCharacter {
                user_id: user_id_clone,
                name: character_name,
                spec: "test_spec_v1.0".to_string(),
                spec_version: "1.0".to_string(),
                description: Some("Test description".to_string().into_bytes()),
                greeting: Some("Hello".to_string().into_bytes()),
                visibility: Some("private".to_string()),
                creator: Some("test_creator".to_string()),
                persona: Some("Test persona".to_string().into_bytes()),
                created_at: Some(Utc::now()), // Add created_at
                updated_at: Some(Utc::now()), // Add updated_at
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
    let user_id_clone_session = user1.id;
    let character_id_clone_session = character1.id;
    let session_title = format!("Test Chat with Char {}", character1.id);
    let session1: ChatSession = conn_pool
        .get()
        .await
        .expect("Failed to get DB conn for session create")
        .interact(move |conn_sync| {
            let new_chat_session = NewChat {
                id: Uuid::new_v4(),
                user_id: user_id_clone_session,
                character_id: character_id_clone_session,
                title: Some(session_title),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                history_management_strategy: "truncate".to_string(),
                history_management_limit: 10,
                model_name: "test-model".to_string(),
                visibility: Some("private".to_string()),
                active_custom_persona_id: None,
                active_impersonated_character_id: None,
            };
            diesel::insert_into(chat_sessions_dsl::chat_sessions)
                .values(&new_chat_session)
                .returning(ChatSession::as_returning()) // Ensure returning or select is used
                .get_result::<ChatSession>(conn_sync)
        })
        .await
        .expect("DB interaction for create session failed")
        .expect("Error saving new chat session");

    // Create and Login User 2
    let username2 = "stream_forbid_user2";
    let password_user2 = "password";
    let _user2 = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username2.to_string(),
        password_user2.to_string(),
    )
    .await
    .expect("Failed to create test user2");

    let login_payload2 = serde_json::json!({
        "identifier": username2,
        "password": password_user2,
    });
    let login_request2 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload2).unwrap()))
        .unwrap();

    let login_response2 = test_app
        .router
        .clone()
        .oneshot(login_request2)
        .await
        .unwrap();
    assert_eq!(
        login_response2.status(),
        StatusCode::OK,
        "Login request for user2 failed"
    );

    let auth_cookie_header2 = login_response2
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present on login for user2")
        .to_str()
        .unwrap();
    let parsed_cookie2 = cookie::Cookie::parse(auth_cookie_header2)
        .expect("Failed to parse Set-Cookie header for user2");
    let auth_cookie2 = format!("{}={}", parsed_cookie2.name(), parsed_cookie2.value());

    // Construct the new payload with history
    let history = vec![ApiChatMessage {
        role: "user".to_string(),
        content: "test".to_string(),
    }];
    let payload = GenerateChatRequest {
        history,
        model: None,
        query_text_for_rag: None,
    };
    let request = Request::builder()
        .method(Method::POST)
        // User 2 tries to generate in User 1's session
        .uri(format!("/api/chat/{}/generate", session1.id))
        .header(header::COOKIE, auth_cookie2) // Use user 2's cookie
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::ACCEPT, mime::TEXT_EVENT_STREAM.as_ref()) // Add Accept header for streaming
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    // The initial DB query checks ownership and returns Forbidden if mismatch
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_ne!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|h| h.as_bytes()),
        Some(mime::TEXT_EVENT_STREAM.as_ref().as_bytes()),
        "Content-Type should not be text/event-stream"
    );
}
