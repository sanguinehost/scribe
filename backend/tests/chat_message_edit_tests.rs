#![cfg(feature = "postgres-backend")]
#![cfg(test)]

use anyhow::Context as _;
use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use bigdecimal::BigDecimal;
use tower::ServiceExt;
use uuid::Uuid;

use diesel::prelude::*;
use scribe_backend::{
    db::DbId,
    models::{
        character_card::NewCharacter,
        characters::Character as DbCharacter,
        chats::{Chat, MessageRole, NewChat, NewChatMessage},
        users::User,
    },
    schema::{characters, chat_messages, chat_sessions},
    test_helpers::{self},
};
use serde_json::json;
use tower_cookies::Cookie;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_update_chat_message_content_success_and_bola() -> anyhow::Result<()> {
    unsafe {
        std::env::set_var("RUST_LOG", "debug");
    }
    let test_app = test_helpers::spawn_app(true, false, false).await;

    // Create User A (Owner)
    let username_a = "test_update_message_owner";
    let password_a = "password_user_a";
    let user_a: User = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username_a.to_string(),
        password_a.to_string(),
    )
    .await?;

    let (_, auth_cookie_a) =
        test_helpers::login_user_via_api(&test_app, username_a, password_a).await;

    // Create User B (Attacker)
    let username_b = "test_update_message_attacker";
    let password_b = "password_user_b";
    let user_b: User = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username_b.to_string(),
        password_b.to_string(),
    )
    .await?;

    let (_, auth_cookie_b) =
        test_helpers::login_user_via_api(&test_app, username_b, password_b).await;

    // Let's create a session directly in DB to bypass needing external calls (like we did in the other test)
    let new_char_a = NewCharacter {
        user_id: user_a.id,
        spec: "test".to_string(),
        spec_version: "1.0".to_string(),
        name: "CharA".to_string(),
        visibility: Some("private".to_string()),
        created_at: chrono::Utc::now().into(),
        updated_at: chrono::Utc::now().into(),
        ..Default::default()
    };
    let char_a: DbCharacter = test_app
        .db_pool
        .get()
        .await?
        .interact(move |conn| {
            diesel::insert_into(characters::table)
                .values(&new_char_a)
                .returning(DbCharacter::as_returning())
                .get_result(conn)
        })
        .await
        .unwrap()?;

    let new_session_a = NewChat {
        id: Uuid::new_v4().into(),
        user_id: user_a.id,
        character_id: char_a.id,
        created_at: chrono::Utc::now().into(),
        updated_at: chrono::Utc::now().into(),
        history_management_strategy: "truncate_summary".to_string(),
        prompt_template_id: "default".to_string(),
        ..Default::default()
    };
    let session_a: Chat = test_app
        .db_pool
        .get()
        .await?
        .interact(move |conn| {
            diesel::insert_into(chat_sessions::table)
                .values(&new_session_a)
                .returning(Chat::as_returning())
                .get_result(conn)
        })
        .await
        .unwrap()?;

    let original_content = "Original Content";
    let message_id = Uuid::new_v4();
    let new_message = NewChatMessage {
        id: message_id.into(),
        session_id: session_a.id,
        user_id: user_a.id,
        message_type: MessageRole::User,
        content: original_content.as_bytes().to_vec().into(),
        content_nonce: None, // PLAIN text for test simplicity so we bypass proper DEK encryption in test setup
        role: Some("user".to_string()),
        created_at: chrono::Utc::now().into(),
        updated_at: chrono::Utc::now().into(),
        model_name: "test".to_string(),
        status: "completed".to_string(),
        ..Default::default()
    };
    test_app
        .db_pool
        .get()
        .await?
        .interact(move |conn| {
            diesel::insert_into(chat_messages::table)
                .values(&new_message)
                .execute(conn)
        })
        .await
        .unwrap()?;

    // === TEST 1: Unauthenticated -> 401 Unauthorized ===
    let update_payload = json!({ "content": "Hacked content!" });
    let req_unauth = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/messages/{message_id}/content"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(update_payload.to_string()))?;
    let res_unauth = test_app.router.clone().oneshot(req_unauth).await?;
    assert_eq!(
        res_unauth.status(),
        StatusCode::UNAUTHORIZED,
        "OWASP: Broken Auth - endpoint should require authentication"
    );

    // === TEST 2: User B tries to edit User A's message -> 403 or 404 (BOLA) ===
    let req_bola = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/messages/{message_id}/content"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, &auth_cookie_b)
        .body(Body::from(update_payload.to_string()))?;
    let res_bola = test_app.router.clone().oneshot(req_bola).await?;
    assert!(
        res_bola.status() == StatusCode::FORBIDDEN || res_bola.status() == StatusCode::NOT_FOUND,
        "OWASP: BOLA - User B should not be able to edit User A's message"
    );

    // === TEST 3: Validation (Empty string) -> 400 Bad Request ===
    let empty_payload = json!({ "content": "   " });
    let req_validation = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/messages/{message_id}/content"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, &auth_cookie_a)
        .body(Body::from(empty_payload.to_string()))?;
    let res_validation = test_app.router.clone().oneshot(req_validation).await?;
    assert_eq!(
        res_validation.status(),
        StatusCode::BAD_REQUEST,
        "OWASP: Input Validation - prevent empty messages"
    );

    // === TEST 4: Happy path update ===
    let happy_payload = json!({ "content": "Updated by Owner" });
    let req_happy = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/messages/{message_id}/content"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, &auth_cookie_a)
        .body(Body::from(happy_payload.to_string()))?;
    let res_happy = test_app.router.clone().oneshot(req_happy).await?;
    assert_eq!(
        res_happy.status(),
        StatusCode::OK,
        "Owner should be able to update their message"
    );

    Ok(())
}
