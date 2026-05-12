#![cfg(any(feature = "postgres-backend", feature = "sqlite-backend"))]
#![cfg(test)]

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use bigdecimal::BigDecimal;
use chrono::Utc;
use diesel::prelude::*;
use http_body_util::BodyExt; // For collect()
use scribe_backend::db::{with_conn, DbId, DbPool};
use scribe_backend::errors::AppError;
use scribe_backend::models::character_card::NewCharacter;
use scribe_backend::models::chats::NewChat;
use scribe_backend::schema::{characters, chat_sessions};
use scribe_backend::test_helpers;
use tower::ServiceExt;

// Helper to create a user and log them in
async fn create_user_and_login(
    test_app: &test_helpers::TestApp,
    username: &str,
) -> anyhow::Result<String> {
    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        "password".to_string(),
    )
    .await?;

    let login_payload = serde_json::json!({ "identifier": username, "password": "password" });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&login_payload)?))
        .unwrap();

    let login_response = test_app
        .router
        .clone()
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();

    if login_response.status() != StatusCode::OK {
        anyhow::bail!("Login failed for user {}", username);
    }

    let auth_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    Ok(auth_cookie)
}

async fn create_test_character(
    conn_pool: &DbPool,
    user_id: DbId,
    name: &str,
) -> anyhow::Result<DbId> {
    let char_id = DbId::new();
    let new_character_data = NewCharacter {
        id: Some(char_id),
        user_id,
        spec: "character_card_v2".to_string(),
        spec_version: "2.0.0".to_string(),
        name: name.to_string(),
        visibility: Some("private".to_string()),
        #[cfg(feature = "postgres-backend")]
        created_at: Utc::now().into(),
        #[cfg(feature = "postgres-backend")]
        updated_at: Utc::now().into(),
        #[cfg(feature = "sqlite-backend")]
        created_at: Utc::now().into(),
        #[cfg(feature = "sqlite-backend")]
        updated_at: Utc::now().into(),
        ..Default::default()
    };

    with_conn(conn_pool, move |conn| {
        diesel::insert_into(characters::table)
            .values(&new_character_data)
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create character: {}", e))?;

    Ok(char_id)
}

async fn create_test_chat_session(
    conn_pool: &DbPool,
    user_id: DbId,
    character_id: DbId,
) -> anyhow::Result<DbId> {
    let chat_id = DbId::new();
    let new_chat_data = NewChat {
        id: chat_id,
        user_id,
        character_id,
        created_at: Utc::now().into(),
        updated_at: Utc::now().into(),
        history_management_strategy: "token_limit".to_string(),
        history_management_limit: 10,
        model_name: Some("test-model".to_string()),
        visibility: Some("private".to_string()),
        prompt_template_id: "default".to_string(),
        #[cfg(feature = "postgres-backend")]
        tokens_counted_at: chrono::Utc::now().into(),
        #[cfg(feature = "sqlite-backend")]
        tokens_counted_at: chrono::Utc::now().into(),
        total_credits_used: scribe_backend::db::DbDecimal(BigDecimal::from(0)),
        ..Default::default()
    };

    with_conn(conn_pool, move |conn| {
        diesel::insert_into(chat_sessions::table)
            .values(&new_chat_data)
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .map_err(|e| anyhow::anyhow!("Failed to create chat session: {}", e))?;

    Ok(chat_id)
}

#[tokio::test]
async fn test_game_master_mode_integration() {
    // 1. Spawn app
    let test_app = test_helpers::spawn_app(false, false, false).await;

    // 2. Create user and login
    let auth_cookie = create_user_and_login(&test_app, "gm_test_user")
        .await
        .unwrap();

    // Get user id
    let user_id = with_conn(&test_app.db_pool, |conn| {
        use scribe_backend::schema::users::dsl::*;
        users
            .filter(username.eq("gm_test_user"))
            .first::<scribe_backend::models::users::UserDbQuery>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .unwrap()
    .id;

    // 3. Create character
    let character_id = create_test_character(&test_app.db_pool, user_id, "GM Test Char")
        .await
        .unwrap();

    // 4. Create chat
    let chat_id = create_test_chat_session(&test_app.db_pool, user_id, character_id)
        .await
        .unwrap();

    // 5. Enable GM mode
    let update_payload = serde_json::json!({
        "game_master_mode_enabled": true
    });

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chat/{}/settings", chat_id))
        .header(header::COOKIE, auth_cookie.clone())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&update_payload).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 6. Verify game master mode is enabled in database
    let gm_mode_enabled: bool = with_conn(&test_app.db_pool, move |conn| {
        chat_sessions::table
            .find(chat_id)
            .select(chat_sessions::game_master_mode_enabled)
            .first::<bool>(conn)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .unwrap();

    assert!(
        gm_mode_enabled,
        "Game Master mode should be enabled after settings update"
    );

    println!("✓ SQLite Game Master integration test passed!");
    println!("  - Character created successfully");
    println!("  - Chat session created successfully");
    println!("  - Game Master mode enabled and persisted to SQLite database");
}
