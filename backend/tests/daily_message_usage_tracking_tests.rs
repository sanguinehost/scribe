#![cfg(feature = "postgres-backend")]
#![cfg(test)]

#[cfg(feature = "payment")]
use anyhow::Context as _;
#[cfg(feature = "payment")]
use scribe_backend::models::chats::Chat;
#[cfg(feature = "payment")]
use scribe_backend::test_helpers;

#[cfg(feature = "payment")]
use scribe_backend::models::{
    characters::Character as DbCharacter, chats::CreateMessageRequest, users::User,
};

#[cfg(feature = "payment")]
use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use bigdecimal::BigDecimal;
#[cfg(feature = "payment")]
use scribe_backend::services::payment::SoftLimitService;
#[cfg(feature = "payment")]
use serde_json::json;
#[cfg(feature = "payment")]
use tower::ServiceExt;
#[cfg(feature = "payment")]
use tower_cookies::Cookie;

#[tokio::test]
#[cfg(feature = "payment")]
async fn test_manual_message_creation_increments_daily_usage() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(true, false, false).await;

    // Create a test user
    let username = "test_daily_usage_user";
    let password = "test_password";
    let user: User = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await
    .context("Failed to create test user")?;

    // Create a test character
    let character: DbCharacter = test_helpers::db::create_test_character(
        &test_app.db_pool,
        user.id,
        "Test Character".to_string(),
    )
    .await
    .context("Failed to create test character")?;

    // Create a chat session using our own helper
    let chat_session: Chat = create_test_chat_session(
        &test_app.db_pool,
        user.id,
        character.id,
        "Test Chat".to_string(),
    )
    .await
    .context("Failed to create test chat session")?;

    // Login the user to get session cookies
    let login_response = test_app
        .router
        .clone()
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "identifier": username,
                        "password": password
                    })
                    .to_string(),
                ))?,
        )
        .await?;

    assert_eq!(login_response.status(), StatusCode::OK);

    // Extract session cookie from the login response
    let set_cookie_header = login_response
        .headers()
        .get("set-cookie")
        .context("No set-cookie header in login response")?
        .to_str()?;

    let session_cookie = Cookie::parse(set_cookie_header)?;

    // Check initial daily usage (should be 0)
    let soft_limit_service = SoftLimitService::new(test_app.config.clone());
    let initial_usage = {
        let pool = test_app.db_pool.clone();
        let user_id = user.id;
        let service_clone = soft_limit_service.clone();
        pool.get()
            .await
            .context("Failed to get DB connection")?
            .interact(move |conn| service_clone.get_or_create_daily_usage(conn, user_id))
            .await
            .expect("DB interaction for get initial usage failed")
            .expect("Error getting initial usage")
    };

    println!("Initial daily usage: {}", initial_usage.message_count);
    assert_eq!(initial_usage.message_count, 0);

    // Send a message via the manual message creation endpoint
    let message_request = CreateMessageRequest {
        role: "user".to_string(),
        content: "Hello, this is a test message".to_string(),
        parts: None,
        attachments: None,
    };

    let message_response = test_app
        .router
        .clone()
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&format!("/api/chats/{}/messages", chat_session.id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::COOKIE,
                    format!("{}={}", session_cookie.name(), session_cookie.value()),
                )
                .body(Body::from(serde_json::to_string(&message_request)?))?,
        )
        .await?;

    println!(
        "Message creation response status: {}",
        message_response.status()
    );
    let response_body = axum::body::to_bytes(message_response.into_body(), usize::MAX).await?;
    let response_text = String::from_utf8_lossy(&response_body);
    println!("Message creation response body: {}", response_text);

    // Check that daily usage has been incremented
    let updated_usage = {
        let pool = test_app.db_pool.clone();
        let user_id = user.id;
        let service_clone = soft_limit_service.clone();
        pool.get()
            .await
            .context("Failed to get DB connection")?
            .interact(move |conn| service_clone.get_or_create_daily_usage(conn, user_id))
            .await
            .expect("DB interaction for get updated usage failed")
            .expect("Error getting updated usage")
    };

    println!("Updated daily usage: {}", updated_usage.message_count);
    assert_eq!(
        updated_usage.message_count, 1,
        "Daily message count should be incremented by 1 after sending a user message"
    );

    Ok(())
}

#[tokio::test]
#[cfg(feature = "payment")]
async fn test_only_user_messages_increment_daily_usage() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(true, false, false).await;

    // Create a test user
    let username = "test_assistant_msg_user";
    let password = "test_password";
    let user: User = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await
    .context("Failed to create test user")?;

    // Create a test character
    let character: DbCharacter = test_helpers::db::create_test_character(
        &test_app.db_pool,
        user.id,
        "Test Character".to_string(),
    )
    .await
    .context("Failed to create test character")?;

    // Create a chat session using our own helper
    let chat_session: Chat = create_test_chat_session(
        &test_app.db_pool,
        user.id,
        character.id,
        "Test Chat".to_string(),
    )
    .await
    .context("Failed to create test chat session")?;

    // Login the user
    let login_response = test_app
        .router
        .clone()
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "identifier": username,
                        "password": password
                    })
                    .to_string(),
                ))?,
        )
        .await?;

    let set_cookie_header = login_response
        .headers()
        .get("set-cookie")
        .context("No set-cookie header in login response")?
        .to_str()?;

    let session_cookie = Cookie::parse(set_cookie_header)?;

    // Send an assistant message (should NOT increment usage)
    let assistant_message_request = CreateMessageRequest {
        role: "assistant".to_string(),
        content: "Hello, this is an assistant response".to_string(),
        parts: None,
        attachments: None,
    };

    let _assistant_response = test_app
        .router
        .clone()
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&format!("/api/chats/{}/messages", chat_session.id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::COOKIE,
                    format!("{}={}", session_cookie.name(), session_cookie.value()),
                )
                .body(Body::from(serde_json::to_string(
                    &assistant_message_request,
                )?))?,
        )
        .await?;

    // Check that daily usage is still 0 (assistant messages don't count)
    let soft_limit_service = SoftLimitService::new(test_app.config.clone());
    let usage_after_assistant = {
        let pool = test_app.db_pool.clone();
        let user_id = user.id;
        let service_clone = soft_limit_service.clone();
        pool.get()
            .await
            .context("Failed to get DB connection")?
            .interact(move |conn| service_clone.get_or_create_daily_usage(conn, user_id))
            .await
            .expect("DB interaction for get usage after assistant failed")
            .expect("Error getting usage after assistant message")
    };

    assert_eq!(
        usage_after_assistant.message_count, 0,
        "Assistant messages should not increment daily usage"
    );

    // Now send a user message (should increment usage)
    let user_message_request = CreateMessageRequest {
        role: "user".to_string(),
        content: "Hello, this is a user message".to_string(),
        parts: None,
        attachments: None,
    };

    let _user_response = test_app
        .router
        .clone()
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(&format!("/api/chats/{}/messages", chat_session.id))
                .header(header::CONTENT_TYPE, "application/json")
                .header(
                    header::COOKIE,
                    format!("{}={}", session_cookie.name(), session_cookie.value()),
                )
                .body(Body::from(serde_json::to_string(&user_message_request)?))?,
        )
        .await?;

    // Check that daily usage is now 1
    let final_usage = {
        let pool = test_app.db_pool.clone();
        let user_id = user.id;
        let service_clone = soft_limit_service.clone();
        pool.get()
            .await
            .context("Failed to get DB connection")?
            .interact(move |conn| service_clone.get_or_create_daily_usage(conn, user_id))
            .await
            .expect("DB interaction for get final usage failed")
            .expect("Error getting final usage")
    };

    assert_eq!(
        final_usage.message_count, 1,
        "Only user messages should increment daily usage"
    );

    Ok(())
}

#[cfg(feature = "payment")]
async fn create_test_chat_session(
    pool: &deadpool_diesel::postgres::Pool,
    user_id: uuid::Uuid,
    character_id: uuid::Uuid,
    title: String,
) -> anyhow::Result<Chat> {
    use chrono::Utc;
    use diesel::prelude::*;
    use scribe_backend::models::chats::NewChat;
    use scribe_backend::schema::chat_sessions::dsl as chat_sessions_dsl;

    let result = pool
        .get()
        .await
        .context("Failed to get DB connection")?
        .interact(move |conn| {
            let new_chat_session = NewChat {
                id: uuid::Uuid::new_v4(),
                user_id,
                character_id,
                title_ciphertext: Some(title.into_bytes()),
                title_nonce: None,
                created_at: Utc::now().into(),
                updated_at: Utc::now().into(),
                history_management_strategy: "truncate".to_string(),
                history_management_limit: 10,
                model_name: "test_model".to_string(),
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
                player_chronicle_id: None,
                total_prompt_tokens: 0,
                total_completion_tokens: 0,
                estimated_cost_cents: 0,
                tokens_counted_at: chrono::Utc::now(),
                total_credits_used: scribe_backend::db::DbDecimal(BigDecimal::from(0)),
                prompt_template_id: "default".to_string(),
                narrative_style_override_ciphertext: None,
                narrative_style_override_nonce: None,
                ..Default::default()
            };
            diesel::insert_into(chat_sessions_dsl::chat_sessions)
                .values(&new_chat_session)
                .returning(Chat::as_returning())
                .get_result::<Chat>(conn)
        })
        .await
        .expect("DB interaction for create session failed")
        .expect("Error saving new session");

    Ok(result)
}
