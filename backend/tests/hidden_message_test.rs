#![cfg(test)]

//! Integration tests for hidden messages (non-completed status)
//!
//! Verifies that messages with status != "completed" are still returned by the API.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

// Diesel imports
use diesel::prelude::*;
use diesel::RunQueryDsl;

// Crate imports
#[cfg(feature = "sqlite-backend")]
use scribe_backend::db::SqliteInteractExt;
use scribe_backend::{
    auth::session_dek::SessionDek,
    crypto,
    db::DbBigInt,
    models::{
        character_card::NewCharacter,
        characters::Character as DbCharacter,
        chats::{Chat, Message as DbChatMessage, MessageRole},
        users::{AccountStatus, NewUser, UserDbQuery, UserRole},
    },
    schema::{characters, chat_messages, chat_sessions, users},
    test_helpers,
};
use secrecy::{ExposeSecret, SecretBox, SecretString};

// --- Helpers (adapted from variant_raw_prompt_test.rs) ---

async fn create_test_user_with_dek(
    test_app: &test_helpers::TestApp,
    username: String,
    password: String,
) -> anyhow::Result<(Uuid, SessionDek)> {
    let mut conn = test_app
        .db_pool
        .get()
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?;

    let password_hash = bcrypt::hash(&password, bcrypt::DEFAULT_COST)
        .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;

    let email = format!("{}@example.com", username);
    let kek_salt = crypto::generate_salt()?;
    let dek = crypto::generate_dek()?;
    let secret_password = SecretString::new(password.into());
    let kek = crypto::derive_kek(&secret_password, &kek_salt)?;
    let (encrypted_dek, dek_nonce) = crypto::encrypt_gcm(dek.expose_secret(), &kek)?;
    let kek_salt_str = kek_salt.clone();

    let new_user = NewUser {
        id: scribe_backend::db::DbId::new(),
        username,
        password_hash,
        email,
        kek_salt: kek_salt_str,
        encrypted_dek: encrypted_dek.into(),
        encrypted_dek_by_recovery: None,
        role: UserRole::User,
        recovery_kek_salt: None,
        dek_nonce: dek_nonce.into(),
        recovery_dek_nonce: None,
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
                .execute(conn)?;

            users::table
                .filter(users::id.eq(new_user.id))
                .select(UserDbQuery::as_select())
                .first(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))??;

    let session_dek = SessionDek(SecretBox::new(Box::new(dek.expose_secret().to_vec())));
    Ok((*user_db.id, session_dek))
}

async fn create_test_chat_session(
    test_app: &test_helpers::TestApp,
    user_id: Uuid,
    auth_cookie: &str,
) -> anyhow::Result<(DbCharacter, Chat, String)> {
    let new_character = NewCharacter {
        id: Some(Uuid::new_v4().into()),
        user_id: user_id.into(),
        spec: "test_char".to_string(),
        spec_version: "1.0".to_string(),
        name: "Test Char".to_string(),
        visibility: Some("private".to_string()),
        created_at: chrono::Utc::now().into(),
        updated_at: chrono::Utc::now().into(),
        ..Default::default()
    };

    let character: DbCharacter = test_app
        .db_pool
        .get()
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?
        .interact(move |conn| {
            let char_id = new_character.id.expect("Character ID must be set");
            diesel::insert_into(characters::table)
                .values(&new_character)
                .execute(conn)?;
            characters::table
                .find(char_id)
                .select(DbCharacter::as_select())
                .first(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Interact error: {:?}", e))??;

    let create_session_payload = json!({
        "character_id": character.id,
        "title": "Test Session",
        "model_name": "gemini-1.5-pro"
    });

    let create_session_request = Request::builder()
        .method(Method::POST)
        .uri("/api/chat/create_session")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_string(&create_session_payload)?))?;

    let create_session_response = test_app
        .router
        .clone()
        .oneshot(create_session_request)
        .await?;
    assert_eq!(create_session_response.status(), StatusCode::CREATED);

    let response_body = create_session_response
        .into_body()
        .collect()
        .await?
        .to_bytes();
    let session_response: Value = serde_json::from_slice(&response_body)?;
    let session_id = session_response["id"].as_str().unwrap().parse::<Uuid>()?;

    let chat_session: Chat = test_app
        .db_pool
        .get()
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(scribe_backend::db::DbId::from(session_id)))
                .select(Chat::as_select())
                .first::<Chat>(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Interact error: {:?}", e))??;
    let chat_id = chat_session.id;
    println!("Created chat_id: {}", chat_id);
    Ok((character, chat_session, auth_cookie.to_string()))
}

async fn create_test_message(
    test_app: &test_helpers::TestApp,
    user_id: Uuid,
    session_id: Uuid,
    content: &str,
    role: MessageRole,
) -> anyhow::Result<DbChatMessage> {
    use scribe_backend::models::chats::DbInsertableChatMessage;

    let new_message = DbInsertableChatMessage {
        id: scribe_backend::db::DbId::new(),
        chat_id: session_id.into(),
        user_id: user_id.into(),
        msg_type: role.clone(),
        content: content.as_bytes().to_vec(),
        content_nonce: None,
        role: Some(role.to_string()),
        parts: None,
        attachments: None,
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: "gemini-1.5-pro".to_string(),
        status: "completed".to_string(),
        error_message: None,
        variant_count: 1,
        current_variant_index: 0,
        credits_charged: 0,
        credits_cost: 0.0,
        actual_cost: 0.0,
        modified_cost: 0.0,
        credit_cost: 0,
        actual_charge: 0.0,
        game_time: None,
    };

    let message: DbChatMessage = test_app
        .db_pool
        .get()
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?
        .interact(move |conn| {
            diesel::insert_into(chat_messages::table)
                .values(&new_message)
                .execute(conn)?;

            chat_messages::table
                .order(chat_messages::created_at.desc())
                .first(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Interact error: {:?}", e))??;

    Ok(message)
}

// --- Test Case ---

#[tokio::test]
async fn test_hidden_streaming_message() -> anyhow::Result<()> {
    std::env::set_var(
        "COOKIE_SIGNING_KEY",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    );
    std::env::set_var("JWT_SECRET", "01234567890123456789012345678901");
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut test_data_guard =
        test_helpers::TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

    let username = "hidden_msg_user";
    let password = "password";
    let (user_id, _session_dek) =
        create_test_user_with_dek(&test_app, username.to_string(), password.to_string()).await?;
    test_data_guard.add_user(user_id.into());

    let (_client, auth_cookie) =
        test_helpers::login_user_via_api(&test_app, username, password).await;

    let (_character, chat_session, auth_cookie) =
        create_test_chat_session(&test_app, user_id, &auth_cookie).await?;

    // 1. Create a message
    let message = create_test_message(
        &test_app,
        user_id,
        *chat_session.id,
        "Streaming Response",
        MessageRole::Assistant,
    )
    .await?;

    // 2. Set status to "streaming" (or anything other than "completed")
    test_app
        .db_pool
        .get()
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?
        .interact(move |conn| {
            diesel::update(chat_messages::table.filter(chat_messages::id.eq(message.id)))
                .set(chat_messages::status.eq("streaming"))
                .execute(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Interact error: {:?}", e))??;

    // 3. Fetch messages using the API
    let get_messages_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/messages?limit=20", chat_session.id))
        .header(header::COOKIE, &auth_cookie)
        .body(Body::empty())?;

    let get_messages_response = test_app
        .router
        .clone()
        .oneshot(get_messages_request)
        .await?;
    assert_eq!(get_messages_response.status(), StatusCode::OK);

    let response_body = get_messages_response
        .into_body()
        .collect()
        .await?
        .to_bytes();
    let paginated_response: Value = serde_json::from_slice(&response_body)?;
    let messages = paginated_response["messages"].as_array().unwrap();

    // 4. Assert that the message is returned
    // CURRENTLY: This assertion should FAIL if the bug exists
    assert_eq!(
        messages.len(),
        1,
        "Should return 1 message even if status is streaming"
    );
    assert_eq!(messages[0]["id"].as_str().unwrap(), message.id.to_string());

    test_data_guard.cleanup().await?;
    Ok(())
}
