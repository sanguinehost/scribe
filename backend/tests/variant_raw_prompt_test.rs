#![cfg(any(feature = "postgres-backend", feature = "sqlite-backend"))]
#![cfg(test)]

//! Integration tests for variant raw prompt retrieval
//!
//! Verifies that fetching a message by ID returns the correct raw_prompt
//! for the selected variant, especially when guidance is involved.

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use chrono::Utc;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

// Diesel imports
use diesel::prelude::*;
use diesel::RunQueryDsl;

// Crate imports
use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHasher};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
// use scribe_backend::db::SqliteInteractExt;
#[cfg(feature = "sqlite-backend")]
use scribe_backend::db::{SqliteInteractExt, SqlitePoolExt};
use scribe_backend::{
    auth::session_dek::SessionDek,
    crypto,
    db::{self},
    models::{
        character_card::NewCharacter,
        characters::Character as DbCharacter,
        chats::{Chat, Message as DbChatMessage, MessageRole, NewChatMessage, NewMessageVariant},
        users::{AccountStatus, NewUser, UserDbQuery, UserRole},
    },
    schema::{characters, chat_messages, chat_sessions, message_variants, users},
    test_helpers,
};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use test_context::futures::TryFutureExt;

// --- Helpers (copied and adapted) ---

async fn create_test_user_with_dek(
    test_app: &test_helpers::TestApp,
    username: String,
    password: String,
) -> anyhow::Result<(Uuid, SessionDek)> {
    #[cfg(feature = "postgres-backend")]
    let mut conn = test_app
        .db_pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?;

    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    let mut conn = test_app
        .db_pool
        .get()
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?;

    let password_hash =
        scribe_backend::auth::hash_password(SecretString::new(password.clone().into()))
            .await
            .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;

    let email = format!("{}@example.com", username);
    let kek_salt = crypto::generate_salt()?;
    let dek = crypto::generate_dek()?;
    let secret_password = SecretString::new(password.into());
    let kek = crypto::derive_kek(&secret_password, &kek_salt)?;
    let (encrypted_dek, dek_nonce) = crypto::encrypt_gcm(dek.expose_secret(), &kek)?;
    // kek_salt is already a Base64 string from generate_salt()

    let new_user = NewUser {
        id: scribe_backend::db::DbId::new(),
        username,
        password_hash,
        email: email,
        kek_salt,
        encrypted_dek: encrypted_dek.into(),
        encrypted_dek_by_recovery: None,
        role: UserRole::User,
        recovery_kek_salt: None,
        dek_nonce: dek_nonce.into(),
        recovery_dek_nonce: None,
        account_status: AccountStatus::Active,
        total_prompt_tokens: scribe_backend::db::DbBigInt::from(0),
        total_completion_tokens: scribe_backend::db::DbBigInt::from(0),
        total_token_cost_cents: scribe_backend::db::DbBigInt::from(0),
        tokens_last_reset_at: None,
        token_usage_updated_at: chrono::Utc::now().into(),
    };

    #[cfg(feature = "postgres-backend")]
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
        .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))?
        .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))?;

    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
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
        .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))?
        .map_err(|e| anyhow::anyhow!("DB interaction failed: {}", e))?;

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
        #[cfg(feature = "postgres-backend")]
        created_at: Some(Utc::now().into()),
        #[cfg(feature = "postgres-backend")]
        updated_at: Some(Utc::now().into()),
        #[cfg(feature = "sqlite-backend")]
        created_at: Utc::now().into(),
        #[cfg(feature = "sqlite-backend")]
        updated_at: Utc::now().into(),
        ..Default::default()
    };

    #[cfg(feature = "postgres-backend")]
    #[cfg(feature = "postgres-backend")]
    let character: DbCharacter = test_app
        .db_pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?
        .interact(move |conn| {
            diesel::insert_into(characters::table)
                .values(&new_character)
                .execute(conn)?;

            characters::table
                .filter(characters::id.eq(new_character.id.unwrap()))
                .select(DbCharacter::as_select())
                .first(conn)
        })
        .await
        .map_err(|_| anyhow::anyhow!("Interact error"))?
        .map_err(|_| anyhow::anyhow!("Interact error"))?;

    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    let character: DbCharacter = test_app
        .db_pool
        .get()
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?
        .interact(move |conn| {
            diesel::insert_into(characters::table)
                .values(&new_character)
                .execute(conn)?;

            characters::table
                .filter(characters::id.eq(new_character.id.unwrap()))
                .select(DbCharacter::as_select())
                .first(conn)
        })
        .await
        .map_err(|_| anyhow::anyhow!("Interact error"))?
        .map_err(|_| anyhow::anyhow!("Interact error"))?;

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

    #[cfg(feature = "postgres-backend")]
    #[cfg(feature = "postgres-backend")]
    let chat_session: Chat = test_app
        .db_pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(scribe_backend::db::DbId::from(session_id)))
                .select(Chat::as_select())
                .first::<Chat>(conn)
        })
        .await
        .map_err(|_| anyhow::anyhow!("Interact error"))?
        .map_err(|_| anyhow::anyhow!("Interact error"))?;

    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
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
        .map_err(|_| anyhow::anyhow!("Interact error"))?
        .map_err(|_| anyhow::anyhow!("Interact error"))?;

    Ok((character, chat_session, auth_cookie.to_string()))
}

async fn create_test_message(
    test_app: &test_helpers::TestApp,
    user_id: scribe_backend::db::DbId,
    session_id: scribe_backend::db::DbId,
    content: &str,
    role: MessageRole,
    session_dek: &SessionDek,
) -> anyhow::Result<DbChatMessage> {
    let (encrypted_content, content_nonce) =
        crypto::encrypt_gcm(content.as_bytes(), &session_dek.0)?;

    let new_message = scribe_backend::models::chats::DbInsertableChatMessage::new(
        session_id,
        user_id,
        role.clone(),
        encrypted_content,
        Some(content_nonce),
        "gemini-1.5-pro".to_string(),
    )
    .with_role(role.to_string())
    .with_status(scribe_backend::models::chats::MessageStatus::Completed);

    #[cfg(feature = "postgres-backend")]
    #[cfg(feature = "postgres-backend")]
    let message: DbChatMessage = test_app
        .db_pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?
        .interact(move |conn| {
            diesel::insert_into(chat_messages::table)
                .values(&new_message)
                .execute(conn)?;

            chat_messages::table
                .order(chat_messages::created_at.desc())
                .first::<DbChatMessage>(conn)
        })
        .await
        .map_err(|_| anyhow::anyhow!("Interact error"))?
        .map_err(|_| anyhow::anyhow!("Interact error"))?;

    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
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
                .first::<DbChatMessage>(conn)
        })
        .await
        .map_err(|_| anyhow::anyhow!("Interact error"))?
        .map_err(|_| anyhow::anyhow!("Interact error"))?;

    Ok(message)
}

async fn create_message_variant_with_raw_prompt(
    test_app: &test_helpers::TestApp,
    user_id: scribe_backend::db::DbId,
    message_id: scribe_backend::db::DbId,
    variant_content: &str,
    raw_prompt: &str,
    session_dek: &SecretBox<Vec<u8>>,
) -> anyhow::Result<()> {
    #[cfg(feature = "postgres-backend")]
    #[cfg(feature = "postgres-backend")]
    let next_index = test_app
        .db_pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?
        .interact(move |conn| {
            let count: i64 = message_variants::table
                .filter(message_variants::parent_message_id.eq(message_id))
                .count()
                .get_result(conn)
                .map_err(|e| anyhow::anyhow!("Failed to count variants: {}", e))?;
            Ok::<i32, anyhow::Error>(if count == 0 { 1 } else { (count + 1) as i32 })
        })
        .await
        .map_err(|_| anyhow::anyhow!("Interact error"))?
        .map_err(|_| anyhow::anyhow!("Interact error"))?;

    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    let next_index = test_app
        .db_pool
        .get()
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?
        .interact(move |conn| {
            let count: i64 = message_variants::table
                .filter(message_variants::parent_message_id.eq(message_id))
                .count()
                .get_result(conn)
                .map_err(|e| anyhow::anyhow!("Failed to count variants: {}", e))?;
            Ok::<i32, anyhow::Error>(if count == 0 { 1 } else { (count + 1) as i32 })
        })
        .await
        .map_err(|_| anyhow::anyhow!("Interact error"))?
        .map_err(|_| anyhow::anyhow!("Interact error"))?;

    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    let next_index = test_app
        .db_pool
        .get()
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?
        .interact(move |conn| {
            let count: i64 = message_variants::table
                .filter(message_variants::parent_message_id.eq(message_id))
                .count()
                .get_result(conn)
                .map_err(|e| anyhow::anyhow!("Failed to count variants: {}", e))?;
            Ok::<i32, anyhow::Error>(if count == 0 { 1 } else { (count + 1) as i32 })
        })
        .await
        .map_err(|_| anyhow::anyhow!("Interact error"))?
        .map_err(|_| anyhow::anyhow!("Interact error"))?;

    let new_variant = NewMessageVariant::new(
        message_id,
        next_index,
        variant_content,
        user_id,
        session_dek,
        Some(raw_prompt),
        None, // game_state
    )?
    .with_token_counts(None, None)
    .with_model_name("gemini-1.5-pro".to_string());

    #[cfg(feature = "postgres-backend")]
    #[cfg(feature = "postgres-backend")]
    test_app
        .db_pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?
        .interact(move |conn| {
            diesel::insert_into(message_variants::table)
                .values(&new_variant)
                .execute(conn)
        })
        .await
        .map_err(|_| anyhow::anyhow!("Interact error"))?
        .map_err(|_| anyhow::anyhow!("Interact error"))?;

    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    test_app
        .db_pool
        .get()
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?
        .interact(move |conn| {
            diesel::insert_into(message_variants::table)
                .values(&new_variant)
                .execute(conn)
        })
        .await
        .map_err(|_| anyhow::anyhow!("Interact error"))?
        .map_err(|_| anyhow::anyhow!("Interact error"))?;

    #[cfg(feature = "postgres-backend")]
    #[cfg(feature = "postgres-backend")]
    test_app
        .db_pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?
        .interact(move |conn| {
            diesel::update(chat_messages::table.filter(chat_messages::id.eq(message_id)))
                .set(chat_messages::variant_count.eq(next_index + 1))
                .execute(conn)
        })
        .await
        .map_err(|_| anyhow::anyhow!("Interact error"))?
        .map_err(|_| anyhow::anyhow!("Interact error"))?;

    #[cfg(all(feature = "sqlite-backend", not(feature = "postgres-backend")))]
    test_app
        .db_pool
        .get()
        .map_err(|e| anyhow::anyhow!("Pool error: {:?}", e))?
        .interact(move |conn| {
            diesel::update(chat_messages::table.filter(chat_messages::id.eq(message_id)))
                .set(chat_messages::variant_count.eq(next_index + 1))
                .execute(conn)
        })
        .await
        .map_err(|_| anyhow::anyhow!("Interact error"))?
        .map_err(|_| anyhow::anyhow!("Interact error"))?;

    Ok(())
}

async fn select_variant(
    test_app: &test_helpers::TestApp,
    auth_cookie: &str,
    message_id: scribe_backend::db::DbId,
    variant_index: i32,
) -> anyhow::Result<Value> {
    let select_variant_payload = json!({
        "variant_index": variant_index
    });

    let select_variant_request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chat/messages/{}/select-variant", message_id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_string(&select_variant_payload)?))?;

    let select_variant_response = test_app
        .router
        .clone()
        .oneshot(select_variant_request)
        .await?;
    assert_eq!(select_variant_response.status(), StatusCode::OK);

    let response_body = select_variant_response
        .into_body()
        .collect()
        .await?
        .to_bytes();
    Ok(serde_json::from_slice(&response_body)?)
}

// --- Test Case ---

#[tokio::test]
async fn test_variant_raw_prompt_retrieval() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let mut test_data_guard =
        test_helpers::TestDataGuard::new(test_app.db_pool.clone(), test_app.test_db_name.clone());

    let username = "raw_prompt_user";
    let password = "password";
    let (user_id, session_dek) =
        create_test_user_with_dek(&test_app, username.to_string(), password.to_string()).await?;
    test_data_guard.add_user(user_id.into());

    let (_client, auth_cookie) =
        test_helpers::login_user_via_api(&test_app, username, password).await;

    let (_character, chat_session, auth_cookie) =
        create_test_chat_session(&test_app, user_id, &auth_cookie).await?;

    // 1. Create original message (Variant 0)
    let original_message = create_test_message(
        &test_app,
        user_id.into(),
        chat_session.id,
        "Original Response",
        MessageRole::Assistant,
        &session_dek,
    )
    .await?;

    // 2. Create Variant 1 with specific raw prompt (simulating guidance injection)
    let variant_raw_prompt =
        "System: You are a helpful assistant.\nUser: Hello\n(SYSTEM INSTRUCTION: Guidance applied)";
    create_message_variant_with_raw_prompt(
        &test_app,
        user_id.into(),
        original_message.id,
        "Variant Response",
        variant_raw_prompt,
        &session_dek.0,
    )
    .await?;

    // 3. Select Variant 1
    select_variant(&test_app, &auth_cookie, original_message.id, 1).await?;

    // 4. Fetch message by ID (the parent ID)
    let get_message_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/messages/{}", original_message.id))
        .header(header::COOKIE, &auth_cookie)
        .body(Body::empty())?;

    let get_message_response = test_app.router.clone().oneshot(get_message_request).await?;
    assert_eq!(get_message_response.status(), StatusCode::OK);

    let response_body = get_message_response.into_body().collect().await?.to_bytes();
    let message_response: Value = serde_json::from_slice(&response_body)?;

    // 5. Verify raw_prompt matches the variant's raw prompt
    let fetched_raw_prompt = message_response["raw_prompt"].as_str();

    #[cfg(feature = "sqlite-backend")]
    {
        assert!(
            fetched_raw_prompt.is_some(),
            "Raw prompt should be present for variant"
        );
        assert_eq!(
            fetched_raw_prompt.unwrap(),
            variant_raw_prompt,
            "Raw prompt should match variant's raw prompt"
        );
    }

    #[cfg(feature = "postgres-backend")]
    {
        // Postgres doesn't support variant raw prompts yet
        assert!(fetched_raw_prompt.is_none());
    }

    test_data_guard.cleanup().await?;
    Ok(())
}
