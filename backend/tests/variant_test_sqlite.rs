#![cfg(feature = "sqlite-backend")]
#![cfg(test)]

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
use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHasher};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use scribe_backend::{
    auth::session_dek::SessionDek,
    crypto,
    models::{
        character_card::NewCharacter,
        characters::Character as DbCharacter,
        chats::{Chat, Message as DbChatMessage, MessageRole, NewChatMessage, NewMessageVariant},
        users::{AccountStatus, NewUser, User, UserDbQuery, UserRole},
    },
    schema::{characters, chat_messages, chat_sessions, message_variants, users},
    test_helpers,
};
use secrecy::{ExposeSecret, SecretBox, SecretString};

// --- Helpers ---

use scribe_backend::db::{DbBlob, DbId, DbTimestamp};

use scribe_backend::auth::user_store::create_user_in_db;

async fn create_test_user_with_dek(
    test_app: &test_helpers::TestApp,
    username: String,
    password: String,
) -> anyhow::Result<(DbId, SessionDek)> {
    let dek = crypto::generate_dek()?;
    let session_dek = SessionDek(SecretBox::new(Box::new(dek.expose_secret().to_vec())));

    // Wrap DEK in SecretString for create_user_in_db
    // Note: create_user_in_db expects Option<SecretString> for DEK, but internally converts it to bytes.
    // Since we already have SecretBox<Vec<u8>>, we can convert it to SecretString if it's valid UTF-8,
    // OR we can just let create_user_in_db generate a NEW DEK and we ignore it?
    // NO, we need the DEK to be the same so we can decrypt!
    // But create_user_in_db takes Option<SecretString> for DEK.
    // DEK is random bytes, might NOT be valid UTF-8 string.
    // Wait, create_user_in_db (line 277) takes `plaintext_dek_opt: Option<SecretString>`.
    // And line 288: `let dek_bytes = provided_dek_ss.expose_secret().as_bytes().to_vec();`
    // This implies the input MUST be a string.
    // But DEK is 32 random bytes. It is NOT a string.
    // This seems like a flaw in `create_user_in_db` signature if it expects DEK as string?
    // Let's check `create_user_in_db` again.
    // `plaintext_dek_opt: Option<SecretString>`.
    // `as_bytes().to_vec()`.
    // If I pass a string, it gets bytes.
    // But I have bytes. I cannot easily convert random bytes to String.

    // Workaround: Use base64 encoded DEK as the "string" passed to create_user_in_db?
    // No, `create_user_in_db` treats the string bytes AS the key material.
    // If I pass base64 string, the key will be the bytes of the base64 string, which is wrong (it would be longer/different entropy).

    // Actually, `create_user_in_db` seems designed for when DEK is provided as a passphrase or something?
    // But `generate_dek` returns `SecretBox<Vec<u8>>`.

    // If I cannot pass my DEK to `create_user_in_db`, I should let it generate one,
    // AND THEN I need to retrieve it?
    // But `create_user_in_db` returns `UserDbQuery`. It does NOT return the plaintext DEK.
    // So if I let it generate, I lose the DEK and cannot decrypt anything in the test.

    // So I MUST use `create_user_in_db` with a known DEK.
    // But `create_user_in_db` forces `SecretString`.

    // Maybe I can generate a DEK that IS a valid String?
    // No, DEK must be 32 bytes for AES-256.

    // Wait, `create_user_in_db` line 288: `let dek_bytes = provided_dek_ss.expose_secret().as_bytes().to_vec();`
    // If I pass a 32-byte string, it works.
    // But random 32 bytes are not guaranteed to be valid UTF-8.

    // I can generate 32 bytes that ARE valid UTF-8?
    // e.g. "01234567890123456789012345678901" (32 chars).
    // This is a weak key, but for testing it's fine!

    let weak_dek_str = "01234567890123456789012345678901";
    let dek_secret_string = SecretString::new(weak_dek_str.into());

    let user_db = create_user_in_db(
        &test_app.db_pool,
        &username,
        &password,
        &format!("{}@example.com", username),
        Some(dek_secret_string),
    )
    .await?;

    let session_dek = SessionDek(SecretBox::new(Box::new(weak_dek_str.as_bytes().to_vec())));
    Ok((user_db.id, session_dek))
}

async fn create_test_chat_session(
    test_app: &test_helpers::TestApp,
    user_id: DbId,
    auth_cookie: &str,
) -> anyhow::Result<(DbCharacter, Chat, String)> {
    let mut conn = test_app.db_pool.get().expect("Failed to get connection");

    let char_id = DbId::new();
    let new_character = NewCharacter {
        id: Some(char_id.clone()),
        user_id: user_id.clone(),
        spec: "test_char".to_string(),
        spec_version: "1.0".to_string(),
        name: "Test Char".to_string(),
        visibility: Some("private".to_string()),
        ..Default::default()
    };

    diesel::insert_into(characters::table)
        .values(&new_character)
        .execute(&mut conn)?;

    let character: DbCharacter = characters::table.find(char_id).first(&mut conn)?;

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
    let session_id = DbId::parse_str(session_response["id"].as_str().unwrap())?;

    let chat_session: Chat = chat_sessions::table
        .filter(chat_sessions::id.eq(session_id))
        .select(Chat::as_select())
        .first::<Chat>(&mut conn)?;

    Ok((character, chat_session, auth_cookie.to_string()))
}

async fn create_test_message(
    test_app: &test_helpers::TestApp,
    user_id: DbId,
    session_id: DbId,
    content: &str,
    role: MessageRole,
    session_dek: &SessionDek,
) -> anyhow::Result<DbChatMessage> {
    let mut conn = test_app.db_pool.get().expect("Failed to get connection");

    let (encrypted_content, content_nonce) =
        crypto::encrypt_gcm(content.as_bytes(), &session_dek.0)?;

    let msg_id = DbId::new();
    let new_message = NewChatMessage {
        id: msg_id.clone(),
        session_id,
        user_id,
        message_type: role.clone(),
        content: encrypted_content,
        content_nonce: Some(content_nonce),
        role: Some(role.to_string()),
        parts: None,
        attachments: None,
        created_at: DbTimestamp::now(),
        updated_at: DbTimestamp::now(),
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: "gemini-1.5-pro".to_string(),
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

    diesel::insert_into(chat_messages::table)
        .values(&new_message)
        .execute(&mut conn)?;

    let message: DbChatMessage = chat_messages::table.find(msg_id).first(&mut conn)?;

    Ok(message)
}

async fn create_message_variant_with_raw_prompt(
    test_app: &test_helpers::TestApp,
    user_id: DbId,
    message_id: DbId,
    variant_content: &str,
    raw_prompt: &str,
    session_dek: &SecretBox<Vec<u8>>,
) -> anyhow::Result<()> {
    let mut conn = test_app.db_pool.get().expect("Failed to get connection");

    let count: i64 = message_variants::table
        .filter(message_variants::parent_message_id.eq(&message_id))
        .count()
        .get_result(&mut conn)?;
    let next_index = if count == 0 { 1 } else { (count + 1) as i32 };

    let new_variant = NewMessageVariant::new(
        message_id.clone(),
        next_index,
        variant_content,
        user_id,
        session_dek,
        None,
        None,
        Some("gemini-1.5-pro".to_string()),
        Some(raw_prompt),
        None,
    )?;

    diesel::insert_into(message_variants::table)
        .values(&new_variant)
        .execute(&mut conn)?;

    diesel::update(chat_messages::table.filter(chat_messages::id.eq(message_id)))
        .set(chat_messages::variant_count.eq(next_index + 1))
        .execute(&mut conn)?;

    Ok(())
}

async fn select_variant(
    test_app: &test_helpers::TestApp,
    auth_cookie: &str,
    message_id: DbId,
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

#[tokio::test]
async fn test_variant_raw_prompt_retrieval_sqlite() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    // TestDataGuard might need adaptation if it uses async pool internally, but let's try
    // If TestDataGuard is generic or handles both, good.
    // Looking at test_helpers.rs, TestDataGuard has cfg(sqlite-backend) impl which is no-op.

    let username = "raw_prompt_user";
    let password = "password";
    let (user_id, session_dek) =
        create_test_user_with_dek(&test_app, username.to_string(), password.to_string()).await?;

    // We can't use test_data_guard.add_user because we don't have the guard easily set up for manual user creation?
    // Actually TestDataGuard::new takes pool.
    // But for SQLite it's a no-op cleanup, so we might not strictly need it if we don't care about cleanup (in-memory DB).

    let (_client, auth_cookie) =
        test_helpers::login_user_via_api(&test_app, username, password).await;

    let (_character, chat_session, auth_cookie) =
        create_test_chat_session(&test_app, user_id.clone(), &auth_cookie).await?;

    // 1. Create original message (Variant 0)
    let original_message = create_test_message(
        &test_app,
        user_id.clone(),
        chat_session.id,
        "Original Response",
        MessageRole::Assistant,
        &session_dek,
    )
    .await?;

    // 2. Create Variant 1 with specific raw prompt
    let variant_raw_prompt =
        "System: You are a helpful assistant.\nUser: Hello\n(SYSTEM INSTRUCTION: Guidance applied)";
    create_message_variant_with_raw_prompt(
        &test_app,
        user_id.clone(),
        original_message.id.clone(),
        "Variant Response",
        variant_raw_prompt,
        &session_dek.0,
    )
    .await?;

    // 3. Select Variant 1
    select_variant(&test_app, &auth_cookie, original_message.id.clone(), 1).await?;

    // 4. Fetch message by ID
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

    assert!(
        fetched_raw_prompt.is_some(),
        "Raw prompt should be present for variant"
    );
    assert_eq!(
        fetched_raw_prompt.unwrap(),
        variant_raw_prompt,
        "Raw prompt should match variant's raw prompt"
    );

    // Also verify content is updated (Chronicle Basis Fix verification)
    let fetched_content = message_response["content"].as_str();
    assert_eq!(
        fetched_content,
        Some("Variant Response"),
        "Message content should be updated to variant content"
    );

    Ok(())
}
