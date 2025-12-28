use diesel::prelude::*;
use scribe_backend::models::chats::{Chat, MessageRole, NewChat};
use scribe_backend::services::chat::message_handling::{save_message, SaveMessageParams};
use scribe_backend::test_helpers::spawn_app;
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;

async fn create_test_user_manual(
    pool: &scribe_backend::db::DbPool,
) -> scribe_backend::models::users::User {
    let username = format!("testuser_{}", scribe_backend::db::DbId::new());
    let email = format!("{}@test.com", username);
    let password = "password";

    // Simplified user creation for testing
    let password_hash =
        scribe_backend::auth::hash_password(SecretString::from(password.to_string()))
            .await
            .unwrap();
    let kek_salt = scribe_backend::crypto::generate_salt().unwrap();
    let plaintext_dek = scribe_backend::crypto::generate_dek().unwrap();
    let kek =
        scribe_backend::crypto::derive_kek(&SecretString::from(password.to_string()), &kek_salt)
            .unwrap();
    let (encrypted_dek, dek_nonce) =
        scribe_backend::crypto::encrypt_gcm(plaintext_dek.expose_secret(), &kek).unwrap();

    let user_id = scribe_backend::db::DbId::new();
    let new_user = scribe_backend::models::users::NewUser {
        #[cfg(feature = "sqlite-backend")]
        id: user_id,
        username: username.clone(),
        password_hash: password_hash.clone(),
        email: email.clone(),
        kek_salt: kek_salt.clone(),
        encrypted_dek: scribe_backend::db::DbBlob::from(encrypted_dek.clone()),
        dek_nonce: scribe_backend::db::DbBlob::from(dek_nonce.clone()),
        encrypted_dek_by_recovery: None,
        recovery_kek_salt: None,
        recovery_dek_nonce: None,
        role: scribe_backend::models::users::UserRole::User,
        account_status: scribe_backend::models::users::AccountStatus::Active,
        total_prompt_tokens: 0,
        total_completion_tokens: 0,
        total_token_cost_cents: 0,
        tokens_last_reset_at: None,
        token_usage_updated_at: scribe_backend::db::DbTimestamp::now(),
    };

    scribe_backend::db::with_conn(pool, move |conn| {
        diesel::insert_into(scribe_backend::schema::users::table)
            .values(&new_user)
            .execute(conn)
            .map_err(|e| scribe_backend::errors::AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .unwrap();

    // Return constructed user directly to avoid Queryable issues in test
    scribe_backend::models::users::User {
        id: user_id,
        username,
        password_hash: password_hash.to_string(),
        email: email,
        kek_salt,
        encrypted_dek: scribe_backend::db::DbBlob::from(encrypted_dek),
        dek_nonce: scribe_backend::db::DbBlob::from(dek_nonce),
        encrypted_dek_by_recovery: None,
        recovery_kek_salt: None,
        recovery_dek_nonce: None,
        role: scribe_backend::models::users::UserRole::User,
        account_status: Some("active".to_string()),
        total_prompt_tokens: 0,
        total_completion_tokens: 0,
        total_token_cost_cents: 0,
        tokens_last_reset_at: None,
        token_usage_updated_at: scribe_backend::db::DbTimestamp::now(),
        created_at: scribe_backend::db::DbTimestamp::now(),
        updated_at: scribe_backend::db::DbTimestamp::now(),
        default_persona_id: None,
        dek: None,
        recovery_phrase: None,
    }
}

#[tokio::test]
async fn test_save_message_with_game_time() {
    // 1. Setup
    // 128 hex chars = 64 bytes
    std::env::set_var("COOKIE_SIGNING_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    std::env::set_var("DEK_ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    // spawn_app(enable_logging, enable_background_workers, enable_rate_limiting)
    let app = spawn_app(false, false, false).await;
    let pool = app.db_pool.clone();
    let user = create_test_user_manual(&pool).await;

    // Create chat session manually
    let session_id = scribe_backend::db::DbId::new();
    let new_session = NewChat {
        #[cfg(feature = "sqlite-backend")]
        id: session_id,
        user_id: user.id,
        character_id: scribe_backend::db::DbId::nil(),
        title_ciphertext: None,
        title_nonce: None,
        created_at: scribe_backend::db::DbTimestamp::now(),
        updated_at: scribe_backend::db::DbTimestamp::now(),
        history_management_strategy: "sliding_window".to_string(),
        history_management_limit: 10,
        model_name: Some("test-model".to_string()),
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
        stop_sequences: scribe_backend::models::OptionalStringArray(None),
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        system_prompt_ciphertext: None,
        system_prompt_nonce: None,
        player_chronicle_id: None,
        total_prompt_tokens: 0,
        total_completion_tokens: 0,
        estimated_cost_cents: 0,
        tokens_counted_at: scribe_backend::db::DbTimestamp::now(),
        total_credits_used: scribe_backend::db::DbDecimal::from(0),
        prompt_template_id: "default".to_string(),
        narrative_style_override_ciphertext: None,
        narrative_style_override_nonce: None,
        game_state: None,
        game_master_mode_enabled: false,
        // Missing fields added
        agent_mode: None,
        logit_bias: None,
        min_p: None,
        top_a: None,
        repetition_penalty: None,
        model_provider: None,
        // Removed missing fields: rag_chronicles_limit, rag_lorebooks_limit, rag_older_chat_limit
    };

    scribe_backend::db::with_conn(&pool, move |conn| {
        diesel::insert_into(scribe_backend::schema::chat_sessions::table)
            .values(&new_session)
            .execute(conn)
            .map_err(|e| scribe_backend::errors::AppError::DatabaseQueryError(e.to_string()))
    })
    .await
    .expect("Failed to create chat session");

    // 2. Define game time
    let game_time = json!({
        "day": 5,
        "time": "08:00",
        "label": "Day 5, Morning"
    });

    // 3. Call save_message
    let params = SaveMessageParams {
        state: app.state.clone(),
        session_id: session_id,
        user_id: user.id,
        message_type_enum: MessageRole::User,
        content: "Hello world",
        role_str: Some("user".to_string()),
        parts: None,
        attachments: None,
        user_dek_secret_box: None,
        model_name: "test-model".to_string(),
        raw_prompt_debug: None,
        status: scribe_backend::models::chats::MessageStatus::Completed,
        error_message: None,
        variant_of: None,
        charge_credits: false,
        credits_cost_override: None,
        game_time: Some(game_time.clone()),
    };

    let saved_message = save_message(params).await.expect("Failed to save message");

    // 4. Verify game_time is stored
    assert!(
        saved_message.game_time.is_some(),
        "Game time should be stored"
    );
    let stored_game_time = saved_message.game_time.unwrap();

    // Handle both Json wrapper and direct Value depending on backend
    let stored_value = stored_game_time.0;

    assert_eq!(stored_value["day"], 5);
    assert_eq!(stored_value["time"], "08:00");
}
