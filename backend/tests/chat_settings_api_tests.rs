#![cfg(test)]

// Common imports needed for settings tests
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use bigdecimal::BigDecimal;
use http_body_util::BodyExt;
use mime;
use serde_json::{Value, json};
use std::str::FromStr;
use tower::ServiceExt;
use uuid::Uuid;

// Crate imports
use scribe_backend::models::chats::{ChatSettingsResponse, UpdateChatSettingsRequest};
use scribe_backend::test_helpers;

// --- Tests for GET /api/chats/{id}/settings ---

#[tokio::test]
#[ignore] // Added ignore for CI
async fn get_chat_settings_success() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "get_settings_user",
        "password",
    )
    .await;
    let character =
        test_helpers::db::create_test_character(&context.app.db_pool, user.id, "Settings Char")
            .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    // Update settings for this session
    let update_data = UpdateChatSettingsRequest {
        system_prompt: Some("Test System Prompt".to_string()),
        temperature: Some(BigDecimal::from_str("0.9").unwrap()),
        max_output_tokens: Some(1024_i32),
        frequency_penalty: Some(BigDecimal::from_str("0.3").unwrap()),
        presence_penalty: Some(BigDecimal::from_str("0.2").unwrap()),
        top_k: Some(30_i32),
        top_p: Some(BigDecimal::from_str("0.85").unwrap()),
        repetition_penalty: Some(BigDecimal::from_str("1.1").unwrap()),
        min_p: Some(BigDecimal::from_str("0.1").unwrap()),
        top_a: Some(BigDecimal::from_str("0.8").unwrap()),
        seed: Some(54321_i32),
        logit_bias: Some(serde_json::json!({
            "20001": -50,
            "20002": 50
        })),
        // Add history fields for completeness, though not the focus of this test
        history_management_strategy: None,
        history_management_limit: None,
    };
    
    test_helpers::db::update_all_chat_settings(
        &context.app.db_pool,
        session.id,
        update_data.system_prompt,
        update_data.temperature,
        update_data.max_output_tokens,
        update_data.frequency_penalty,
        update_data.presence_penalty,
        update_data.top_k,
        update_data.top_p,
        update_data.repetition_penalty,
        update_data.min_p,
        update_data.top_a,
        update_data.seed,
        update_data.logit_bias,
        // Pass None for history fields as they are not being set here
        None,
        None,
    )
    .await;
    
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&body).expect("Failed to deserialize settings response");

    // Check all fields match expected values
    assert_eq!(
        settings_resp.system_prompt,
        Some("Test System Prompt".to_string())
    );
    assert_eq!(
        settings_resp.temperature,
        Some(BigDecimal::from_str("0.9").unwrap())
    );
    assert_eq!(settings_resp.max_output_tokens, Some(1024_i32));
    assert_eq!(
        settings_resp.frequency_penalty,
        Some(BigDecimal::from_str("0.3").unwrap())
    );
    assert_eq!(
        settings_resp.presence_penalty,
        Some(BigDecimal::from_str("0.2").unwrap())
    );
    assert_eq!(settings_resp.top_k, Some(30_i32));
    assert_eq!(
        settings_resp.top_p,
        Some(BigDecimal::from_str("0.85").unwrap())
    );
    assert_eq!(
        settings_resp.repetition_penalty,
        Some(BigDecimal::from_str("1.1").unwrap())
    );
    assert_eq!(
        settings_resp.min_p,
        Some(BigDecimal::from_str("0.1").unwrap())
    );
    assert_eq!(
        settings_resp.top_a,
        Some(BigDecimal::from_str("0.8").unwrap())
    );
    assert_eq!(settings_resp.seed, Some(54321_i32));
    assert_eq!(
        settings_resp.logit_bias,
        Some(serde_json::json!({
            "20001": -50,
            "20002": 50
        }))
    );
    // Check history fields (should be defaults from DB migration)
    assert_eq!(settings_resp.history_management_strategy, "none");
    assert_eq!(settings_resp.history_management_limit, 20);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn get_chat_settings_defaults() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "get_defaults_user",
        "password",
    )
    .await;
    let character =
        test_helpers::db::create_test_character(&context.app.db_pool, user.id, "Defaults Char")
            .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;
    // No settings updated, should be NULL

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&body).expect("Failed to deserialize settings response");

    // Check all fields are None
    assert_eq!(settings_resp.system_prompt, None);
    assert_eq!(settings_resp.temperature, None);
    assert_eq!(settings_resp.max_output_tokens, None);
    assert_eq!(settings_resp.frequency_penalty, None);
    assert_eq!(settings_resp.presence_penalty, None);
    assert_eq!(settings_resp.top_k, None);
    assert_eq!(settings_resp.top_p, None);
    assert_eq!(settings_resp.repetition_penalty, None);
    assert_eq!(settings_resp.min_p, None);
    assert_eq!(settings_resp.top_a, None);
    assert_eq!(settings_resp.seed, None);
    assert_eq!(settings_resp.logit_bias, None);
    // Check history fields (should be defaults from DB migration)
    assert_eq!(settings_resp.history_management_strategy, "none");
    assert_eq!(settings_resp.history_management_limit, 20);
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn test_get_chat_settings_not_found() {
    // Covers chat_service.rs lines 392, 425-426
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "get_settings_404_user",
        "password",
    )
    .await;
    let non_existent_session_id = Uuid::new_v4();
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", non_existent_session_id))
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
async fn test_get_chat_settings_forbidden() {
    // Covers chat_service.rs lines 392, 425-426
    let context = test_helpers::setup_test_app().await;
    // User A creates a session
    let (_auth_cookie_a, user_a) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "get_settings_forbid_user_a",
        "password",
    )
    .await;
    let char_a = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user_a.id,
        "Get Settings Forbidden Char A",
    )
    .await;
    let session_a = test_helpers::db::create_test_chat_session(
        &context.app.db_pool,
        user_a.id,
        char_a.id,
    )
    .await;

    // User B logs in
    let (auth_cookie_b, _user_b) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "get_settings_forbid_user_b",
        "password",
    )
    .await;

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", session_a.id)) // User B requests User A's settings
        .header(header::COOKIE, auth_cookie_b)
        .body(Body::empty())
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();
    // The service layer returns NotFound when the filter `user_id.eq(user_id)` fails
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}


// --- Tests for PUT /api/chats/{id}/settings ---

#[tokio::test]
#[ignore] // Added ignore for CI
async fn update_chat_settings_success_full() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "update_settings_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Update Settings Char",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    let new_prompt = "New System Prompt";
    let new_temp = BigDecimal::from_str("0.9").unwrap();
    let new_tokens = 1024_i32;
    let new_freq_penalty = BigDecimal::from_str("0.3").unwrap();
    let new_pres_penalty = BigDecimal::from_str("0.2").unwrap();
    let new_top_k = 30_i32;
    let new_top_p = BigDecimal::from_str("0.85").unwrap();
    let new_rep_penalty = BigDecimal::from_str("1.1").unwrap();
    let new_min_p = BigDecimal::from_str("0.1").unwrap();
    let new_top_a = BigDecimal::from_str("0.8").unwrap();
    let new_seed = 54321_i32;
    let new_logit_bias = serde_json::json!({
        "20001": -50,
        "20002": 50
    });

    let payload = UpdateChatSettingsRequest {
        system_prompt: Some(new_prompt.to_string()),
        temperature: Some(new_temp.clone()),
        max_output_tokens: Some(new_tokens),
        frequency_penalty: Some(new_freq_penalty.clone()),
        presence_penalty: Some(new_pres_penalty.clone()),
        top_k: Some(new_top_k),
        top_p: Some(new_top_p.clone()),
        repetition_penalty: Some(new_rep_penalty.clone()),
        min_p: Some(new_min_p.clone()),
        top_a: Some(new_top_a.clone()),
        seed: Some(new_seed),
        logit_bias: Some(new_logit_bias.clone()),
        // Add history fields for completeness
        history_management_strategy: Some("sliding_window_messages".to_string()),
        history_management_limit: Some(10),
    };
    
    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify changes in DB
    let db_settings = test_helpers::db::get_chat_session_settings(&context.app.db_pool, session.id)
        .await
        .unwrap();

    // Check all fields
    assert_eq!(db_settings.0, Some(new_prompt.to_string())); // system_prompt
    assert_eq!(db_settings.1, Some(new_temp)); // temperature
    assert_eq!(db_settings.2, Some(new_tokens)); // max_output_tokens
    assert_eq!(db_settings.3, Some(new_freq_penalty)); // frequency_penalty
    assert_eq!(db_settings.4, Some(new_pres_penalty)); // presence_penalty
    assert_eq!(db_settings.5, Some(new_top_k)); // top_k
    assert_eq!(db_settings.6, Some(new_top_p)); // top_p
    assert_eq!(db_settings.7, Some(new_rep_penalty)); // repetition_penalty
    assert_eq!(db_settings.8, Some(new_min_p)); // min_p
    assert_eq!(db_settings.9, Some(new_top_a)); // top_a
    assert_eq!(db_settings.10, Some(new_seed)); // seed

    // For JSON comparison, need to deserialize
    let db_logit_bias: serde_json::Value = serde_json::from_value(db_settings.11.unwrap()).unwrap();
    assert_eq!(db_logit_bias, new_logit_bias); // logit_bias
    // Check history fields
    assert_eq!(db_settings.12, "sliding_window_messages"); // history_management_strategy
    assert_eq!(db_settings.13, 10); // history_management_limit
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn update_chat_settings_success_partial() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "update_partial_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Update Partial Char",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    // Get initial settings to compare against
    let initial_settings =
        test_helpers::db::get_chat_session_settings(&context.app.db_pool, session.id)
            .await
            .unwrap();

    let new_temp = BigDecimal::from_str("1.2").unwrap();
    let payload = UpdateChatSettingsRequest {
        system_prompt: None, // Send None to test partial update
        temperature: Some(new_temp.clone()),
        max_output_tokens: None, // Send None to test partial update
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        repetition_penalty: None,
        min_p: None,
        top_a: None,
        seed: None,
        logit_bias: None,
        // Add history fields for completeness
        history_management_strategy: None,
        history_management_limit: None,
    };
    
    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify changes in DB
    let db_settings = test_helpers::db::get_chat_session_settings(&context.app.db_pool, session.id)
        .await
        .unwrap();

    // Verify that fields *not* in the payload are unchanged
    // and fields *in* the payload are updated.
    assert_eq!(db_settings.0, initial_settings.0); // System prompt should be unchanged (was Some, payload was None)
    assert_eq!(db_settings.1, Some(new_temp)); // Temperature should be updated
    assert_eq!(db_settings.2, initial_settings.2); // Max tokens should be unchanged
    // History fields should also be unchanged
    assert_eq!(db_settings.12, initial_settings.12);
    assert_eq!(db_settings.13, initial_settings.13);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn update_chat_settings_invalid_data() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "update_invalid_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Update Invalid Char",
    )
    .await;
    let session =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user.id, character.id)
            .await;

    let invalid_payloads = vec![
        // Temperature validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: Some(BigDecimal::from_str("-0.1").unwrap()), // Negative temperature
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: Some(BigDecimal::from_str("2.1").unwrap()), // Temperature > 2.0
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        // Max tokens validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: Some(0), // Zero tokens
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: Some(-100), // Negative tokens
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        // Frequency penalty validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: Some(BigDecimal::from_str("-2.1").unwrap()), // < -2.0
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: Some(BigDecimal::from_str("2.1").unwrap()), // > 2.0
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        // Presence penalty validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: Some(BigDecimal::from_str("-2.1").unwrap()), // < -2.0
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: Some(BigDecimal::from_str("2.1").unwrap()), // > 2.0
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        // Top-k validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: Some(-1), // Negative top_k
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        // Top-p validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: Some(BigDecimal::from_str("-0.1").unwrap()), // < 0
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: Some(BigDecimal::from_str("1.1").unwrap()), // > 1.0
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        // Repetition penalty validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: Some(BigDecimal::from_str("0").unwrap()), // <= 0
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        // Min-p validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: Some(BigDecimal::from_str("-0.1").unwrap()), // < 0
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: Some(BigDecimal::from_str("1.1").unwrap()), // > 1.0
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        // Top-a validation
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: Some(BigDecimal::from_str("-0.1").unwrap()), // < 0
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: Some(BigDecimal::from_str("1.1").unwrap()), // > 1.0
            seed: None,
            logit_bias: None,
            history_management_strategy: None,
            history_management_limit: None,
        },
        // Invalid logit_bias format
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: Some(serde_json::json!(["invalid", "format"])), // Should be object
            history_management_strategy: None,
            history_management_limit: None,
        },
        // History Management Validation
        UpdateChatSettingsRequest {
            system_prompt: None, temperature: None, max_output_tokens: None, frequency_penalty: None,
            presence_penalty: None, top_k: None, top_p: None, repetition_penalty: None, min_p: None,
            top_a: None, seed: None, logit_bias: None,
            history_management_strategy: Some("invalid-strategy".to_string()), // Invalid strategy name
            history_management_limit: Some(10),
        },
        UpdateChatSettingsRequest {
            system_prompt: None, temperature: None, max_output_tokens: None, frequency_penalty: None,
            presence_penalty: None, top_k: None, top_p: None, repetition_penalty: None, min_p: None,
            top_a: None, seed: None, logit_bias: None,
            history_management_strategy: Some("none".to_string()),
            history_management_limit: Some(0), // Zero limit
        },
        UpdateChatSettingsRequest {
            system_prompt: None, temperature: None, max_output_tokens: None, frequency_penalty: None,
            presence_penalty: None, top_k: None, top_p: None, repetition_penalty: None, min_p: None,
            top_a: None, seed: None, logit_bias: None,
            history_management_strategy: Some("none".to_string()),
            history_management_limit: Some(-5), // Negative limit
        },
        ];
        
        for (i, payload) in invalid_payloads.iter().enumerate() {
        let request = Request::builder()
            .method(Method::PUT)
            .uri(format!("/api/chats/{}/settings", session.id))
            .header(header::COOKIE, &auth_cookie)
            .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();

        let response = context.app.router.clone().oneshot(request).await.unwrap();
        // Expect Bad Request for validation errors on PUT
        // Update: Payload 16 (invalid logit_bias format) currently returns 200 OK, indicating a validation bug.
        // We expect 400, but the test fails here until validation is fixed in the model/handler.
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Failed for payload index {}: {:?}",
            i,
            payload
        );
    }
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn update_chat_settings_forbidden() {
    let context = test_helpers::setup_test_app().await;
    let (_auth_cookie1, user1) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "update_settings_user1",
        "password",
    )
    .await;
    let character1 = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user1.id,
        "Update Settings Char 1",
    )
    .await;
    let session1 =
        test_helpers::db::create_test_chat_session(&context.app.db_pool, user1.id, character1.id)
            .await;
    let (auth_cookie2, _user2) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "update_settings_user2",
        "password",
    )
    .await;

    let payload = UpdateChatSettingsRequest {
        system_prompt: Some("Attempted Update".to_string()),
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        repetition_penalty: None,
        min_p: None,
        top_a: None,
        seed: None,
        logit_bias: None,
        // Add history fields for completeness
        history_management_strategy: None,
        history_management_limit: None,
    };
    
    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session1.id)) // User 2 tries to update User 1's settings
        .header(header::COOKIE, auth_cookie2)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN); // Handler returns NotFound if update affects 0 rows due to ownership check
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn update_chat_settings_not_found() {
    let context = test_helpers::setup_test_app().await;
    let (auth_cookie, _user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "update_settings_404_user",
        "password",
    )
    .await;
    let non_existent_session_id = Uuid::new_v4();

    let payload = UpdateChatSettingsRequest {
        system_prompt: Some("Attempted Update".to_string()),
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        repetition_penalty: None,
        min_p: None,
        top_a: None,
        seed: None,
        logit_bias: None,
        // Add history fields for completeness
        history_management_strategy: None,
        history_management_limit: None,
    };
    
    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", non_existent_session_id))
        .header(header::COOKIE, auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn update_chat_settings_unauthorized() {
    let context = test_helpers::setup_test_app().await;
    let session_id = Uuid::new_v4(); // Dummy ID

    let payload = UpdateChatSettingsRequest {
        system_prompt: Some("Attempted Update".to_string()),
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        repetition_penalty: None,
        min_p: None,
        top_a: None,
        seed: None,
        logit_bias: None,
        // Add history fields for completeness
        history_management_strategy: None,
        history_management_limit: None,
    };
    
    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session_id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();
    // No auth cookie

    let response = context.app.router.oneshot(request).await.unwrap();
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