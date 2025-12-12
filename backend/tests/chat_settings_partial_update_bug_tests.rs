#![cfg(feature = "postgres-backend")]
#![cfg(test)]

// Tests to demonstrate the bug where partial updates clear chronicle_id and active_custom_persona_id
// These tests SHOULD FAIL initially, demonstrating the bug exists

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use bigdecimal::BigDecimal;
use chrono::Utc;
use http_body_util::BodyExt;
use std::str::FromStr;
use tower::ServiceExt;
use uuid::Uuid;

use diesel::prelude::*;
use scribe_backend::models::character_card::NewCharacter;
use scribe_backend::models::characters::Character as DbCharacter;
use scribe_backend::models::chats::{
    Chat as DbChat, ChatSettingsResponse, NewChat, UpdateChatSettingsRequest,
};
use scribe_backend::schema::{characters, chat_sessions};
use scribe_backend::test_helpers;

async fn setup_test_env(
    test_app: &test_helpers::TestApp,
    username: &str,
) -> anyhow::Result<(String, DbCharacter, DbChat)> {
    // Create user
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        "password".to_string(),
    )
    .await?;

    // Login to get auth cookie
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

    let new_character_data = NewCharacter {
        user_id: user.id,
        spec: "character_card_v2".to_string(),
        spec_version: "2.0.0".to_string(),
        name: "Test Character".to_string(),
        visibility: Some("private".to_string()),
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
        ..Default::default()
    };

    let character: DbCharacter = test_app
        .db_pool
        .get()
        .await
        .unwrap()
        .interact(move |actual_conn| {
            diesel::insert_into(characters::table)
                .values(&new_character_data)
                .get_result::<DbCharacter>(actual_conn)
        })
        .await
        .expect("Interact char insert failed")
        .expect("Diesel char insert failed");

    let new_chat_data = NewChat {
        id: Uuid::new_v4(),
        user_id: user.id,
        character_id: character.id,
        title_ciphertext: Some("Test Chat".as_bytes().to_vec()),
        title_nonce: Some(vec![0u8; 12]),
        created_at: Utc::now().into(),
        updated_at: Utc::now().into(),
        history_management_strategy: "token_limit".to_string(),
        history_management_limit: 10,
        model_name: "initial-model".to_string(),
        visibility: Some("private".to_string()),
        active_custom_persona_id: None,
        prompt_template_id: "default".to_string(),
        narrative_style_override_ciphertext: None,
        narrative_style_override_nonce: None,
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
        tokens_counted_at: Utc::now(),
        total_credits_used: BigDecimal::from(0),
    };

    let session: DbChat = test_app
        .db_pool
        .get()
        .await
        .unwrap()
        .interact(move |actual_conn| {
            diesel::insert_into(chat_sessions::table)
                .values(&new_chat_data)
                .returning(DbChat::as_returning())
                .get_result(actual_conn)
        })
        .await
        .expect("Interact chat insert failed")
        .expect("Diesel chat insert failed");

    Ok((auth_cookie, character, session))
}

#[tokio::test]
async fn test_partial_update_preserves_chronicle_id() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let (auth_cookie, _character, session) = setup_test_env(&test_app, "chronicle_preserve_user")
        .await
        .expect("Failed to setup test environment");

    // First, create a chronicle
    let chronicle_payload = serde_json::json!({
        "name": "Test Chronicle for Preservation",
        "description": "A test chronicle"
    });

    let create_chronicle_request = Request::builder()
        .method(Method::POST)
        .uri("/api/chronicles")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(
            serde_json::to_string(&chronicle_payload).unwrap(),
        ))
        .unwrap();

    let chronicle_response = test_app
        .router
        .clone()
        .clone()
        .oneshot(create_chronicle_request)
        .await
        .unwrap();
    assert_eq!(chronicle_response.status(), StatusCode::CREATED);

    let chronicle_body = chronicle_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let chronicle_data: serde_json::Value = serde_json::from_slice(&chronicle_body).unwrap();
    let chronicle_id = chronicle_data["id"].as_str().unwrap();
    let chronicle_uuid = Uuid::parse_str(chronicle_id).unwrap();

    // Set the chronicle association
    let set_chronicle_data = UpdateChatSettingsRequest {
        system_prompt: None,
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        model_name: None,
        history_management_strategy: None,
        history_management_limit: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: Some(chronicle_uuid),
        agent_mode: None,
        model_provider: None,
        active_custom_persona_id: None,
        prompt_template_id: Some("neutral_roleplay".to_string()),
    };

    let set_request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chat/{}/settings", session.id))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(
            serde_json::to_string(&set_chronicle_data).unwrap(),
        ))
        .unwrap();

    let set_response = test_app
        .router
        .clone()
        .clone()
        .oneshot(set_request)
        .await
        .unwrap();
    assert_eq!(set_response.status(), StatusCode::OK);

    let set_body = set_response.into_body().collect().await.unwrap().to_bytes();
    let set_settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&set_body).expect("Failed to deserialize settings response");
    assert_eq!(set_settings_resp.chronicle_id, Some(chronicle_uuid));

    // NOW THE BUG: Update a DIFFERENT setting (model_name) without including chronicle_id
    // The chronicle_id field is omitted (None), which should mean "don't change it"
    // But the bug causes it to be cleared
    let partial_update_data = UpdateChatSettingsRequest {
        system_prompt: None,
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        model_name: Some("updated-model-name".to_string()), // Only updating model_name
        history_management_strategy: None,
        history_management_limit: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: None, // NOT PROVIDED - should preserve existing value
        agent_mode: None,
        model_provider: None,
        active_custom_persona_id: None,
        prompt_template_id: None,
    };

    let partial_request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chat/{}/settings", session.id))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(
            serde_json::to_string(&partial_update_data).unwrap(),
        ))
        .unwrap();

    let partial_response = test_app
        .router
        .clone()
        .clone()
        .oneshot(partial_request)
        .await
        .unwrap();
    assert_eq!(partial_response.status(), StatusCode::OK);

    let partial_body = partial_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let partial_settings_resp: ChatSettingsResponse = serde_json::from_slice(&partial_body)
        .expect("Failed to deserialize partial update response");

    // THIS ASSERTION WILL FAIL DUE TO THE BUG
    // The chronicle_id should still be present (preserved), but the bug clears it
    assert_eq!(
        partial_settings_resp.chronicle_id,
        Some(chronicle_uuid),
        "chronicle_id should be preserved when not included in partial update"
    );

    // Verify the model_name was updated
    assert_eq!(partial_settings_resp.model_name, "updated-model-name");
}

#[tokio::test]
async fn test_partial_update_preserves_active_custom_persona_id() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let (auth_cookie, _character, session) = setup_test_env(&test_app, "persona_preserve_user")
        .await
        .expect("Failed to setup test environment");

    // First, create a custom persona
    let persona_payload = serde_json::json!({
        "name": "Test Persona for Preservation",
        "description": "A test persona"
    });

    let create_persona_request = Request::builder()
        .method(Method::POST)
        .uri("/api/personas")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(serde_json::to_string(&persona_payload).unwrap()))
        .unwrap();

    let persona_response = test_app
        .router
        .clone()
        .clone()
        .oneshot(create_persona_request)
        .await
        .unwrap();
    assert_eq!(persona_response.status(), StatusCode::CREATED);

    let persona_body = persona_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let persona_data: serde_json::Value = serde_json::from_slice(&persona_body).unwrap();
    let persona_id = persona_data["id"].as_str().unwrap();
    let persona_uuid = Uuid::parse_str(persona_id).unwrap();

    // Set the persona association
    let set_persona_data = UpdateChatSettingsRequest {
        system_prompt: None,
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        model_name: None,
        history_management_strategy: None,
        history_management_limit: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: None,
        agent_mode: None,
        model_provider: None,
        active_custom_persona_id: Some(persona_uuid),
        prompt_template_id: Some("neutral_roleplay".to_string()),
    };

    let set_request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chat/{}/settings", session.id))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(
            serde_json::to_string(&set_persona_data).unwrap(),
        ))
        .unwrap();

    let set_response = test_app
        .router
        .clone()
        .clone()
        .oneshot(set_request)
        .await
        .unwrap();
    assert_eq!(set_response.status(), StatusCode::OK);

    let set_body = set_response.into_body().collect().await.unwrap().to_bytes();
    let set_settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&set_body).expect("Failed to deserialize settings response");
    assert_eq!(
        set_settings_resp.active_custom_persona_id,
        Some(persona_uuid)
    );

    // NOW THE BUG: Update a DIFFERENT setting (temperature) without including active_custom_persona_id
    // The active_custom_persona_id field is omitted (None), which should mean "don't change it"
    // But the bug causes it to be cleared
    let partial_update_data = UpdateChatSettingsRequest {
        system_prompt: None,
        temperature: Some(BigDecimal::from_str("0.8").unwrap()), // Only updating temperature
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        model_name: None,
        history_management_strategy: None,
        history_management_limit: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: None,
        agent_mode: None,
        model_provider: None,
        active_custom_persona_id: None, // NOT PROVIDED - should preserve existing value
        prompt_template_id: None,
    };

    let partial_request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chat/{}/settings", session.id))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(
            serde_json::to_string(&partial_update_data).unwrap(),
        ))
        .unwrap();

    let partial_response = test_app
        .router
        .clone()
        .clone()
        .oneshot(partial_request)
        .await
        .unwrap();
    assert_eq!(partial_response.status(), StatusCode::OK);

    let partial_body = partial_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let partial_settings_resp: ChatSettingsResponse = serde_json::from_slice(&partial_body)
        .expect("Failed to deserialize partial update response");

    // THIS ASSERTION WILL FAIL DUE TO THE BUG
    // The active_custom_persona_id should still be present (preserved), but the bug clears it
    assert_eq!(
        partial_settings_resp.active_custom_persona_id,
        Some(persona_uuid),
        "active_custom_persona_id should be preserved when not included in partial update"
    );

    // Verify the temperature was updated
    assert_eq!(
        partial_settings_resp.temperature,
        Some(BigDecimal::from_str("0.8").unwrap())
    );
}
