#![cfg(test)]

// Common imports needed for settings tests
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use bigdecimal::BigDecimal;
use http_body_util::BodyExt;
use mime;
// Removed unused: use serde_json::{Value, json};
use std::str::FromStr;
use tower::ServiceExt;
use uuid::Uuid;

// Diesel and model imports
use diesel::prelude::*;
use scribe_backend::schema::{characters, chats};
use scribe_backend::models::{
    characters::{Character as DbCharacter, NewCharacter},
    chats::{Chat as DbChat, NewChat, ChatSettingsResponse, UpdateChatSettingsRequest},
};
use scribe_backend::test_helpers;

// --- Tests for GET /api/chats/{id}/settings ---

#[tokio::test]
async fn get_chat_settings_success() {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().expect("Failed to get DB connection");

    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "get_settings_user",
        "password",
    )
    .await;

    let login_payload = serde_json::json!({
        "identifier": "get_settings_user",
        "password": "password"
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
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();
    
    let new_character = NewCharacter {
        user_id: user.id,
        name: "Settings Char".to_string(),
        description: None,
        persona: None,
        world_scenario: None,
        greeting_message: None,
        example_dialogue: None,
        avatar_uri: None,
        voice_id: None,
        visual_description: None,
        system_prompt_override: None,
        is_public: Some(false),
        data: None,
        user_persona: None,
        chat_persona: None,
        custom_tags: None,
        known_facts: None,
    };
    let character: DbCharacter = diesel::insert_into(characters::table)
        .values(&new_character)
        .get_result(&mut conn)
        .expect("Error saving new character");

    let new_chat = NewChat {
        user_id: user.id,
        character_id: character.id,
        title: Some(format!("Chat with {}", character.name)),
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
        logit_bias: None,
        history_management_strategy: None, // DB default 'none'
        history_management_limit: None,    // DB default 20
        model_name: None,
        gemini_enable_code_execution: None,
        gemini_thinking_budget: None,
        encrypted_dek: None,
        dek_nonce: None,
        encrypted_title: None,
        title_nonce: None,
        encrypted_system_prompt: None,
        system_prompt_nonce: None,
    };
    let session: DbChat = diesel::insert_into(chats::table)
        .values(&new_chat)
        .get_result(&mut conn)
        .expect("Error saving new chat session");

    // Update settings for this session via API endpoint
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
        history_management_strategy: None, 
        history_management_limit: None,    
        model_name: Some("gemini-2.5-flash-preview-04-17".to_string()),
        gemini_enable_code_execution: None,
        gemini_thinking_budget: None,
    };

    let update_request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::COOKIE, auth_cookie.clone()) 
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&update_data).unwrap()))
        .unwrap();

    let update_response = test_app
        .router
        .clone()
        .oneshot(update_request)
        .await
        .unwrap();
    assert_eq!(update_response.status(), StatusCode::OK);
    
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::COOKIE, auth_cookie) 
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap(); 
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&body).expect("Failed to deserialize settings response");

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
    // These are returned by the API based on current DB state after PUT,
    // PUT request had None for history fields, so service layer should use existing values or defaults.
    // The ChatSettingsResponse struct has non-optional history fields.
    // Default values from DB are 'none' and 20. If PUT doesn't change them, they remain.
    // If PUT *can* change them (e.g. to "token_limit", 100), then those would be reflected.
    // The update_data had None for history fields, so they should remain their defaults ('none', 20)
    // or whatever they were before the PUT if they were previously set.
    // Since this is a new session, they will be the defaults.
    assert_eq!(settings_resp.history_management_strategy, "none"); 
    assert_eq!(settings_resp.history_management_limit, 20);
    assert_eq!(settings_resp.model_name, Some("gemini-2.5-flash-preview-04-17".to_string()));
}

#[tokio::test]
async fn get_chat_settings_defaults() {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().expect("Failed to get DB connection");
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "get_defaults_user",
        "password",
    )
    .await;

    let login_payload = serde_json::json!({
        "identifier": "get_defaults_user",
        "password": "password"
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
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    let new_character = NewCharacter {
        user_id: user.id,
        name: "Defaults Char".to_string(),
        description: None, persona: None, world_scenario: None, greeting_message: None,
        example_dialogue: None, avatar_uri: None, voice_id: None, visual_description: None,
        system_prompt_override: None, is_public: Some(false), data: None, user_persona: None,
        chat_persona: None, custom_tags: None, known_facts: None,
    };
    let character: DbCharacter = diesel::insert_into(characters::table)
        .values(&new_character)
        .get_result(&mut conn)
        .expect("Error saving new character");

    let new_chat = NewChat {
        user_id: user.id, character_id: character.id, title: Some(format!("Chat with {}", character.name)),
        system_prompt: None, temperature: None, max_output_tokens: None, frequency_penalty: None,
        presence_penalty: None, top_k: None, top_p: None, repetition_penalty: None, min_p: None,
        top_a: None, seed: None, logit_bias: None, history_management_strategy: None,
        history_management_limit: None, model_name: None, gemini_enable_code_execution: None,
        gemini_thinking_budget: None, encrypted_dek: None, dek_nonce: None, encrypted_title: None,
        title_nonce: None, encrypted_system_prompt: None, system_prompt_nonce: None,
    };
    let session: DbChat = diesel::insert_into(chats::table)
        .values(&new_chat)
        .get_result(&mut conn)
        .expect("Error saving new chat session");

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&body).expect("Failed to deserialize settings response");

    // For a new chat session with no settings explicitly set via API,
    // optional fields in ChatSettingsResponse should be None.
    // Non-optional fields (history strategy/limit) will have their DB defaults.
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
    assert_eq!(settings_resp.model_name, None); // Default model_name is None
    // Check history fields (should be defaults from DB migration)
    assert_eq!(settings_resp.history_management_strategy, "none");
    assert_eq!(settings_resp.history_management_limit, 20);
}

#[tokio::test]
async fn test_get_chat_settings_not_found() {
    let test_app = test_helpers::spawn_app(false, false).await;
    let _user = test_helpers::db::create_test_user( // User needed for login
        &test_app.db_pool,
        "get_settings_404_user",
        "password",
    )
    .await;

    let login_payload = serde_json::json!({
        "identifier": "get_settings_404_user",
        "password": "password"
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
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    let non_existent_session_id = Uuid::new_v4();
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", non_existent_session_id))
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_chat_settings_forbidden() {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().expect("Failed to get DB connection");
    
    let user_a = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "get_settings_forbid_user_a",
        "password",
    )
    .await;
    
    // Login User A (not strictly needed for this test's core logic but good practice)
    let login_payload_a = serde_json::json!({ "identifier": "get_settings_forbid_user_a", "password": "password" });
    let login_request_a = Request::builder().method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload_a).unwrap())).unwrap();
    let login_response_a = test_app.router.clone().oneshot(login_request_a).await.unwrap();
    assert_eq!(login_response_a.status(), StatusCode::OK);
    
    let new_character_a = NewCharacter {
        user_id: user_a.id, name: "Get Settings Forbidden Char A".to_string(),
        description: None, persona: None, world_scenario: None, greeting_message: None,
        example_dialogue: None, avatar_uri: None, voice_id: None, visual_description: None,
        system_prompt_override: None, is_public: Some(false), data: None, user_persona: None,
        chat_persona: None, custom_tags: None, known_facts: None,
    };
    let char_a: DbCharacter = diesel::insert_into(characters::table)
        .values(&new_character_a).get_result(&mut conn).expect("Error saving char_a");

    let new_chat_a = NewChat {
        user_id: user_a.id, character_id: char_a.id, title: Some("Chat A".to_string()),
        system_prompt: None, temperature: None, max_output_tokens: None, frequency_penalty: None,
        presence_penalty: None, top_k: None, top_p: None, repetition_penalty: None, min_p: None,
        top_a: None, seed: None, logit_bias: None, history_management_strategy: None,
        history_management_limit: None, model_name: None, gemini_enable_code_execution: None,
        gemini_thinking_budget: None, encrypted_dek: None, dek_nonce: None, encrypted_title: None,
        title_nonce: None, encrypted_system_prompt: None, system_prompt_nonce: None,
    };
    let session_a: DbChat = diesel::insert_into(chats::table)
        .values(&new_chat_a).get_result(&mut conn).expect("Error saving session_a");

    let _user_b = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "get_settings_forbid_user_b",
        "password",
    )
    .await;
    let login_payload_b = serde_json::json!({ "identifier": "get_settings_forbid_user_b", "password": "password" });
    let login_request_b = Request::builder().method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload_b).unwrap())).unwrap();
    let login_response_b = test_app.router.clone().oneshot(login_request_b).await.unwrap();
    assert_eq!(login_response_b.status(), StatusCode::OK);
    let auth_cookie_b = login_response_b.headers().get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present").to_str().unwrap().to_string();

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", session_a.id)) 
        .header(header::COOKIE, auth_cookie_b)
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND); // Service layer returns NotFound for auth failure on GET
}


// --- Tests for PUT /api/chats/{id}/settings ---

#[tokio::test]
async fn update_chat_settings_success_full() {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().expect("Failed to get DB connection");
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "update_settings_user",
        "password",
    )
    .await;
    
    let login_payload = serde_json::json!({ "identifier": "update_settings_user", "password": "password" });
    let login_request = Request::builder().method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap())).unwrap();
    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response.headers().get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present").to_str().unwrap().to_string();
    
    let new_character = NewCharacter {
        user_id: user.id, name: "Update Settings Char".to_string(),
        description: None, persona: None, world_scenario: None, greeting_message: None,
        example_dialogue: None, avatar_uri: None, voice_id: None, visual_description: None,
        system_prompt_override: None, is_public: Some(false), data: None, user_persona: None,
        chat_persona: None, custom_tags: None, known_facts: None,
    };
    let character: DbCharacter = diesel::insert_into(characters::table)
        .values(&new_character).get_result(&mut conn).expect("Error saving character");

    let new_chat_model = NewChat { // Renamed to avoid conflict with new_chat module
        user_id: user.id, character_id: character.id, title: Some("Chat to Update".to_string()),
        system_prompt: None, temperature: None, max_output_tokens: None, frequency_penalty: None,
        presence_penalty: None, top_k: None, top_p: None, repetition_penalty: None, min_p: None,
        top_a: None, seed: None, logit_bias: None, history_management_strategy: None,
        history_management_limit: None, model_name: None, gemini_enable_code_execution: None,
        gemini_thinking_budget: None, encrypted_dek: None, dek_nonce: None, encrypted_title: None,
        title_nonce: None, encrypted_system_prompt: None, system_prompt_nonce: None,
    };
    let session: DbChat = diesel::insert_into(chats::table)
        .values(&new_chat_model).get_result(&mut conn).expect("Error saving chat session");

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
    let new_logit_bias = serde_json::json!({ "20001": -50, "20002": 50 });
    let new_history_strategy = "sliding_window_messages".to_string();
    let new_history_limit = 10;

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
        history_management_strategy: Some(new_history_strategy.clone()),
        history_management_limit: Some(new_history_limit),
        model_name: None,
        gemini_enable_code_execution: None,
        gemini_thinking_budget: None,
    };
    
    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let fetched_chat: DbChat = chats::table
        .filter(chats::id.eq(session.id))
        .first(&mut conn)
        .expect("Error fetching chat session after update");

    // Assuming direct fields are updated if not encrypted, or service handles decryption for GET.
    // For direct DB check, we check the fields on DbChat model.
    // If E2EE is active for a field, its plaintext version on DbChat might be None,
    // and encrypted version would have data. Test might need adjustment if plaintext is None.
    // For now, assuming plaintext fields on DbChat reflect the latest state for non-encrypted items,
    // or that the service layer (during PUT) updates these plaintext DB columns too.
    assert_eq!(fetched_chat.system_prompt.as_deref(), Some(new_prompt));
    assert_eq!(fetched_chat.temperature, Some(new_temp));
    assert_eq!(fetched_chat.max_output_tokens, Some(new_tokens));
    assert_eq!(fetched_chat.frequency_penalty, Some(new_freq_penalty));
    assert_eq!(fetched_chat.presence_penalty, Some(new_pres_penalty));
    assert_eq!(fetched_chat.top_k, Some(new_top_k));
    assert_eq!(fetched_chat.top_p, Some(new_top_p));
    assert_eq!(fetched_chat.repetition_penalty, Some(new_rep_penalty));
    assert_eq!(fetched_chat.min_p, Some(new_min_p));
    assert_eq!(fetched_chat.top_a, Some(new_top_a));
    assert_eq!(fetched_chat.seed, Some(new_seed));
    assert_eq!(fetched_chat.logit_bias, Some(new_logit_bias));
    assert_eq!(fetched_chat.history_management_strategy, new_history_strategy);
    assert_eq!(fetched_chat.history_management_limit, new_history_limit);
}

#[tokio::test]
async fn update_chat_settings_success_partial() {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().expect("Failed to get DB connection");
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "update_partial_user",
        "password",
    )
    .await;
    
    let login_payload = serde_json::json!({ "identifier": "update_partial_user", "password": "password" });
    let login_request = Request::builder().method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap())).unwrap();
    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response.headers().get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present").to_str().unwrap().to_string();
    
    let new_character = NewCharacter {
        user_id: user.id, name: "Update Partial Char".to_string(),
        description: None, persona: None, world_scenario: None, greeting_message: None,
        example_dialogue: None, avatar_uri: None, voice_id: None, visual_description: None,
        system_prompt_override: Some("Initial System Prompt".to_string()), // Give it an initial value
        is_public: Some(false), data: None, user_persona: None,
        chat_persona: None, custom_tags: None, known_facts: None,
    };
    let character: DbCharacter = diesel::insert_into(characters::table)
        .values(&new_character).get_result(&mut conn).expect("Error saving character");

    let new_chat_model = NewChat {
        user_id: user.id, character_id: character.id, title: Some("Chat Partial Update".to_string()),
        system_prompt: Some("Initial System Prompt".to_string()), // Initial value for a setting
        temperature: Some(BigDecimal::from_str("0.5").unwrap()), // Initial value
        max_output_tokens: Some(512), // Initial value
        history_management_strategy: Some("token_limit".to_string()), // Initial value
        history_management_limit: Some(1000), // Initial value
        frequency_penalty: None, presence_penalty: None, top_k: None, top_p: None,
        repetition_penalty: None, min_p: None, top_a: None, seed: None, logit_bias: None,
        model_name: None, gemini_enable_code_execution: None, gemini_thinking_budget: None,
        encrypted_dek: None, dek_nonce: None, encrypted_title: None, title_nonce: None,
        encrypted_system_prompt: None, system_prompt_nonce: None,
    };
    let session: DbChat = diesel::insert_into(chats::table)
        .values(&new_chat_model).get_result(&mut conn).expect("Error saving chat session");

    let initial_chat_state: DbChat = chats::table
        .filter(chats::id.eq(session.id))
        .first(&mut conn)
        .expect("Error fetching initial chat session state");

    let new_temp = BigDecimal::from_str("1.2").unwrap();
    let payload = UpdateChatSettingsRequest {
        system_prompt: None, 
        temperature: Some(new_temp.clone()),
        max_output_tokens: None, 
        frequency_penalty: None, presence_penalty: None, top_k: None, top_p: None,
        repetition_penalty: None, min_p: None, top_a: None, seed: None, logit_bias: None,
        history_management_strategy: None, history_management_limit: None, model_name: None,
        gemini_enable_code_execution: None, gemini_thinking_budget: None,
    };
    
    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let updated_chat_state: DbChat = chats::table
        .filter(chats::id.eq(session.id))
        .first(&mut conn)
        .expect("Error fetching updated chat session state");

    assert_eq!(updated_chat_state.system_prompt, initial_chat_state.system_prompt); 
    assert_eq!(updated_chat_state.temperature, Some(new_temp)); 
    assert_eq!(updated_chat_state.max_output_tokens, initial_chat_state.max_output_tokens); 
    assert_eq!(updated_chat_state.history_management_strategy, initial_chat_state.history_management_strategy);
    assert_eq!(updated_chat_state.history_management_limit, initial_chat_state.history_management_limit);
}

#[tokio::test]
async fn update_chat_settings_invalid_data() {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().expect("Failed to get DB connection");
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "update_invalid_user",
        "password",
    )
    .await;
    
    let login_payload = serde_json::json!({ "identifier": "update_invalid_user", "password": "password" });
    let login_request = Request::builder().method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap())).unwrap();
    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response.headers().get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present").to_str().unwrap().to_string();
    
    let new_character = NewCharacter {
        user_id: user.id, name: "Update Invalid Char".to_string(),
        description: None, persona: None, world_scenario: None, greeting_message: None,
        example_dialogue: None, avatar_uri: None, voice_id: None, visual_description: None,
        system_prompt_override: None, is_public: Some(false), data: None, user_persona: None,
        chat_persona: None, custom_tags: None, known_facts: None,
    };
    let character: DbCharacter = diesel::insert_into(characters::table)
        .values(&new_character).get_result(&mut conn).expect("Error saving character");

    let new_chat_model = NewChat {
        user_id: user.id, character_id: character.id, title: Some("Chat Invalid Update".to_string()),
        system_prompt: None, temperature: None, max_output_tokens: None, frequency_penalty: None,
        presence_penalty: None, top_k: None, top_p: None, repetition_penalty: None, min_p: None,
        top_a: None, seed: None, logit_bias: None, history_management_strategy: None,
        history_management_limit: None, model_name: None, gemini_enable_code_execution: None,
        gemini_thinking_budget: None, encrypted_dek: None, dek_nonce: None, encrypted_title: None,
        title_nonce: None, encrypted_system_prompt: None, system_prompt_nonce: None,
    };
    let session: DbChat = diesel::insert_into(chats::table)
        .values(&new_chat_model).get_result(&mut conn).expect("Error saving chat session");

    // Note: The original file had a truncated invalid_payloads. 
    // This test will only use the first entry if that's all that was provided.
    // For a more complete test, all original invalid_payloads entries would be needed.
    let invalid_payloads = vec![
        UpdateChatSettingsRequest {
            system_prompt: None,
            temperature: Some(BigDecimal::from_str("-0.1").unwrap()), // Negative temperature
            max_output_tokens: None, frequency_penalty: None, presence_penalty: None,
            top_k: None, top_p: None, repetition_penalty: None, min_p: None, top_a: None,
            seed: None, logit_bias: None, history_management_strategy: None,
            history_management_limit: None, model_name: None, gemini_enable_code_execution: None,
            gemini_thinking_budget: None,
        },
        // Example of another invalid payload (max_output_tokens too low)
        UpdateChatSettingsRequest {
            temperature: None, max_output_tokens: Some(0), // Assuming 0 is invalid
            ..Default::default() // Fill others with None or valid defaults if needed
        },
        // Example for history_management_strategy (invalid value)
        UpdateChatSettingsRequest {
            history_management_strategy: Some("invalid_strategy_value".to_string()),
            ..Default::default()
        },
        // Example for history_management_limit (invalid value, e.g. negative)
        UpdateChatSettingsRequest {
            history_management_limit: Some(-5),
            ..Default::default()
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

        let response = test_app.router.clone().oneshot(request).await.unwrap();
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
async fn update_chat_settings_forbidden() {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().expect("Failed to get DB connection");
    
    let user1 = test_helpers::db::create_test_user(
        &test_app.db_pool, "update_settings_user1", "password").await;
    
    let login_payload1 = serde_json::json!({ "identifier": "update_settings_user1", "password": "password" });
    let login_request1 = Request::builder().method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload1).unwrap())).unwrap();
    let login_response1 = test_app.router.clone().oneshot(login_request1).await.unwrap();
    assert_eq!(login_response1.status(), StatusCode::OK);
    // let _auth_cookie1 = login_response1.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
    
    let new_character1 = NewCharacter {
        user_id: user1.id, name: "Update Settings Char 1".to_string(),
        description: None, persona: None, world_scenario: None, greeting_message: None,
        example_dialogue: None, avatar_uri: None, voice_id: None, visual_description: None,
        system_prompt_override: None, is_public: Some(false), data: None, user_persona: None,
        chat_persona: None, custom_tags: None, known_facts: None,
    };
    let character1: DbCharacter = diesel::insert_into(characters::table)
        .values(&new_character1).get_result(&mut conn).expect("Error saving character1");

    let new_chat1 = NewChat {
        user_id: user1.id, character_id: character1.id, title: Some("Chat1".to_string()),
        system_prompt: None, temperature: None, max_output_tokens: None, frequency_penalty: None,
        presence_penalty: None, top_k: None, top_p: None, repetition_penalty: None, min_p: None,
        top_a: None, seed: None, logit_bias: None, history_management_strategy: None,
        history_management_limit: None, model_name: None, gemini_enable_code_execution: None,
        gemini_thinking_budget: None, encrypted_dek: None, dek_nonce: None, encrypted_title: None,
        title_nonce: None, encrypted_system_prompt: None, system_prompt_nonce: None,
    };
    let session1: DbChat = diesel::insert_into(chats::table)
        .values(&new_chat1).get_result(&mut conn).expect("Error saving session1");
            
    let _user2 = test_helpers::db::create_test_user(
        &test_app.db_pool, "update_settings_user2", "password").await;
    
    let login_payload2 = serde_json::json!({ "identifier": "update_settings_user2", "password": "password" });
    let login_request2 = Request::builder().method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload2).unwrap())).unwrap();
    let login_response2 = test_app.router.clone().oneshot(login_request2).await.unwrap();
    assert_eq!(login_response2.status(), StatusCode::OK);
    let auth_cookie2 = login_response2.headers().get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present").to_str().unwrap().to_string();

    let payload = UpdateChatSettingsRequest {
        system_prompt: Some("Attempted Update".to_string()),
        temperature: None, max_output_tokens: None, frequency_penalty: None, presence_penalty: None,
        top_k: None, top_p: None, repetition_penalty: None, min_p: None, top_a: None,
        seed: None, logit_bias: None, history_management_strategy: None,
        history_management_limit: None, model_name: None, gemini_enable_code_execution: None,
        gemini_thinking_budget: None,
    };
    
    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session1.id)) 
        .header(header::COOKIE, auth_cookie2)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();
    // The service layer should return FORBIDDEN if the user does not own the chat session.
    // Or NOT_FOUND if the query `WHERE id = ? AND user_id = ?` finds 0 rows.
    // The original comment said "Handler returns NotFound if update affects 0 rows due to ownership check"
    // Let's stick to FORBIDDEN as a more accurate HTTP status for this scenario.
    // If the service layer's `UPDATE ... WHERE id = ? AND user_id = ?` affects 0 rows,
    // it might indeed return a 404 if it then tries to fetch the updated record and fails.
    // The original test asserted FORBIDDEN. Let's keep that.
    assert_eq!(response.status(), StatusCode::FORBIDDEN); 
}

#[tokio::test]
async fn update_chat_settings_not_found() {
    let test_app = test_helpers::spawn_app(false, false).await;
    // No need for mut conn if no DB entities are created for this specific test path
    let _user = test_helpers::db::create_test_user( // User for login
        &test_app.db_pool,
        "update_settings_404_user",
        "password",
    )
    .await;
    
    let login_payload = serde_json::json!({ "identifier": "update_settings_404_user", "password": "password" });
    let login_request = Request::builder().method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap())).unwrap();
    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response.headers().get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present").to_str().unwrap().to_string();
    
    let non_existent_session_id = Uuid::new_v4();

    let payload = UpdateChatSettingsRequest {
        system_prompt: Some("Attempted Update".to_string()),
        temperature: None, max_output_tokens: None, frequency_penalty: None, presence_penalty: None,
        top_k: None, top_p: None, repetition_penalty: None, min_p: None, top_a: None,
        seed: None, logit_bias: None, history_management_strategy: None,
        history_management_limit: None, model_name: None, gemini_enable_code_execution: None,
        gemini_thinking_budget: None,
    };
    
    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", non_existent_session_id))
        .header(header::COOKIE, auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn update_chat_settings_unauthorized() {
    let test_app = test_helpers::spawn_app(false, false).await;
    let session_id = Uuid::new_v4(); 

    let payload = UpdateChatSettingsRequest {
        system_prompt: Some("Attempted Update".to_string()),
        temperature: None, max_output_tokens: None, frequency_penalty: None, presence_penalty: None,
        top_k: None, top_p: None, repetition_penalty: None, min_p: None, top_a: None,
        seed: None, logit_bias: None, history_management_strategy: None,
        history_management_limit: None, model_name: None, gemini_enable_code_execution: None,
        gemini_thinking_budget: None,
    };
    
    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session_id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

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