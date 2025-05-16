#![cfg(test)]

// Common imports needed for settings tests
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use bigdecimal::BigDecimal;
use chrono::Utc;
use http_body_util::BodyExt;
use mime;
use serde_json; // Added for to_vec in set_history_settings
// Removed unused: use serde_json::{Value, json};
use std::str::FromStr;
use tower::ServiceExt;
use uuid::Uuid;

// Diesel and model imports
use diesel::prelude::*;
use scribe_backend::models::characters::Character as DbCharacter;
use scribe_backend::models::character_card::NewCharacter;
use scribe_backend::models::chats::{
    Chat as DbChat,
    NewChat, 
    ChatSettingsResponse, 
    UpdateChatSettingsRequest
};
use scribe_backend::schema::{characters, chat_sessions};
use scribe_backend::test_helpers;
use scribe_backend::services::chat_service;
use std::sync::Arc;
use scribe_backend::state::AppState;
use anyhow; // Added for Result in set_history_settings

// --- Tests for GET /api/chats/{id}/settings ---

#[tokio::test]
async fn get_chat_settings_success() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let conn_pool = test_app.db_pool.clone(); 

    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "get_settings_user".to_string(),
        "password".to_string(),
    )
    .await
    .expect("Failed to create test user");

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

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    let new_character_data = NewCharacter { 
        user_id: user.id,
        spec: "character_card_v2_get_success".to_string(),
        spec_version: "2.0.0".to_string(),
        name: "Get Settings Success Char".to_string(),
        visibility: Some("private".to_string()),
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
        description: None, description_nonce: None, personality: None, personality_nonce: None,
        scenario: None, scenario_nonce: None, first_mes: None, first_mes_nonce: None,
        mes_example: None, mes_example_nonce: None, creator_notes: None, creator_notes_nonce: None,
        system_prompt: None, system_prompt_nonce: None, post_history_instructions: None, post_history_instructions_nonce: None,
        tags: Some(vec![Some("test".to_string())]), creator: None, character_version: None, alternate_greetings: None,
        nickname: None, creator_notes_multilingual: None, source: None, group_only_greetings: None,
        creation_date: None, modification_date: None, extensions: None, persona: None, persona_nonce: None,
        world_scenario: None, world_scenario_nonce: None, avatar: None, chat: None, greeting: None, greeting_nonce: None,
        definition: None, definition_nonce: None, default_voice: None, category: None, definition_visibility: None,
        example_dialogue: None, example_dialogue_nonce: None, favorite: None, first_message_visibility: None,
        migrated_from: None, model_prompt: None, model_prompt_nonce: None, model_prompt_visibility: None,
        persona_visibility: None, sharing_visibility: None, status: None, system_prompt_visibility: None,
        system_tags: None, token_budget: None, usage_hints: None, user_persona: None, user_persona_nonce: None,
        user_persona_visibility: None, world_scenario_visibility: None,
    };
    
    let character_conn_pool = conn_pool.clone();
    let character: DbCharacter = character_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::insert_into(characters::table)
            .values(&new_character_data)
            .get_result::<DbCharacter>(actual_conn)
    }).await.expect("Interact failed for character insert").expect("Diesel query failed for character insert");

    let new_chat_data = NewChat { 
        id: Uuid::new_v4(),
        user_id: user.id,
        character_id: character.id,
        title: Some(format!("Chat with {}", character.name)),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        history_management_strategy: "truncate_summary".to_string(), 
        history_management_limit: 20, 
        model_name: "initial-model-for-get-success".to_string(), 
        visibility: Some("private".to_string()), 
    };
    let new_chat_data_clone = new_chat_data.clone(); 
    let session_conn_pool = conn_pool.clone();
    let session: DbChat = session_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::insert_into(chat_sessions::table)
            .values(&new_chat_data_clone)
            .returning(DbChat::as_returning()) 
            .get_result(actual_conn)
    }).await.expect("Interact failed for chat insert").expect("Diesel query failed for chat insert");

    let session_id_for_update = session.id;
    let update_conn_pool = conn_pool.clone();
    update_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::update(chat_sessions::table.find(session_id_for_update))
            .set((
                chat_sessions::system_prompt.eq(Some("Test System Prompt".to_string())),
                chat_sessions::temperature.eq(Some(BigDecimal::from_str("0.9").unwrap())),
                chat_sessions::max_output_tokens.eq(Some(1024_i32)),
                chat_sessions::frequency_penalty.eq(Some(BigDecimal::from_str("0.3").unwrap())),
                chat_sessions::presence_penalty.eq(Some(BigDecimal::from_str("0.2").unwrap())),
                chat_sessions::top_k.eq(Some(40_i32)),
                chat_sessions::top_p.eq(Some(BigDecimal::from_str("0.95").unwrap())),
                chat_sessions::repetition_penalty.eq(Some(BigDecimal::from_str("1.1").unwrap())),
                chat_sessions::min_p.eq(Some(BigDecimal::from_str("0.01").unwrap())),
                chat_sessions::top_a.eq(Some(BigDecimal::from_str("0.1").unwrap())),
                chat_sessions::seed.eq(Some(12345_i32)),
                chat_sessions::logit_bias.eq(Some(serde_json::json!({ "20001": -50, "20002": 50 }))),
                chat_sessions::model_name.eq("gemini-2.5-flash-preview-04-17".to_string()), 
                chat_sessions::history_management_strategy.eq("truncate_summary".to_string()), 
                chat_sessions::history_management_limit.eq(20), 
                chat_sessions::gemini_thinking_budget.eq(Some(30_i32)),
                chat_sessions::gemini_enable_code_execution.eq(Some(true)),
            ))
            .execute(actual_conn)
    }).await.expect("Interact failed for chat update").expect("Diesel query failed for chat update");
    
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&body).expect("Failed to deserialize settings response");

    assert_eq!(settings_resp.system_prompt, Some("Test System Prompt".to_string()));
    assert_eq!(settings_resp.temperature, Some(BigDecimal::from_str("0.9").unwrap()));
    assert_eq!(settings_resp.max_output_tokens, Some(1024_i32));
    assert_eq!(settings_resp.frequency_penalty, Some(BigDecimal::from_str("0.3").unwrap()));
    assert_eq!(settings_resp.presence_penalty, Some(BigDecimal::from_str("0.2").unwrap()));
    assert_eq!(settings_resp.top_k, Some(40_i32));
    assert_eq!(settings_resp.top_p, Some(BigDecimal::from_str("0.95").unwrap()));
    assert_eq!(settings_resp.repetition_penalty, Some(BigDecimal::from_str("1.1").unwrap()));
    assert_eq!(settings_resp.min_p, Some(BigDecimal::from_str("0.01").unwrap()));
    assert_eq!(settings_resp.top_a, Some(BigDecimal::from_str("0.1").unwrap()));
    assert_eq!(settings_resp.seed, Some(12345_i32));
    assert_eq!(settings_resp.logit_bias, Some(serde_json::json!({ "20001": -50, "20002": 50 })) );
    assert_eq!(settings_resp.model_name, "gemini-2.5-flash-preview-04-17".to_string());
    assert_eq!(settings_resp.history_management_strategy, "truncate_summary");
    assert_eq!(settings_resp.history_management_limit, 20);
    assert_eq!(settings_resp.gemini_thinking_budget, Some(30_i32));
    assert_eq!(settings_resp.gemini_enable_code_execution, Some(true));
}

#[tokio::test]
async fn get_chat_settings_defaults() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let conn_pool = test_app.db_pool.clone();
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "get_defaults_user".to_string(),
        "password".to_string(),
    )
    .await
    .expect("Failed to create test user");

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

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    let character_default_description = "This is the character\'s default description.".to_string();

    let new_character_data = NewCharacter {
        user_id: user.id,
        spec: "character_card_v2_get_defaults".to_string(),
        spec_version: "2.0.0".to_string(),
        name: "Get Defaults Char".to_string(),
        visibility: Some("private".to_string()),
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
        description: Some(character_default_description.as_bytes().to_vec()), 
        description_nonce: None,
        personality: None, personality_nonce: None,
        scenario: None, scenario_nonce: None, first_mes: None, first_mes_nonce: None,
        mes_example: None, mes_example_nonce: None, creator_notes: None, creator_notes_nonce: None,
        system_prompt: None, system_prompt_nonce: None, 
        post_history_instructions: None, post_history_instructions_nonce: None,
        tags: Some(vec![Some("test".to_string())]), creator: None, character_version: None, alternate_greetings: None,
        nickname: None, creator_notes_multilingual: None, source: None, group_only_greetings: None,
        creation_date: None, modification_date: None, extensions: None, persona: None, persona_nonce: None,
        world_scenario: None, world_scenario_nonce: None, avatar: None, chat: None, greeting: None, greeting_nonce: None,
        definition: None, definition_nonce: None, default_voice: None, category: None, definition_visibility: None,
        example_dialogue: None, example_dialogue_nonce: None, favorite: None, first_message_visibility: None,
        migrated_from: None, model_prompt: None, model_prompt_nonce: None, model_prompt_visibility: None,
        persona_visibility: None, sharing_visibility: None, status: None, system_prompt_visibility: None,
        system_tags: None, token_budget: None, usage_hints: None, user_persona: None, user_persona_nonce: None,
        user_persona_visibility: None, world_scenario_visibility: None,
    };
    let char_conn_pool = conn_pool.clone();
    let character: DbCharacter = char_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::insert_into(characters::table)
            .values(&new_character_data)
            .get_result::<DbCharacter>(actual_conn)
    }).await.expect("Interact char insert failed").expect("Diesel char insert failed");

    let new_chat_data = NewChat {
        id: Uuid::new_v4(),
        user_id: user.id,
        character_id: character.id,
        title: Some(format!("Default Chat with {}", character.name)),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        history_management_strategy: "token_limit".to_string(), 
        history_management_limit: 1000, 
        model_name: "scribe-default-model".to_string(), 
        visibility: Some("private".to_string()),
    };
    let new_chat_data_clone = new_chat_data.clone();
    let session_conn_pool = conn_pool.clone();
    let _session: DbChat = session_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::insert_into(chat_sessions::table)
            .values(&new_chat_data_clone)
            .returning(DbChat::as_returning())
            .get_result(actual_conn)
    }).await.expect("Interact chat insert failed").expect("Diesel chat insert failed");

    // Construct AppState for the service call
    let app_state_for_service = AppState {
        pool: test_app.db_pool.clone(),
        config: test_app.config.clone(),
        ai_client: test_app.ai_client.clone(),
        embedding_client: test_app.mock_embedding_client.clone(),
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone(),
        embedding_call_tracker: test_app.embedding_call_tracker.clone(),
        token_counter: Arc::new(scribe_backend::services::hybrid_token_counter::HybridTokenCounter::new_local_only(
            scribe_backend::services::tokenizer_service::TokenizerService::new("/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model")
                .expect("Failed to create tokenizer for test"))),
    };

    let created_chat_session = chat_service::create_session_and_maybe_first_message(
        Arc::new(app_state_for_service), 
        user.id, 
        character.id, 
        None
    ).await.expect("Failed to create chat session via service");

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", created_chat_session.id))
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&body).expect("Failed to deserialize settings response");

    assert_eq!(settings_resp.system_prompt, Some(character_default_description)); 
    
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
    
    assert_eq!(settings_resp.model_name, "gemini-2.5-pro-preview-03-25"); 
    assert_eq!(settings_resp.history_management_strategy, "message_window"); 
    assert_eq!(settings_resp.history_management_limit, 20); 
    
    assert_eq!(settings_resp.gemini_thinking_budget, None); 
    assert_eq!(settings_resp.gemini_enable_code_execution, None); 
}

#[tokio::test]
async fn test_get_chat_settings_not_found() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "get_settings_404_user".to_string(),
        "password".to_string(),
    )
    .await
    .expect("Failed to create test user for 404 test");

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
    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
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

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    // For non-existent chat IDs (test case), the API returns NOT_FOUND
    // (For existing chat IDs owned by someone else, it returns FORBIDDEN)
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_chat_settings_forbidden() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let conn_pool = test_app.db_pool.clone();
    
    let user_a = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "get_settings_forbid_usera".to_string(),
        "password".to_string(),
    )
    .await.expect("Failed to create user_a");
    
    let _user_b = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "get_settings_forbid_userb".to_string(),
        "password".to_string(),
    )
    .await.expect("Failed to create user_b");

    let login_payload_b = serde_json::json!({ "identifier": "get_settings_forbid_userb", "password": "password" });
    let login_request2 = Request::builder().method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload_b).unwrap())).unwrap();
    let login_response2 = test_app.router.clone().oneshot(login_request2).await.unwrap();
    assert_eq!(login_response2.status(), StatusCode::OK);
    let auth_cookie2 = login_response2.headers().get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present").to_str().unwrap().to_string();
    
    let new_character_a_data = NewCharacter {
        user_id: user_a.id,
        spec: "character_card_v2_get_forbidden".to_string(),
        spec_version: "2.0.0".to_string(),
        name: "Get Settings Forbidden Char A".to_string(),
        visibility: Some("private".to_string()),
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
        description: None, description_nonce: None, personality: None, personality_nonce: None,
        scenario: None, scenario_nonce: None, first_mes: None, first_mes_nonce: None,
        mes_example: None, mes_example_nonce: None, creator_notes: None, creator_notes_nonce: None,
        system_prompt: None, system_prompt_nonce: None, post_history_instructions: None, post_history_instructions_nonce: None,
        tags: Some(vec![Some("test".to_string())]), creator: None, character_version: None, alternate_greetings: None,
        nickname: None, creator_notes_multilingual: None, source: None, group_only_greetings: None,
        creation_date: None, modification_date: None, extensions: None, persona: None, persona_nonce: None,
        world_scenario: None, world_scenario_nonce: None, avatar: None, chat: None, greeting: None, greeting_nonce: None,
        definition: None, definition_nonce: None, default_voice: None, category: None, definition_visibility: None,
        example_dialogue: None, example_dialogue_nonce: None, favorite: None, first_message_visibility: None,
        migrated_from: None, model_prompt: None, model_prompt_nonce: None, model_prompt_visibility: None,
        persona_visibility: None, sharing_visibility: None, status: None, system_prompt_visibility: None,
        system_tags: None, token_budget: None, usage_hints: None, user_persona: None, user_persona_nonce: None,
        user_persona_visibility: None, world_scenario_visibility: None,
    };
    let char_a_conn_pool = conn_pool.clone();
    let char_a: DbCharacter = char_a_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::insert_into(characters::table)
            .values(&new_character_a_data).get_result::<DbCharacter>(actual_conn)
    }).await.expect("Interact char_a insert failed").expect("Diesel char_a insert failed");

    let new_chat_a_data = NewChat {
        id: Uuid::new_v4(),
        user_id: user_a.id,
        character_id: char_a.id,
        title: Some("User1 Chat Session Forbid Test".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        history_management_strategy: "token_limit".to_string(),
        history_management_limit: 10, 
        model_name: "forbidden-model".to_string(),
        visibility: Some("private".to_string()),
    };
    let new_chat_a_data_clone = new_chat_a_data.clone();
    let session_a_conn_pool = conn_pool.clone();
    let session_a: DbChat = session_a_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::insert_into(chat_sessions::table)
            .values(&new_chat_a_data_clone).returning(DbChat::as_returning()).get_result(actual_conn)
    }).await.expect("Interact session_a insert failed").expect("Diesel session_a insert failed");

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", session_a.id)) 
        .header(header::COOKIE, auth_cookie2)
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    // For existing chat IDs owned by someone else, the endpoint returns FORBIDDEN
    // (For non-existent chat IDs, it returns NOT_FOUND)
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}


// --- Tests for PUT /api/chats/{id}/settings ---

#[tokio::test]
async fn update_chat_settings_success_full() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let conn_pool = test_app.db_pool.clone();
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "update_settings_user".to_string(),
        "password".to_string(),
    )
    .await
    .expect("Failed to create test user");
    
    let login_payload = serde_json::json!({ "identifier": "update_settings_user", "password": "password" });
    let login_request = Request::builder().method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap())).unwrap();
    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response.headers().get(header::SET_COOKIE).expect("Set-Cookie header should be present").to_str().unwrap().to_string();

    let new_character_data = NewCharacter {
        user_id: user.id,
        spec: "character_card_v2_update_full".to_string(),
        spec_version: "2.0.0".to_string(),
        name: "Update Full Settings Char".to_string(),
        visibility: Some("private".to_string()),
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
        description: None, description_nonce: None, personality: None, personality_nonce: None,
        scenario: None, scenario_nonce: None, first_mes: None, first_mes_nonce: None,
        mes_example: None, mes_example_nonce: None, creator_notes: None, creator_notes_nonce: None,
        system_prompt: None, system_prompt_nonce: None, post_history_instructions: None, post_history_instructions_nonce: None,
        tags: Some(vec![Some("test".to_string())]), creator: None, character_version: None, alternate_greetings: None,
        nickname: None, creator_notes_multilingual: None, source: None, group_only_greetings: None,
        creation_date: None, modification_date: None, extensions: None, persona: None, persona_nonce: None,
        world_scenario: None, world_scenario_nonce: None, avatar: None, chat: None, greeting: None, greeting_nonce: None,
        definition: None, definition_nonce: None, default_voice: None, category: None, definition_visibility: None,
        example_dialogue: None, example_dialogue_nonce: None, favorite: None, first_message_visibility: None,
        migrated_from: None, model_prompt: None, model_prompt_nonce: None, model_prompt_visibility: None,
        persona_visibility: None, sharing_visibility: None, status: None, system_prompt_visibility: None,
        system_tags: None, token_budget: None, usage_hints: None, user_persona: None, user_persona_nonce: None,
        user_persona_visibility: None, world_scenario_visibility: None,
    };
    let char_conn_pool = conn_pool.clone();
    let character: DbCharacter = char_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::insert_into(characters::table)
            .values(&new_character_data)
            .get_result::<DbCharacter>(actual_conn)
    }).await.expect("Interact char insert failed").expect("Diesel char insert failed");

    let new_chat_data = NewChat {
        id: Uuid::new_v4(),
        user_id: user.id,
        character_id: character.id,
        title: Some(format!("Update Test Chat Full with {}", character.name)),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        history_management_strategy: "token_limit".to_string(), 
        history_management_limit: 10, 
        model_name: "initial-model".to_string(), 
        visibility: Some("private".to_string()),
    };
    let new_chat_data_clone = new_chat_data.clone();
    let session_conn_pool = conn_pool.clone();
    let session: DbChat = session_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::insert_into(chat_sessions::table)
            .values(&new_chat_data_clone)
            .returning(DbChat::as_returning())
            .get_result(actual_conn)
    }).await.expect("Interact chat insert failed").expect("Diesel chat insert failed");

    let update_data = UpdateChatSettingsRequest {
        system_prompt: Some("Updated System Prompt".to_string()),
        temperature: Some(BigDecimal::from_str("0.75").unwrap()),
        max_output_tokens: Some(512_i32),
        frequency_penalty: Some(BigDecimal::from_str("0.15").unwrap()),
        presence_penalty: Some(BigDecimal::from_str("0.12").unwrap()),
        top_k: Some(30_i32),
        top_p: Some(BigDecimal::from_str("0.88").unwrap()),
        repetition_penalty: Some(BigDecimal::from_str("1.05").unwrap()),
        min_p: Some(BigDecimal::from_str("0.03").unwrap()),
        top_a: Some(BigDecimal::from_str("0.08").unwrap()),
        seed: Some(54321_i32),
        logit_bias: Some(serde_json::json!({ "30001": -20, "30002": 20})),
        model_name: Some("updated-model-name".to_string()),
        history_management_strategy: Some("token_limit".to_string()),
        history_management_limit: Some(100),
        gemini_thinking_budget: Some(60_i32),
        gemini_enable_code_execution: Some(false),
    };

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(serde_json::to_string(&update_data).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&body).expect("Failed to deserialize settings response");

    assert_eq!(settings_resp.system_prompt, Some("Updated System Prompt".to_string()));
    assert_eq!(settings_resp.temperature, Some(BigDecimal::from_str("0.75").unwrap()));
    assert_eq!(settings_resp.max_output_tokens, Some(512_i32));
    assert_eq!(settings_resp.model_name, "updated-model-name".to_string());
    assert_eq!(settings_resp.history_management_strategy, "token_limit");
    assert_eq!(settings_resp.history_management_limit, 100);
    assert_eq!(settings_resp.gemini_thinking_budget, Some(60_i32));
    assert_eq!(settings_resp.gemini_enable_code_execution, Some(false));
}

#[tokio::test]
async fn update_chat_settings_success_partial() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let conn_pool = test_app.db_pool.clone();
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "update_partial_user".to_string(),
        "password".to_string(),
    )
    .await
    .expect("Failed to create test user");
    
    let login_payload = serde_json::json!({ "identifier": "update_partial_user", "password": "password" });
    let login_request = Request::builder().method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap())).unwrap();
    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response.headers().get(header::SET_COOKIE).expect("Set-Cookie header should be present").to_str().unwrap().to_string();

    let new_character_data = NewCharacter {
        user_id: user.id,
        spec: "character_card_v2_update_partial".to_string(),
        spec_version: "2.0.0".to_string(),
        name: "Update Partial Settings Char".to_string(),
        visibility: Some("private".to_string()),
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
        description: None, description_nonce: None, personality: None, personality_nonce: None,
        scenario: None, scenario_nonce: None, first_mes: None, first_mes_nonce: None,
        mes_example: None, mes_example_nonce: None, creator_notes: None, creator_notes_nonce: None,
        system_prompt: None, system_prompt_nonce: None, post_history_instructions: None, post_history_instructions_nonce: None,
        tags: Some(vec![Some("test".to_string())]), creator: None, character_version: None, alternate_greetings: None,
        nickname: None, creator_notes_multilingual: None, source: None, group_only_greetings: None,
        creation_date: None, modification_date: None, extensions: None, persona: None, persona_nonce: None,
        world_scenario: None, world_scenario_nonce: None, avatar: None, chat: None, greeting: None, greeting_nonce: None,
        definition: None, definition_nonce: None, default_voice: None, category: None, definition_visibility: None,
        example_dialogue: None, example_dialogue_nonce: None, favorite: None, first_message_visibility: None,
        migrated_from: None, model_prompt: None, model_prompt_nonce: None, model_prompt_visibility: None,
        persona_visibility: None, sharing_visibility: None, status: None, system_prompt_visibility: None,
        system_tags: None, token_budget: None, usage_hints: None, user_persona: None, user_persona_nonce: None,
        user_persona_visibility: None, world_scenario_visibility: None,
    };
    let char_conn_pool = conn_pool.clone();
    let character: DbCharacter = char_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::insert_into(characters::table)
            .values(&new_character_data)
            .get_result::<DbCharacter>(actual_conn)
    }).await.expect("Interact char insert failed").expect("Diesel char insert failed");

    let initial_model_name = "initial-partial-model".to_string();
    let initial_system_prompt_val = "Initial System Prompt".to_string();
    let initial_temp_val = BigDecimal::from_str("0.5").unwrap();
    let initial_max_tokens_val = 100_i32;
    let initial_hist_strat_val = "none".to_string();
    let initial_hist_limit_val = 0_i32;


    let new_chat_data = NewChat {
        id: Uuid::new_v4(),
        user_id: user.id,
        character_id: character.id,
        title: Some(format!("Update Test Chat Partial with {}", character.name)),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        history_management_strategy: initial_hist_strat_val.clone(), 
        history_management_limit: initial_hist_limit_val,        
        model_name: initial_model_name.clone(), 
        visibility: Some("private".to_string()),
    };
    let new_chat_data_clone = new_chat_data.clone();
    let session_conn_pool = conn_pool.clone();
    let session: DbChat = session_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::insert_into(chat_sessions::table)
            .values(&new_chat_data_clone)
            .returning(DbChat::as_returning())
            .get_result(actual_conn)
    }).await.expect("Interact chat insert failed").expect("Diesel chat insert failed");

    let session_id_for_update = session.id;
    let update_conn_pool = conn_pool.clone();
    let initial_system_prompt_clone = initial_system_prompt_val.clone();
    let initial_temp_clone = initial_temp_val.clone();

    update_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::update(chat_sessions::table.find(session_id_for_update))
            .set((
                chat_sessions::system_prompt.eq(Some(initial_system_prompt_clone)),
                chat_sessions::temperature.eq(Some(initial_temp_clone)),
                chat_sessions::max_output_tokens.eq(Some(initial_max_tokens_val)),
            ))
            .execute(actual_conn)
    }).await.expect("Interact for initial chat settings update failed").expect("Diesel update for initial settings failed");


    let update_data = UpdateChatSettingsRequest {
        system_prompt: Some("Partially Updated System Prompt".to_string()),
        temperature: None, 
        max_output_tokens: Some(200), 
        frequency_penalty: None, presence_penalty: None, top_k: None, top_p: None,
        repetition_penalty: None, min_p: None, top_a: None, seed: None, logit_bias: None,
        model_name: None, 
        history_management_strategy: None, 
        history_management_limit: None,    
        gemini_thinking_budget: None, gemini_enable_code_execution: None,
    };

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(serde_json::to_string(&update_data).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&body).expect("Failed to deserialize settings response");

    assert_eq!(settings_resp.system_prompt, Some("Partially Updated System Prompt".to_string()));
    assert_eq!(settings_resp.max_output_tokens, Some(200));
    assert_eq!(settings_resp.temperature, Some(initial_temp_val)); 
    assert_eq!(settings_resp.model_name, initial_model_name);
    assert_eq!(settings_resp.history_management_strategy, initial_hist_strat_val);
    assert_eq!(settings_resp.history_management_limit, initial_hist_limit_val);
}

#[tokio::test]
async fn update_chat_settings_invalid_data() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let conn_pool = test_app.db_pool.clone();
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "update_invalid_user".to_string(),
        "password".to_string(),
    )
    .await
    .expect("Failed to create test user");
    
    let login_payload = serde_json::json!({ "identifier": "update_invalid_user", "password": "password" });
    let login_request = Request::builder().method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap())).unwrap();
    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response.headers().get(header::SET_COOKIE).expect("Set-Cookie header should be present").to_str().unwrap().to_string();

    let new_character_data = NewCharacter {
        user_id: user.id,
        spec: "character_card_v2_update_invalid".to_string(),
        spec_version: "2.0.0".to_string(),
        name: "Update Invalid Data Char".to_string(),
        visibility: Some("private".to_string()),
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
        description: None, description_nonce: None, personality: None, personality_nonce: None,
        scenario: None, scenario_nonce: None, first_mes: None, first_mes_nonce: None,
        mes_example: None, mes_example_nonce: None, creator_notes: None, creator_notes_nonce: None,
        system_prompt: None, system_prompt_nonce: None, post_history_instructions: None, post_history_instructions_nonce: None,
        tags: Some(vec![Some("test".to_string())]), creator: None, character_version: None, alternate_greetings: None,
        nickname: None, creator_notes_multilingual: None, source: None, group_only_greetings: None,
        creation_date: None, modification_date: None, extensions: None, persona: None, persona_nonce: None,
        world_scenario: None, world_scenario_nonce: None, avatar: None, chat: None, greeting: None, greeting_nonce: None,
        definition: None, definition_nonce: None, default_voice: None, category: None, definition_visibility: None,
        example_dialogue: None, example_dialogue_nonce: None, favorite: None, first_message_visibility: None,
        migrated_from: None, model_prompt: None, model_prompt_nonce: None, model_prompt_visibility: None,
        persona_visibility: None, sharing_visibility: None, status: None, system_prompt_visibility: None,
        system_tags: None, token_budget: None, usage_hints: None, user_persona: None, user_persona_nonce: None,
        user_persona_visibility: None, world_scenario_visibility: None,
    };
    let char_conn_pool = conn_pool.clone();
    let character: DbCharacter = char_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::insert_into(characters::table)
            .values(&new_character_data)
            .get_result::<DbCharacter>(actual_conn)
    }).await.expect("Interact char insert failed").expect("Diesel char insert failed");

    let new_chat_data = NewChat {
        id: Uuid::new_v4(),
        user_id: user.id,
        character_id: character.id,
        title: Some(format!("Invalid Update Test Chat with {}", character.name)),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        history_management_strategy: "token_limit".to_string(), 
        history_management_limit: 10, 
        model_name: "invalid-data-model".to_string(), 
        visibility: Some("private".to_string()),
    };
    let new_chat_data_clone = new_chat_data.clone();
    let session_conn_pool = conn_pool.clone();
    let session: DbChat = session_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::insert_into(chat_sessions::table)
            .values(&new_chat_data_clone)
            .returning(DbChat::as_returning())
            .get_result(actual_conn)
    }).await.expect("Interact chat insert failed").expect("Diesel chat insert failed");

    let invalid_update_data = serde_json::json!({
        "temperature": "not_a_number"
    });

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session.id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(serde_json::to_string(&invalid_update_data).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn update_chat_settings_forbidden() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let conn_pool = test_app.db_pool.clone();
    
    let user1 = test_helpers::db::create_test_user(
        &test_app.db_pool, "update_settings_user1".to_string(), "password".to_string()).await.expect("user1 creation failed");
    
    let _user2 = test_helpers::db::create_test_user(
        &test_app.db_pool, "update_settings_user2".to_string(), "password".to_string()).await.expect("user2 creation failed");

    let login_payload2 = serde_json::json!({ "identifier": "update_settings_user2", "password": "password" });
    let login_request2 = Request::builder().method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload2).unwrap())).unwrap();
    let login_response2 = test_app.router.clone().oneshot(login_request2).await.unwrap();
    assert_eq!(login_response2.status(), StatusCode::OK);
    let auth_cookie2 = login_response2.headers().get(header::SET_COOKIE).expect("Set-Cookie header user2").to_str().unwrap().to_string();

    let new_character_user1_data = NewCharacter {
        user_id: user1.id,
        spec: "character_card_v2_update_forbidden".to_string(),
        spec_version: "2.0.0".to_string(),
        name: "Update Forbidden Settings Char".to_string(),
        visibility: Some("private".to_string()),
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
        description: None, description_nonce: None, personality: None, personality_nonce: None,
        scenario: None, scenario_nonce: None, first_mes: None, first_mes_nonce: None,
        mes_example: None, mes_example_nonce: None, creator_notes: None, creator_notes_nonce: None,
        system_prompt: None, system_prompt_nonce: None, post_history_instructions: None, post_history_instructions_nonce: None,
        tags: Some(vec![Some("test".to_string())]), creator: None, character_version: None, alternate_greetings: None,
        nickname: None, creator_notes_multilingual: None, source: None, group_only_greetings: None,
        creation_date: None, modification_date: None, extensions: None, persona: None, persona_nonce: None,
        world_scenario: None, world_scenario_nonce: None, avatar: None, chat: None, greeting: None, greeting_nonce: None,
        definition: None, definition_nonce: None, default_voice: None, category: None, definition_visibility: None,
        example_dialogue: None, example_dialogue_nonce: None, favorite: None, first_message_visibility: None,
        migrated_from: None, model_prompt: None, model_prompt_nonce: None, model_prompt_visibility: None,
        persona_visibility: None, sharing_visibility: None, status: None, system_prompt_visibility: None,
        system_tags: None, token_budget: None, usage_hints: None, user_persona: None, user_persona_nonce: None,
        user_persona_visibility: None, world_scenario_visibility: None,
    };
    let char1_conn_pool = conn_pool.clone();
    let character_user1: DbCharacter = char1_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::insert_into(characters::table)
            .values(&new_character_user1_data)
            .get_result::<DbCharacter>(actual_conn)
    }).await.expect("Interact char1 insert failed").expect("Diesel char1 insert failed");

    let new_chat_user1_data = NewChat {
        id: Uuid::new_v4(),
        user_id: user1.id,
        character_id: character_user1.id,
        title: Some("User1 Chat Session Forbid Test".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        history_management_strategy: "token_limit".to_string(),
        history_management_limit: 10, 
        model_name: "forbidden-model".to_string(),
        visibility: Some("private".to_string()),
    };
    let new_chat_user1_data_clone = new_chat_user1_data.clone();
    let session1_conn_pool = conn_pool.clone();
    let session_user1: DbChat = session1_conn_pool.get().await.unwrap().interact(move |actual_conn| {
        diesel::insert_into(chat_sessions::table)
            .values(&new_chat_user1_data_clone).returning(DbChat::as_returning()).get_result(actual_conn)
    }).await.expect("Interact session1 insert failed").expect("Diesel session1 insert failed");

    let update_data = UpdateChatSettingsRequest {
        system_prompt: Some("Attempted Update by User2".to_string()),
        temperature: None, max_output_tokens: None, frequency_penalty: None, presence_penalty: None, 
        top_k: None, top_p: None, repetition_penalty: None, min_p: None, top_a: None, seed: None, 
        logit_bias: None, model_name: None, history_management_strategy: None, 
        history_management_limit: None, gemini_thinking_budget: None, gemini_enable_code_execution: None,
    };

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session_user1.id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie2)
        .body(Body::from(serde_json::to_string(&update_data).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn update_chat_settings_not_found() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let _user = test_helpers::db::create_test_user( 
        &test_app.db_pool, "update_notfound_user".to_string(), "password".to_string()).await.expect("user creation failed");
    
    let login_payload = serde_json::json!({ "identifier": "update_notfound_user", "password": "password" });
    let login_request = Request::builder().method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap())).unwrap();
    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response.headers().get(header::SET_COOKIE).expect("Set-Cookie header").to_str().unwrap().to_string();

    let non_existent_session_id = Uuid::new_v4();
    let update_data = UpdateChatSettingsRequest {
        system_prompt: Some("Update for Non-existent Session".to_string()),
        temperature: None, max_output_tokens: None, frequency_penalty: None, presence_penalty: None, 
        top_k: None, top_p: None, repetition_penalty: None, min_p: None, top_a: None, seed: None, 
        logit_bias: None, model_name: None, history_management_strategy: None, 
        history_management_limit: None, gemini_thinking_budget: None, gemini_enable_code_execution: None,
    };

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", non_existent_session_id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(serde_json::to_string(&update_data).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_chat_settings_unauthorized() {
    let test_app = test_helpers::spawn_app(false, false, false).await;

    let session_id_for_unauth = Uuid::new_v4();

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}/settings", session_id_for_unauth))
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// Helper to set history management settings via API

#[tokio::test]
async fn update_chat_settings_unauthorized() {
    let test_app = test_helpers::spawn_app(false, false, false).await;

    let session_id_for_unauth = Uuid::new_v4();
    let update_data = UpdateChatSettingsRequest {
        system_prompt: Some("Unauthorized Update Attempt".to_string()),
        temperature: None, max_output_tokens: None, frequency_penalty: None, presence_penalty: None, 
        top_k: None, top_p: None, repetition_penalty: None, min_p: None, top_a: None, seed: None, 
        logit_bias: None, model_name: None, history_management_strategy: None, 
        history_management_limit: None, gemini_thinking_budget: None, gemini_enable_code_execution: None,
    };

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chats/{}/settings", session_id_for_unauth))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&update_data).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
