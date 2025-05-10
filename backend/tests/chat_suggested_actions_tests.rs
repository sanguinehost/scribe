#![cfg(test)]

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use diesel::prelude::*; // Added
use http_body_util::BodyExt;
use mime;
use serde_json::json;
use tower::ServiceExt;
use tower_cookies::Cookie;
use uuid::Uuid;

// Crate imports
use scribe_backend::{
    models::{
        auth::LoginPayload,
        characters::{Character as DbCharacter, NewCharacter, CharacterVisibility},
        chats::{ChatSession, ChatType, NewChat, SuggestedActionsRequest, SuggestedActionsResponse},
    },
    schema::{characters, chat_sessions},
    test_helpers::{self, TestApp, TestDataGuard},
};
use anyhow::Context as _;

#[tokio::test]
async fn test_suggested_actions_success() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().expect("Failed to get DB connection");

    let user_guard = TestDataGuard::new(
        test_helpers::db::create_test_user(
            &test_app.db_pool,
            "suggested_actions_user",
            "password",
        )
        .await?,
        test_app.db_pool.clone(),
    );
    let user = &user_guard.entity;

    // API Login
    let login_payload = json!({
        "identifier": user.username,
        "password": "password",
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload)?))?;
    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed");
    let raw_cookie_header = login_response
        .headers()
        .get(header::SET_COOKIE)
        .context("Set-Cookie header missing from login response")?
        .to_str()?;
    let parsed_cookie = Cookie::parse(raw_cookie_header.to_string())?;
    assert_eq!(parsed_cookie.name(), "id");
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());

    let new_character = NewCharacter {
        user_id: user.id,
        name: "Suggested Actions Character".to_string(),
        description: Some("A test character for suggested actions.".to_string()),
        system_prompt: Some("You are a helpful character.".to_string()),
        user_prompt: Some("User: {{userInput}}".to_string()),
        ai_prompt_prefix: Some("Character:".to_string()),
        ai_prompt_suffix: None,
        context_length: 1024,
        greeting: Some("Hello from Suggested Actions Character!".to_string()),
        avatar_url: None,
        visibility: CharacterVisibility::Private,
        data: None,
    };
    let character_guard = TestDataGuard::new(
        diesel::insert_into(characters::table)
            .values(&new_character)
            .get_result::<DbCharacter>(&mut conn)?,
        test_app.db_pool.clone(),
    );
    let character = &character_guard.entity;

    let new_chat_session = NewChat {
        user_id: user.id,
        character_id: Some(character.id),
        name: Some("Test Chat for Suggested Actions".to_string()),
        chat_type: ChatType::Character,
        model_name: Some("test-model-suggested".to_string()),
        system_prompt_override: None,
        temperature: None,
        top_p: None,
        top_k: None,
        max_output_tokens: None,
        history_compression_threshold: None,
    };
    let session_guard = TestDataGuard::new(
        diesel::insert_into(chat_sessions::table)
            .values(&new_chat_session)
            .get_result::<ChatSession>(&mut conn)?,
        test_app.db_pool.clone(),
    );
    let session = &session_guard.entity;

    // Mock AI response
    let mock_suggestions = json!([
        {"action": "Tell me more about your day"},
        {"action": "Ask about my hobbies"},
        {"action": "Show me a riddle"}
    ]);
    
    test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock client should be present")
        .set_response(Ok(genai::chat::ChatResponse {
            model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "gemini-2.5-flash-preview-04-17"),
            provider_model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "gemini-2.5-flash-preview-04-17"),
            content: Some(genai::chat::MessageContent::Text(mock_suggestions.to_string())),
            reasoning_content: None,
            usage: Default::default(),
        }));

    let payload = SuggestedActionsRequest {
        character_first_message: "Hello, I am a medieval wizard. What brings you to my tower?".to_string(),
        user_first_message: Some("I need help with a magical potion.".to_string()),
        ai_first_response: Some("Ah, potions! My specialty. What kind are you looking to brew?".to_string()),
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/suggested-actions", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload)?))?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await?.to_bytes();
    let suggested_actions: SuggestedActionsResponse =
        serde_json::from_slice(&body)?;

    assert!(!suggested_actions.suggestions.is_empty());
    assert_eq!(suggested_actions.suggestions.len(), 3);
    assert_eq!(suggested_actions.suggestions[0].action, "Tell me more about your day");
    assert_eq!(suggested_actions.suggestions[1].action, "Ask about my hobbies");
    assert_eq!(suggested_actions.suggestions[2].action, "Show me a riddle");
    Ok(())
}

#[tokio::test]
async fn test_suggested_actions_unauthorized() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().expect("Failed to get DB connection");

    let user_guard = TestDataGuard::new(
        test_helpers::db::create_test_user(
            &test_app.db_pool,
            "suggested_actions_unauth_user",
            "password",
        )
        .await?,
        test_app.db_pool.clone(),
    );
    let user = &user_guard.entity;

    let new_character = NewCharacter {
        user_id: user.id,
        name: "Unauth Actions Character".to_string(),
        description: Some("Test character".to_string()),
        system_prompt: Some("You are a test character.".to_string()),
        user_prompt: Some("User: {{userInput}}".to_string()),
        ai_prompt_prefix: Some("AI:".to_string()),
        ai_prompt_suffix: None,
        context_length: 1024,
        greeting: Some("Hello!".to_string()),
        avatar_url: None,
        visibility: CharacterVisibility::Private,
        data: None,
    };
    let character_guard = TestDataGuard::new(
        diesel::insert_into(characters::table)
            .values(&new_character)
            .get_result::<DbCharacter>(&mut conn)?,
        test_app.db_pool.clone(),
    );
    let character = &character_guard.entity;

    let new_chat_session = NewChat {
        user_id: user.id,
        character_id: Some(character.id),
        name: Some("Test Chat Unauth".to_string()),
        chat_type: ChatType::Character,
        model_name: Some("test-default-model".to_string()),
        system_prompt_override: None,
        temperature: None,
        top_p: None,
        top_k: None,
        max_output_tokens: None,
        history_compression_threshold: None,
    };
    let session_guard = TestDataGuard::new(
        diesel::insert_into(chat_sessions::table)
            .values(&new_chat_session)
            .get_result::<ChatSession>(&mut conn)?,
        test_app.db_pool.clone(),
    );
    let session = &session_guard.entity;

    let payload = SuggestedActionsRequest {
        character_first_message: "Hello there!".to_string(),
        user_first_message: Some("Hi".to_string()),
        ai_first_response: Some("How are you today?".to_string()),
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/suggested-actions", session.id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload)?))?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn test_suggested_actions_forbidden() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().expect("Failed to get DB connection");
    
    let user_a_guard = TestDataGuard::new(
        test_helpers::db::create_test_user(
            &test_app.db_pool,
            "suggested_actions_user_a",
            "password",
        )
        .await?,
        test_app.db_pool.clone(),
    );
    let user_a = &user_a_guard.entity;

    let new_character_a = NewCharacter {
        user_id: user_a.id,
        name: "User A Character".to_string(),
        description: Some("Test character for User A".to_string()),
        system_prompt: Some("You are User A's character.".to_string()),
        user_prompt: Some("User: {{userInput}}".to_string()),
        ai_prompt_prefix: Some("AI:".to_string()),
        ai_prompt_suffix: None,
        context_length: 1024,
        greeting: Some("Hello from User A's Character!".to_string()),
        avatar_url: None,
        visibility: CharacterVisibility::Private,
        data: None,
    };
    let character_a_guard = TestDataGuard::new(
        diesel::insert_into(characters::table)
            .values(&new_character_a)
            .get_result::<DbCharacter>(&mut conn)?,
        test_app.db_pool.clone(),
    );
    let character_a = &character_a_guard.entity;

    let new_chat_session_a = NewChat {
        user_id: user_a.id,
        character_id: Some(character_a.id),
        name: Some("Test Chat for User A".to_string()),
        chat_type: ChatType::Character,
        model_name: Some("test-model-user-a".to_string()),
        system_prompt_override: None,
        temperature: None,
        top_p: None,
        top_k: None,
        max_output_tokens: None,
        history_compression_threshold: None,
    };
    let session_a_guard = TestDataGuard::new(
        diesel::insert_into(chat_sessions::table)
            .values(&new_chat_session_a)
            .get_result::<ChatSession>(&mut conn)?,
        test_app.db_pool.clone(),
    );
    let session_a = &session_a_guard.entity;
    
    let user_b_guard = TestDataGuard::new(
        test_helpers::db::create_test_user(
            &test_app.db_pool,
            "suggested_actions_user_b",
            "password",
        )
        .await?,
        test_app.db_pool.clone(),
    );
    let user_b = &user_b_guard.entity;

    let login_payload_b = json!({
        "identifier": user_b.username,
        "password": "password",
    });
    let login_request_b = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload_b)?))?;
    let login_response_b = test_app.router.clone().oneshot(login_request_b).await?;
    assert_eq!(login_response_b.status(), StatusCode::OK, "Login for User B failed");
    let raw_cookie_header_b = login_response_b.headers().get(header::SET_COOKIE).context("Set-Cookie missing for User B")?.to_str()?;
    let parsed_cookie_b = Cookie::parse(raw_cookie_header_b.to_string())?;
    let auth_cookie_b = format!("{}={}", parsed_cookie_b.name(), parsed_cookie_b.value());

    let payload = SuggestedActionsRequest {
        character_first_message: "Hello there!".to_string(),
        user_first_message: Some("Hi".to_string()),
        ai_first_response: Some("How are you today?".to_string()),
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/suggested-actions", session_a.id)) // User B tries to access User A's session
        .header(header::COOKIE, &auth_cookie_b)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload)?))?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn test_suggested_actions_session_not_found() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false).await;
    // let mut conn = test_app.db_pool.get().expect("Failed to get DB connection"); // Not strictly needed if no DB writes for this test's main path

    let user_guard = TestDataGuard::new(
        test_helpers::db::create_test_user(
            &test_app.db_pool,
            "suggested_actions_404_user",
            "password",
        )
        .await?,
        test_app.db_pool.clone(),
    );
    let user = &user_guard.entity;

    let login_payload = json!({ "identifier": user.username, "password": "password" });
    let login_request = Request::builder()
        .method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload)?))?;
    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK);
    let raw_cookie_header = login_response.headers().get(header::SET_COOKIE).context("Set-Cookie missing")?.to_str()?;
    let parsed_cookie = Cookie::parse(raw_cookie_header.to_string())?;
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());

    let non_existent_session_id = Uuid::new_v4();

    let payload = SuggestedActionsRequest {
        character_first_message: "Hello there!".to_string(),
        user_first_message: Some("Hi".to_string()),
        ai_first_response: Some("How are you today?".to_string()),
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/suggested-actions", non_existent_session_id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload)?))?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn test_suggested_actions_ai_error() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().expect("Failed to get DB connection");

    let user_guard = TestDataGuard::new(
        test_helpers::db::create_test_user(
            &test_app.db_pool,
            "suggested_actions_error_user",
            "password",
        )
        .await?,
        test_app.db_pool.clone(),
    );
    let user = &user_guard.entity;

    let login_payload = json!({ "identifier": user.username, "password": "password" });
    let login_request = Request::builder()
        .method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload)?))?;
    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK);
    let raw_cookie_header = login_response.headers().get(header::SET_COOKIE).context("Set-Cookie missing")?.to_str()?;
    let parsed_cookie = Cookie::parse(raw_cookie_header.to_string())?;
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());

    let new_character = NewCharacter {
        user_id: user.id,
        name: "Error Actions Character".to_string(),
        description: Some("Test character for AI error".to_string()),
        system_prompt: Some("You are a test character.".to_string()),
        user_prompt: Some("User: {{userInput}}".to_string()),
        ai_prompt_prefix: Some("AI:".to_string()),
        ai_prompt_suffix: None,
        context_length: 1024,
        greeting: Some("Hello!".to_string()),
        avatar_url: None,
        visibility: CharacterVisibility::Private,
        data: None,
    };
    let character_guard = TestDataGuard::new(
        diesel::insert_into(characters::table)
            .values(&new_character)
            .get_result::<DbCharacter>(&mut conn)?,
        test_app.db_pool.clone(),
    );
    let character = &character_guard.entity;

    let new_chat_session = NewChat {
        user_id: user.id,
        character_id: Some(character.id),
        name: Some("Test Chat AI Error".to_string()),
        chat_type: ChatType::Character,
        model_name: Some("test-default-model".to_string()),
        system_prompt_override: None,
        temperature: None,
        top_p: None,
        top_k: None,
        max_output_tokens: None,
        history_compression_threshold: None,
    };
    let session_guard = TestDataGuard::new(
        diesel::insert_into(chat_sessions::table)
            .values(&new_chat_session)
            .get_result::<ChatSession>(&mut conn)?,
        test_app.db_pool.clone(),
    );
    let session = &session_guard.entity;

    test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock client should be present")
        .set_response(Err(scribe_backend::errors::AppError::AiServiceError(
            "Mock AI error for testing".to_string(),
        )));

    let payload = SuggestedActionsRequest {
        character_first_message: "Hello there!".to_string(),
        user_first_message: Some("Hi".to_string()),
        ai_first_response: Some("How are you today?".to_string()),
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/suggested-actions", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload)?))?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}

#[tokio::test]
async fn test_suggested_actions_invalid_json_response() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().expect("Failed to get DB connection");

    let user_guard = TestDataGuard::new(
        test_helpers::db::create_test_user(
            &test_app.db_pool,
            "suggested_actions_invalid_json_user",
            "password",
        )
        .await?,
        test_app.db_pool.clone(),
    );
    let user = &user_guard.entity;

    let login_payload = json!({ "identifier": user.username, "password": "password" });
    let login_request = Request::builder()
        .method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload)?))?;
    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK);
    let raw_cookie_header = login_response.headers().get(header::SET_COOKIE).context("Set-Cookie missing")?.to_str()?;
    let parsed_cookie = Cookie::parse(raw_cookie_header.to_string())?;
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());

    let new_character = NewCharacter {
        user_id: user.id,
        name: "Invalid JSON Character".to_string(),
        description: Some("Test character for invalid JSON response".to_string()),
        system_prompt: Some("You are a test character.".to_string()),
        user_prompt: Some("User: {{userInput}}".to_string()),
        ai_prompt_prefix: Some("AI:".to_string()),
        ai_prompt_suffix: None,
        context_length: 1024,
        greeting: Some("Hello!".to_string()),
        avatar_url: None,
        visibility: CharacterVisibility::Private,
        data: None,
    };
    let character_guard = TestDataGuard::new(
        diesel::insert_into(characters::table)
            .values(&new_character)
            .get_result::<DbCharacter>(&mut conn)?,
        test_app.db_pool.clone(),
    );
    let character = &character_guard.entity;

    let new_chat_session = NewChat {
        user_id: user.id,
        character_id: Some(character.id),
        name: Some("Test Chat Invalid JSON".to_string()),
        chat_type: ChatType::Character,
        model_name: Some("test-default-model".to_string()),
        system_prompt_override: None,
        temperature: None,
        top_p: None,
        top_k: None,
        max_output_tokens: None,
        history_compression_threshold: None,
    };
    let session_guard = TestDataGuard::new(
        diesel::insert_into(chat_sessions::table)
            .values(&new_chat_session)
            .get_result::<ChatSession>(&mut conn)?,
        test_app.db_pool.clone(),
    );
    let session = &session_guard.entity;

    test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock client should be present")
        .set_response(Ok(genai::chat::ChatResponse {
            model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "gemini-2.5-flash-preview-04-17"),
            provider_model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "gemini-2.5-flash-preview-04-17"),
            content: Some(genai::chat::MessageContent::Text("This is not valid JSON".to_string())),
            reasoning_content: None,
            usage: Default::default(),
        }));

    let payload = SuggestedActionsRequest {
        character_first_message: "Hello there!".to_string(),
        user_first_message: Some("Hi".to_string()),
        ai_first_response: Some("How are you today?".to_string()),
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/suggested-actions", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload)?))?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    Ok(())
}

#[tokio::test]
async fn test_suggested_actions_success_optional_fields_none() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false).await;
    let mut conn = test_app.db_pool.get().expect("Failed to get DB connection");

    let user_guard = TestDataGuard::new(
        test_helpers::db::create_test_user(
            &test_app.db_pool,
            "suggested_actions_optional_user",
            "password",
        )
        .await?,
        test_app.db_pool.clone(),
    );
    let user = &user_guard.entity;

    let login_payload = json!({ "identifier": user.username, "password": "password" });
    let login_request = Request::builder()
        .method(Method::POST).uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload)?))?;
    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK);
    let raw_cookie_header = login_response.headers().get(header::SET_COOKIE).context("Set-Cookie missing")?.to_str()?;
    let parsed_cookie = Cookie::parse(raw_cookie_header.to_string())?;
    let auth_cookie = format!("{}={}", parsed_cookie.name(), parsed_cookie.value());

    let new_character = NewCharacter {
        user_id: user.id,
        name: "Suggested Actions Optional Character".to_string(),
        description: Some("Test character for optional fields".to_string()),
        system_prompt: Some("You are a test character.".to_string()),
        user_prompt: Some("User: {{userInput}}".to_string()),
        ai_prompt_prefix: Some("AI:".to_string()),
        ai_prompt_suffix: None,
        context_length: 1024,
        greeting: Some("Hello!".to_string()),
        avatar_url: None,
        visibility: CharacterVisibility::Private,
        data: None,
    };
    let character_guard = TestDataGuard::new(
        diesel::insert_into(characters::table)
            .values(&new_character)
            .get_result::<DbCharacter>(&mut conn)?,
        test_app.db_pool.clone(),
    );
    let character = &character_guard.entity;

    let new_chat_session = NewChat {
        user_id: user.id,
        character_id: Some(character.id),
        name: Some("Test Chat Optional Fields".to_string()),
        chat_type: ChatType::Character,
        model_name: Some("test-default-model".to_string()),
        system_prompt_override: None,
        temperature: None,
        top_p: None,
        top_k: None,
        max_output_tokens: None,
        history_compression_threshold: None,
    };
    let session_guard = TestDataGuard::new(
        diesel::insert_into(chat_sessions::table)
            .values(&new_chat_session)
            .get_result::<ChatSession>(&mut conn)?,
        test_app.db_pool.clone(),
    );
    let session = &session_guard.entity;

    let mock_suggestions = json!([
        {"action": "What is the meaning of the void?"},
        {"action": "How did I get here?"}
    ]);
    
    test_app
        .mock_ai_client
        .as_ref()
        .expect("Mock client should be present")
        .set_response(Ok(genai::chat::ChatResponse {
            model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "gemini-2.5-flash-preview-04-17"),
            provider_model_iden: genai::ModelIden::new(genai::adapter::AdapterKind::Gemini, "gemini-2.5-flash-preview-04-17"),
            content: Some(genai::chat::MessageContent::Text(mock_suggestions.to_string())),
            reasoning_content: None,
            usage: Default::default(),
        }));

    let payload = SuggestedActionsRequest {
        character_first_message: "You are in the void.".to_string(),
        user_first_message: None,
        ai_first_response: None,
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/suggested-actions", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload)?))?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::OK, "Expected OK status for optional fields being None");

    let body = response.into_body().collect().await?.to_bytes();
    let suggested_actions: SuggestedActionsResponse =
        serde_json::from_slice(&body).expect("Failed to deserialize response with optional fields None");

    assert!(!suggested_actions.suggestions.is_empty());
    assert_eq!(suggested_actions.suggestions.len(), 2);
    assert_eq!(suggested_actions.suggestions[0].action, "What is the meaning of the void?");
    assert_eq!(suggested_actions.suggestions[1].action, "How did I get here?");
    Ok(())
}