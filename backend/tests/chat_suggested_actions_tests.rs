#![cfg(test)]

use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use mime;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

// Crate imports
use scribe_backend::models::chats::{SuggestedActionsRequest, SuggestedActionsResponse};
use scribe_backend::test_helpers;

#[tokio::test]
async fn test_suggested_actions_success() {
    // Setup test app with mock AI
    let context = test_helpers::setup_test_app(false).await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "suggested_actions_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Suggested Actions Character",
    )
    .await;
    let session = test_helpers::db::create_test_chat_session(
        &context.app.db_pool,
        user.id,
        character.id,
    )
    .await;

    // Mock AI response
    let mock_suggestions = json!([
        {"action": "Tell me more about your day"},
        {"action": "Ask about my hobbies"},
        {"action": "Show me a riddle"}
    ]);
    
    // Set up the mock AI client to return our mock suggestions
    context
        .app
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

    // Create request payload
    let payload = SuggestedActionsRequest {
        character_first_message: "Hello, I am a medieval wizard. What brings you to my tower?".to_string(),
        user_first_message: Some("I need help with a magical potion.".to_string()),
        ai_first_response: Some("Ah, potions! My specialty. What kind are you looking to brew?".to_string()),
    };

    // Send request
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/suggested-actions", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Check response content
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let suggested_actions: SuggestedActionsResponse =
        serde_json::from_slice(&body).unwrap();

    // Verify the response structure
    assert!(!suggested_actions.suggestions.is_empty());
    assert_eq!(suggested_actions.suggestions.len(), 3);
    assert_eq!(suggested_actions.suggestions[0].action, "Tell me more about your day");
    assert_eq!(suggested_actions.suggestions[1].action, "Ask about my hobbies");
    assert_eq!(suggested_actions.suggestions[2].action, "Show me a riddle");
}

#[tokio::test]
async fn test_suggested_actions_unauthorized() {
    let context = test_helpers::setup_test_app(false).await;
    let (_auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "suggested_actions_unauth_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Unauth Actions Character",
    )
    .await;
    let session = test_helpers::db::create_test_chat_session(
        &context.app.db_pool,
        user.id,
        character.id,
    )
    .await;

    // Create request payload
    let payload = SuggestedActionsRequest {
        character_first_message: "Hello there!".to_string(),
        user_first_message: Some("Hi".to_string()),
        ai_first_response: Some("How are you today?".to_string()),
    };

    // Send request without auth cookie
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/suggested-actions", session.id))
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_suggested_actions_forbidden() {
    let context = test_helpers::setup_test_app(false).await;
    
    // Create user A and their session
    let (_auth_cookie_a, user_a) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "suggested_actions_user_a",
        "password",
    )
    .await;
    let character_a = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user_a.id,
        "User A Character",
    )
    .await;
    let session_a = test_helpers::db::create_test_chat_session(
        &context.app.db_pool,
        user_a.id,
        character_a.id,
    )
    .await;
    
    // Create user B and authenticate
    let (auth_cookie_b, _user_b) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "suggested_actions_user_b",
        "password",
    )
    .await;

    // Create request payload
    let payload = SuggestedActionsRequest {
        character_first_message: "Hello there!".to_string(),
        user_first_message: Some("Hi".to_string()),
        ai_first_response: Some("How are you today?".to_string()),
    };

    // User B tries to access User A's session
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/suggested-actions", session_a.id))
        .header(header::COOKIE, &auth_cookie_b)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_suggested_actions_session_not_found() {
    let context = test_helpers::setup_test_app(false).await;
    let (auth_cookie, _user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "suggested_actions_404_user",
        "password",
    )
    .await;

    let non_existent_session_id = Uuid::new_v4();

    // Create request payload
    let payload = SuggestedActionsRequest {
        character_first_message: "Hello there!".to_string(),
        user_first_message: Some("Hi".to_string()),
        ai_first_response: Some("How are you today?".to_string()),
    };

    // Send request with non-existent session ID
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/suggested-actions", non_existent_session_id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_suggested_actions_ai_error() {
    let context = test_helpers::setup_test_app(false).await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "suggested_actions_error_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Error Actions Character",
    )
    .await;
    let session = test_helpers::db::create_test_chat_session(
        &context.app.db_pool,
        user.id,
        character.id,
    )
    .await;

    // Set up the mock AI client to return an error
    context
        .app
        .mock_ai_client
        .as_ref()
        .expect("Mock client should be present")
        .set_response(Err(scribe_backend::errors::AppError::AiServiceError(
            "Mock AI error for testing".to_string(),
        )));

    // Create request payload
    let payload = SuggestedActionsRequest {
        character_first_message: "Hello there!".to_string(),
        user_first_message: Some("Hi".to_string()),
        ai_first_response: Some("How are you today?".to_string()),
    };

    // Send request
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/suggested-actions", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    
    // The handler maps AI errors to internal server errors
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_suggested_actions_invalid_json_response() {
    let context = test_helpers::setup_test_app(false).await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "suggested_actions_invalid_json_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Invalid JSON Character",
    )
    .await;
    let session = test_helpers::db::create_test_chat_session(
        &context.app.db_pool,
        user.id,
        character.id,
    )
    .await;

    // Set up the mock AI client to return an invalid JSON format
    context
        .app
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

    // Create request payload
    let payload = SuggestedActionsRequest {
        character_first_message: "Hello there!".to_string(),
        user_first_message: Some("Hi".to_string()),
        ai_first_response: Some("How are you today?".to_string()),
    };

    // Send request
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/suggested-actions", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    
    // The handler should return an internal server error for JSON parsing failures
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn test_suggested_actions_success_optional_fields_none() {
    // Setup test app with mock AI
    let context = test_helpers::setup_test_app(false).await;
    let (auth_cookie, user) = test_helpers::auth::create_test_user_and_login(
        &context.app,
        "suggested_actions_optional_user",
        "password",
    )
    .await;
    let character = test_helpers::db::create_test_character(
        &context.app.db_pool,
        user.id,
        "Suggested Actions Optional Character",
    )
    .await;
    let session = test_helpers::db::create_test_chat_session(
        &context.app.db_pool,
        user.id,
        character.id,
    )
    .await;

    // Mock AI response
    let mock_suggestions = json!([
        {"action": "What is the meaning of the void?"},
        {"action": "How did I get here?"}
    ]);
    
    context
        .app
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

    // Create request payload with None for optional fields
    let payload = SuggestedActionsRequest {
        character_first_message: "You are in the void.".to_string(),
        user_first_message: None,
        ai_first_response: None,
    };

    // Send request
    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chats/{}/suggested-actions", session.id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = context.app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK, "Expected OK status for optional fields being None");

    // Check response content
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let suggested_actions: SuggestedActionsResponse =
        serde_json::from_slice(&body).expect("Failed to deserialize response with optional fields None");

    assert!(!suggested_actions.suggestions.is_empty());
    assert_eq!(suggested_actions.suggestions.len(), 2);
    assert_eq!(suggested_actions.suggestions[0].action, "What is the meaning of the void?");
    assert_eq!(suggested_actions.suggestions[1].action, "How did I get here?");
}