// #![cfg(feature = "postgres-backend")]
#![cfg(test)]

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use scribe_backend::{
    models::chats::{ApiChatMessage, GenerateChatRequest},
    test_helpers,
};
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
#[ignore] // Run manually with GEMINI_API_KEY and RUN_INTEGRATION_TESTS=true
async fn test_gemini_reasoning_streaming_real_ai() {
    if std::env::var("RUN_INTEGRATION_TESTS").is_err() {
        println!("Skipping real AI reasoning test: RUN_INTEGRATION_TESTS not set");
        return;
    }

    if std::env::var("GEMINI_API_KEY").is_err() {
        println!("Skipping real AI reasoning test: GEMINI_API_KEY not set");
        return;
    }

    // Spawn app with real AI enabled
    let test_app = test_helpers::spawn_app(false, true, false).await;

    let username = "reasoning_real_user";
    let password = "password";
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await
    .expect("Failed to create test user");

    let auth_cookie =
        test_helpers::login_user_via_router(&test_app.router, username, password).await;

    // Queue mock RAG responses to prevent panic
    test_app
        .mock_embedding_pipeline_service
        .add_retrieve_response(Ok(vec![]));
    test_app
        .mock_embedding_pipeline_service
        .add_retrieve_response(Ok(vec![]));
    test_app
        .mock_embedding_pipeline_service
        .add_retrieve_response(Ok(vec![]));

    // Create a character
    let character = test_helpers::db::create_test_character(
        &test_app.db_pool,
        user.id,
        "Gemini Reasoner".to_string(),
    )
    .await
    .expect("Failed to create character");

    // Create a session via API
    let request_body = json!({ "title": "Test Chat", "character_id": character.id });
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats/create_session")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, &auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();
    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let session_json: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("Failed to deserialize session");
    let session_id = session_json
        .get("id")
        .expect("No id in session")
        .as_str()
        .expect("id not string")
        .to_string();

    // Use gemini-3-flash-preview to test Gemini 3 thinking support
    let model_name = "gemini-2.5-flash";

    let payload = GenerateChatRequest {
        history: vec![ApiChatMessage { id: None, current_variant_index: None, variant_count: None,
            role: "user".to_string(),
            content: "Please provide a rigorous proof (thinking step-by-step) for the following problem: Show that for any positive integer n, the number of ways to tile a 2 x n rectangle with dominoes (1x2 tiles) is equal to the (n+1)-th Fibonacci number (where F1=1, F2=1, F3=2, etc.).".to_string(),
        }],
        model: Some(model_name.to_string()),
        query_text_for_rag: None,
        analysis_mode: None,
        guidance: None,
        variant_of: None,
        parent_message_id: None,
        game_master_mode_enabled: None,
        thinking_level: Some("high".to_string()), // Test with a high thinking level
        agent_mode: None,
    };

    let request = Request::builder()
        .method(Method::POST)
        .uri(format!("/api/chat/{}/generate", session_id))
        .header(header::COOKIE, &auth_cookie)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::ACCEPT, mime::TEXT_EVENT_STREAM.as_ref())
        .header("X-Request-Thinking", "true")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body();
    let actual_events = test_helpers::collect_full_sse_events(body).await;

    println!("Received {} events", actual_events.len());

    let mut found_reasoning = false;
    let mut found_content = false;

    for event in &actual_events {
        if event.event.as_deref() == Some("thinking") {
            found_reasoning = true;
            println!("Reasoning chunk (thinking): [RECEIVED]");
        }
        if event.event.as_deref() == Some("content") {
            found_content = true;
        }
    }

    assert!(
        found_reasoning,
        "Should have received at least one reasoning chunk"
    );
    assert!(
        found_content,
        "Should have received at least one content chunk"
    );
}
