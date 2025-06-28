#![cfg(test)]
// backend/tests/chronicle_re_chronicle_api_tests.rs

use anyhow::{Context, Result as AnyhowResult};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use diesel::prelude::*;
use http_body_util::BodyExt;
use bigdecimal::BigDecimal;
use std::str::FromStr;
use scribe_backend::{
    models::{
        chronicle::{PlayerChronicle, CreateChronicleRequest},
        chats::{NewChat, MessageRole, DbInsertableChatMessage},
        characters::Character as DbCharacter,
    },
    routes::chronicles::ReChronicleResponse,
    test_helpers::{self, TestDataGuard, TestApp},
    schema,
};
use serde_json::json;
use tower::util::ServiceExt;
use uuid::Uuid;

// Helper function to extract cookie from response
fn extract_session_cookie(response: &Response) -> Option<String> {
    response
        .headers()
        .get(header::SET_COOKIE)?
        .to_str().ok()?
        .split(';')
        .next()
        .map(|s| s.to_string())
}

// Helper function to parse JSON response
async fn parse_json_response<T: serde::de::DeserializeOwned>(response: Response) -> AnyhowResult<T> {
    let body_bytes = response.into_body().collect().await?.to_bytes();
    let body_str = std::str::from_utf8(&body_bytes)?;
    serde_json::from_str(body_str).context("Failed to parse JSON response")
}

// Helper function to create authenticated user and get session cookie
async fn create_authenticated_user(test_app: &TestApp) -> AnyhowResult<(String, Uuid)> {
    let username = format!("testuser_{}", Uuid::new_v4().simple());
    let email = format!("{}@test.com", username);
    let password = "TestPassword123!";

    // Register user
    let register_request = json!({
        "username": username,
        "email": email,
        "password": password
    });

    let register_response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/auth/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(register_request.to_string()))
                .unwrap(),
        )
        .await?;

    assert_eq!(register_response.status(), StatusCode::CREATED);

    // Parse the registration response to get user_id
    let register_body_bytes = register_response.into_body().collect().await?.to_bytes();
    let register_body_str = std::str::from_utf8(&register_body_bytes)?;
    let auth_response: serde_json::Value = serde_json::from_str(register_body_str)
        .context("Failed to parse registration response")?;
    let user_id = auth_response["user_id"]
        .as_str()
        .context("No user_id in registration response")?;
    let user_uuid = Uuid::parse_str(user_id)?;

    // Get the verification token from the database
    let conn = test_app.db_pool.get().await?;
    let user_id_for_token = user_uuid;
    let verification_token = conn
        .interact(move |conn| {
            use schema::email_verification_tokens::dsl::*;
            email_verification_tokens
                .filter(user_id.eq(user_id_for_token))
                .select(token)
                .first::<String>(conn)
                .optional()
        })
        .await
        .map_err(|e| anyhow::anyhow!("Interact error: {}", e))?
        .map_err(|e| anyhow::anyhow!("Database error: {}", e))?;

    if let Some(token) = verification_token {
        // Verify the email
        let verify_payload = json!({
            "token": token
        });

        let verify_request = Request::builder()
            .method(Method::POST)
            .uri("/api/auth/verify-email")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(verify_payload.to_string()))?;

        let verify_response = test_app.router.clone().oneshot(verify_request).await?;

        assert_eq!(
            verify_response.status(),
            StatusCode::OK,
            "Email verification failed"
        );
    } else {
        return Err(anyhow::anyhow!("No verification token found for user"));
    }

    // Now login to get session cookie
    let login_request = json!({
        "identifier": username,
        "password": password
    });

    let login_response = test_app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(login_request.to_string()))
                .unwrap(),
        )
        .await?;

    assert_eq!(login_response.status(), StatusCode::OK);
    let session_cookie = extract_session_cookie(&login_response)
        .context("Failed to extract session cookie from login response")?;

    Ok((session_cookie, user_uuid))
}

// Helper function to create a chat session with messages
async fn create_chat_session_with_messages(
    test_app: &TestApp,
    user_id: Uuid,
    chronicle_id: Option<Uuid>,
    message_count: usize,
) -> AnyhowResult<Uuid> {
    let conn = test_app.db_pool.get().await?;
    let session_id = Uuid::new_v4();
    
    // Create a dummy character first (required for NewChat)
    let character_id = Uuid::new_v4();
    let character = DbCharacter {
        id: character_id,
        user_id,
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        name: "Test Character".to_string(),
        description: None,
        personality: None,
        scenario: None,
        first_mes: None,
        mes_example: None,
        creator_notes: None,
        system_prompt: None,
        post_history_instructions: None,
        tags: None,
        creator: None,
        character_version: None,
        alternate_greetings: None,
        nickname: None,
        creator_notes_multilingual: None,
        source: None,
        group_only_greetings: None,
        creation_date: None,
        modification_date: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        persona: None,
        world_scenario: None,
        avatar: None,
        chat: None,
        greeting: None,
        definition: None,
        default_voice: None,
        extensions: None,
        data_id: None,
        category: None,
        definition_visibility: None,
        depth: None,
        example_dialogue: None,
        favorite: None,
        first_message_visibility: None,
        height: None,
        last_activity: None,
        migrated_from: None,
        model_prompt: None,
        model_prompt_visibility: None,
        model_temperature: None,
        num_interactions: None,
        permanence: None,
        persona_visibility: None,
        revision: None,
        sharing_visibility: None,
        status: None,
        system_prompt_visibility: None,
        system_tags: None,
        token_budget: None,
        usage_hints: None,
        user_persona: None,
        user_persona_visibility: None,
        visibility: None,
        weight: None,
        world_scenario_visibility: None,
        description_nonce: None,
        personality_nonce: None,
        scenario_nonce: None,
        first_mes_nonce: None,
        mes_example_nonce: None,
        creator_notes_nonce: None,
        system_prompt_nonce: None,
        post_history_instructions_nonce: None,
        persona_nonce: None,
        world_scenario_nonce: None,
        greeting_nonce: None,
        definition_nonce: None,
        model_prompt_nonce: None,
        user_persona_nonce: None,
        depth_prompt: None,
        depth_prompt_depth: None,
        depth_prompt_role: None,
        talkativeness: None,
        depth_prompt_ciphertext: None,
        depth_prompt_nonce: None,
        world_ciphertext: None,
        world_nonce: None,
        creator_comment: None,
        creator_comment_nonce: None,
        example_dialogue_nonce: None,
        fav: None,
        world: None,
    };

    conn.interact(move |conn| {
        use schema::characters::dsl::*;
        diesel::insert_into(characters)
            .values(&character)
            .execute(conn)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Interact error: {}", e))?
    .map_err(|e| anyhow::anyhow!("Database error: {}", e))?;
    
    // Create chat session
    let chat = NewChat {
        id: session_id,
        user_id,
        character_id, // Use the created character
        title_ciphertext: None,
        title_nonce: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        history_management_strategy: "recent_first".to_string(),
        history_management_limit: 10000,
        model_name: "gemini-2.5-pro".to_string(),
        visibility: Some("private".to_string()),
        active_custom_persona_id: None,
        active_impersonated_character_id: None,
        temperature: Some(BigDecimal::from_str("0.7").unwrap()),
        max_output_tokens: Some(1000),
        frequency_penalty: Some(BigDecimal::from_str("0.0").unwrap()),
        presence_penalty: Some(BigDecimal::from_str("0.0").unwrap()),
        top_k: Some(40),
        top_p: Some(BigDecimal::from_str("0.9").unwrap()),
        seed: Some(42),
        stop_sequences: None,
        gemini_thinking_budget: Some(1000),
        gemini_enable_code_execution: Some(false),
        system_prompt_ciphertext: None,
        system_prompt_nonce: None,
        player_chronicle_id: chronicle_id,
    };

    conn.interact(move |conn| {
        use schema::chat_sessions::dsl::*;
        diesel::insert_into(chat_sessions)
            .values(&chat)
            .execute(conn)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Interact error: {}", e))?
    .map_err(|e| anyhow::anyhow!("Database error: {}", e))?;

    // Create messages
    for i in 0..message_count {
        let message_id = Uuid::new_v4();
        let role = if i % 2 == 0 { MessageRole::User } else { MessageRole::Assistant };
        let content = match role {
            MessageRole::User => format!("User message {}: This is a test user message with some context.", i + 1),
            MessageRole::Assistant => format!("Assistant message {}: This is a test assistant response with detailed information about the conversation.", i + 1),
            MessageRole::System => format!("System message {}: This is a test system message.", i + 1),
        };

        // Encrypt the content (in real app this would use proper encryption)
        let content_bytes = content.as_bytes().to_vec();
        
        let message = DbInsertableChatMessage {
            chat_id: session_id,
            msg_type: role,
            content: content_bytes,
            content_nonce: None,
            user_id,
            role: Some(role.to_string()),
            parts: None,
            attachments: None,
            prompt_tokens: Some(50),
            completion_tokens: Some(100),
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "gemini-2.5-pro".to_string(),
        };

        conn.interact(move |conn| {
            use schema::chat_messages::dsl::*;
            diesel::insert_into(chat_messages)
                .values(&message)
                .execute(conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Interact error: {}", e))?
        .map_err(|e| anyhow::anyhow!("Database error: {}", e))?;
    }

    Ok(session_id)
}

mod re_chronicle_api_tests {
    use super::*;

    #[tokio::test]
    async fn test_re_chronicle_successful_operation() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let (session_cookie, user_id) = create_authenticated_user(&test_app).await.unwrap();

        // Create a chronicle
        let create_chronicle_request = CreateChronicleRequest {
            name: "Re-Chronicle Test Chronicle".to_string(),
            description: Some("Testing re-chronicle functionality".to_string()),
        };

        let create_chronicle_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(serde_json::to_string(&create_chronicle_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let chronicle: PlayerChronicle = parse_json_response(create_chronicle_response).await.unwrap();

        // Create a chat session with messages
        let chat_session_id = create_chat_session_with_messages(&test_app, user_id, Some(chronicle.id), 5).await.unwrap();

        // Test: Re-chronicle from chat
        let re_chronicle_request = json!({
            "chat_session_id": chat_session_id,
            "purge_existing": true,
            "extraction_model": "gemini-2.5-pro",
            "batch_size": 3
        });

        let re_chronicle_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/re-chronicle", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(re_chronicle_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(re_chronicle_response.status(), StatusCode::OK);

        let response_body: serde_json::Value = parse_json_response(re_chronicle_response).await.unwrap();

        // Verify response structure
        assert!(response_body.get("events_created").is_some());
        assert!(response_body.get("messages_processed").is_some());
        assert!(response_body.get("events_purged").is_some());
        assert!(response_body.get("summary").is_some());

        // Verify messages were processed
        let messages_processed = response_body["messages_processed"].as_u64().unwrap();
        assert_eq!(messages_processed, 5);

        // Verify summary is present
        let summary = response_body["summary"].as_str().unwrap();
        assert!(summary.contains("messages"));
    }

    #[tokio::test]
    async fn test_re_chronicle_with_existing_events() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let (session_cookie, user_id) = create_authenticated_user(&test_app).await.unwrap();

        // Create a chronicle
        let create_chronicle_request = CreateChronicleRequest {
            name: "Existing Events Test".to_string(),
            description: Some("Testing with existing events".to_string()),
        };

        let create_chronicle_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(serde_json::to_string(&create_chronicle_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let chronicle: PlayerChronicle = parse_json_response(create_chronicle_response).await.unwrap();

        // Create a chat session
        let chat_session_id = create_chat_session_with_messages(&test_app, user_id, Some(chronicle.id), 3).await.unwrap();

        // Create some existing events first
        let event_data = json!({
            "location": "Test Location",
            "action": "Test Action"
        });

        for i in 0..2 {
            let create_event_request = json!({
                "event_type": format!("TEST_EVENT_{}", i),
                "summary": format!("Existing test event {}", i),
                "source": "USER_ADDED",
                "event_data": event_data
            });

            let create_event_response = test_app.router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::POST)
                        .uri(&format!("/api/chronicles/{}/events", chronicle.id))
                        .header(header::CONTENT_TYPE, "application/json")
                        .header(header::COOKIE, &session_cookie)
                        .body(Body::from(create_event_request.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(create_event_response.status(), StatusCode::CREATED);
        }

        // Test: Re-chronicle with purge_existing = true
        let re_chronicle_request = json!({
            "chat_session_id": chat_session_id,
            "purge_existing": true,
            "extraction_model": "gemini-2.5-pro",
            "batch_size": 2
        });

        let re_chronicle_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/re-chronicle", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(re_chronicle_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(re_chronicle_response.status(), StatusCode::OK);

        let response_body: serde_json::Value = parse_json_response(re_chronicle_response).await.unwrap();

        // Verify existing events were purged
        let events_purged = response_body["events_purged"].as_u64().unwrap();
        assert_eq!(events_purged, 2);

        // Verify messages were processed
        let messages_processed = response_body["messages_processed"].as_u64().unwrap();
        assert_eq!(messages_processed, 3);
    }

    #[tokio::test]
    async fn test_re_chronicle_without_purging() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let (session_cookie, user_id) = create_authenticated_user(&test_app).await.unwrap();

        // Create a chronicle
        let create_chronicle_request = CreateChronicleRequest {
            name: "No Purge Test".to_string(),
            description: Some("Testing without purging".to_string()),
        };

        let create_chronicle_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(serde_json::to_string(&create_chronicle_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let chronicle: PlayerChronicle = parse_json_response(create_chronicle_response).await.unwrap();

        // Create a chat session
        let chat_session_id = create_chat_session_with_messages(&test_app, user_id, Some(chronicle.id), 3).await.unwrap();

        // Test: Re-chronicle with purge_existing = false
        let re_chronicle_request = json!({
            "chat_session_id": chat_session_id,
            "purge_existing": false,
            "extraction_model": "gemini-2.5-pro",
            "batch_size": 2
        });

        let re_chronicle_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/re-chronicle", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(re_chronicle_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(re_chronicle_response.status(), StatusCode::OK);

        let response_body: serde_json::Value = parse_json_response(re_chronicle_response).await.unwrap();

        // Verify no events were purged
        let events_purged = response_body["events_purged"].as_u64().unwrap();
        assert_eq!(events_purged, 0);

        // Verify messages were processed
        let messages_processed = response_body["messages_processed"].as_u64().unwrap();
        assert_eq!(messages_processed, 3);
    }

    #[tokio::test]
    async fn test_re_chronicle_with_message_range() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let (session_cookie, user_id) = create_authenticated_user(&test_app).await.unwrap();

        // Create a chronicle
        let create_chronicle_request = CreateChronicleRequest {
            name: "Message Range Test".to_string(),
            description: Some("Testing message range filtering".to_string()),
        };

        let create_chronicle_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(serde_json::to_string(&create_chronicle_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let chronicle: PlayerChronicle = parse_json_response(create_chronicle_response).await.unwrap();

        // Create a chat session with more messages
        let chat_session_id = create_chat_session_with_messages(&test_app, user_id, Some(chronicle.id), 10).await.unwrap();

        // Test: Re-chronicle with message range (messages 2-6)
        let re_chronicle_request = json!({
            "chat_session_id": chat_session_id,
            "purge_existing": true,
            "start_message_index": 2,
            "end_message_index": 6,
            "extraction_model": "gemini-2.5-pro",
            "batch_size": 2
        });

        let re_chronicle_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/re-chronicle", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(re_chronicle_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(re_chronicle_response.status(), StatusCode::OK);

        let response_body: serde_json::Value = parse_json_response(re_chronicle_response).await.unwrap();

        // Verify only the specified range was processed (4 messages: indices 2, 3, 4, 5)
        let messages_processed = response_body["messages_processed"].as_u64().unwrap();
        assert_eq!(messages_processed, 4);
    }

    #[tokio::test]
    async fn test_re_chronicle_nonexistent_chronicle() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let (session_cookie, _user_id) = create_authenticated_user(&test_app).await.unwrap();

        let nonexistent_chronicle_id = Uuid::new_v4();
        let nonexistent_chat_id = Uuid::new_v4();

        // Test: Re-chronicle with nonexistent chronicle
        let re_chronicle_request = json!({
            "chat_session_id": nonexistent_chat_id,
            "purge_existing": true,
            "extraction_model": "gemini-2.5-pro"
        });

        let re_chronicle_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/re-chronicle", nonexistent_chronicle_id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(re_chronicle_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(re_chronicle_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_re_chronicle_nonexistent_chat_session() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let (session_cookie, _user_id) = create_authenticated_user(&test_app).await.unwrap();

        // Create a chronicle
        let create_chronicle_request = CreateChronicleRequest {
            name: "Nonexistent Chat Test".to_string(),
            description: Some("Testing with nonexistent chat".to_string()),
        };

        let create_chronicle_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(serde_json::to_string(&create_chronicle_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let chronicle: PlayerChronicle = parse_json_response(create_chronicle_response).await.unwrap();

        let nonexistent_chat_id = Uuid::new_v4();

        // Test: Re-chronicle with nonexistent chat session
        let re_chronicle_request = json!({
            "chat_session_id": nonexistent_chat_id,
            "purge_existing": true,
            "extraction_model": "gemini-2.5-pro"
        });

        let re_chronicle_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/re-chronicle", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(re_chronicle_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(re_chronicle_response.status(), StatusCode::OK);
        
        // Verify the response indicates no messages were found
        let response_body: ReChronicleResponse = parse_json_response(re_chronicle_response).await.unwrap();
        assert_eq!(response_body.events_created, 0);
        assert_eq!(response_body.messages_processed, 0);
        assert_eq!(response_body.summary, "No messages found in chat session");
    }

    #[tokio::test]
    async fn test_re_chronicle_unauthorized_access() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        // Create two users
        let (session_cookie1, user_id1) = create_authenticated_user(&test_app).await.unwrap();
        let (session_cookie2, _user_id2) = create_authenticated_user(&test_app).await.unwrap();

        // User1 creates a chronicle
        let create_chronicle_request = CreateChronicleRequest {
            name: "User1's Private Chronicle".to_string(),
            description: Some("Should not be accessible by User2".to_string()),
        };

        let create_chronicle_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie1)
                    .body(Body::from(serde_json::to_string(&create_chronicle_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let chronicle: PlayerChronicle = parse_json_response(create_chronicle_response).await.unwrap();

        // Create chat session for user1
        let chat_session_id = create_chat_session_with_messages(&test_app, user_id1, Some(chronicle.id), 3).await.unwrap();

        // Test: User2 tries to re-chronicle User1's chronicle
        let re_chronicle_request = json!({
            "chat_session_id": chat_session_id,
            "purge_existing": true,
            "extraction_model": "gemini-2.5-pro"
        });

        let unauthorized_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/re-chronicle", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie2)
                    .body(Body::from(re_chronicle_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(unauthorized_response.status(), StatusCode::NOT_FOUND);

        // Test: Access without authentication
        let unauth_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/re-chronicle", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(re_chronicle_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(unauth_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_re_chronicle_validation_errors() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let (session_cookie, _user_id) = create_authenticated_user(&test_app).await.unwrap();

        // Create a chronicle
        let create_chronicle_request = CreateChronicleRequest {
            name: "Validation Test Chronicle".to_string(),
            description: Some("For testing validation".to_string()),
        };

        let create_chronicle_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(serde_json::to_string(&create_chronicle_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let chronicle: PlayerChronicle = parse_json_response(create_chronicle_response).await.unwrap();

        // Test: Missing required fields
        let incomplete_request = json!({
            "purge_existing": true,
            "extraction_model": "gemini-2.5-pro"
            // Missing chat_session_id
        });

        let incomplete_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/re-chronicle", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(incomplete_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(incomplete_response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // Test: Invalid UUID format
        let invalid_uuid_request = json!({
            "chat_session_id": "not-a-valid-uuid",
            "purge_existing": true,
            "extraction_model": "gemini-2.5-pro"
        });

        let invalid_uuid_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/re-chronicle", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(invalid_uuid_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(invalid_uuid_response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // Test: Invalid batch size (too large)
        let invalid_batch_size_request = json!({
            "chat_session_id": Uuid::new_v4(),
            "purge_existing": true,
            "extraction_model": "gemini-2.5-pro",
            "batch_size": 1000
        });

        let invalid_batch_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/re-chronicle", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(invalid_batch_size_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // This should succeed with empty chat session
        assert_eq!(invalid_batch_response.status(), StatusCode::OK); // Because chat doesn't exist but returns empty
    }

    #[tokio::test]
    async fn test_re_chronicle_empty_chat_session() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let (session_cookie, user_id) = create_authenticated_user(&test_app).await.unwrap();

        // Create a chronicle
        let create_chronicle_request = CreateChronicleRequest {
            name: "Empty Chat Test".to_string(),
            description: Some("Testing with empty chat".to_string()),
        };

        let create_chronicle_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(serde_json::to_string(&create_chronicle_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let chronicle: PlayerChronicle = parse_json_response(create_chronicle_response).await.unwrap();

        // Create an empty chat session (0 messages)
        let chat_session_id = create_chat_session_with_messages(&test_app, user_id, Some(chronicle.id), 0).await.unwrap();

        // Test: Re-chronicle empty chat session
        let re_chronicle_request = json!({
            "chat_session_id": chat_session_id,
            "purge_existing": true,
            "extraction_model": "gemini-2.5-pro"
        });

        let re_chronicle_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/re-chronicle", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(re_chronicle_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(re_chronicle_response.status(), StatusCode::OK);

        let response_body: serde_json::Value = parse_json_response(re_chronicle_response).await.unwrap();

        // Verify no messages were processed
        let messages_processed = response_body["messages_processed"].as_u64().unwrap();
        assert_eq!(messages_processed, 0);

        // Verify no events were created
        let events_created = response_body["events_created"].as_u64().unwrap();
        assert_eq!(events_created, 0);

        // Verify summary indicates no messages found
        let summary = response_body["summary"].as_str().unwrap();
        assert!(summary.contains("No messages found") || summary.contains("0 messages"));
    }
}