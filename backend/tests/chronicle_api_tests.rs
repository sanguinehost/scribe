#![cfg(test)]
// backend/tests/chronicle_api_tests.rs

use anyhow::{Context, Result as AnyhowResult};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use diesel::prelude::*;
use http_body_util::BodyExt;
use scribe_backend::{
    models::{
        chronicle::{PlayerChronicle, CreateChronicleRequest, UpdateChronicleRequest, PlayerChronicleWithCounts},
        chronicle_event::{ChronicleEvent, CreateEventRequest, EventSource},
        chats::{Chat, ChatMode, MessageRole, DbInsertableChatMessage},
    },
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
async fn create_authenticated_user(test_app: &TestApp) -> AnyhowResult<String> {
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

    Ok(session_cookie)
}

mod api_tests {
    use super::*;

    #[tokio::test]
    async fn test_chronicle_lifecycle_api() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let session_cookie = create_authenticated_user(&test_app).await.unwrap();

        // Test: Create Chronicle
        let create_request = CreateChronicleRequest {
            name: "Epic Adventure Chronicle".to_string(),
            description: Some("A grand tale of heroes and dragons".to_string()),
        };

        let create_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(serde_json::to_string(&create_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(create_response.status(), StatusCode::CREATED);
        let created_chronicle: PlayerChronicle = parse_json_response(create_response).await.unwrap();

        assert_eq!(created_chronicle.name, create_request.name);
        assert_eq!(created_chronicle.description, create_request.description);
        // User ID will be set by the authenticated session

        // Test: Get Chronicles List
        let list_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/chronicles")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(list_response.status(), StatusCode::OK);
        let chronicles: Vec<PlayerChronicleWithCounts> = parse_json_response(list_response).await.unwrap();

        assert_eq!(chronicles.len(), 1);
        assert_eq!(chronicles[0].chronicle.id, created_chronicle.id);
        assert_eq!(chronicles[0].event_count, 0);
        assert_eq!(chronicles[0].chat_session_count, 0);

        // Test: Get Specific Chronicle
        let get_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&format!("/api/chronicles/{}", created_chronicle.id))
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(get_response.status(), StatusCode::OK);
        let retrieved_chronicle: PlayerChronicle = parse_json_response(get_response).await.unwrap();
        assert_eq!(retrieved_chronicle.id, created_chronicle.id);

        // Test: Update Chronicle
        let update_request = UpdateChronicleRequest {
            name: Some("Updated Epic Adventure".to_string()),
            description: Some("An even grander tale".to_string()),
        };

        let update_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri(&format!("/api/chronicles/{}", created_chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(serde_json::to_string(&update_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(update_response.status(), StatusCode::OK);
        let updated_chronicle: PlayerChronicle = parse_json_response(update_response).await.unwrap();

        assert_eq!(updated_chronicle.name, "Updated Epic Adventure");
        assert_eq!(updated_chronicle.description, Some("An even grander tale".to_string()));

        // Test: Delete Chronicle
        let delete_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(&format!("/api/chronicles/{}", created_chronicle.id))
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(delete_response.status(), StatusCode::NO_CONTENT);

        // Test: Verify Chronicle Deleted
        let get_deleted_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&format!("/api/chronicles/{}", created_chronicle.id))
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(get_deleted_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_chronicle_events_api() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let session_cookie = create_authenticated_user(&test_app).await.unwrap();

        // Create a chronicle first
        let create_chronicle_request = CreateChronicleRequest {
            name: "Event Test Chronicle".to_string(),
            description: Some("For testing events".to_string()),
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

        // Test: Create Event
        let event_data = json!({
            "location": "Misty Forest",
            "weather": "foggy",
            "danger_level": "moderate"
        });

        let create_event_request = CreateEventRequest {
            event_type: "EXPLORATION".to_string(),
            summary: "The party enters the mysterious misty forest".to_string(),
            source: EventSource::UserAdded,
            event_data: Some(event_data.clone()),
            timestamp_iso8601: None,
        };

        let create_event_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/events", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(serde_json::to_string(&create_event_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(create_event_response.status(), StatusCode::CREATED);
        let created_event: ChronicleEvent = parse_json_response(create_event_response).await.unwrap();

        assert_eq!(created_event.event_type, create_event_request.event_type);
        assert_eq!(created_event.summary, create_event_request.summary);
        assert_eq!(created_event.source, EventSource::UserAdded.to_string());
        assert_eq!(created_event.event_data, Some(event_data));
        assert_eq!(created_event.chronicle_id, chronicle.id);

        // Test: Get Chronicle Events
        let get_events_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&format!("/api/chronicles/{}/events", chronicle.id))
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(get_events_response.status(), StatusCode::OK);
        let events: Vec<ChronicleEvent> = parse_json_response(get_events_response).await.unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, created_event.id);

        // Test: Get Events with Query Parameters (filtering)
        let get_filtered_events_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&format!("/api/chronicles/{}/events?event_type=EXPLORATION&limit=10", chronicle.id))
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(get_filtered_events_response.status(), StatusCode::OK);
        let filtered_events: Vec<ChronicleEvent> = parse_json_response(get_filtered_events_response).await.unwrap();

        assert_eq!(filtered_events.len(), 1);
        assert_eq!(filtered_events[0].id, created_event.id);

        // Test: Delete Event
        let delete_event_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri(&format!("/api/chronicles/{}/events/{}", chronicle.id, created_event.id))
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(delete_event_response.status(), StatusCode::NO_CONTENT);

        // Test: Verify Event Deleted
        let get_events_after_delete_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&format!("/api/chronicles/{}/events", chronicle.id))
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let events_after_delete: Vec<ChronicleEvent> = parse_json_response(get_events_after_delete_response).await.unwrap();
        assert_eq!(events_after_delete.len(), 0);
    }

    #[tokio::test]
    async fn test_chronicle_unauthorized_access() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        // Test: Access without authentication
        let unauth_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri("/api/chronicles")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(unauth_response.status(), StatusCode::UNAUTHORIZED);

        // Create two users
        let session_cookie1 = create_authenticated_user(&test_app).await.unwrap();
        let session_cookie2 = create_authenticated_user(&test_app).await.unwrap();

        // User1 creates a chronicle
        let create_request = CreateChronicleRequest {
            name: "User1's Private Chronicle".to_string(),
            description: Some("Should not be accessible by User2".to_string()),
        };

        let create_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie1)
                    .body(Body::from(serde_json::to_string(&create_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let chronicle: PlayerChronicle = parse_json_response(create_response).await.unwrap();

        // Test: User2 tries to access User1's chronicle
        let unauthorized_get_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&format!("/api/chronicles/{}", chronicle.id))
                    .header(header::COOKIE, &session_cookie2)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(unauthorized_get_response.status(), StatusCode::NOT_FOUND);

        // Test: User2 tries to create event in User1's chronicle
        let event_request = CreateEventRequest {
            event_type: "UNAUTHORIZED_EVENT".to_string(),
            summary: "This should not be allowed".to_string(),
            source: EventSource::UserAdded,
            event_data: None,
            timestamp_iso8601: None,
        };

        let unauthorized_event_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/events", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie2)
                    .body(Body::from(serde_json::to_string(&event_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(unauthorized_event_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_chronicle_validation_errors() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let session_cookie = create_authenticated_user(&test_app).await.unwrap();

        // Test: Create chronicle with invalid data (empty name)
        let invalid_request = json!({
            "name": "",
            "description": "This should fail"
        });

        let invalid_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(invalid_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(invalid_response.status(), StatusCode::UNPROCESSABLE_ENTITY);

        // Test: Create chronicle with missing required fields
        let incomplete_request = json!({
            "description": "Missing name field"
        });

        let incomplete_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(incomplete_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(incomplete_response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_nonexistent_resources() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let session_cookie = create_authenticated_user(&test_app).await.unwrap();

        let nonexistent_id = Uuid::new_v4();

        // Test: Get nonexistent chronicle
        let get_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::GET)
                    .uri(&format!("/api/chronicles/{}", nonexistent_id))
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(get_response.status(), StatusCode::NOT_FOUND);

        // Test: Create event in nonexistent chronicle
        let event_request = CreateEventRequest {
            event_type: "TEST".to_string(),
            summary: "Test event".to_string(),
            source: EventSource::UserAdded,
            event_data: None,
            timestamp_iso8601: None,
        };

        let event_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/events", nonexistent_id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(serde_json::to_string(&event_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(event_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_extract_events_from_chat_api() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let session_cookie = create_authenticated_user(&test_app).await.unwrap();

        // Create a chronicle first
        let create_chronicle_request = CreateChronicleRequest {
            name: "Event Extraction Test Chronicle".to_string(),
            description: Some("For testing event extraction".to_string()),
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

        // Create a mock chat session with messages
        let chat_session_id = Uuid::new_v4();
        
        // Test: Extract events from nonexistent chat session
        let invalid_extract_request = json!({
            "chat_session_id": chat_session_id,
            "extraction_model": "gemini-2.5-flash-lite-preview-06-17"
        });

        let invalid_extract_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/extract-events", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(invalid_extract_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Should return NOT_FOUND for nonexistent chat session
        assert_eq!(invalid_extract_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_extract_events_validation() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let session_cookie = create_authenticated_user(&test_app).await.unwrap();

        // Create a chronicle first
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
            "extraction_model": "gemini-2.5-flash-lite-preview-06-17"
            // Missing chat_session_id
        });

        let incomplete_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/extract-events", chronicle.id))
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
            "extraction_model": "gemini-2.5-flash-lite-preview-06-17"
        });

        let invalid_uuid_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/extract-events", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(invalid_uuid_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(invalid_uuid_response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_extract_events_unauthorized() {
        let test_app = test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let chronicle_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // Test: Extract events without authentication
        let extract_request = json!({
            "chat_session_id": chat_session_id,
            "extraction_model": "gemini-2.5-flash-lite-preview-06-17"
        });

        let unauth_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/extract-events", chronicle_id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(extract_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(unauth_response.status(), StatusCode::UNAUTHORIZED);

        // Test: Extract events from chronicle owned by different user
        let session_cookie1 = create_authenticated_user(&test_app).await.unwrap();
        let session_cookie2 = create_authenticated_user(&test_app).await.unwrap();

        // User1 creates a chronicle
        let create_request = CreateChronicleRequest {
            name: "User1's Chronicle".to_string(),
            description: Some("Private chronicle".to_string()),
        };

        let create_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie1)
                    .body(Body::from(serde_json::to_string(&create_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let chronicle: PlayerChronicle = parse_json_response(create_response).await.unwrap();

        // User2 tries to extract events from User1's chronicle
        let unauthorized_extract_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/extract-events", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie2)
                    .body(Body::from(extract_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(unauthorized_extract_response.status(), StatusCode::NOT_FOUND);
    }
}