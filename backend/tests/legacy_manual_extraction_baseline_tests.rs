#![cfg(test)]
// backend/tests/legacy_manual_extraction_baseline_tests.rs
//
// These tests establish the baseline behavior of the old manual extraction system
// before we remove it in favor of the new agentic narrative layer.
// They document how the manual extraction endpoints currently work.

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
        chronicle::{PlayerChronicle, CreateChronicleRequest},
        lorebook_dtos::CreateLorebookPayload,
    },
    test_helpers::{TestDataGuard, TestApp},
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

// Helper function to create a mock chat session ID for testing
// In production, this would need to exist in database, but for API testing,
// we can test error handling with non-existent IDs
fn create_mock_chat_session_id() -> Uuid {
    Uuid::new_v4()
}

mod baseline_tests {
    use super::*;

    #[tokio::test]
    async fn test_manual_extract_events_endpoint_baseline() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let session_cookie = create_authenticated_user(&test_app).await.unwrap();

        // Create a chronicle first
        let create_chronicle_request = CreateChronicleRequest {
            name: "Baseline Test Chronicle".to_string(),
            description: Some("For testing manual extraction baseline".to_string()),
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

        assert_eq!(create_chronicle_response.status(), StatusCode::CREATED);
        let chronicle: PlayerChronicle = parse_json_response(create_chronicle_response).await.unwrap();

        // Create a mock chat session ID (non-existent) for testing error handling
        let chat_session_id = create_mock_chat_session_id();

        // BASELINE TEST: Manual extract events endpoint behavior with nonexistent chat
        let extract_request = json!({
            "chat_session_id": chat_session_id,
            "extraction_model": "gemini-2.5-flash-lite-preview-06-17"
        });

        // Test the manual extraction endpoint: POST /api/chronicles/{id}/extract-events
        let extract_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/extract-events", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(extract_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // BASELINE ASSERTION: Should handle nonexistent chat gracefully
        // This documents the current behavior - might be 404 or 400 depending on implementation
        assert!(
            extract_response.status().is_client_error() || extract_response.status().is_server_error(),
            "Manual extraction should reject nonexistent chat sessions with an error"
        );
    }

    #[tokio::test]
    async fn test_manual_create_chronicle_from_chat_baseline() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let session_cookie = create_authenticated_user(&test_app).await.unwrap();

        // Create a mock chat session ID for testing error handling
        let chat_session_id = create_mock_chat_session_id();

        // BASELINE TEST: Manual create chronicle from chat endpoint behavior with nonexistent chat
        let create_request = json!({
            "chat_session_id": chat_session_id,
            "chronicle_name": "Generated Chronicle",
            "chronicle_description": "Chronicle created from chat session"
        });

        // Test the manual chronicle creation endpoint: POST /api/chronicles/from-chat
        let create_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/chronicles/from-chat")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(create_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // BASELINE ASSERTION: Should handle nonexistent chat gracefully
        assert!(
            create_response.status().is_client_error() || create_response.status().is_server_error(),
            "Manual chronicle creation should reject nonexistent chat sessions with an error"
        );
    }

    #[tokio::test]
    async fn test_manual_extract_events_validation_baseline() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
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

        // BASELINE TEST: Invalid request validation
        let invalid_request = json!({
            // Missing required chat_session_id
            "extraction_model": "gemini-2.5-flash-lite-preview-06-17"
        });

        let invalid_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/extract-events", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(invalid_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // BASELINE ASSERTION: Should reject invalid requests
        assert_eq!(invalid_response.status(), StatusCode::BAD_REQUEST);

        // BASELINE TEST: Nonexistent chat session
        let nonexistent_chat_request = json!({
            "chat_session_id": Uuid::new_v4(),
            "extraction_model": "gemini-2.5-flash-lite-preview-06-17"
        });

        let nonexistent_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/extract-events", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(nonexistent_chat_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // BASELINE ASSERTION: Should handle nonexistent chat gracefully
        assert!(nonexistent_response.status().is_client_error() || nonexistent_response.status().is_server_error());
    }

    #[tokio::test]
    async fn test_manual_extract_events_unauthorized_baseline() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());

        let chronicle_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        // BASELINE TEST: Unauthorized access
        let extract_request = json!({
            "chat_session_id": chat_session_id,
            "extraction_model": "gemini-2.5-flash-lite-preview-06-17"
        });

        let unauthorized_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/extract-events", chronicle_id))
                    .header(header::CONTENT_TYPE, "application/json")
                    // No authentication cookie
                    .body(Body::from(extract_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // BASELINE ASSERTION: Should require authentication
        assert!(unauthorized_response.status() == StatusCode::UNAUTHORIZED || unauthorized_response.status() == StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_manual_lorebook_extraction_baseline() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let session_cookie = create_authenticated_user(&test_app).await.unwrap();

        // Create a lorebook first
        let create_lorebook_request = CreateLorebookPayload {
            name: "Baseline Test Lorebook".to_string(),
            description: Some("For testing manual lorebook extraction baseline".to_string()),
        };

        let create_lorebook_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/lorebooks")
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(serde_json::to_string(&create_lorebook_request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(create_lorebook_response.status(), StatusCode::CREATED);
        let lorebook: scribe_backend::models::lorebook_dtos::LorebookResponse = parse_json_response(create_lorebook_response).await.unwrap();

        // Create a mock chat session ID for testing error handling
        let chat_session_id = create_mock_chat_session_id();

        // BASELINE TEST: Manual lorebook extraction endpoint behavior with nonexistent chat
        let extract_request = json!({
            "chat_session_id": chat_session_id,
            "extraction_model": "gemini-2.5-flash-lite-preview-06-17"
        });

        // Test the manual lorebook extraction endpoint: POST /api/lorebooks/{id}/extract-from-chat
        let extract_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/lorebooks/{}/extract-from-chat", lorebook.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(extract_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // BASELINE ASSERTION: Should handle nonexistent chat gracefully
        assert!(
            extract_response.status().is_client_error() || extract_response.status().is_server_error(),
            "Manual lorebook extraction should reject nonexistent chat sessions with an error"
        );
    }

    #[tokio::test]
    async fn test_manual_extraction_model_parameter_baseline() {
        let test_app = scribe_backend::test_helpers::spawn_app_permissive_rate_limiting(false, false, false).await;
        let mut _guard = TestDataGuard::new(test_app.db_pool.clone());
        let session_cookie = create_authenticated_user(&test_app).await.unwrap();

        // Create a chronicle
        let create_chronicle_request = CreateChronicleRequest {
            name: "Model Parameter Test Chronicle".to_string(),
            description: Some("For testing model parameter handling".to_string()),
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
        let chat_session_id = create_mock_chat_session_id();

        // BASELINE TEST: Default model parameter behavior
        let default_model_request = json!({
            "chat_session_id": chat_session_id
            // No extraction_model specified - should use default
        });

        let default_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/extract-events", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(default_model_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // BASELINE ASSERTION: Should use default model when not specified
        assert_eq!(default_response.status(), StatusCode::OK);

        // BASELINE TEST: Custom model parameter behavior
        let custom_model_request = json!({
            "chat_session_id": chat_session_id,
            "extraction_model": "custom-model-name"
        });

        let custom_response = test_app.router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(&format!("/api/chronicles/{}/extract-events", chronicle.id))
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::from(custom_model_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // BASELINE ASSERTION: Should accept custom model parameter
        // (Might fail with model error, but should accept the parameter)
        assert!(custom_response.status() == StatusCode::OK || custom_response.status().is_server_error());
    }
}