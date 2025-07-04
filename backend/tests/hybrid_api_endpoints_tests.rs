//! Tests for Hybrid API Endpoints
//!
//! These tests verify Phase 4.2.3 implementation:
//! - GET /api/chronicles/{id}/entities - current entity states
//! - GET /api/entities/{id}/timeline - entity's chronicle events  
//! - GET /api/chronicles/{id}/relationships - current relationship graph

use anyhow::{Context, Result as AnyhowResult};
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use diesel::prelude::*;
use http_body_util::BodyExt;
use scribe_backend::{
    test_helpers::{spawn_app_permissive_rate_limiting, TestApp, TestDataGuard},
    models::chronicle::{CreateChronicleRequest, PlayerChronicle},
    routes::chronicles::{
        ChronicleEntitiesResponse, EntityTimelineResponse, ChronicleRelationshipsResponse
    },
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

/// Test the GET /api/chronicles/{id}/entities endpoint
#[tokio::test]
async fn test_get_chronicle_entities_endpoint() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create a test user and login
    let session_cookie = create_authenticated_user(&app).await?;
    
    // Create a test chronicle
    let chronicle_request = CreateChronicleRequest {
        name: "Test Chronicle for Entities".to_string(),
        description: Some("Testing entity states endpoint".to_string()),
    };
    
    // Create chronicle via API
    let create_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/chronicles")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::from(serde_json::to_string(&chronicle_request)?))
                .unwrap(),
        )
        .await?;
    
    assert_eq!(create_response.status(), StatusCode::CREATED);
    let chronicle: PlayerChronicle = parse_json_response(create_response).await?;
    
    // Test GET /api/chronicles/{id}/entities
    let get_entities_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/entities", chronicle.id))
                .header(header::COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    assert_eq!(get_entities_response.status(), StatusCode::OK);
    let entities_response: ChronicleEntitiesResponse = parse_json_response(get_entities_response).await?;
    
    // Verify response structure
    assert_eq!(entities_response.chronicle_id, chronicle.id);
    assert_eq!(entities_response.entities.len(), 0); // No entities initially
    assert_eq!(entities_response.metadata.total_entities, 0);
    // ECS should be available but no entities found
    assert!(entities_response.metadata.ecs_enhanced);
    
    Ok(())
}

/// Test the GET /api/chronicles/{id}/entities endpoint with query parameters
#[tokio::test]
async fn test_get_chronicle_entities_with_params() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create a test user and login
    let session_cookie = create_authenticated_user(&app).await?;
    
    // Create a test chronicle
    let chronicle_request = CreateChronicleRequest {
        name: "Test Chronicle with Params".to_string(),
        description: Some("Testing entity endpoint parameters".to_string()),
    };
    
    let create_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/chronicles")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::from(serde_json::to_string(&chronicle_request)?))
                .unwrap(),
        )
        .await?;
    
    let chronicle: PlayerChronicle = parse_json_response(create_response).await?;
    
    // Test with query parameters
    let get_entities_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!(
                    "/api/chronicles/{}/entities?limit=10&include_current_state=true&include_relationships=false&confidence_threshold=0.8",
                    chronicle.id
                ))
                .header(header::COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    assert_eq!(get_entities_response.status(), StatusCode::OK);
    let entities_response: ChronicleEntitiesResponse = parse_json_response(get_entities_response).await?;
    
    // Verify response
    assert_eq!(entities_response.chronicle_id, chronicle.id);
    assert_eq!(entities_response.metadata.total_entities, 0);
    
    Ok(())
}

/// Test the GET /api/entities/{id}/timeline endpoint
#[tokio::test]
async fn test_get_entity_timeline_endpoint() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create a test user and login
    let session_cookie = create_authenticated_user(&app).await?;
    
    // Use a random entity ID for testing
    let entity_id = Uuid::new_v4();
    
    // Test GET /api/entities/{id}/timeline
    let get_timeline_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/entities/{}/timeline?include_current_state=false", entity_id))
                .header(header::COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    assert_eq!(get_timeline_response.status(), StatusCode::OK);
    let timeline_response: EntityTimelineResponse = parse_json_response(get_timeline_response).await?;
    
    // Verify response structure
    assert_eq!(timeline_response.entity_id, entity_id);
    assert_eq!(timeline_response.chronicle_events.len(), 0); // No events initially
    assert!(timeline_response.current_state.is_none()); // No current state for non-existent entity
    assert_eq!(timeline_response.metadata.total_events, 0);
    assert!(timeline_response.metadata.ecs_enhanced);
    
    Ok(())
}

/// Test the GET /api/entities/{id}/timeline endpoint with query parameters
#[tokio::test]
async fn test_get_entity_timeline_with_params() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create a test user and login
    let session_cookie = create_authenticated_user(&app).await?;
    
    let entity_id = Uuid::new_v4();
    
    // Test with query parameters
    let get_timeline_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!(
                    "/api/entities/{}/timeline?limit=50&include_current_state=false&include_relationships=true",
                    entity_id
                ))
                .header(header::COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    assert_eq!(get_timeline_response.status(), StatusCode::OK);
    let timeline_response: EntityTimelineResponse = parse_json_response(get_timeline_response).await?;
    
    // Verify response
    assert_eq!(timeline_response.entity_id, entity_id);
    assert_eq!(timeline_response.metadata.total_events, 0);
    
    Ok(())
}

/// Test the GET /api/chronicles/{id}/relationships endpoint
#[tokio::test]
async fn test_get_chronicle_relationships_endpoint() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create a test user and login
    let session_cookie = create_authenticated_user(&app).await?;
    
    // Create a test chronicle
    let chronicle_request = CreateChronicleRequest {
        name: "Test Chronicle for Relationships".to_string(),
        description: Some("Testing relationships endpoint".to_string()),
    };
    
    let create_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/chronicles")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::from(serde_json::to_string(&chronicle_request)?))
                .unwrap(),
        )
        .await?;
    
    let chronicle: PlayerChronicle = parse_json_response(create_response).await?;
    
    // Test GET /api/chronicles/{id}/relationships
    let get_relationships_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/relationships", chronicle.id))
                .header(header::COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    assert_eq!(get_relationships_response.status(), StatusCode::OK);
    let relationships_response: ChronicleRelationshipsResponse = parse_json_response(get_relationships_response).await?;
    
    // Verify response structure
    assert_eq!(relationships_response.chronicle_id, chronicle.id);
    assert_eq!(relationships_response.relationships.len(), 0); // No relationships initially
    assert_eq!(relationships_response.metadata.total_relationships, 0);
    assert!(relationships_response.metadata.ecs_enhanced);
    
    Ok(())
}

/// Test the GET /api/chronicles/{id}/relationships endpoint with query parameters
#[tokio::test]
async fn test_get_chronicle_relationships_with_params() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create a test user and login
    let session_cookie = create_authenticated_user(&app).await?;
    
    // Create a test chronicle
    let chronicle_request = CreateChronicleRequest {
        name: "Test Chronicle with Relationship Params".to_string(),
        description: Some("Testing relationship endpoint parameters".to_string()),
    };
    
    let create_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/chronicles")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::from(serde_json::to_string(&chronicle_request)?))
                .unwrap(),
        )
        .await?;
    
    let chronicle: PlayerChronicle = parse_json_response(create_response).await?;
    
    // Test with query parameters
    let get_relationships_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!(
                    "/api/chronicles/{}/relationships?limit=20&confidence_threshold=0.7",
                    chronicle.id
                ))
                .header(header::COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    assert_eq!(get_relationships_response.status(), StatusCode::OK);
    let relationships_response: ChronicleRelationshipsResponse = parse_json_response(get_relationships_response).await?;
    
    // Verify response
    assert_eq!(relationships_response.chronicle_id, chronicle.id);
    assert_eq!(relationships_response.metadata.total_relationships, 0);
    
    Ok(())
}

/// Test unauthorized access to the new endpoints
#[tokio::test]
async fn test_unauthorized_access_to_hybrid_endpoints() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    let chronicle_id = Uuid::new_v4();
    let entity_id = Uuid::new_v4();
    
    // Test chronicle entities endpoint without auth
    let entities_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/entities", chronicle_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    assert_eq!(entities_response.status(), StatusCode::UNAUTHORIZED);
    
    // Test entity timeline endpoint without auth
    let timeline_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/entities/{}/timeline", entity_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    assert_eq!(timeline_response.status(), StatusCode::UNAUTHORIZED);
    
    // Test chronicle relationships endpoint without auth
    let relationships_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/relationships", chronicle_id))
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    assert_eq!(relationships_response.status(), StatusCode::UNAUTHORIZED);
    
    Ok(())
}

/// Test access to non-existent chronicle
#[tokio::test]
async fn test_access_to_non_existent_chronicle() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create a test user and login
    let session_cookie = create_authenticated_user(&app).await?;
    
    let non_existent_chronicle_id = Uuid::new_v4();
    
    // Test chronicle entities endpoint with non-existent chronicle
    let entities_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/entities", non_existent_chronicle_id))
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    assert_eq!(entities_response.status(), StatusCode::NOT_FOUND);
    
    // Test chronicle relationships endpoint with non-existent chronicle
    let relationships_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/relationships", non_existent_chronicle_id))
                .header(header::COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    assert_eq!(relationships_response.status(), StatusCode::NOT_FOUND);
    
    Ok(())
}

/// Test response structure for all endpoints
#[tokio::test]
async fn test_response_structure_completeness() -> AnyhowResult<()> {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let _guard = TestDataGuard::new(app.db_pool.clone());
    
    // Create a test user and login
    let session_cookie = create_authenticated_user(&app).await?;
    
    // Create a test chronicle
    let chronicle_request = CreateChronicleRequest {
        name: "Structure Test Chronicle".to_string(),
        description: Some("Testing response structures".to_string()),
    };
    
    let create_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/chronicles")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::from(serde_json::to_string(&chronicle_request)?))
                .unwrap(),
        )
        .await?;
    
    let chronicle: PlayerChronicle = parse_json_response(create_response).await?;
    let entity_id = Uuid::new_v4();
    
    // Test all endpoints and verify complete response structures
    
    // Chronicle entities
    let entities_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/entities", chronicle.id))
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    let entities_body_bytes = entities_response.into_body().collect().await?.to_bytes();
    let entities_json: serde_json::Value = serde_json::from_slice(&entities_body_bytes)?;
    assert!(entities_json["chronicle_id"].is_string());
    assert!(entities_json["entities"].is_array());
    assert!(entities_json["metadata"]["total_entities"].is_number());
    assert!(entities_json["metadata"]["ecs_enhanced"].is_boolean());
    assert!(entities_json["metadata"]["warnings"].is_array());
    
    // Entity timeline
    let timeline_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/entities/{}/timeline", entity_id))
                .header(header::COOKIE, session_cookie.clone())
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    let timeline_body_bytes = timeline_response.into_body().collect().await?.to_bytes();
    let timeline_json: serde_json::Value = serde_json::from_slice(&timeline_body_bytes)?;
    assert!(timeline_json["entity_id"].is_string());
    assert!(timeline_json["chronicle_events"].is_array());
    assert!(timeline_json["metadata"]["total_events"].is_number());
    assert!(timeline_json["metadata"]["ecs_enhanced"].is_boolean());
    assert!(timeline_json["metadata"]["warnings"].is_array());
    
    // Chronicle relationships
    let relationships_response = app.router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(&format!("/api/chronicles/{}/relationships", chronicle.id))
                .header(header::COOKIE, session_cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await?;
    
    let relationships_body_bytes = relationships_response.into_body().collect().await?.to_bytes();
    let relationships_json: serde_json::Value = serde_json::from_slice(&relationships_body_bytes)?;
    assert!(relationships_json["chronicle_id"].is_string());
    assert!(relationships_json["relationships"].is_array());
    assert!(relationships_json["metadata"]["total_relationships"].is_number());
    assert!(relationships_json["metadata"]["ecs_enhanced"].is_boolean());
    assert!(relationships_json["metadata"]["warnings"].is_array());
    
    Ok(())
}