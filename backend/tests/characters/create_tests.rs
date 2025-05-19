#![cfg(test)]
use super::helpers::{
    get_text_body, insert_test_user_with_password, run_db_op, spawn_app,
};
use axum::{
    body::{Body},
    http::{header, Method, Request, StatusCode},
};
use reqwest::StatusCode as ReqwestStatusCode;
use scribe_backend::test_helpers::{ensure_tracing_initialized, TestDataGuard};
use serde_json::json;
use tower::ServiceExt; // For oneshot
use uuid::Uuid;

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_create_character_minimal_fields() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    // --- Setup Test User ---
    let test_password = "testpassword123";
    let test_username = format!("create_char_user_{}", Uuid::new_v4());
    let username_for_insert = test_username.clone();
    let _user = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_for_insert, test_password)
    })
    .await?;
    let (user, _) = _user; // Destructure the tuple, ignore dek
    guard.add_user(user.id);

    // -- Simulate Login ---
    let login_body = json!({
        "identifier": test_username.clone(),
        "password": test_password
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body)?))?;

    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed");

    let session_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Login response missing Set-Cookie header"))?
        .to_str()?
        .split(';')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid Set-Cookie format"))?
        .to_string();

    // --- Simulate Character Creation with Minimal Fields ---
    let create_body = json!({
        "name": "Test Manual Character",
        "description": "A test character created manually",
        "first_mes": "Hello, I'm a manually created test character!"
    });

    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, &session_cookie)
        .body(Body::from(serde_json::to_vec(&create_body)?))?;

    let create_response = test_app.router.clone().oneshot(create_request).await?;
    
    // Log response for debugging
    let (status, body_text) = get_text_body(create_response).await?;
    tracing::info!("Response status: {}, body: {}", status, body_text);
    
    assert_eq!(status, StatusCode::CREATED, "Character creation failed");
    
    // Parse response to ensure it contains the created character data
    let response_json: serde_json::Value = serde_json::from_str(&body_text)?;
    
    // Check that the response contains the expected fields
    assert_eq!(response_json["name"], "Test Manual Character");
    assert_eq!(response_json["description"], "A test character created manually");
    assert_eq!(response_json["first_mes"], "Hello, I'm a manually created test character!");
    
    // Check that the response contains an ID
    assert!(response_json["id"].is_string(), "Response does not contain an ID");

    // --- Cleanup ---
    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
async fn test_create_character_unauthorized() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;

    // --- Attempt to Create Character Without Authentication ---
    let create_body = json!({
        "name": "Test Unauthorized Character",
        "description": "This creation attempt should fail",
        "first_mes": "Hello, I shouldn't exist!"
    });

    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&create_body)?))?;

    let create_response = test_app.router.clone().oneshot(create_request).await?;
    
    assert_eq!(create_response.status(), StatusCode::UNAUTHORIZED, 
        "Unauthenticated character creation should return 401");

    Ok(())
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_create_character_all_fields() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    // --- Setup Test User ---
    let test_password = "testpassword123";
    let test_username = format!("create_char_all_fields_user_{}", Uuid::new_v4());
    let username_for_insert = test_username.clone();
    let _user = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_for_insert, test_password)
    })
    .await?;
    let (user, _) = _user; // Destructure the tuple, ignore dek
    guard.add_user(user.id);

    // -- Simulate Login ---
    let login_body = json!({
        "identifier": test_username.clone(),
        "password": test_password
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body)?))?;

    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed");

    let session_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Login response missing Set-Cookie header"))?
        .to_str()?
        .split(';')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid Set-Cookie format"))?
        .to_string();

    // --- Simulate Character Creation with All Fields ---
    let create_body = json!({
        "name": "Complete Test Character",
        "description": "A test character with all fields populated",
        "first_mes": "Hello, I'm a complete test character with all fields!",
        "personality": "Friendly, helpful, and detailed",
        "scenario": "In a test environment responding to API requests",
        "mes_example": "User: How are you?\nCharacter: I'm doing great, thanks for asking!",
        "creator_notes": "This character was created for testing the manual creation API",
        "system_prompt": "You are a test character created via the API",
        "post_history_instructions": "Continue being helpful in your responses",
        "tags": ["test", "api", "manual_creation"],
        "creator": "API Tester",
        "character_version": "1.0.0",
        "alternate_greetings": ["Hey there!", "Greetings, tester!"]
    });

    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, &session_cookie)
        .body(Body::from(serde_json::to_vec(&create_body)?))?;

    let create_response = test_app.router.clone().oneshot(create_request).await?;
    
    let (status, body_text) = get_text_body(create_response).await?;
    tracing::info!("Response status: {}, body: {}", status, body_text);
    
    assert_eq!(status, StatusCode::CREATED, "Character creation failed");
    
    // Parse response to ensure it contains the created character data
    let response_json: serde_json::Value = serde_json::from_str(&body_text)?;
    
    // Check essential fields
    assert_eq!(response_json["name"], "Complete Test Character");
    assert_eq!(response_json["description"], "A test character with all fields populated");
    assert_eq!(response_json["first_mes"], "Hello, I'm a complete test character with all fields!");
    
    // Check optional fields
    assert_eq!(response_json["personality"], "Friendly, helpful, and detailed");
    assert_eq!(response_json["scenario"], "In a test environment responding to API requests");
    assert_eq!(response_json["mes_example"], "User: How are you?\nCharacter: I'm doing great, thanks for asking!");
    assert_eq!(response_json["creator_notes"], "This character was created for testing the manual creation API");
    assert_eq!(response_json["system_prompt"], "You are a test character created via the API");
    assert_eq!(response_json["post_history_instructions"], "Continue being helpful in your responses");
    
    // Check array fields
    let tags = &response_json["tags"].as_array().expect("tags should be an array");
    assert!(tags.contains(&json!("test")));
    assert!(tags.contains(&json!("api")));
    assert!(tags.contains(&json!("manual_creation")));
    
    let greetings = &response_json["alternate_greetings"].as_array().expect("alternate_greetings should be an array");
    assert!(greetings.contains(&json!("Hey there!")));
    assert!(greetings.contains(&json!("Greetings, tester!")));
    
    // --- Cleanup ---
    guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_create_character_missing_required_fields() -> Result<(), anyhow::Error> {
    ensure_tracing_initialized();
    let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
    let pool = test_app.db_pool.clone();
    let mut guard = TestDataGuard::new(pool.clone());

    // --- Setup Test User ---
    let test_password = "testpassword123";
    let test_username = format!("create_char_missing_fields_user_{}", Uuid::new_v4());
    let username_for_insert = test_username.clone();
    let _user = run_db_op(&pool, move |conn| {
        insert_test_user_with_password(conn, &username_for_insert, test_password)
    })
    .await?;
    let (user, _) = _user; // Destructure the tuple, ignore dek
    guard.add_user(user.id);

    // -- Simulate Login ---
    let login_body = json!({
        "identifier": test_username.clone(),
        "password": test_password
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body)?))?;

    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK, "Login failed");

    let session_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Login response missing Set-Cookie header"))?
        .to_str()?
        .split(';')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid Set-Cookie format"))?
        .to_string();

    // Test cases for missing required fields
    let test_cases = vec![
        // Missing name
        json!({
            "description": "A test character missing the name",
            "first_mes": "Hello, I have no name!"
        }),
        // Missing description
        json!({
            "name": "No Description Character",
            "first_mes": "Hello, I have no description!"
        }),
        // Missing first_mes
        json!({
            "name": "No First Message Character",
            "description": "A test character missing the first message"
        }),
        // Empty object
        json!({})
    ];

    for (i, test_case) in test_cases.iter().enumerate() {
        let create_request = Request::builder()
            .method(Method::POST)
            .uri("/api/characters")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(serde_json::to_vec(test_case)?))?;

        let create_response = test_app.router.clone().oneshot(create_request).await?;
        
        let (status, body_text) = get_text_body(create_response).await?;
        tracing::info!("Test case {}: Response status: {}, body: {}", i, status, body_text);
        
        assert_eq!(status, StatusCode::BAD_REQUEST, 
            "Character creation with missing required fields should fail with 400 Bad Request");
        
        // Check that the error message mentions required fields
        assert!(body_text.contains("required"), 
            "Error should mention that required fields are missing");
    }

    // --- Cleanup ---
    guard.cleanup().await?;
    Ok(())
}