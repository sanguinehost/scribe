use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use scribe_backend::test_helpers;
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
#[ignore] // Use real AI for this test
async fn test_character_generation_with_lorebook_context() {
    let test_app = test_helpers::spawn_app(true, true, false).await; // Use real AI, mock vector DB
    
    // Create test user and login
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "loreuser@example.com".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    // Login first
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "identifier": "loreuser@example.com",
                "password": "password123"
            }).to_string()
        ))
        .unwrap();

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    
    // Debug login response if it fails
    let login_status = login_response.status();
    if login_status != StatusCode::OK {
        let login_body = login_response.into_body().collect().await.unwrap().to_bytes();
        let login_response_text = String::from_utf8(login_body.to_vec()).unwrap();
        panic!("Login failed with status {}: {}", login_status, login_response_text);
    }

    // Extract session cookie from login response
    let cookie_header = login_response.headers().get("set-cookie");
    let session_cookie = if let Some(cookie) = cookie_header {
        cookie.to_str().unwrap().split(';').next().unwrap().to_string()
    } else {
        panic!("No session cookie found in login response");
    };

    // Step 1: Create a test lorebook with relevant entries
    let create_lorebook_request = Request::builder()
        .method(Method::POST)
        .uri("/api/lorebooks")
        .header("content-type", "application/json")
        .header("cookie", &session_cookie)
        .body(Body::from(
            json!({
                "name": "Lassenia World",
                "description": "Fantasy world lore for character generation testing"
            }).to_string()
        ))
        .unwrap();

    let lorebook_response = test_app.router.clone().oneshot(create_lorebook_request).await.unwrap();
    assert_eq!(lorebook_response.status(), StatusCode::CREATED);
    
    let lorebook_body = lorebook_response.into_body().collect().await.unwrap().to_bytes();
    let lorebook_data: serde_json::Value = serde_json::from_slice(&lorebook_body).unwrap();
    let lorebook_id = lorebook_data["id"].as_str().unwrap();

    // Step 2: Add lorebook entries with Lassenia-related content
    let create_entry_request = Request::builder()
        .method(Method::POST)
        .uri(&format!("/api/lorebooks/{}/entries", lorebook_id))
        .header("content-type", "application/json")
        .header("cookie", &session_cookie)
        .body(Body::from(
            json!({
                "name": "Lassenia Character Profile",
                "content": "Lassenia is the crown princess of the Ethereal Kingdom, known for her silver hair that glows faintly in moonlight and her ability to communicate with spirits. She stands tall at 5'8\" with piercing violet eyes that seem to see beyond the physical realm. Born with the rare gift of spirit magic, she serves as a bridge between the living and the dead.",
                "keywords": ["Lassenia", "princess", "spirit magic", "silver hair", "violet eyes"]
            }).to_string()
        ))
        .unwrap();

    let entry_response = test_app.router.clone().oneshot(create_entry_request).await.unwrap();
    assert_eq!(entry_response.status(), StatusCode::CREATED);

    // Add another related entry
    let create_entry2_request = Request::builder()
        .method(Method::POST)
        .uri(&format!("/api/lorebooks/{}/entries", lorebook_id))
        .header("content-type", "application/json")
        .header("cookie", &session_cookie)
        .body(Body::from(
            json!({
                "name": "Ethereal Kingdom",
                "content": "The Ethereal Kingdom exists at the crossroads between the material and spirit worlds. Its capital, Luminspire, is built from crystalline structures that amplify spiritual energy. The kingdom is ruled by those blessed with spirit magic, and the royal bloodline has maintained this gift for over a thousand years.",
                "keywords": ["Ethereal Kingdom", "Luminspire", "spirit world", "crystalline", "royal bloodline"]
            }).to_string()
        ))
        .unwrap();

    let entry2_response = test_app.router.clone().oneshot(create_entry2_request).await.unwrap();
    assert_eq!(entry2_response.status(), StatusCode::CREATED);

    // Wait a moment for embedding processing
    tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;

    // Step 3: Test character generation with lorebook context
    let generate_request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters/generate/field")
        .header("content-type", "application/json")
        .header("cookie", session_cookie)
        .body(Body::from(
            json!({
                "field": "description",
                "style": "narrative",
                "user_prompt": "Generate a detailed description of Lassenia as a mysterious and powerful character",
                "character_context": {
                    "name": "Lassenia",
                    "tags": ["fantasy", "princess", "magic"]
                },
                "generation_options": null,
                "lorebook_id": lorebook_id
            }).to_string()
        ))
        .unwrap();

    let generate_response = test_app.router.clone().oneshot(generate_request).await.unwrap();
    
    let status = generate_response.status();
    let body = generate_response.into_body().collect().await.unwrap().to_bytes();
    let response_text = String::from_utf8(body.to_vec()).unwrap();
    
    println!("Generate response status: {}", status);
    println!("Generate response body: {}", response_text);

    // Assertions
    assert_eq!(status, StatusCode::OK, "Generation should succeed");
    
    let json_response: serde_json::Value = serde_json::from_str(&response_text)
        .expect("Response should be valid JSON");
    
    assert!(json_response.get("content").is_some(), "Response should have 'content' field");
    let content = json_response["content"].as_str().expect("Content should be string");
    assert!(!content.trim().is_empty(), "Content should not be empty");
    
    // Verify that lorebook context was integrated
    let content_lower = content.to_lowercase();
    let has_character_elements = content_lower.contains("lassenia") 
        || content_lower.contains("princess") 
        || content_lower.contains("spirit");
    let has_world_elements = content_lower.contains("ethereal") 
        || content_lower.contains("kingdom") 
        || content_lower.contains("crystalline");
    
    // At least one type of lorebook context should be present
    assert!(
        has_character_elements || has_world_elements,
        "Generated content should incorporate lorebook context. Content: {}",
        content
    );
    
    println!("✅ Successfully generated character description with lorebook context");
    println!("Content preview: {}...", content.chars().take(200).collect::<String>());
}

#[tokio::test]
#[ignore] // Use real AI for this test
async fn test_alternate_greeting_generation_with_lorebook() {
    let test_app = test_helpers::spawn_app(true, true, false).await;
    
    // Create test user and login
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "greetinguser@example.com".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    // Login
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "identifier": "greetinguser@example.com",
                "password": "password123"
            }).to_string()
        ))
        .unwrap();

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    let session_cookie = login_response.headers().get("set-cookie")
        .unwrap().to_str().unwrap().split(';').next().unwrap().to_string();

    // Create lorebook with scenario-relevant content
    let create_lorebook_request = Request::builder()
        .method(Method::POST)
        .uri("/api/lorebooks")
        .header("content-type", "application/json")
        .header("cookie", &session_cookie)
        .body(Body::from(
            json!({
                "name": "Academy Scenarios",
                "description": "Settings and scenarios for academy-based roleplay"
            }).to_string()
        ))
        .unwrap();

    let lorebook_response = test_app.router.clone().oneshot(create_lorebook_request).await.unwrap();
    let lorebook_body = lorebook_response.into_body().collect().await.unwrap().to_bytes();
    let lorebook_data: serde_json::Value = serde_json::from_slice(&lorebook_body).unwrap();
    let lorebook_id = lorebook_data["id"].as_str().unwrap();

    // Add scenario entry
    let create_entry_request = Request::builder()
        .method(Method::POST)
        .uri(&format!("/api/lorebooks/{}/entries", lorebook_id))
        .header("content-type", "application/json")
        .header("cookie", &session_cookie)
        .body(Body::from(
            json!({
                "name": "Mystic Academy Library",
                "content": "The Grand Library of Mystic Academy contains thousands of ancient tomes and scrolls. Students often meet here for study sessions, but it's also where forbidden knowledge is hidden in the restricted section. The library is overseen by the stern but caring Librarian Thorne.",
                "keywords": ["library", "academy", "study", "books", "forbidden knowledge", "Thorne"]
            }).to_string()
        ))
        .unwrap();

    let entry_response = test_app.router.clone().oneshot(create_entry_request).await.unwrap();
    assert_eq!(entry_response.status(), StatusCode::CREATED);

    // Wait for embedding processing
    tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;

    // Test alternate greeting generation with lorebook context
    let generate_request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters/generate/field")
        .header("content-type", "application/json")
        .header("cookie", session_cookie)
        .body(Body::from(
            json!({
                "field": "alternate_greeting",
                "style": "auto",
                "user_prompt": "You encounter the character in the academy library while they're researching something mysterious",
                "character_context": {
                    "name": "Aria",
                    "description": "A curious student with a talent for uncovering secrets",
                    "personality": "Inquisitive, brave, sometimes reckless when pursuing knowledge",
                    "first_mes": "Hey there! I'm Aria. Want to join me for some studying?"
                },
                "generation_options": null,
                "lorebook_id": lorebook_id
            }).to_string()
        ))
        .unwrap();

    let generate_response = test_app.router.clone().oneshot(generate_request).await.unwrap();
    
    let status = generate_response.status();
    let body = generate_response.into_body().collect().await.unwrap().to_bytes();
    let response_text = String::from_utf8(body.to_vec()).unwrap();
    
    println!("Alternate greeting response status: {}", status);
    println!("Alternate greeting response: {}", response_text);

    assert_eq!(status, StatusCode::OK);
    
    let json_response: serde_json::Value = serde_json::from_str(&response_text).unwrap();
    let content = json_response["content"].as_str().unwrap();
    
    // Verify the greeting incorporates lorebook context
    let content_lower = content.to_lowercase();
    let has_library_context = content_lower.contains("library") 
        || content_lower.contains("books") 
        || content_lower.contains("study");
    let has_character_voice = content_lower.contains("aria") 
        || content.contains("\""); // Should include dialogue
    
    assert!(has_library_context, "Alternate greeting should incorporate library context from lorebook");
    assert!(has_character_voice, "Alternate greeting should maintain character voice");
    assert!(content.len() > 100, "Alternate greeting should be substantial");
    
    println!("✅ Successfully generated alternate greeting with lorebook context");
}

#[tokio::test]
async fn test_character_generation_without_lorebook() {
    let test_app = test_helpers::spawn_app(false, true, false).await; // Mock AI for faster testing
    
    // Create test user and login
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "nolorebook@example.com".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "identifier": "nolorebook@example.com",
                "password": "password123"
            }).to_string()
        ))
        .unwrap();

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    let session_cookie = login_response.headers().get("set-cookie")
        .unwrap().to_str().unwrap().split(';').next().unwrap().to_string();

    // Test generation without lorebook_id (should still work)
    let generate_request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters/generate/field")
        .header("content-type", "application/json")
        .header("cookie", session_cookie)
        .body(Body::from(
            json!({
                "field": "description",
                "style": "traits",
                "user_prompt": "A brave knight with a mysterious past",
                "character_context": {
                    "name": "Sir Galahad"
                },
                "generation_options": null,
                "lorebook_id": null
            }).to_string()
        ))
        .unwrap();

    let generate_response = test_app.router.clone().oneshot(generate_request).await.unwrap();
    
    let status = generate_response.status();
    assert_eq!(status, StatusCode::OK, "Generation should work without lorebook");
    
    let body = generate_response.into_body().collect().await.unwrap().to_bytes();
    let response_text = String::from_utf8(body.to_vec()).unwrap();
    let json_response: serde_json::Value = serde_json::from_str(&response_text).unwrap();
    
    assert!(json_response.get("content").is_some(), "Should generate content without lorebook");
    
    println!("✅ Character generation works correctly without lorebook");
}

#[tokio::test]
async fn test_character_generation_with_invalid_lorebook_id() {
    let test_app = test_helpers::spawn_app(false, true, false).await;
    
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "invalidlore@example.com".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "identifier": "invalidlore@example.com",
                "password": "password123"
            }).to_string()
        ))
        .unwrap();

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    let session_cookie = login_response.headers().get("set-cookie")
        .unwrap().to_str().unwrap().split(';').next().unwrap().to_string();

    // Test with non-existent lorebook_id (should still generate, but without lorebook context)
    let fake_lorebook_id = "550e8400-e29b-41d4-a716-446655440000"; // Valid UUID format
    
    let generate_request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters/generate/field")
        .header("content-type", "application/json")
        .header("cookie", session_cookie)
        .body(Body::from(
            json!({
                "field": "personality",
                "style": "auto",
                "user_prompt": "A wise mentor character",
                "character_context": {
                    "name": "Master Chen"
                },
                "generation_options": null,
                "lorebook_id": fake_lorebook_id
            }).to_string()
        ))
        .unwrap();

    let generate_response = test_app.router.clone().oneshot(generate_request).await.unwrap();
    
    let status = generate_response.status();
    // Should still succeed - lorebook query failure should not break generation
    assert_eq!(status, StatusCode::OK, "Generation should succeed even with invalid lorebook_id");
    
    let body = generate_response.into_body().collect().await.unwrap().to_bytes();
    let response_text = String::from_utf8(body.to_vec()).unwrap();
    let json_response: serde_json::Value = serde_json::from_str(&response_text).unwrap();
    
    assert!(json_response.get("content").is_some(), "Should generate content despite invalid lorebook");
    
    println!("✅ Character generation gracefully handles invalid lorebook IDs");
}

#[tokio::test] 
async fn test_request_validation_with_lorebook_integration() {
    let test_app = test_helpers::spawn_app(false, true, false).await;
    
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "validation@example.com".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "identifier": "validation@example.com",
                "password": "password123"
            }).to_string()
        ))
        .unwrap();

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    let session_cookie = login_response.headers().get("set-cookie")
        .unwrap().to_str().unwrap().split(';').next().unwrap().to_string();

    // Test with malformed lorebook_id
    let generate_request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters/generate/field")
        .header("content-type", "application/json")
        .header("cookie", session_cookie)
        .body(Body::from(
            json!({
                "field": "description",
                "style": "auto", 
                "user_prompt": "Test character",
                "character_context": null,
                "generation_options": null,
                "lorebook_id": "not-a-valid-uuid"
            }).to_string()
        ))
        .unwrap();

    let generate_response = test_app.router.clone().oneshot(generate_request).await.unwrap();
    
    // Should return validation error for malformed UUID
    assert_eq!(generate_response.status(), StatusCode::BAD_REQUEST);
    
    println!("✅ Request validation properly handles malformed lorebook_id");
}