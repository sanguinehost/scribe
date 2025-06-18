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
async fn test_alternate_greeting_generation() {
    let test_app = test_helpers::spawn_app(true, true, false).await; // Use real AI, mock vector DB
    
    // Create test user and login
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "testuser@example.com".to_string(),
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
                "identifier": "testuser@example.com",
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

    // Test alternate greeting generation
    let generate_request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters/generate/field")
        .header("content-type", "application/json")
        .header("cookie", session_cookie)
        .body(Body::from(
            json!({
                "field": "alternate_greeting",
                "style": "auto",
                "user_prompt": "You are a new hire at the energy company on the security team and Solomon has been tasked with being your buddy and getting you set up",
                "character_context": {
                    "name": "Solomon",
                    "description": "A seasoned security professional at an energy company. Mid-40s, gruff but reliable, with years of experience in industrial security. Known for being thorough and having a dry sense of humor.",
                    "personality": "Professional, experienced, somewhat gruff but ultimately helpful. Takes security seriously but isn't above making dry jokes.",
                    "scenario": "Working at a large energy company's main facility",
                    "first_mes": "\"Another day, another potential security breach to worry about. At least the coffee's decent today. Name's Solomon, by the way. I handle security around here - been doing it for about fifteen years now.\"",
                    "tags": null,
                    "mes_example": null,
                    "system_prompt": null,
                    "depth_prompt": null,
                    "alternate_greetings": null,
                    "lorebook_entries": null,
                    "associated_persona": null
                },
                "generation_options": null
            }).to_string()
        ))
        .unwrap();

    let generate_response = test_app.router.clone().oneshot(generate_request).await.unwrap();
    
    let status = generate_response.status();
    let body = generate_response.into_body().collect().await.unwrap().to_bytes();
    let response_text = String::from_utf8(body.to_vec()).unwrap();
    
    println!("Generate response status: {}", status);
    println!("Generate response body: {}", response_text);

    // For now, just check we get a response (not 500)
    // We'll enhance validation once we see what's actually happening
    assert_ne!(status, StatusCode::INTERNAL_SERVER_ERROR, "Should not get internal server error");
    
    if status == StatusCode::OK {
        let json_response: Result<serde_json::Value, _> = serde_json::from_str(&response_text);
        match json_response {
            Ok(json) => {
                println!("✅ Successful JSON response: {:#}", json);
                assert!(json.get("content").is_some(), "Response should have 'content' field");
                let content = json["content"].as_str().expect("Content should be string");
                assert!(!content.trim().is_empty(), "Content should not be empty");
                
                // Check if it follows either narrative or system/game structure
                let has_good_length = content.len() > 200; // Should be substantial
                let has_character_name = content.to_lowercase().contains("solomon");
                let mentions_scenario = content.to_lowercase().contains("security") || content.to_lowercase().contains("energy") || content.to_lowercase().contains("new hire");
                
                // Check for narrative style (dialogue, rich descriptions)
                let is_narrative_style = content.contains("\"") && content.chars().filter(|&c| c == '\n').count() >= 3;
                
                // Check for system/game style (CURRENT STATE and INVENTORY sections)
                let is_system_style = content.contains("CURRENT STATE:") && content.contains("INVENTORY");
                
                let has_proper_structure = is_narrative_style || is_system_style;
                
                if has_good_length && has_character_name && mentions_scenario && has_proper_structure {
                    println!("✅ Generated alternate greeting has proper structure:");
                    println!("  - Substantial length: {} characters", content.len());
                    println!("  - Character name mentioned: {}", has_character_name);
                    println!("  - Scenario relevant: {}", mentions_scenario);
                    if is_narrative_style {
                        println!("  - Format: Narrative style (dialogue and rich descriptions)");
                    } else if is_system_style {
                        println!("  - Format: System/Game style (CURRENT STATE + INVENTORY)");
                    }
                    println!("Content preview: {}...", content.chars().take(300).collect::<String>());
                } else {
                    println!("⚠️  Generated content may not follow expected structure:");
                    println!("  - Substantial length: {} characters", content.len());
                    println!("  - Character name mentioned: {}", has_character_name);
                    println!("  - Scenario relevant: {}", mentions_scenario);
                    println!("  - Narrative style: {}", is_narrative_style);
                    println!("  - System/Game style: {}", is_system_style);
                    println!("Full content: {}", content);
                }
            }
            Err(e) => {
                panic!("Response is not valid JSON: {}, Response: {}", e, response_text);
            }
        }
    }
}

#[tokio::test]
#[ignore] // Use real AI for this test
async fn test_simple_wizard_description() {
    let test_app = test_helpers::spawn_app(true, true, false).await;
    
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "wizard@example.com".to_string(),
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
                "identifier": "wizard@example.com", 
                "password": "password123"
            }).to_string()
        ))
        .unwrap();

    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    let session_cookie = login_response.headers().get("set-cookie")
        .unwrap().to_str().unwrap().split(';').next().unwrap().to_string();

    // Test with minimal system prompt - let's try different styles
    let test_cases = vec![
        ("auto", "A simple wizard character"),
        ("traits", "A wizard with basic traits"),
        ("narrative", "A wise old wizard"),
    ];

    for (style, prompt) in test_cases {
        println!("Testing style: {} with prompt: {}", style, prompt);
        
        let generate_request = Request::builder()
            .method(Method::POST)
            .uri("/api/characters/generate/field")
            .header("content-type", "application/json")
            .header("cookie", &session_cookie)
            .body(Body::from(
                json!({
                    "field": "description",
                    "style": style,
                    "user_prompt": prompt,
                    "character_context": null,
                    "generation_options": null
                }).to_string()
            ))
            .unwrap();

        let generate_response = test_app.router.clone().oneshot(generate_request).await.unwrap();
        
        let status = generate_response.status();
        let body = generate_response.into_body().collect().await.unwrap().to_bytes();
        let response_text = String::from_utf8(body.to_vec()).unwrap();
        
        println!("Style '{}' - Status: {}", style, status);
        println!("Style '{}' - Response: {}", style, response_text);

        if status == StatusCode::OK {
            let json_response: Result<serde_json::Value, _> = serde_json::from_str(&response_text);
            if let Ok(json) = json_response {
                if let Some(content) = json.get("content") {
                    println!("✅ Style '{}' generated content: {}", style, content);
                }
            }
        }
        
        // Give the API a moment between requests
        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
    }
}