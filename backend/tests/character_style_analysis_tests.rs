use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt;
use scribe_backend::test_helpers;
use serde_json::json;
use tower::ServiceExt;

/// Helper to login and get session cookie
async fn login_and_get_cookie(router: &axum::Router, email: &str, password: &str) -> String {
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "identifier": email,
                "password": password
            })
            .to_string(),
        ))
        .unwrap();

    let login_response = router.clone().oneshot(login_request).await.unwrap();

    let login_status = login_response.status();
    if login_status != StatusCode::OK {
        let login_body = login_response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let login_response_text = String::from_utf8(login_body.to_vec()).unwrap();
        panic!(
            "Login failed with status {}: {}",
            login_status, login_response_text
        );
    }

    login_response
        .headers()
        .get("set-cookie")
        .expect("No session cookie found")
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string()
}

/// Helper to call style analysis endpoint
async fn analyze_style(
    router: &axum::Router,
    session_cookie: &str,
    content: &str,
) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters/analyze/style")
        .header("content-type", "application/json")
        .header("cookie", session_cookie)
        .body(Body::from(
            json!({
                "content": content
            })
            .to_string(),
        ))
        .unwrap();

    let response = router.clone().oneshot(request).await.unwrap();

    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let response_text = String::from_utf8(body.to_vec()).unwrap();

    let json: serde_json::Value = serde_json::from_str(&response_text)
        .unwrap_or_else(|_| panic!("Failed to parse JSON response: {}", response_text));

    (status, json)
}

#[tokio::test]
#[ignore] // Requires real AI
async fn test_traits_style_detection() {
    let test_app = test_helpers::spawn_app(true, true, false).await;

    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "traits_user@example.com".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let session_cookie =
        login_and_get_cookie(&test_app.router, "traits_user@example.com", "password123").await;

    // Traits-style content: short, punchy characteristics
    let traits_content =
        "Tall. Athletic build. Green eyes. Former soldier. Quiet. Strategic thinker. \
                          Loyal to friends. Distrusts authority. Skilled in hand-to-hand combat. \
                          Has a scar above left eyebrow.";

    let (status, json) = analyze_style(&test_app.router, &session_cookie, traits_content).await;

    assert_eq!(status, StatusCode::OK, "Style analysis should succeed");

    // Verify response structure
    assert!(
        json.get("detected_style").is_some(),
        "Should have detected_style field"
    );
    assert!(
        json.get("confidence").is_some(),
        "Should have confidence field"
    );
    assert!(
        json.get("style_indicators").is_some(),
        "Should have style_indicators field"
    );
    assert!(
        json.get("recommendations").is_some(),
        "Should have recommendations field"
    );

    let detected_style = json["detected_style"].as_str().unwrap();
    let confidence = json["confidence"].as_f64().unwrap();

    println!("Detected style: {}", detected_style);
    println!("Confidence: {}", confidence);
    println!("Indicators: {}", json["style_indicators"]);
    println!("Recommendations: {}", json["recommendations"]);

    // Should detect as traits style with reasonable confidence
    assert_eq!(
        detected_style, "traits",
        "Should detect traits-style content"
    );
    assert!(
        confidence >= 0.6,
        "Should have reasonable confidence for clear traits style"
    );
}

#[tokio::test]
#[ignore] // Requires real AI
async fn test_narrative_style_detection() {
    let test_app = test_helpers::spawn_app(true, true, false).await;

    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "narrative_user@example.com".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let session_cookie = login_and_get_cookie(
        &test_app.router,
        "narrative_user@example.com",
        "password123",
    )
    .await;

    // Narrative-style content: flowing prose with complete sentences
    let narrative_content = "Captain Elena stands at the helm, her weathered hands gripping the wheel \
                             as storm clouds gather on the horizon. Years at sea have carved lines into \
                             her face, each one telling a story of survival and triumph. She commands \
                             respect not through fear, but through her unwavering dedication to her crew \
                             and her ship. When she speaks, her voice carries the authority of someone \
                             who has faced death and emerged stronger.";

    let (status, json) = analyze_style(&test_app.router, &session_cookie, narrative_content).await;

    assert_eq!(status, StatusCode::OK);

    let detected_style = json["detected_style"].as_str().unwrap();
    let confidence = json["confidence"].as_f64().unwrap();

    println!("Detected style: {}", detected_style);
    println!("Confidence: {}", confidence);

    assert_eq!(
        detected_style, "narrative",
        "Should detect narrative-style content"
    );
    assert!(
        confidence >= 0.6,
        "Should have reasonable confidence for clear narrative style"
    );
}

#[tokio::test]
#[ignore] // Requires real AI
async fn test_profile_style_detection() {
    let test_app = test_helpers::spawn_app(true, true, false).await;

    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "profile_user@example.com".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let session_cookie =
        login_and_get_cookie(&test_app.router, "profile_user@example.com", "password123").await;

    // Profile-style content: structured field/value format
    let profile_content = "Name: Dr. Sarah Chen\n\
                          Age: 34\n\
                          Occupation: Quantum Physicist\n\
                          Education: Ph.D. in Theoretical Physics from MIT\n\
                          Personality: Brilliant, focused, sometimes socially awkward\n\
                          Hobbies: Chess, classical music, hiking\n\
                          Notable Achievements: Published 15 papers on quantum entanglement\n\
                          Current Project: Leading research on quantum computing applications";

    let (status, json) = analyze_style(&test_app.router, &session_cookie, profile_content).await;

    assert_eq!(status, StatusCode::OK);

    let detected_style = json["detected_style"].as_str().unwrap();
    let confidence = json["confidence"].as_f64().unwrap();

    println!("Detected style: {}", detected_style);
    println!("Confidence: {}", confidence);

    assert_eq!(
        detected_style, "profile",
        "Should detect profile-style content"
    );
    assert!(
        confidence >= 0.6,
        "Should have reasonable confidence for clear profile style"
    );
}

#[tokio::test]
#[ignore] // Requires real AI
async fn test_worldbuilding_style_detection() {
    let test_app = test_helpers::spawn_app(true, true, false).await;

    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "worldbuilding_user@example.com".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let session_cookie = login_and_get_cookie(
        &test_app.router,
        "worldbuilding_user@example.com",
        "password123",
    )
    .await;

    // Worldbuilding-style content: rich world context with {{char}} notation
    let worldbuilding_content = "{{char}} is a Guardian of the Stellar Nexus, one of the ancient beings \
                                 tasked with maintaining balance across the multiverse. In the year 3047, \
                                 when humanity first discovered interdimensional travel, the Guardians revealed \
                                 themselves to prevent catastrophic paradoxes. {{char}} specifically oversees \
                                 Timeline Sigma-7, where magic and technology have merged into a single unified \
                                 force known as Technomancy. The Nexus itself exists outside conventional spacetime, \
                                 accessible only through specially calibrated jump gates scattered across known space.";

    let (status, json) =
        analyze_style(&test_app.router, &session_cookie, worldbuilding_content).await;

    assert_eq!(status, StatusCode::OK);

    let detected_style = json["detected_style"].as_str().unwrap();
    let confidence = json["confidence"].as_f64().unwrap();

    println!("Detected style: {}", detected_style);
    println!("Confidence: {}", confidence);

    assert_eq!(
        detected_style, "worldbuilding",
        "Should detect worldbuilding-style content"
    );
    assert!(
        confidence >= 0.5,
        "Should have reasonable confidence for worldbuilding style"
    );
}

#[tokio::test]
#[ignore] // Requires real AI
async fn test_system_style_detection() {
    let test_app = test_helpers::spawn_app(true, true, false).await;

    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "system_user@example.com".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let session_cookie =
        login_and_get_cookie(&test_app.router, "system_user@example.com", "password123").await;

    // System-style content: AI behavior instructions with placeholders
    let system_content = "{{char}} will generate random encounters based on the current location. \
                         {{char}} will track {{user}}'s health, stamina, and inventory throughout the adventure. \
                         When {{user}} attempts an action, {{char}} will determine success or failure based on \
                         their stats and the difficulty. {{char}} will never speak for {{user}} or decide their \
                         actions. {{char}} will maintain consistency with previously established world state. \
                         {{char}} will provide detailed descriptions of NPCs, locations, and events.";

    let (status, json) = analyze_style(&test_app.router, &session_cookie, system_content).await;

    assert_eq!(status, StatusCode::OK);

    let detected_style = json["detected_style"].as_str().unwrap();
    let confidence = json["confidence"].as_f64().unwrap();

    println!("Detected style: {}", detected_style);
    println!("Confidence: {}", confidence);

    assert_eq!(
        detected_style, "system",
        "Should detect system-style content"
    );
    assert!(
        confidence >= 0.6,
        "Should have reasonable confidence for clear system style"
    );
}

#[tokio::test]
#[ignore] // Requires real AI
async fn test_group_style_detection() {
    let test_app = test_helpers::spawn_app(true, true, false).await;

    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "group_user@example.com".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let session_cookie =
        login_and_get_cookie(&test_app.router, "group_user@example.com", "password123").await;

    // Group-style content: multiple character definitions
    let group_content = "Characters(\"Captain Martinez, Engineer Jackson, Navigator Kim\")\n\n\
                        Captain Martinez(\"A former pirate turned legitimate cargo hauler. Tough, \
                        pragmatic, with a hidden soft spot for her crew. Mid-40s with cybernetic \
                        enhancements from past battles.\")\n\n\
                        Engineer Jackson(\"Young prodigy who can fix anything with duct tape and \
                        determination. Optimistic to a fault, provides comic relief during tense \
                        situations. Always covered in grease.\")\n\n\
                        Navigator Kim(\"Mysterious ex-military navigator with classified past. \
                        Rarely speaks but never misses a calculation. Rumored to have psychic \
                        abilities for spacetime navigation.\")";

    let (status, json) = analyze_style(&test_app.router, &session_cookie, group_content).await;

    assert_eq!(status, StatusCode::OK);

    let detected_style = json["detected_style"].as_str().unwrap();
    let confidence = json["confidence"].as_f64().unwrap();

    println!("Detected style: {}", detected_style);
    println!("Confidence: {}", confidence);

    assert_eq!(detected_style, "group", "Should detect group-style content");
    assert!(
        confidence >= 0.5,
        "Should have reasonable confidence for group style"
    );
}

#[tokio::test]
#[ignore] // Requires real AI
async fn test_empty_content_handling() {
    let test_app = test_helpers::spawn_app(true, true, false).await;

    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "empty_user@example.com".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let session_cookie =
        login_and_get_cookie(&test_app.router, "empty_user@example.com", "password123").await;

    // Test with empty string
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters/analyze/style")
        .header("content-type", "application/json")
        .header("cookie", &session_cookie)
        .body(Body::from(
            json!({
                "content": ""
            })
            .to_string(),
        ))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();

    // Empty content should still work, but might detect as "auto" with low confidence
    // or return an error - either is acceptable
    let status = response.status();
    assert!(
        status == StatusCode::OK || status == StatusCode::BAD_REQUEST,
        "Empty content should either succeed or return bad request"
    );
}

#[tokio::test]
#[ignore] // Requires real AI
async fn test_very_short_content() {
    let test_app = test_helpers::spawn_app(true, true, false).await;

    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "short_user@example.com".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let session_cookie =
        login_and_get_cookie(&test_app.router, "short_user@example.com", "password123").await;

    // Very short content - should still attempt to detect
    let short_content = "A wizard.";

    let (status, json) = analyze_style(&test_app.router, &session_cookie, short_content).await;

    assert_eq!(status, StatusCode::OK);

    // Should have a response, but confidence might be low
    let confidence = json["confidence"].as_f64().unwrap();
    println!("Short content confidence: {}", confidence);

    // Very short content might have lower confidence
    assert!(
        confidence >= 0.0 && confidence <= 1.0,
        "Confidence should be between 0 and 1"
    );
}

#[tokio::test]
async fn test_authentication_required() {
    let test_app = test_helpers::spawn_app(true, true, false).await;

    // Try to analyze style without authentication
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters/analyze/style")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "content": "Some content to analyze"
            })
            .to_string(),
        ))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();

    let status = response.status();

    // Should require authentication
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Style analysis should require authentication"
    );
}

#[tokio::test]
#[ignore] // Requires real AI
async fn test_missing_content_field() {
    let test_app = test_helpers::spawn_app(true, true, false).await;

    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "missing_field_user@example.com".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let session_cookie = login_and_get_cookie(
        &test_app.router,
        "missing_field_user@example.com",
        "password123",
    )
    .await;

    // Send request without content field
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/characters/analyze/style")
        .header("content-type", "application/json")
        .header("cookie", &session_cookie)
        .body(Body::from(
            json!({
                "not_content": "Some text"
            })
            .to_string(),
        ))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();

    let status = response.status();

    // Should return bad request for missing field
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "Should return bad request when content field is missing"
    );
}

#[tokio::test]
#[ignore] // Requires real AI
async fn test_confidence_values() {
    let test_app = test_helpers::spawn_app(true, true, false).await;

    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "confidence_user@example.com".to_string(),
        "password123".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let session_cookie = login_and_get_cookie(
        &test_app.router,
        "confidence_user@example.com",
        "password123",
    )
    .await;

    // Test multiple different styles to verify confidence is within valid range
    let test_cases = vec![
        ("Tall. Athletic. Green eyes.", "traits"),
        ("The wizard stood in the tower.", "narrative"),
        ("Name: John\nAge: 30", "profile"),
    ];

    for (content, expected_style) in test_cases {
        let (status, json) = analyze_style(&test_app.router, &session_cookie, content).await;

        assert_eq!(status, StatusCode::OK);

        let confidence = json["confidence"].as_f64().unwrap();
        let detected_style = json["detected_style"].as_str().unwrap();

        println!(
            "Content: '{}' | Expected: {} | Detected: {} | Confidence: {}",
            content, expected_style, detected_style, confidence
        );

        // Confidence should always be between 0 and 1
        assert!(
            confidence >= 0.0 && confidence <= 1.0,
            "Confidence must be between 0 and 1, got {}",
            confidence
        );

        // Give API a moment between requests
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }
}
