#![cfg(test)]
//! Integration tests for agentic lorebook API endpoints
//!
//! These tests verify that the API endpoints correctly:
//! - Expose the agentic lorebook tools via REST API
//! - Handle authentication and authorization
//! - Validate request payloads
//! - Return properly formatted responses
//! - Handle errors gracefully

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use bcrypt;
use chrono::Utc;
use deadpool_diesel::postgres::Pool;
use diesel::{prelude::*, PgConnection, RunQueryDsl};
use genai::{
    adapter::AdapterKind,
    chat::{ChatResponse, Usage},
    ModelIden,
};
use http_body_util::BodyExt;
use scribe_backend::{
    auth::session_dek::SessionDek,
    crypto,
    models::{
        lorebook_dtos::{
            AnalyzeLorebookResponse, CreateLorebookPayload, ExtractLorebookEntriesFromChatResponse,
            GenerateLorebookEntriesPayload, GenerateLorebookEntriesResponse,
        },
        users::{AccountStatus, NewUser, UserDbQuery, UserRole},
    },
    schema::users,
    test_helpers::{ensure_tracing_initialized, TestDataGuard},
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

/// Helper to hash a password for tests
fn hash_test_password(password: &str) -> String {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).expect("Failed to hash test password with bcrypt")
}

/// Helper to insert a unique test user with a known password hash
fn insert_test_user_with_password(
    conn: &mut PgConnection,
    username: &str,
    password: &str,
) -> Result<(scribe_backend::models::users::User, SessionDek), diesel::result::Error> {
    let hashed_password = hash_test_password(password);
    let email = format!("{username}@example.com");

    let kek_salt = crypto::generate_salt().expect("Failed to generate KEK salt for test user");
    let dek = crypto::generate_dek().expect("Failed to generate DEK for test user");

    let secret_password = SecretString::new(password.to_string().into());
    let kek = crypto::derive_kek(&secret_password, &kek_salt)
        .expect("Failed to derive KEK for test user");

    let (encrypted_dek, dek_nonce) = crypto::encrypt_gcm(dek.expose_secret(), &kek)
        .expect("Failed to encrypt DEK for test user");

    let new_user = NewUser {
        username: username.to_string(),
        password_hash: hashed_password,
        email,
        kek_salt,
        encrypted_dek,
        encrypted_dek_by_recovery: None,
        role: UserRole::User,
        recovery_kek_salt: None,
        dek_nonce,
        recovery_dek_nonce: None,
        account_status: AccountStatus::Active,
        total_prompt_tokens: 0,
        total_completion_tokens: 0,
        total_token_cost_cents: 0,
        tokens_last_reset_at: None,
        token_usage_updated_at: Utc::now(),
    };
    diesel::insert_into(users::table)
        .values(&new_user)
        .returning(UserDbQuery::as_returning())
        .get_result::<UserDbQuery>(conn)
        .map(|user_db| (user_db.into(), SessionDek(dek)))
}

/// Helper function to run DB operations via pool interact
async fn run_db_op<F, T>(pool: &Pool, op: F) -> Result<T, anyhow::Error>
where
    F: FnOnce(&mut PgConnection) -> Result<T, diesel::result::Error> + Send + 'static,
    T: Send + 'static,
{
    let obj = pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get DB conn from pool: {}", e))?;
    match obj.interact(op).await {
        Ok(Ok(data)) => Ok(data),
        Ok(Err(db_err)) => Err(anyhow::Error::new(db_err)),
        Err(interact_err) => Err(anyhow::anyhow!(
            "Deadpool interact error: {:?}",
            interact_err
        )),
    }
}

/// Helper to extract JSON body from response
async fn get_json_body<T>(
    response: axum::http::Response<Body>,
) -> Result<(StatusCode, T), anyhow::Error>
where
    T: serde::de::DeserializeOwned,
{
    let status = response.status();
    let body_bytes = response.into_body().collect().await?.to_bytes();
    let body_text = String::from_utf8(body_bytes.to_vec())?;
    let data: T = serde_json::from_str(&body_text)?;
    Ok((status, data))
}

/// Helper to extract text body from response
async fn get_text_body(
    response: axum::http::Response<Body>,
) -> Result<(StatusCode, String), anyhow::Error> {
    let status = response.status();
    let body_bytes = response.into_body().collect().await?.to_bytes();
    let body_text = String::from_utf8(body_bytes.to_vec())?;
    Ok((status, body_text))
}

/// Helper to login and get session cookie
async fn login_user(
    test_app: &scribe_backend::test_helpers::TestApp,
    username: &str,
    password: &str,
) -> Result<String, anyhow::Error> {
    let login_body = json!({
        "identifier": username,
        "password": password
    });

    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&login_body)?))?;

    let login_response = test_app.router.clone().oneshot(login_request).await?;

    if login_response.status() != StatusCode::OK {
        return Err(anyhow::anyhow!(
            "Login failed with status: {}",
            login_response.status()
        ));
    }

    let session_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .ok_or_else(|| anyhow::anyhow!("Login response missing Set-Cookie header"))?
        .to_str()?
        .split(';')
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid Set-Cookie format"))?
        .to_string();

    Ok(session_cookie)
}

/// Helper to create test lorebook via API
async fn create_test_lorebook_via_api(
    test_app: &scribe_backend::test_helpers::TestApp,
    session_cookie: &str,
) -> Result<Uuid, anyhow::Error> {
    let create_payload = CreateLorebookPayload {
        name: "Test Lorebook for AI".to_string(),
        description: Some("Test lorebook for AI generation and analysis".to_string()),
    };

    let create_request = Request::builder()
        .method(Method::POST)
        .uri("/api/lorebooks")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, session_cookie)
        .body(Body::from(serde_json::to_vec(&create_payload)?))?;

    let create_response = test_app.router.clone().oneshot(create_request).await?;

    if create_response.status() != StatusCode::CREATED {
        return Err(anyhow::anyhow!(
            "Failed to create lorebook: status={}",
            create_response.status()
        ));
    }

    let (_, lorebook): (_, serde_json::Value) = get_json_body(create_response).await?;
    let lorebook_id = Uuid::parse_str(lorebook["id"].as_str().unwrap())?;
    Ok(lorebook_id)
}

mod generate_entries_api_tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_entries_endpoint_success() -> Result<(), anyhow::Error> {
        ensure_tracing_initialized();
        let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
        let pool = test_app.db_pool.clone();
        let mut guard = TestDataGuard::new(pool.clone(), None);

        // Create test user
        let test_password = "testpassword123";
        let test_username = format!("gen_api_user_{}", Uuid::new_v4());
        let username_clone = test_username.clone();
        let (user, _) = run_db_op(&pool, move |conn| {
            insert_test_user_with_password(conn, &username_clone, test_password)
        })
        .await?;
        guard.add_user(user.id);

        // Login
        let session_cookie = login_user(&test_app, &test_username, test_password).await?;

        // Create lorebook
        let lorebook_id = create_test_lorebook_via_api(&test_app, &session_cookie).await?;

        // Configure mock AI client to return valid batch lorebook entries
        if let Some(mock_client) = &test_app.mock_ai_client {
            let batch_response = json!({
                "entries": [
                    {
                        "name": "The Prancing Pony Tavern",
                        "content": "A warm and welcoming establishment known for its hearty meals and strong ale",
                        "keys": ["prancing pony", "tavern", "inn"],
                        "category": "location",
                        "reasoning": "Central gathering place for adventurers"
                    },
                    {
                        "name": "Barliman Butterbur",
                        "content": "The jovial innkeeper of the Prancing Pony, always ready with a story",
                        "keys": ["barliman", "innkeeper", "butterbur"],
                        "category": "character",
                        "reasoning": "Key NPC for quest hooks and local information"
                    },
                    {
                        "name": "The Lost Artifact Quest",
                        "content": "Rumors speak of an ancient relic hidden in the nearby ruins",
                        "keys": ["artifact", "quest", "ruins"],
                        "category": "lore",
                        "reasoning": "Main quest hook for the campaign"
                    }
                ],
                "reasoning": "Generated diverse entries for a medieval fantasy tavern setting",
                "quality_assessment": "Entries provide good hooks for roleplay and adventure"
            });

            let ai_response = ChatResponse {
                model_iden: ModelIden::new(AdapterKind::Gemini, "gemini/mock-model"),
                provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini/mock-model"),
                contents: vec![genai::chat::MessageContent::Text(
                    batch_response.to_string(),
                )],
                reasoning_content: None,
                usage: Usage {
                    prompt_tokens: Some(100),
                    completion_tokens: Some(200),
                    total_tokens: Some(300),
                    prompt_tokens_details: None,
                    completion_tokens_details: None,
                },
            };

            mock_client.set_response(Ok(ai_response));
        }

        // Call generate entries endpoint
        let generate_payload = GenerateLorebookEntriesPayload {
            theme: "medieval fantasy tavern with colorful NPCs".to_string(),
            count: 3,
            context: Some("Campaign setting for D&D 5e".to_string()),
        };

        let generate_request = Request::builder()
            .method(Method::POST)
            .uri(&format!("/api/lorebooks/{}/ai/generate", lorebook_id))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(serde_json::to_vec(&generate_payload)?))?;

        let generate_response = test_app.router.clone().oneshot(generate_request).await?;

        let (status, result): (StatusCode, GenerateLorebookEntriesResponse) =
            get_json_body(generate_response).await?;

        assert_eq!(status, StatusCode::OK, "Generate entries should succeed");
        assert!(result.success);
        assert_eq!(result.entries_generated, 3, "Should generate 3 entries");
        assert_eq!(result.entries.len(), 3, "Should return 3 entry previews");
        assert!(!result.message.is_empty());

        // Verify entries have IDs and titles
        for entry in &result.entries {
            assert!(!entry.entry_title.is_empty());
            assert_ne!(entry.id, Uuid::nil());
        }

        guard.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_generate_entries_requires_authentication() -> Result<(), anyhow::Error> {
        ensure_tracing_initialized();
        let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;

        let lorebook_id = Uuid::new_v4();
        let generate_payload = GenerateLorebookEntriesPayload {
            theme: "test theme".to_string(),
            count: 3,
            context: None,
        };

        let generate_request = Request::builder()
            .method(Method::POST)
            .uri(&format!("/api/lorebooks/{}/ai/generate", lorebook_id))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&generate_payload)?))?;

        let generate_response = test_app.router.clone().oneshot(generate_request).await?;

        assert_eq!(
            generate_response.status(),
            StatusCode::UNAUTHORIZED,
            "Should require authentication"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_generate_entries_validates_payload() -> Result<(), anyhow::Error> {
        ensure_tracing_initialized();
        let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
        let pool = test_app.db_pool.clone();
        let mut guard = TestDataGuard::new(pool.clone(), None);

        // Create and login user
        let test_password = "testpassword123";
        let test_username = format!("validation_user_{}", Uuid::new_v4());
        let username_clone = test_username.clone();
        let (user, _) = run_db_op(&pool, move |conn| {
            insert_test_user_with_password(conn, &username_clone, test_password)
        })
        .await?;
        guard.add_user(user.id);

        let session_cookie = login_user(&test_app, &test_username, test_password).await?;
        let lorebook_id = create_test_lorebook_via_api(&test_app, &session_cookie).await?;

        // Test empty theme
        let empty_theme_request = Request::builder()
            .method(Method::POST)
            .uri(&format!("/api/lorebooks/{}/ai/generate", lorebook_id))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(serde_json::to_vec(&json!({
                "theme": "",
                "count": 3,
            }))?))?;

        let response = test_app.router.clone().oneshot(empty_theme_request).await?;
        assert!(
            response.status().is_client_error(),
            "Should reject empty theme"
        );

        // Test count out of range (too high)
        let high_count_request = Request::builder()
            .method(Method::POST)
            .uri(&format!("/api/lorebooks/{}/ai/generate", lorebook_id))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(serde_json::to_vec(&json!({
                "theme": "test theme",
                "count": 25,
            }))?))?;

        let response = test_app.router.clone().oneshot(high_count_request).await?;
        assert!(
            response.status().is_client_error(),
            "Should reject count > 20"
        );

        guard.cleanup().await?;
        Ok(())
    }
}

mod analyze_lorebook_api_tests {
    use super::*;

    #[tokio::test]
    async fn test_analyze_endpoint_success() -> Result<(), anyhow::Error> {
        ensure_tracing_initialized();
        let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
        let pool = test_app.db_pool.clone();
        let mut guard = TestDataGuard::new(pool.clone(), None);

        // Create and login user
        let test_password = "testpassword123";
        let test_username = format!("analyze_api_user_{}", Uuid::new_v4());
        let username_clone = test_username.clone();
        let (user, _) = run_db_op(&pool, move |conn| {
            insert_test_user_with_password(conn, &username_clone, test_password)
        })
        .await?;
        guard.add_user(user.id);

        let session_cookie = login_user(&test_app, &test_username, test_password).await?;
        let lorebook_id = create_test_lorebook_via_api(&test_app, &session_cookie).await?;

        // Configure mock AI client to return valid analysis results
        if let Some(mock_client) = &test_app.mock_ai_client {
            // The analyze tool expects the raw AI response to be structured output
            let analysis_response = json!({
                "analysis": {
                    "gaps": [
                        "Missing information about the world's magic system",
                        "No entries for major political factions",
                        "Limited geographic details"
                    ],
                    "consistency_issues": [
                        "Timeline inconsistencies need resolution"
                    ],
                    "improvement_suggestions": [
                        "Add more character motivations and backgrounds",
                        "Include sensory details for locations",
                        "Expand on historical events"
                    ],
                    "recommended_themes": [
                        "The Arcane Council and magical governance",
                        "Trade routes and economic centers",
                        "Ancient ruins and their mysteries"
                    ]
                }
            });

            let ai_response = ChatResponse {
                model_iden: ModelIden::new(AdapterKind::Gemini, "gemini/mock-model"),
                provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini/mock-model"),
                contents: vec![genai::chat::MessageContent::Text(
                    analysis_response.to_string(),
                )],
                reasoning_content: None,
                usage: Usage {
                    prompt_tokens: Some(150),
                    completion_tokens: Some(180),
                    total_tokens: Some(330),
                    prompt_tokens_details: None,
                    completion_tokens_details: None,
                },
            };

            mock_client.set_response(Ok(ai_response));
        }

        // Call analyze endpoint
        let analyze_request = Request::builder()
            .method(Method::POST)
            .uri(&format!("/api/lorebooks/{}/ai/analyze", lorebook_id))
            .header(header::COOKIE, &session_cookie)
            .body(Body::empty())?;

        let analyze_response = test_app.router.clone().oneshot(analyze_request).await?;

        let (status, result): (StatusCode, AnalyzeLorebookResponse) =
            get_json_body(analyze_response).await?;

        assert_eq!(status, StatusCode::OK, "Analyze should succeed");
        assert!(result.success);
        assert_eq!(result.entries_analyzed, 0, "Empty lorebook has 0 entries");

        // For empty lorebooks, the tool returns a default analysis without calling AI
        assert_eq!(
            result.analysis.gaps.len(),
            1,
            "Empty lorebook should have 1 gap"
        );
        assert!(
            result.analysis.gaps[0].contains("No entries found"),
            "Gap should mention no entries"
        );
        assert_eq!(
            result.analysis.consistency_issues.len(),
            0,
            "Empty lorebook has no consistency issues"
        );
        assert_eq!(
            result.analysis.improvement_suggestions.len(),
            1,
            "Should have 1 suggestion"
        );
        assert_eq!(
            result.analysis.recommended_themes.len(),
            0,
            "Empty lorebook has no recommended themes"
        );

        guard.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_analyze_requires_authentication() -> Result<(), anyhow::Error> {
        ensure_tracing_initialized();
        let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;

        let lorebook_id = Uuid::new_v4();

        let analyze_request = Request::builder()
            .method(Method::POST)
            .uri(&format!("/api/lorebooks/{}/ai/analyze", lorebook_id))
            .body(Body::empty())?;

        let analyze_response = test_app.router.clone().oneshot(analyze_request).await?;

        assert_eq!(
            analyze_response.status(),
            StatusCode::UNAUTHORIZED,
            "Should require authentication"
        );

        Ok(())
    }
}

mod token_tracking_tests {
    use super::*;

    #[tokio::test]
    async fn test_generate_entries_tracks_token_usage() -> Result<(), anyhow::Error> {
        ensure_tracing_initialized();
        let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
        let pool = test_app.db_pool.clone();
        let mut guard = TestDataGuard::new(pool.clone(), None);

        // Create test user
        let test_password = "testpassword123";
        let test_username = format!("token_track_user_{}", Uuid::new_v4());
        let username_clone = test_username.clone();
        let (user, _) = run_db_op(&pool, move |conn| {
            insert_test_user_with_password(conn, &username_clone, test_password)
        })
        .await?;
        guard.add_user(user.id);

        // Login
        let session_cookie = login_user(&test_app, &test_username, test_password).await?;

        // Create lorebook
        let lorebook_id = create_test_lorebook_via_api(&test_app, &session_cookie).await?;

        // Configure mock AI client with specific token usage
        if let Some(mock_client) = &test_app.mock_ai_client {
            let batch_response = json!({
                "entries": [
                    {
                        "name": "Test Entry",
                        "content": "Test content for token tracking",
                        "keys": ["test", "token"],
                        "category": "lore",
                        "reasoning": "Testing token tracking"
                    }
                ],
                "reasoning": "Token tracking test",
                "quality_assessment": "Good quality"
            });

            let ai_response = ChatResponse {
                model_iden: ModelIden::new(AdapterKind::Gemini, "gemini/mock-model"),
                provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini/mock-model"),
                contents: vec![genai::chat::MessageContent::Text(
                    batch_response.to_string(),
                )],
                reasoning_content: None,
                usage: Usage {
                    prompt_tokens: Some(1250),
                    completion_tokens: Some(3750),
                    total_tokens: Some(5000),
                    prompt_tokens_details: None,
                    completion_tokens_details: None,
                },
            };

            mock_client.set_response(Ok(ai_response));
        }

        // Call generate entries endpoint
        let generate_payload = GenerateLorebookEntriesPayload {
            theme: "test theme for token tracking".to_string(),
            count: 1,
            context: Some("Testing token usage tracking".to_string()),
        };

        let generate_request = Request::builder()
            .method(Method::POST)
            .uri(&format!("/api/lorebooks/{}/ai/generate", lorebook_id))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(serde_json::to_vec(&generate_payload)?))?;

        let generate_response = test_app.router.clone().oneshot(generate_request).await?;

        let (status, result): (StatusCode, GenerateLorebookEntriesResponse) =
            get_json_body(generate_response).await?;

        // Verify successful response
        assert_eq!(status, StatusCode::OK, "Generate entries should succeed");
        assert!(result.success);
        assert_eq!(result.entries_generated, 1, "Should generate 1 entry");

        // Note: We cannot directly verify logging in this test, but the handler
        // should have logged: prompt_tokens=1250, completion_tokens=3750, total_tokens=5000

        guard.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_analyze_lorebook_tracks_token_usage() -> Result<(), anyhow::Error> {
        ensure_tracing_initialized();
        let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
        let pool = test_app.db_pool.clone();
        let mut guard = TestDataGuard::new(pool.clone(), None);

        // Create and login user
        let test_password = "testpassword123";
        let test_username = format!("token_analyze_user_{}", Uuid::new_v4());
        let username_clone = test_username.clone();
        let (user, _) = run_db_op(&pool, move |conn| {
            insert_test_user_with_password(conn, &username_clone, test_password)
        })
        .await?;
        guard.add_user(user.id);

        let session_cookie = login_user(&test_app, &test_username, test_password).await?;
        let lorebook_id = create_test_lorebook_via_api(&test_app, &session_cookie).await?;

        // Configure mock AI client with specific token usage
        if let Some(mock_client) = &test_app.mock_ai_client {
            let analysis_response = json!({
                "analysis": {
                    "gaps": ["Test gap 1", "Test gap 2"],
                    "consistency_issues": ["Test issue"],
                    "improvement_suggestions": ["Test suggestion"],
                    "recommended_themes": ["Test theme"]
                }
            });

            let ai_response = ChatResponse {
                model_iden: ModelIden::new(AdapterKind::Gemini, "gemini/mock-model"),
                provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini/mock-model"),
                contents: vec![genai::chat::MessageContent::Text(
                    analysis_response.to_string(),
                )],
                reasoning_content: None,
                usage: Usage {
                    prompt_tokens: Some(800),
                    completion_tokens: Some(1200),
                    total_tokens: Some(2000),
                    prompt_tokens_details: None,
                    completion_tokens_details: None,
                },
            };

            mock_client.set_response(Ok(ai_response));
        }

        // Call analyze endpoint
        let analyze_request = Request::builder()
            .method(Method::POST)
            .uri(&format!("/api/lorebooks/{}/ai/analyze", lorebook_id))
            .header(header::COOKIE, &session_cookie)
            .body(Body::empty())?;

        let analyze_response = test_app.router.clone().oneshot(analyze_request).await?;

        let (status, result): (StatusCode, AnalyzeLorebookResponse) =
            get_json_body(analyze_response).await?;

        // Verify successful response
        assert_eq!(status, StatusCode::OK, "Analyze should succeed");
        assert!(result.success);

        // Note: We cannot directly verify logging in this test, but the handler
        // should have logged: prompt_tokens=800, completion_tokens=1200, total_tokens=2000

        guard.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_generate_entries_handles_missing_token_usage() -> Result<(), anyhow::Error> {
        ensure_tracing_initialized();
        let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
        let pool = test_app.db_pool.clone();
        let mut guard = TestDataGuard::new(pool.clone(), None);

        // Create test user
        let test_password = "testpassword123";
        let test_username = format!("missing_token_user_{}", Uuid::new_v4());
        let username_clone = test_username.clone();
        let (user, _) = run_db_op(&pool, move |conn| {
            insert_test_user_with_password(conn, &username_clone, test_password)
        })
        .await?;
        guard.add_user(user.id);

        let session_cookie = login_user(&test_app, &test_username, test_password).await?;
        let lorebook_id = create_test_lorebook_via_api(&test_app, &session_cookie).await?;

        // Configure mock AI client with NO token usage (None values)
        if let Some(mock_client) = &test_app.mock_ai_client {
            let batch_response = json!({
                "entries": [
                    {
                        "name": "Test Entry",
                        "content": "Test content",
                        "keys": ["test"],
                        "category": "lore",
                        "reasoning": "Testing"
                    }
                ],
                "reasoning": "Test",
                "quality_assessment": "Good"
            });

            let ai_response = ChatResponse {
                model_iden: ModelIden::new(AdapterKind::Gemini, "gemini/mock-model"),
                provider_model_iden: ModelIden::new(AdapterKind::Gemini, "gemini/mock-model"),
                contents: vec![genai::chat::MessageContent::Text(
                    batch_response.to_string(),
                )],
                reasoning_content: None,
                usage: Usage {
                    prompt_tokens: None,
                    completion_tokens: None,
                    total_tokens: None,
                    prompt_tokens_details: None,
                    completion_tokens_details: None,
                },
            };

            mock_client.set_response(Ok(ai_response));
        }

        // Call generate entries endpoint
        let generate_payload = GenerateLorebookEntriesPayload {
            theme: "test theme".to_string(),
            count: 1,
            context: None,
        };

        let generate_request = Request::builder()
            .method(Method::POST)
            .uri(&format!("/api/lorebooks/{}/ai/generate", lorebook_id))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(serde_json::to_vec(&generate_payload)?))?;

        let generate_response = test_app.router.clone().oneshot(generate_request).await?;

        let (status, result): (StatusCode, GenerateLorebookEntriesResponse) =
            get_json_body(generate_response).await?;

        // Should still succeed with 0 token counts
        assert_eq!(status, StatusCode::OK, "Should handle missing token usage");
        assert!(result.success);
        assert_eq!(result.entries_generated, 1);

        guard.cleanup().await?;
        Ok(())
    }
}

mod extract_from_chat_api_tests {
    use super::*;
    use scribe_backend::models::{chats::MessageRole, Chat, NewChat, NewChatMessage};
    use scribe_backend::schema::{chat_messages, chat_sessions};

    /// Helper to create test chat session
    async fn create_test_chat_session(
        pool: &Pool,
        user_id: Uuid,
        character_id: Uuid,
    ) -> Result<Uuid, anyhow::Error> {
        let chat_id = Uuid::new_v4();
        let now = Utc::now();
        let new_chat = NewChat {
            id: chat_id,
            user_id,
            character_id,
            title_ciphertext: None,
            title_nonce: None,
            created_at: now,
            updated_at: now,
            history_management_strategy: "sliding_window".to_string(),
            history_management_limit: 20,
            model_name: "gemini-2.5-flash".to_string(),
            visibility: Some("private".to_string()),
            active_custom_persona_id: None,
            active_impersonated_character_id: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            seed: None,
            stop_sequences: None,
            gemini_thinking_budget: None,
            gemini_enable_code_execution: None,
            system_prompt_ciphertext: None,
            system_prompt_nonce: None,
            player_chronicle_id: None,
            total_prompt_tokens: 0,
            total_completion_tokens: 0,
            estimated_cost_cents: 0,
            tokens_counted_at: now,
            total_credits_used: bigdecimal::BigDecimal::from(0),
            prompt_template_id: "default".to_string(),
            narrative_style_override_ciphertext: None,
            narrative_style_override_nonce: None,
        };

        run_db_op(pool, move |conn| {
            diesel::insert_into(chat_sessions::table)
                .values(&new_chat)
                .returning(Chat::as_returning())
                .get_result::<Chat>(conn)
        })
        .await?;

        Ok(chat_id)
    }

    /// Helper to create test messages in a chat session
    async fn create_test_messages(
        pool: &Pool,
        session_id: Uuid,
        user_id: Uuid,
        dek: &SessionDek,
    ) -> Result<(), anyhow::Error> {
        use scribe_backend::services::EncryptionService;

        let encryption_service = EncryptionService::new();
        let dek_bytes = dek.0.expose_secret();

        // Create 5 test messages
        let messages_data = vec![
            ("User", "Hello, tell me about this tavern."),
            (
                "Assistant",
                "The tavern is a cozy place with warm lighting.",
            ),
            ("User", "Who is the owner?"),
            (
                "Assistant",
                "Barliman Butterbur owns this fine establishment.",
            ),
            ("User", "What can I order here?"),
        ];

        for (_i, (role, content)) in messages_data.iter().enumerate() {
            let (content_ciphertext, content_nonce) = encryption_service
                .encrypt(content, dek_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to encrypt message: {}", e))?;

            let message_role = if *role == "User" {
                MessageRole::User
            } else {
                MessageRole::Assistant
            };

            let new_message = NewChatMessage {
                id: Uuid::new_v4(),
                session_id,
                user_id,
                message_type: message_role,
                content: content_ciphertext,
                content_nonce: Some(content_nonce),
                created_at: Utc::now(),
                updated_at: Utc::now(),
                role: Some(role.to_string()),
                parts: None,
                attachments: None,
                prompt_tokens: None,
                completion_tokens: None,
                raw_prompt_ciphertext: None,
                raw_prompt_nonce: None,
                model_name: "gemini-2.5-flash".to_string(),
            };

            run_db_op(pool, move |conn| {
                diesel::insert_into(chat_messages::table)
                    .values(&new_message)
                    .execute(conn)
            })
            .await?;
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_extract_from_chat_placeholder_response() -> Result<(), anyhow::Error> {
        ensure_tracing_initialized();
        let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
        let pool = test_app.db_pool.clone();
        let mut guard = TestDataGuard::new(pool.clone(), None);

        // Create test user
        let test_password = "testpassword123";
        let test_username = format!("extract_user_{}", Uuid::new_v4());
        let username_clone = test_username.clone();
        let (user, dek) = run_db_op(&pool, move |conn| {
            insert_test_user_with_password(conn, &username_clone, test_password)
        })
        .await?;
        guard.add_user(user.id);

        // Login
        let session_cookie = login_user(&test_app, &test_username, test_password).await?;

        // Create lorebook
        let lorebook_id = create_test_lorebook_via_api(&test_app, &session_cookie).await?;

        // Create test character (simplified - just need the ID for chat session)
        let character_id = Uuid::new_v4();

        // Create chat session and messages
        let chat_session_id = create_test_chat_session(&pool, user.id, character_id).await?;
        create_test_messages(&pool, chat_session_id, user.id, &dek).await?;

        // Call extract endpoint
        let extract_payload = json!({
            "chat_session_id": chat_session_id.to_string(),
            "start_message_index": 0,
            "end_message_index": 4,
        });

        let extract_request = Request::builder()
            .method(Method::POST)
            .uri(&format!("/api/lorebooks/{}/extract-from-chat", lorebook_id))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(serde_json::to_vec(&extract_payload)?))?;

        let extract_response = test_app.router.clone().oneshot(extract_request).await?;

        let (status, result): (StatusCode, ExtractLorebookEntriesFromChatResponse) =
            get_json_body(extract_response).await?;

        // Verify placeholder response (current implementation)
        assert_eq!(status, StatusCode::OK, "Extract should succeed");
        assert!(result.success);
        assert_eq!(result.entries_extracted, 0, "Placeholder returns 0 entries");
        assert!(
            result.message.contains("AI implementation pending"),
            "Should indicate AI pending"
        );

        guard.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_extract_from_chat_requires_authentication() -> Result<(), anyhow::Error> {
        ensure_tracing_initialized();
        let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;

        let lorebook_id = Uuid::new_v4();
        let chat_session_id = Uuid::new_v4();

        let extract_payload = json!({
            "chat_session_id": chat_session_id.to_string(),
        });

        let extract_request = Request::builder()
            .method(Method::POST)
            .uri(&format!("/api/lorebooks/{}/extract-from-chat", lorebook_id))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&extract_payload)?))?;

        let extract_response = test_app.router.clone().oneshot(extract_request).await?;

        assert_eq!(
            extract_response.status(),
            StatusCode::UNAUTHORIZED,
            "Should require authentication"
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_extract_from_chat_handles_no_messages() -> Result<(), anyhow::Error> {
        ensure_tracing_initialized();
        let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
        let pool = test_app.db_pool.clone();
        let mut guard = TestDataGuard::new(pool.clone(), None);

        // Create test user
        let test_password = "testpassword123";
        let test_username = format!("extract_no_msgs_user_{}", Uuid::new_v4());
        let username_clone = test_username.clone();
        let (user, _) = run_db_op(&pool, move |conn| {
            insert_test_user_with_password(conn, &username_clone, test_password)
        })
        .await?;
        guard.add_user(user.id);

        // Login
        let session_cookie = login_user(&test_app, &test_username, test_password).await?;

        // Create lorebook
        let lorebook_id = create_test_lorebook_via_api(&test_app, &session_cookie).await?;

        // Create empty chat session
        let character_id = Uuid::new_v4();
        let chat_session_id = create_test_chat_session(&pool, user.id, character_id).await?;

        // Call extract endpoint with empty chat
        let extract_payload = json!({
            "chat_session_id": chat_session_id.to_string(),
        });

        let extract_request = Request::builder()
            .method(Method::POST)
            .uri(&format!("/api/lorebooks/{}/extract-from-chat", lorebook_id))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(serde_json::to_vec(&extract_payload)?))?;

        let extract_response = test_app.router.clone().oneshot(extract_request).await?;

        let (status, result): (StatusCode, ExtractLorebookEntriesFromChatResponse) =
            get_json_body(extract_response).await?;

        assert_eq!(status, StatusCode::OK, "Should handle empty chat");
        assert!(
            !result.success,
            "Should return success=false for no messages"
        );
        assert_eq!(result.entries_extracted, 0);
        assert!(
            result.message.contains("No messages found"),
            "Should indicate no messages"
        );

        guard.cleanup().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_extract_from_chat_validates_message_indices() -> Result<(), anyhow::Error> {
        ensure_tracing_initialized();
        let test_app = scribe_backend::test_helpers::spawn_app(false, false, false).await;
        let pool = test_app.db_pool.clone();
        let mut guard = TestDataGuard::new(pool.clone(), None);

        // Create test user
        let test_password = "testpassword123";
        let test_username = format!("extract_validate_user_{}", Uuid::new_v4());
        let username_clone = test_username.clone();
        let (user, dek) = run_db_op(&pool, move |conn| {
            insert_test_user_with_password(conn, &username_clone, test_password)
        })
        .await?;
        guard.add_user(user.id);

        // Login
        let session_cookie = login_user(&test_app, &test_username, test_password).await?;

        // Create lorebook
        let lorebook_id = create_test_lorebook_via_api(&test_app, &session_cookie).await?;

        // Create chat session with messages
        let character_id = Uuid::new_v4();
        let chat_session_id = create_test_chat_session(&pool, user.id, character_id).await?;
        create_test_messages(&pool, chat_session_id, user.id, &dek).await?;

        // Test invalid indices (start > end)
        let invalid_payload = json!({
            "chat_session_id": chat_session_id.to_string(),
            "start_message_index": 4,
            "end_message_index": 1,
        });

        let invalid_request = Request::builder()
            .method(Method::POST)
            .uri(&format!("/api/lorebooks/{}/extract-from-chat", lorebook_id))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(serde_json::to_vec(&invalid_payload)?))?;

        let invalid_response = test_app.router.clone().oneshot(invalid_request).await?;

        assert!(
            invalid_response.status().is_client_error(),
            "Should reject invalid index range"
        );

        guard.cleanup().await?;
        Ok(())
    }
}
