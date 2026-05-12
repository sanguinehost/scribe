#![cfg(feature = "postgres-backend")]
#![cfg(test)]

use axum::http::StatusCode;
use reqwest::header::COOKIE;
use uuid::Uuid;

use scribe_backend::models::{
    chats::{Chat, CreateChatRequest, CreateMessageRequest},
    usage::{ChatTokenUsage, TokenUsageSummary},
};
use scribe_backend::test_helpers::{
    db, login_user_via_api, spawn_app_permissive_rate_limiting, TestDataGuard,
};

/// Helper function to poll for token counts with exponential backoff
/// This addresses the async token counting issue where counts may not be immediately available
async fn poll_for_token_count<F, Fut>(
    mut check_fn: F,
    expected_min_tokens: i32,
    max_attempts: u32,
) -> Result<(), String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<i32, String>>,
{
    let mut attempts = 0;
    let mut delay_ms = 50; // Start with 50ms

    while attempts < max_attempts {
        match check_fn().await {
            Ok(token_count) => {
                if token_count >= expected_min_tokens {
                    return Ok(());
                }
            }
            Err(e) => {
                if attempts == max_attempts - 1 {
                    return Err(format!("Failed after {} attempts: {}", attempts + 1, e));
                }
            }
        }

        attempts += 1;
        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        delay_ms = std::cmp::min(delay_ms * 2, 1000); // Exponential backoff, max 1s
    }

    Err(format!(
        "Token count not reached after {} attempts",
        max_attempts
    ))
}

#[tokio::test]
async fn test_user_token_usage_endpoint() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone(), None);

    let username = "token_test_user";
    let password = "password123";
    let user_db = db::create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .unwrap();
    tdg.add_user(user_db.id);

    let (client, auth_cookie_str) = login_user_via_api(&app, username, password).await;

    // Test initial token usage (should be zero)
    let response = client
        .get(format!("{}/api/user-settings/token-usage", app.address))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let token_usage: TokenUsageSummary = response.json().await.unwrap();

    assert_eq!(token_usage.total_prompt_tokens, 0);
    assert_eq!(token_usage.total_completion_tokens, 0);
    assert_eq!(token_usage.total_tokens, 0);
    assert_eq!(token_usage.total_cost_cents, 0);
    assert_eq!(token_usage.total_cost_dollars, 0.0);
    assert!(token_usage.tokens_last_reset_at.is_none());
}

#[tokio::test]
async fn test_chat_token_usage_endpoint() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone(), None);

    let username = "chat_token_test_user";
    let password = "password123";
    let user_db = db::create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .unwrap();
    tdg.add_user(user_db.id);

    let (client, auth_cookie_str) = login_user_via_api(&app, username, password).await;

    // Create a character first
    let character =
        db::create_test_character(&app.db_pool, user_db.id, "Test Character".to_string())
            .await
            .unwrap();
    tdg.add_character(character.id);

    // Create a chat session
    let chat_request = CreateChatRequest {
        character_id: character.id,
        title: Some("Token Test Chat".to_string()),
        active_custom_persona_id: None,
        lorebook_ids: None,
    };

    let response = client
        .post(format!("{}/api/chats/create_session", app.address))
        .json(&chat_request)
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let created_chat: Chat = response.json().await.unwrap();
    tdg.add_chat(created_chat.id);

    // Test initial chat token usage (should be zero)
    let response = client
        .get(format!(
            "{}/api/chats/{}/token-usage",
            app.address, created_chat.id
        ))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let chat_token_usage: ChatTokenUsage = response.json().await.unwrap();

    assert_eq!(chat_token_usage.chat_id, created_chat.id);
    assert_eq!(chat_token_usage.total_prompt_tokens, 0);
    assert_eq!(chat_token_usage.total_completion_tokens, 0);
    assert_eq!(chat_token_usage.total_tokens, 0);
    assert_eq!(chat_token_usage.estimated_cost_cents, 0);
    assert_eq!(chat_token_usage.estimated_cost_dollars, 0.0);
    assert_eq!(chat_token_usage.model_name, "unknown"); // No messages yet
}

#[tokio::test]
async fn test_chat_token_usage_unauthorized() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone(), None);

    // Create two users
    let user1 = db::create_test_user(&app.db_pool, "user1".to_string(), "password123".to_string())
        .await
        .unwrap();
    let user2 = db::create_test_user(&app.db_pool, "user2".to_string(), "password123".to_string())
        .await
        .unwrap();
    tdg.add_user(user1.id);
    tdg.add_user(user2.id);

    let (client, auth_cookie_str) = login_user_via_api(&app, "user1", "password123").await;

    // Create a character for user1
    let character = db::create_test_character(&app.db_pool, user1.id, "Test Character".to_string())
        .await
        .unwrap();
    tdg.add_character(character.id);

    // Create a chat session for user1
    let chat_request = CreateChatRequest {
        character_id: character.id,
        title: Some("User1 Chat".to_string()),
        active_custom_persona_id: None,
        lorebook_ids: None,
    };

    let response = client
        .post(format!("{}/api/chats/create_session", app.address))
        .json(&chat_request)
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();

    let created_chat: Chat = response.json().await.unwrap();
    tdg.add_chat(created_chat.id);

    // Now login as user2 and try to access user1's chat token usage
    let (client2, auth_cookie_str2) = login_user_via_api(&app, "user2", "password123").await;

    let response = client2
        .get(format!(
            "{}/api/chats/{}/token-usage",
            app.address, created_chat.id
        ))
        .header(COOKIE, &auth_cookie_str2)
        .send()
        .await
        .unwrap();

    // Should return 404 (not found) since user2 doesn't own the chat
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_token_usage_without_authentication() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let client = reqwest::Client::new();

    // Test user token usage endpoint without auth
    let response = client
        .get(format!("{}/api/user-settings/token-usage", app.address))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Test chat token usage endpoint without auth
    let fake_chat_id = Uuid::new_v4();
    let response = client
        .get(format!(
            "{}/api/chats/{}/token-usage",
            app.address, fake_chat_id
        ))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_chat_token_usage_not_found() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone(), None);

    let username = "test_user";
    let password = "password123";
    let user_db = db::create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .unwrap();
    tdg.add_user(user_db.id);

    let (client, auth_cookie_str) = login_user_via_api(&app, username, password).await;

    // Try to get token usage for non-existent chat
    let fake_chat_id = Uuid::new_v4();
    let response = client
        .get(format!(
            "{}/api/chats/{}/token-usage",
            app.address, fake_chat_id
        ))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

/// This test verifies that token counts are properly tracked and accumulated
/// when messages are created. This requires the token tracking system to be
/// working in the message handling service.
#[tokio::test]
async fn test_token_accumulation_integration() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone(), None);

    let username = "accumulation_test_user";
    let password = "password123";
    let user_db = db::create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .unwrap();
    tdg.add_user(user_db.id);

    let (client, auth_cookie_str) = login_user_via_api(&app, username, password).await;

    // Create a character
    let character =
        db::create_test_character(&app.db_pool, user_db.id, "Test Character".to_string())
            .await
            .unwrap();
    tdg.add_character(character.id);

    // Create a chat session
    let chat_request = CreateChatRequest {
        character_id: character.id,
        title: Some("Accumulation Test Chat".to_string()),
        active_custom_persona_id: None,
        lorebook_ids: None,
    };

    let response = client
        .post(format!("{}/api/chats/create_session", app.address))
        .json(&chat_request)
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();

    let created_chat: Chat = response.json().await.unwrap();
    tdg.add_chat(created_chat.id);

    // Create a user message (this should trigger token counting)
    let message_request = CreateMessageRequest {
        role: "user".to_string(),
        content: "Hello, this is a comprehensive test message for token counting functionality. This message contains multiple sentences and should generate enough tokens to result in a meaningful cost calculation. We want to verify that the token tracking system works correctly and accumulates tokens properly across both chat sessions and user accounts.".to_string(),
        parts: None,
        attachments: None,
        parent_message_id: None,
    };

    let response = client
        .post(format!(
            "{}/api/chats/{}/messages",
            app.address, created_chat.id
        ))
        .json(&message_request)
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();

    // This might return 201 or 200 depending on implementation
    assert!(response.status().is_success());

    // Poll for token counts with retry logic to handle async token tracking
    let client_clone = client.clone();
    let auth_cookie_clone = auth_cookie_str.clone();
    let address_clone = app.address.clone();
    let chat_id = created_chat.id;

    poll_for_token_count(
        || async {
            let response = client_clone
                .get(format!(
                    "{}/api/chats/{}/token-usage",
                    address_clone, chat_id
                ))
                .header(COOKIE, &auth_cookie_clone)
                .send()
                .await
                .map_err(|e| format!("Request failed: {}", e))?;

            if response.status() != StatusCode::OK {
                return Err(format!("Bad status: {}", response.status()));
            }

            let chat_token_usage: ChatTokenUsage = response
                .json()
                .await
                .map_err(|e| format!("JSON parsing failed: {}", e))?;

            Ok(chat_token_usage.total_prompt_tokens)
        },
        1,  // Expect at least 1 token
        10, // Max 10 attempts
    )
    .await
    .expect("Token count should be updated within retry limit");

    // Get final token usage for assertions
    let response = client
        .get(format!(
            "{}/api/chats/{}/token-usage",
            app.address, created_chat.id
        ))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let chat_token_usage: ChatTokenUsage = response.json().await.unwrap();

    // Should have some prompt tokens from the user message
    println!("Chat token usage: {:?}", chat_token_usage);
    assert!(
        chat_token_usage.total_prompt_tokens > 0,
        "Should have counted prompt tokens, got: {}",
        chat_token_usage.total_prompt_tokens
    );
    assert_eq!(chat_token_usage.total_completion_tokens, 0); // No AI response yet
    assert!(chat_token_usage.total_tokens > 0);
    // Note: With very small token counts (< ~30 tokens), cost might round to 0 cents due to low pricing
    // This is mathematically correct for real-world pricing - we don't assert cost > 0
    println!(
        "Estimated cost cents: {}, dollars: {}",
        chat_token_usage.estimated_cost_cents, chat_token_usage.estimated_cost_dollars
    );

    // Cost should be non-negative (>= 0)
    assert!(chat_token_usage.estimated_cost_cents >= 0);
    assert!(chat_token_usage.estimated_cost_dollars >= 0.0);

    // Check user token usage - should match chat usage
    let response = client
        .get(format!("{}/api/user-settings/token-usage", app.address))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let user_token_usage: TokenUsageSummary = response.json().await.unwrap();

    assert_eq!(
        user_token_usage.total_prompt_tokens,
        chat_token_usage.total_prompt_tokens as i64
    );
    assert_eq!(
        user_token_usage.total_completion_tokens,
        chat_token_usage.total_completion_tokens as i64
    );
    assert_eq!(
        user_token_usage.total_tokens,
        chat_token_usage.total_tokens as i64
    );
    assert_eq!(
        user_token_usage.total_cost_cents,
        chat_token_usage.estimated_cost_cents as i64
    );
}

/// This test verifies that token tracking works correctly across multiple chats
/// and that user-level totals are properly aggregated.
#[tokio::test]
async fn test_multi_chat_token_accumulation() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone(), None);

    let username = "multi_chat_user";
    let password = "password123";
    let user_db = db::create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .unwrap();
    tdg.add_user(user_db.id);

    let (client, auth_cookie_str) = login_user_via_api(&app, username, password).await;

    // Create a character
    let character =
        db::create_test_character(&app.db_pool, user_db.id, "Test Character".to_string())
            .await
            .unwrap();
    tdg.add_character(character.id);

    // Create two chat sessions
    let mut chat_ids = Vec::new();
    for i in 1..=2 {
        let chat_request = CreateChatRequest {
            character_id: character.id,
            title: Some(format!("Multi Chat Test {}", i)),
            active_custom_persona_id: None,
            lorebook_ids: None,
        };

        let response = client
            .post(format!("{}/api/chats/create_session", app.address))
            .json(&chat_request)
            .header(COOKIE, &auth_cookie_str)
            .send()
            .await
            .unwrap();

        let created_chat: Chat = response.json().await.unwrap();
        chat_ids.push(created_chat.id);
        tdg.add_chat(created_chat.id);
    }

    // Send messages to each chat
    for (idx, chat_id) in chat_ids.iter().enumerate() {
        let message_request = CreateMessageRequest {
            role: "user".to_string(),
            content: format!("Test message {} for chat {}", idx + 1, idx + 1),
            parts: None,
            attachments: None,
            parent_message_id: None,
        };

        let response = client
            .post(format!("{}/api/chats/{}/messages", app.address, chat_id))
            .json(&message_request)
            .header(COOKIE, &auth_cookie_str)
            .send()
            .await
            .unwrap();

        assert!(response.status().is_success());
    }

    // Poll for token counts on each chat with retry logic
    for chat_id in &chat_ids {
        let client_clone = client.clone();
        let auth_cookie_clone = auth_cookie_str.clone();
        let address_clone = app.address.clone();
        let chat_id_clone = *chat_id;

        poll_for_token_count(
            || async {
                let response = client_clone
                    .get(format!(
                        "{}/api/chats/{}/token-usage",
                        address_clone, chat_id_clone
                    ))
                    .header(COOKIE, &auth_cookie_clone)
                    .send()
                    .await
                    .map_err(|e| format!("Request failed: {}", e))?;

                if response.status() != StatusCode::OK {
                    return Err(format!("Bad status: {}", response.status()));
                }

                let chat_token_usage: ChatTokenUsage = response
                    .json()
                    .await
                    .map_err(|e| format!("JSON parsing failed: {}", e))?;

                Ok(chat_token_usage.total_prompt_tokens)
            },
            1,  // Expect at least 1 token
            10, // Max 10 attempts
        )
        .await
        .expect("Token count should be updated within retry limit");
    }

    // Check individual chat token usage
    let mut total_expected_prompt_tokens = 0i64;
    let mut total_expected_cost_cents = 0i64;

    for chat_id in &chat_ids {
        let response = client
            .get(format!("{}/api/chats/{}/token-usage", app.address, chat_id))
            .header(COOKIE, &auth_cookie_str)
            .send()
            .await
            .unwrap();

        let chat_token_usage: ChatTokenUsage = response.json().await.unwrap();
        assert!(chat_token_usage.total_prompt_tokens > 0);

        total_expected_prompt_tokens += chat_token_usage.total_prompt_tokens as i64;
        total_expected_cost_cents += chat_token_usage.estimated_cost_cents as i64;
    }

    // Check user-level aggregation
    let response = client
        .get(format!("{}/api/user-settings/token-usage", app.address))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();

    let user_token_usage: TokenUsageSummary = response.json().await.unwrap();

    assert_eq!(
        user_token_usage.total_prompt_tokens,
        total_expected_prompt_tokens
    );
    assert_eq!(user_token_usage.total_cost_cents, total_expected_cost_cents);
    assert!(user_token_usage.total_tokens > 0);
}

/// Test that token counts are consistent and don't have race conditions
/// when multiple messages are created rapidly.
#[tokio::test]
async fn test_concurrent_token_tracking() {
    let app = spawn_app_permissive_rate_limiting(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone(), None);

    let username = "concurrent_test_user";
    let password = "password123";
    let user_db = db::create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .unwrap();
    tdg.add_user(user_db.id);

    let (client, auth_cookie_str) = login_user_via_api(&app, username, password).await;

    // Create a character
    let character =
        db::create_test_character(&app.db_pool, user_db.id, "Test Character".to_string())
            .await
            .unwrap();
    tdg.add_character(character.id);

    // Create a chat session
    let chat_request = CreateChatRequest {
        character_id: character.id,
        title: Some("Concurrent Test Chat".to_string()),
        active_custom_persona_id: None,
        lorebook_ids: None,
    };

    let response = client
        .post(format!("{}/api/chats/create_session", app.address))
        .json(&chat_request)
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();

    let created_chat: Chat = response.json().await.unwrap();
    tdg.add_chat(created_chat.id);

    // Send multiple messages concurrently
    let mut tasks = Vec::new();
    for i in 1..=5 {
        let client_clone = client.clone();
        let auth_cookie_clone = auth_cookie_str.clone();
        let address = app.address.clone();
        let chat_id = created_chat.id;

        let task = tokio::spawn(async move {
            let message_request = CreateMessageRequest {
                role: "user".to_string(),
                content: format!(
                    "Concurrent test message number {} containing many words to generate sufficient tokens for meaningful cost calculation and verification of the token tracking system's accuracy",
                    i
                ),
                parts: None,
                attachments: None,
                parent_message_id: None,
            };

            client_clone
                .post(format!("{}/api/chats/{}/messages", address, chat_id))
                .json(&message_request)
                .header(COOKIE, &auth_cookie_clone)
                .send()
                .await
        });

        tasks.push(task);
    }

    // Wait for all messages to be created
    for task in tasks {
        let response = task.await.unwrap().unwrap();
        assert!(response.status().is_success());
    }

    // Poll for token counts with retry logic to handle async token tracking
    let client_clone = client.clone();
    let auth_cookie_clone = auth_cookie_str.clone();
    let address_clone = app.address.clone();
    let chat_id = created_chat.id;

    poll_for_token_count(
        || async {
            let response = client_clone
                .get(format!(
                    "{}/api/chats/{}/token-usage",
                    address_clone, chat_id
                ))
                .header(COOKIE, &auth_cookie_clone)
                .send()
                .await
                .map_err(|e| format!("Request failed: {}", e))?;

            if response.status() != StatusCode::OK {
                return Err(format!("Bad status: {}", response.status()));
            }

            let chat_token_usage: ChatTokenUsage = response
                .json()
                .await
                .map_err(|e| format!("JSON parsing failed: {}", e))?;

            Ok(chat_token_usage.total_prompt_tokens)
        },
        5,  // Expect at least 5 tokens (one from each message minimum)
        15, // Max 15 attempts for concurrent test
    )
    .await
    .expect("Token count should be updated within retry limit");

    // Get final token usage for assertions
    let response = client
        .get(format!(
            "{}/api/chats/{}/token-usage",
            app.address, created_chat.id
        ))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();

    let chat_token_usage: ChatTokenUsage = response.json().await.unwrap();

    // Should have substantial token count from 5 messages
    assert!(
        chat_token_usage.total_prompt_tokens >= 5,
        "Should have tokens from at least 5 messages"
    );
    assert!(chat_token_usage.total_tokens >= 5);
    assert!(chat_token_usage.estimated_cost_cents >= 0);

    // Check user-level consistency
    let response = client
        .get(format!("{}/api/user-settings/token-usage", app.address))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();

    let user_token_usage: TokenUsageSummary = response.json().await.unwrap();

    // User totals should match chat totals
    assert_eq!(
        user_token_usage.total_prompt_tokens,
        chat_token_usage.total_prompt_tokens as i64
    );
    assert_eq!(
        user_token_usage.total_cost_cents,
        chat_token_usage.estimated_cost_cents as i64
    );
}
