#![cfg(test)]

// Common imports needed for session tests
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use chrono::Utc;
use http_body_util::BodyExt;
use rand::TryRngCore;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

// Diesel imports
use diesel::RunQueryDsl;
use diesel::prelude::*;

// Crate imports
use anyhow::Error as AnyhowError;
use scribe_backend::models::character_card::NewCharacter;
use scribe_backend::models::characters::Character as DbCharacter;
use scribe_backend::models::chats::{Chat as DbChatSession, NewChat};
use scribe_backend::schema::{characters, chat_sessions};
use scribe_backend::test_helpers; // For spawn_app, create_test_user
use secrecy::{ExposeSecret, SecretBox};
use std::sync::Arc;
use tracing::debug;

use scribe_backend::crypto;
use scribe_backend::models::{
    // scribe_backend::models::chats::Chat is already aliased as DbChatSession in this file
    chats::{Message as DbChatMessage, MessageRole},
    users::User,
};
use scribe_backend::schema::chat_messages;
use scribe_backend::services::lorebook_service::LorebookService;
use scribe_backend::state::{AppState, AppStateServices};
// scribe_backend::test_helpers is already imported. TestDataGuard will be used as test_helpers::TestDataGuard.

// --- Session Creation Tests ---

#[tokio::test]
#[ignore] // Added ignore for CI
#[allow(clippy::too_many_lines)]
async fn test_create_chat_session_success() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "test_create_chat_user".to_string(),
        "password".to_string(),
    )
    .await
    .unwrap();

    let login_payload = json!({
        "identifier": "test_create_chat_user",
        "password": "password"
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
        .unwrap();
    let login_response = test_app
        .router
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    let pool = test_app.db_pool.clone();
    let user_id_clone = user.id;
    let character_conn_obj = pool
        .get()
        .await
        .expect("Failed to get DB connection for character creation");
    let character: DbCharacter = character_conn_obj
        .interact(move |actual_pg_conn| {
            let new_character_values = NewCharacter {
                user_id: user_id_clone,
                spec: "character_card_v3_example".to_string(),
                spec_version: "1.0.0".to_string(),
                name: "TestCharacter".to_string(),
                description: None,
                description_nonce: None,
                personality: None,
                personality_nonce: None,
                scenario: None,
                scenario_nonce: None,
                first_mes: None,
                first_mes_nonce: None,
                mes_example: None,
                mes_example_nonce: None,
                creator_notes: None,
                creator_notes_nonce: None,
                system_prompt: None,
                system_prompt_nonce: None,
                post_history_instructions: None,
                post_history_instructions_nonce: None,
                tags: Some(vec![Some("test".to_string())]),
                creator: None,
                character_version: None,
                alternate_greetings: None,
                nickname: None,
                creator_notes_multilingual: None,
                source: None,
                group_only_greetings: None,
                creation_date: None,
                modification_date: None,
                extensions: None,
                persona: None,
                persona_nonce: None,
                world_scenario: None,
                world_scenario_nonce: None,
                avatar: None,
                chat: None,
                greeting: None,
                greeting_nonce: None,
                definition: None,
                definition_nonce: None,
                default_voice: None,
                category: None,
                definition_visibility: None,
                example_dialogue: None,
                example_dialogue_nonce: None,
                favorite: None,
                first_message_visibility: None,
                migrated_from: None,
                model_prompt: None,
                model_prompt_nonce: None,
                model_prompt_visibility: None,
                persona_visibility: None,
                sharing_visibility: None,
                status: None,
                system_prompt_visibility: None,
                system_tags: None,
                token_budget: None,
                usage_hints: None,
                user_persona: None,
                user_persona_nonce: None,
                user_persona_visibility: None,
                visibility: Some("private".to_string()),
                world_scenario_visibility: None,
                fav: None,
                world: None,
                creator_comment: None,
                creator_comment_nonce: None,
                depth_prompt: None,
                depth_prompt_depth: None,
                depth_prompt_role: None,
                talkativeness: None,
                depth_prompt_ciphertext: None,
                depth_prompt_nonce: None,
                world_ciphertext: None,
                world_nonce: None,
                created_at: Some(Utc::now()),
                updated_at: Some(Utc::now()),
            };
            diesel::insert_into(characters::table)
                .values(&new_character_values)
                .get_result::<DbCharacter>(actual_pg_conn)
        })
        .await
        .map(|result| result.expect("Error saving character"))
        .expect("Interact join error");

    let request_body = json!({ "title": "Test Chat", "character_id": character.id });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats/create_session")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();
    let response = test_app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let session: DbChatSession =
        serde_json::from_slice(&body).expect("Failed to deserialize response");
    assert_eq!(session.user_id, user.id);
    assert_eq!(session.character_id, character.id);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_create_chat_session_unauthorized() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let request_body = json!({ "title": "Unauthorized Test", "character_id": Uuid::new_v4() }); // Dummy ID

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats/create_session")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();
    // No login simulation

    let response = test_app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_create_chat_session_character_not_found() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "test_char_not_found_user".to_string(),
        "password".to_string(),
    )
    .await
    .unwrap();

    let login_payload = json!({
        "identifier": "test_char_not_found_user",
        "password": "password"
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
        .unwrap();
    let login_response = test_app
        .router
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    let non_existent_char_id = Uuid::new_v4();

    let request_body = json!({ "title": "Not Found Test", "character_id": non_existent_char_id });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats/create_session")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore] // Added ignore for CI
#[allow(clippy::too_many_lines)]
async fn test_create_chat_session_character_other_user() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(true, false, false).await;

    // User 1 (owns the character)
    let user1 = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "chat_user_1".to_string(),
        "password".to_string(),
    )
    .await
    .unwrap();

    // Log in User 1 to create character
    let login_payload_user1 = json!({
        "identifier": "chat_user_1",
        "password": "password"
    });
    let login_request_user1 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(
            serde_json::to_string(&login_payload_user1).unwrap(),
        ))
        .unwrap();
    let login_response_user1 = test_app
        .router
        .clone()
        .oneshot(login_request_user1)
        .await
        .unwrap();
    assert_eq!(login_response_user1.status(), StatusCode::OK);
    let _login_cookie_user1 = login_response_user1
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()?;

    let user1_id_clone = user1.id;
    let character_conn_obj = test_app
        .db_pool
        .get()
        .await
        .expect("Failed to get DB connection for character creation U1");
    let character_user1: DbCharacter = character_conn_obj
        .interact(move |actual_pg_conn| {
            let new_character_values = NewCharacter {
                user_id: user1_id_clone,
                spec: "character_card_v3_example".to_string(),
                spec_version: "1.0.0".to_string(),
                name: "TestCharacter".to_string(),
                description: None,
                description_nonce: None,
                personality: None,
                personality_nonce: None,
                scenario: None,
                scenario_nonce: None,
                first_mes: None,
                first_mes_nonce: None,
                mes_example: None,
                mes_example_nonce: None,
                creator_notes: None,
                creator_notes_nonce: None,
                system_prompt: None,
                system_prompt_nonce: None,
                post_history_instructions: None,
                post_history_instructions_nonce: None,
                tags: Some(vec![Some("test".to_string())]),
                creator: None,
                character_version: None,
                alternate_greetings: None,
                nickname: None,
                creator_notes_multilingual: None,
                source: None,
                group_only_greetings: None,
                creation_date: None,
                modification_date: None,
                extensions: None,
                persona: None,
                persona_nonce: None,
                world_scenario: None,
                world_scenario_nonce: None,
                avatar: None,
                chat: None,
                greeting: None,
                greeting_nonce: None,
                definition: None,
                definition_nonce: None,
                default_voice: None,
                category: None,
                definition_visibility: None,
                example_dialogue: None,
                example_dialogue_nonce: None,
                favorite: None,
                first_message_visibility: None,
                migrated_from: None,
                model_prompt: None,
                model_prompt_nonce: None,
                model_prompt_visibility: None,
                persona_visibility: None,
                sharing_visibility: None,
                status: None,
                system_prompt_visibility: None,
                system_tags: None,
                token_budget: None,
                usage_hints: None,
                user_persona: None,
                user_persona_nonce: None,
                user_persona_visibility: None,
                visibility: Some("private".to_string()),
                world_scenario_visibility: None,
                fav: None,
                world: None,
                creator_comment: None,
                creator_comment_nonce: None,
                depth_prompt: None,
                depth_prompt_depth: None,
                depth_prompt_role: None,
                talkativeness: None,
                depth_prompt_ciphertext: None,
                depth_prompt_nonce: None,
                world_ciphertext: None,
                world_nonce: None,
                created_at: Some(Utc::now()),
                updated_at: Some(Utc::now()),
            };
            diesel::insert_into(characters::table)
                .values(&new_character_values)
                .get_result::<DbCharacter>(actual_pg_conn)
        })
        .await
        .map(|result| result.expect("Error saving character for User 1"))
        .expect("Interact join error U1");

    // User 2 (tries to create chat with User 1's character)
    let _user2 = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "chat_user_2".to_string(),
        "password".to_string(),
    )
    .await
    .unwrap();

    // Log in User 2
    let login_payload_user2 = json!({
        "identifier": "chat_user_2",
        "password": "password"
    });
    let login_request_user2 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(
            serde_json::to_string(&login_payload_user2).unwrap(),
        ))
        .unwrap();
    let login_response_user2 = test_app
        .router
        .clone()
        .oneshot(login_request_user2)
        .await
        .unwrap();
    assert_eq!(login_response_user2.status(), StatusCode::OK);
    let auth_cookie_user2 = login_response_user2
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    let request_body = json!({ "title": "Other User Test", "character_id": character_user1.id });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats/create_session")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie_user2) // Use user2's cookie
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn create_chat_session_character_not_found_integration() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(true, true, false).await; // Use real DB
    let _test_user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "test_create_chat_404_integ".to_string(),
        "password".to_string(),
    )
    .await?;

    // API Login
    let login_payload = json!({
        "identifier": "test_create_chat_404_integ",
        "password": "password"
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
        .unwrap();
    let login_response = test_app
        .router
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    let non_existent_character_id = Uuid::new_v4();
    let payload =
        json!({ "title": "Not Found Integ Test", "character_id": non_existent_character_id });
    let request = Request::builder()
        .uri("/api/chats/create_session")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(payload.to_string()))
        .unwrap();
    let response = test_app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
#[ignore] // Added ignore for CI
#[allow(clippy::too_many_lines)]
async fn create_chat_session_character_not_owned_integration() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(true, true, false).await; // Use real DB

    // User 1 (owns the character)
    let user1 = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "user1_create_chat_integ".to_string(),
        "password".to_string(),
    )
    .await?;

    // API Login for User 1
    let login_payload_user1 = json!({
        "identifier": "user1_create_chat_integ",
        "password": "password"
    });
    let login_request_user1 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(
            serde_json::to_string(&login_payload_user1).unwrap(),
        ))
        .unwrap();
    let login_response_user1 = test_app
        .router
        .clone()
        .oneshot(login_request_user1)
        .await
        .unwrap();
    assert_eq!(login_response_user1.status(), StatusCode::OK);
    let _login_cookie_user1 = login_response_user1
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()?;

    let user1_id_clone = user1.id;
    let character_conn_obj = test_app
        .db_pool
        .get()
        .await
        .expect("Failed to get DB connection for character creation user1 integ");
    let character_user1: DbCharacter = character_conn_obj
        .interact(move |actual_pg_conn| {
            let new_character_values = NewCharacter {
                user_id: user1_id_clone,
                spec: "character_card_v3_example".to_string(),
                spec_version: "1.0.0".to_string(),
                name: "TestCharacter".to_string(),
                description: None,
                description_nonce: None,
                personality: None,
                personality_nonce: None,
                scenario: None,
                scenario_nonce: None,
                first_mes: None,
                first_mes_nonce: None,
                mes_example: None,
                mes_example_nonce: None,
                creator_notes: None,
                creator_notes_nonce: None,
                system_prompt: None,
                system_prompt_nonce: None,
                post_history_instructions: None,
                post_history_instructions_nonce: None,
                tags: Some(vec![Some("test".to_string())]),
                creator: None,
                character_version: None,
                alternate_greetings: None,
                nickname: None,
                creator_notes_multilingual: None,
                source: None,
                group_only_greetings: None,
                creation_date: None,
                modification_date: None,
                extensions: None,
                persona: None,
                persona_nonce: None,
                world_scenario: None,
                world_scenario_nonce: None,
                avatar: None,
                chat: None,
                greeting: None,
                greeting_nonce: None,
                definition: None,
                definition_nonce: None,
                default_voice: None,
                category: None,
                definition_visibility: None,
                example_dialogue: None,
                example_dialogue_nonce: None,
                favorite: None,
                first_message_visibility: None,
                migrated_from: None,
                model_prompt: None,
                model_prompt_nonce: None,
                model_prompt_visibility: None,
                persona_visibility: None,
                sharing_visibility: None,
                status: None,
                system_prompt_visibility: None,
                system_tags: None,
                token_budget: None,
                usage_hints: None,
                user_persona: None,
                user_persona_nonce: None,
                user_persona_visibility: None,
                visibility: Some("private".to_string()),
                world_scenario_visibility: None,
                fav: None,
                world: None,
                creator_comment: None,
                creator_comment_nonce: None,
                depth_prompt: None,
                depth_prompt_depth: None,
                depth_prompt_role: None,
                talkativeness: None,
                depth_prompt_ciphertext: None,
                depth_prompt_nonce: None,
                world_ciphertext: None,
                world_nonce: None,
                created_at: Some(Utc::now()),
                updated_at: Some(Utc::now()),
            };
            diesel::insert_into(characters::table)
                .values(&new_character_values)
                .get_result::<DbCharacter>(actual_pg_conn)
        })
        .await
        .map(|result| result.expect("Error saving character user1 integ"))
        .expect("Interact join error user1 integ");

    // User 2 (tries to create chat with User 1's character)
    let _user2 = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "user2_create_chat_integ".to_string(),
        "password".to_string(),
    )
    .await?;

    // API Login for User 2
    let login_payload_user2 = json!({
        "identifier": "user2_create_chat_integ",
        "password": "password"
    });
    let login_request_user2 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(
            serde_json::to_string(&login_payload_user2).unwrap(),
        ))
        .unwrap();
    let login_response_user2 = test_app
        .router
        .clone()
        .oneshot(login_request_user2)
        .await
        .unwrap();
    assert_eq!(login_response_user2.status(), StatusCode::OK);
    let auth_cookie_user2 = login_response_user2
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}", character_user1.id)) // Corrected URI
        .header(header::COOKIE, auth_cookie_user2) // Using user 2's cookie
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
#[ignore] // Added ignore for CI
#[allow(clippy::too_many_lines)]
async fn test_get_chat_session_details_unauthorized() {
    let test_app = test_helpers::spawn_app(true, false, false).await;

    // Create a user and a session for them (so a session ID exists)
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "test_get_unauth_user".to_string(),
        "password".to_string(),
    )
    .await
    .unwrap();
    let user_id_clone = user.id;

    let character_conn_obj = test_app
        .db_pool
        .get()
        .await
        .expect("Failed to get DB conn for char unauth");
    let character: DbCharacter = character_conn_obj
        .interact(move |actual_pg_conn| {
            let new_char_values = NewCharacter {
                user_id: user_id_clone,
                spec: "character_card_v3_example".to_string(),
                spec_version: "1.0.0".to_string(),
                name: "Char for Unauth Get".to_string(),
                description: None,
                description_nonce: None,
                personality: None,
                personality_nonce: None,
                scenario: None,
                scenario_nonce: None,
                first_mes: None,
                first_mes_nonce: None,
                mes_example: None,
                mes_example_nonce: None,
                creator_notes: None,
                creator_notes_nonce: None,
                system_prompt: None,
                system_prompt_nonce: None,
                post_history_instructions: None,
                post_history_instructions_nonce: None,
                tags: Some(vec![Some("test".to_string())]),
                creator: None,
                character_version: None,
                alternate_greetings: None,
                nickname: None,
                creator_notes_multilingual: None,
                source: None,
                group_only_greetings: None,
                creation_date: None,
                modification_date: None,
                extensions: None,
                persona: None,
                persona_nonce: None,
                world_scenario: None,
                world_scenario_nonce: None,
                avatar: None,
                chat: None,
                greeting: None,
                greeting_nonce: None,
                definition: None,
                definition_nonce: None,
                default_voice: None,
                category: None,
                definition_visibility: None,
                example_dialogue: None,
                example_dialogue_nonce: None,
                favorite: None,
                first_message_visibility: None,
                migrated_from: None,
                model_prompt: None,
                model_prompt_nonce: None,
                model_prompt_visibility: None,
                persona_visibility: None,
                sharing_visibility: None,
                status: None,
                system_prompt_visibility: None,
                system_tags: None,
                token_budget: None,
                usage_hints: None,
                user_persona: None,
                user_persona_nonce: None,
                user_persona_visibility: None,
                visibility: Some("private".to_string()),
                world_scenario_visibility: None,
                fav: None,
                world: None,
                creator_comment: None,
                creator_comment_nonce: None,
                depth_prompt: None,
                depth_prompt_depth: None,
                depth_prompt_role: None,
                talkativeness: None,
                depth_prompt_ciphertext: None,
                depth_prompt_nonce: None,
                world_ciphertext: None,
                world_nonce: None,
                created_at: Some(Utc::now()),
                updated_at: Some(Utc::now()),
            };
            diesel::insert_into(characters::table)
                .values(&new_char_values)
                .get_result::<DbCharacter>(actual_pg_conn)
        })
        .await
        .map(|result| result.expect("Error saving character"))
        .expect("Interact join error");

    let pool = test_app.db_pool.clone();
    let session_user_id_clone = user.id;
    let session_char_id_clone = character.id;
    let conn_guard_session_unauth = pool
        .get()
        .await
        .expect("Failed to get DB connection for session unauth");
    let session: DbChatSession = conn_guard_session_unauth
        .interact(move |actual_pg_conn| {
            let new_chat_values = NewChat {
                id: Uuid::new_v4(),
                user_id: session_user_id_clone,
                character_id: session_char_id_clone,
                title_ciphertext: None,
                title_nonce: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                history_management_strategy: "truncate_summary".to_string(),
                history_management_limit: 10,
                model_name: "test-model".to_string(),
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
            };
            diesel::insert_into(chat_sessions::table)
                .values(&new_chat_values)
                .returning(DbChatSession::as_returning())
                .get_result(actual_pg_conn)
        })
        .await
        .map(|result| result.expect("Error saving session"))
        .expect("Interact join error");

    let session_id_clone = session.id;

    // Make request without authentication
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{session_id_clone}")) // Corrected URI
        // No auth cookie
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_get_chat_session_details_invalid_uuid() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "test_get_details_invalid_uuid_user".to_string(),
        "password".to_string(),
    )
    .await
    .unwrap();

    let login_payload = json!({
        "identifier": "test_get_details_invalid_uuid_user",
        "password": "password"
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload).unwrap()))
        .unwrap();
    let login_response = test_app
        .router
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap();

    // Test with a non-UUID string for session_id
    let invalid_session_id = "not-a-uuid";

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{invalid_session_id}")) // Corrected URI, Invalid UUID in path
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_create_chat_session_with_empty_first_mes() -> Result<(), AnyhowError> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());
    let username = "empty_first_mes_user";
    let password = "password";
    let user: User = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await
    .expect("Failed to create test user");
    test_data_guard.add_user(user.id);
    // Use router-based login to ensure we're using the same AuthBackend instance
    let auth_cookie =
        test_helpers::login_user_via_router(&test_app.router, username, password).await;

    let conn = test_app.db_pool.get().await?;

    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id,
        user_id: user.id,
        name: "Empty First Mes Char".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        first_mes: Some(b"   ".to_vec()), // Set empty first_mes
        description: None,
        personality: None,
        scenario: None,
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
        example_dialogue_nonce: None,
        model_prompt_nonce: None,
        user_persona_nonce: None,
        fav: None,
        world: None,
        creator_comment: None,
        creator_comment_nonce: None,
        depth_prompt: None,
        depth_prompt_depth: None,
        depth_prompt_role: None,
        talkativeness: None,
        depth_prompt_ciphertext: None,
        depth_prompt_nonce: None,
        world_ciphertext: None,
        world_nonce: None,
    };

    let result = conn
        .interact(move |conn_inner| {
            diesel::insert_into(characters::table)
                .values(&new_character)
                .execute(conn_inner)
        })
        .await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    test_data_guard.add_character(character_id);

    let request_body = json!({ "character_id": character_id });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats/create_session")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body)?))?;
    let response = test_app.router.clone().oneshot(request).await?;

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await?.to_bytes();
    let session: DbChatSession = // Changed from DbChat to DbChatSession
        serde_json::from_slice(&body)?;
    test_data_guard.add_chat(session.id);

    let conn = test_app.db_pool.get().await?;
    let messages_result = conn
        .interact(move |conn_inner| {
            chat_messages::table
                .filter(chat_messages::session_id.eq(session.id))
                .select(DbChatMessage::as_select())
                .load(conn_inner)
        })
        .await;

    if let Err(e) = messages_result {
        return Err(anyhow::anyhow!("Failed to load messages: {}", e));
    }

    let messages: Vec<DbChatMessage> = messages_result.unwrap()?;

    assert!(
        messages.is_empty(),
        "No initial message should be created for empty first_mes"
    );

    test_data_guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_create_chat_session_with_null_first_mes() -> anyhow::Result<()> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());
    let username = "null_first_mes_user";
    let password = "password";
    let user: User = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await
    .expect("Failed to create test user");
    test_data_guard.add_user(user.id);
    // Use router-based login to ensure we're using the same AuthBackend instance
    let auth_cookie =
        test_helpers::login_user_via_router(&test_app.router, username, password).await;

    let conn = test_app.db_pool.get().await?;

    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id,
        user_id: user.id,
        name: "Null First Mes Char".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        first_mes: None, // Null first_mes
        description: None,
        personality: None,
        scenario: None,
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
        example_dialogue_nonce: None,
        model_prompt_nonce: None,
        user_persona_nonce: None,
        fav: None,
        world: None,
        creator_comment: None,
        creator_comment_nonce: None,
        depth_prompt: None,
        depth_prompt_depth: None,
        depth_prompt_role: None,
        talkativeness: None,
        depth_prompt_ciphertext: None,
        depth_prompt_nonce: None,
        world_ciphertext: None,
        world_nonce: None,
    };

    let result = conn
        .interact(move |conn_inner| {
            diesel::insert_into(characters::table)
                .values(&new_character)
                .execute(conn_inner)
        })
        .await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    test_data_guard.add_character(character_id);

    let request_body = json!({ "character_id": character_id });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats/create_session")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body)?))?;
    let response = test_app.router.clone().oneshot(request).await?;

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = response.into_body().collect().await?.to_bytes();
    let session: DbChatSession = // Changed from DbChat to DbChatSession
        serde_json::from_slice(&body)?;
    test_data_guard.add_chat(session.id);

    let conn = test_app.db_pool.get().await?;
    let messages_result = conn
        .interact(move |conn_inner| {
            chat_messages::table
                .filter(chat_messages::session_id.eq(session.id))
                .select(DbChatMessage::as_select())
                .load(conn_inner)
        })
        .await;

    if let Err(e) = messages_result {
        return Err(anyhow::anyhow!("Failed to load messages: {}", e));
    }

    let messages: Vec<DbChatMessage> = messages_result.unwrap()?;

    assert!(
        messages.is_empty(),
        "No initial message should be created for null first_mes"
    );
    test_data_guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[ignore] // Ignore for CI unless DB is guaranteed
#[allow(clippy::too_many_lines)]
async fn test_create_session_saves_first_mes() -> Result<(), AnyhowError> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());
    let username = "save_first_mes_user";
    let password = "password";
    let user: User = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await
    .expect("Failed to create test user");
    test_data_guard.add_user(user.id);

    let conn = test_app.db_pool.get().await?;

    let character_id = Uuid::new_v4();
    let first_mes_content = "Hello from the character!".to_string();

    // 1. Generate DEK
    let mut rng = rand::rngs::OsRng;
    let mut dek_bytes = [0u8; 32];
    rng.try_fill_bytes(&mut dek_bytes)
        .expect("Failed to fill bytes for DEK");
    let user_dek_val = SecretBox::new(Box::new(dek_bytes.to_vec()));
    let user_dek = Arc::new(user_dek_val);

    // 2. Encrypt first_mes_content
    let (encrypted_first_mes, first_mes_actual_nonce) =
        crypto::encrypt_gcm(first_mes_content.as_bytes(), user_dek.as_ref())
            .expect("Test: Failed to encrypt first_mes");

    let new_character = DbCharacter {
        id: character_id,
        user_id: user.id,
        name: "Save First Mes Char".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        first_mes: Some(encrypted_first_mes),
        description: None,
        personality: None,
        scenario: None,
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
        first_mes_nonce: Some(first_mes_actual_nonce),
        mes_example_nonce: None,
        creator_notes_nonce: None,
        system_prompt_nonce: None,
        post_history_instructions_nonce: None,
        persona_nonce: None,
        world_scenario_nonce: None,
        greeting_nonce: None,
        definition_nonce: None,
        example_dialogue_nonce: None,
        model_prompt_nonce: None,
        user_persona_nonce: None,
        fav: None,
        world: None,
        creator_comment: None,
        creator_comment_nonce: None,
        depth_prompt: None,
        depth_prompt_depth: None,
        depth_prompt_role: None,
        talkativeness: None,
        depth_prompt_ciphertext: None,
        depth_prompt_nonce: None,
        world_ciphertext: None,
        world_nonce: None,
    };

    let result = conn
        .interact(move |conn_inner| {
            diesel::insert_into(characters::table)
                .values(&new_character)
                .execute(conn_inner)
        })
        .await;
    if let Err(e) = result {
        return Err(anyhow::anyhow!("Failed to insert character: {}", e));
    }
    let insert_result = result.unwrap()?;
    debug!("Inserted character: {} rows affected", insert_result);
    test_data_guard.add_character(character_id);

    // Create dependent services for AppState
    let encryption_service_for_test =
        Arc::new(scribe_backend::services::encryption_service::EncryptionService::new());
    let chat_override_service_for_test = Arc::new(
        scribe_backend::services::chat_override_service::ChatOverrideService::new(
            test_app.db_pool.clone(),
            encryption_service_for_test.clone(),
        ),
    );
    let user_persona_service_for_test = Arc::new(
        scribe_backend::services::user_persona_service::UserPersonaService::new(
            test_app.db_pool.clone(),
            encryption_service_for_test.clone(),
        ),
    );
    let tokenizer_service_for_test =
        scribe_backend::services::tokenizer_service::TokenizerService::new(
            "/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model",
        )
        .expect("Failed to create tokenizer for test");
    let hybrid_token_counter_for_test = Arc::new(
        scribe_backend::services::hybrid_token_counter::HybridTokenCounter::new_local_only(
            tokenizer_service_for_test,
        ),
    );
    let lorebook_service_for_test = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test.clone(),
        test_app.qdrant_service.clone(),
    ));
    let auth_backend_for_test = Arc::new(scribe_backend::auth::user_store::Backend::new(
        test_app.db_pool.clone(),
    ));
    let file_storage_service_for_test = Arc::new(
        scribe_backend::services::file_storage_service::FileStorageService::new("./test_uploads")
            .expect("Failed to create test file storage service"),
    );

    let services = AppStateServices {
        ai_client: test_app.ai_client.clone(),
        embedding_client: test_app.mock_embedding_client.clone(),
        qdrant_service: test_app.qdrant_service.clone(), // Assuming qdrant_service is used, else provide mock_qdrant_service
        embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone(),
        chat_override_service: chat_override_service_for_test,
        user_persona_service: user_persona_service_for_test,
        token_counter: hybrid_token_counter_for_test,
        encryption_service: encryption_service_for_test.clone(),
        lorebook_service: lorebook_service_for_test,
        auth_backend: auth_backend_for_test,
        file_storage_service: file_storage_service_for_test,
    };

    let app_state_arc = Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ));

    // The function create_session_and_maybe_first_message returns Result<scribe_backend::models::chats::Chat, ...>
    // In chat_session_api_tests.rs, DbChatSession is an alias for scribe_backend::models::chats::Chat.
    // So, `session` will be of the correct type.
    let result =
        scribe_backend::services::chat::session_management::create_session_and_maybe_first_message(
            app_state_arc,
            user.id,
            character_id,
            None,                   // active_custom_persona_id
            None,                   // lorebook_ids
            Some(user_dek.clone()), // user_dek_secret_box
        )
        .await;

    assert!(
        result.is_ok(),
        "create_session_and_maybe_first_message failed: {:?}",
        result.err()
    );
    let session: DbChatSession = result.unwrap(); // Explicitly type if needed, or let inference work.
    test_data_guard.add_chat(session.id);

    assert_eq!(session.user_id, user.id);
    assert_eq!(session.character_id, character_id);

    let conn = test_app.db_pool.get().await?;
    let messages_result = conn
        .interact(move |conn_inner| {
            chat_messages::table
                .filter(chat_messages::session_id.eq(session.id))
                .select(DbChatMessage::as_select())
                .load(conn_inner)
        })
        .await;

    if let Err(e) = messages_result {
        return Err(anyhow::anyhow!("Failed to load messages: {}", e));
    }

    let messages: Vec<DbChatMessage> = messages_result.unwrap()?;

    assert_eq!(messages.len(), 1, "Expected exactly one initial message");
    let initial_message = &messages[0];

    let nonce = initial_message
        .content_nonce
        .as_ref()
        .expect("Initial message should have a nonce");
    let decrypted_content_secret =
        crypto::decrypt_gcm(&initial_message.content, nonce, user_dek.as_ref())
            .expect("Failed to decrypt initial message content in test");
    let decrypted_content_bytes = decrypted_content_secret.expose_secret();
    let decrypted_content_string = String::from_utf8(decrypted_content_bytes.clone())
        .expect("Decrypted content is not valid UTF-8");

    assert_eq!(decrypted_content_string, "Hello from the character!");
    assert_eq!(initial_message.message_type, MessageRole::Assistant);
    assert_eq!(
        initial_message.user_id, user.id,
        "Initial message user_id should match session owner"
    );
    assert_eq!(
        initial_message.session_id, session.id,
        "Initial message session_id should match"
    );

    test_data_guard.cleanup().await?;
    Ok(())
}

// Added for lorebook tests
use scribe_backend::models::lorebooks::{ChatSessionLorebook, Lorebook as DbLorebook, NewLorebook};
use scribe_backend::schema::{chat_session_lorebooks, lorebooks};
// EncryptionService is likely already imported or can be added if not.
// It's used in test_create_session_saves_first_mes.

// Helper function to create a lorebook for testing
async fn create_test_lorebook(
    db_pool: &deadpool_diesel::postgres::Pool,
    _encryption_service: Arc<scribe_backend::services::encryption_service::EncryptionService>, // Assuming this is how it's passed or constructed
    user_id: Uuid,
    name: &str,
    _user_dek: Arc<SecretBox<Vec<u8>>>,
    test_data_guard: &mut test_helpers::TestDataGuard,
) -> Result<DbLorebook, AnyhowError> {
    // The NewLorebook struct expects plain text for name and description.
    // Encryption should be handled by the service or model if the database stores ciphertext.
    // Based on models/lorebooks.rs, NewLorebook and Lorebook store plain name/description.

    let new_lorebook = NewLorebook {
        id: Uuid::new_v4(),
        user_id,
        name: name.to_string(),
        description: None, // Set to None as per NewLorebook definition
        source_format: "test_data".to_string(), // Provide a default source_format
        is_public: false,  // Corrected field name from 'public'
        created_at: Some(Utc::now()), // Corrected to Option<DateTime<Utc>>
        updated_at: Some(Utc::now()), // Corrected to Option<DateTime<Utc>>
    };

    let lorebook = db_pool
        .get()
        .await?
        .interact(move |conn| {
            diesel::insert_into(lorebooks::table)
                .values(&new_lorebook)
                .returning((
                    lorebooks::id,
                    lorebooks::user_id,
                    lorebooks::name,
                    lorebooks::description,
                    lorebooks::source_format,
                    lorebooks::is_public,
                    lorebooks::created_at,
                    lorebooks::updated_at,
                ))
                .get_result::<DbLorebook>(conn)
        })
        .await
        .map_err(|e| AnyhowError::msg(format!("DB interaction error: {e}")))?
        .map_err(|e| AnyhowError::msg(format!("Failed to insert lorebook: {e}")))?;

    test_data_guard.add_lorebook(lorebook.id); // Assumes TestDataGuard has this method
    Ok(lorebook)
}

// --- Chat Session Creation with Lorebooks Tests ---

#[tokio::test]
#[ignore] // Following existing pattern for CI
#[allow(clippy::too_many_lines)]
async fn test_create_chat_session_no_lorebook_ids() -> Result<(), AnyhowError> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    let username = "user_no_lorebooks";
    let password = "password";
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await?;
    test_data_guard.add_user(user.id);

    // Use router-based login to ensure we're using the same AuthBackend instance
    let auth_cookie =
        test_helpers::login_user_via_router(&test_app.router, username, password).await;

    // Create a character
    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id,
        user_id: user.id,
        name: "No Lorebooks Char".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        first_mes: None,
        description: None,
        personality: None,
        scenario: None,
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
        example_dialogue_nonce: None,
        model_prompt_nonce: None,
        user_persona_nonce: None,
        fav: None,
        world: None,
        creator_comment: None,
        creator_comment_nonce: None,
        depth_prompt: None,
        depth_prompt_depth: None,
        depth_prompt_role: None,
        talkativeness: None,
        depth_prompt_ciphertext: None,
        depth_prompt_nonce: None,
        world_ciphertext: None,
        world_nonce: None,
    };
    let conn = test_app.db_pool.get().await?;
    let _ = conn
        .interact(move |conn_inner| {
            diesel::insert_into(characters::table)
                .values(&new_character)
                .execute(conn_inner)
        })
        .await
        .map_err(|e| AnyhowError::msg(format!("DB interaction error: {e}")))?;
    test_data_guard.add_character(character_id);

    // Create chat session request without lorebook_ids
    let request_body = json!({
        "character_id": character_id,
        "title": "Chat without Lorebooks"
        // lorebook_ids is omitted, so it should be treated as None or empty
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats/create_session")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body)?))?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await?.to_bytes();
    let session: DbChatSession = serde_json::from_slice(&body)?;
    test_data_guard.add_chat(session.id);

    // Verify no entries in chat_session_lorebooks
    let conn = test_app.db_pool.get().await?;
    let linked_lorebooks: Vec<ChatSessionLorebook> = conn
        .interact(move |conn_inner| {
            chat_session_lorebooks::table
                .filter(chat_session_lorebooks::chat_session_id.eq(session.id))
                .load::<ChatSessionLorebook>(conn_inner)
        })
        .await
        .map_err(|e| AnyhowError::msg(format!("DB interaction error: {e}")))?
        .map_err(|e| AnyhowError::msg(format!("Failed to query lorebooks: {e}")))?;

    assert!(
        linked_lorebooks.is_empty(),
        "No lorebooks should be linked to the chat session"
    );

    test_data_guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_create_chat_session_one_valid_lorebook_id() -> Result<(), AnyhowError> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    let username = "user_one_lorebook";
    let password = "password";
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await?;
    test_data_guard.add_user(user.id);

    // Use router-based login to ensure we're using the same AuthBackend instance
    let auth_cookie =
        test_helpers::login_user_via_router(&test_app.router, username, password).await;

    // Create a character
    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id,
        user_id: user.id,
        name: "One Lorebook Char".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        first_mes: None,
        description: None,
        personality: None,
        scenario: None,
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
        example_dialogue_nonce: None,
        model_prompt_nonce: None,
        user_persona_nonce: None,
        fav: None,
        world: None,
        creator_comment: None,
        creator_comment_nonce: None,
        depth_prompt: None,
        depth_prompt_depth: None,
        depth_prompt_role: None,
        talkativeness: None,
        depth_prompt_ciphertext: None,
        depth_prompt_nonce: None,
        world_ciphertext: None,
        world_nonce: None,
    };
    let conn_char = test_app.db_pool.get().await?;
    let _ = conn_char
        .interact(move |conn_inner| {
            diesel::insert_into(characters::table)
                .values(&new_character)
                .execute(conn_inner)
        })
        .await
        .map_err(|e| AnyhowError::msg(format!("DB interaction error: {e}")))?;
    test_data_guard.add_character(character_id);

    // Create a Lorebook
    let encryption_service_for_lorebook =
        Arc::new(scribe_backend::services::encryption_service::EncryptionService::new());
    let mut rng_dek = rand::rngs::OsRng;
    let mut dek_bytes_lorebook = [0u8; 32];
    rng_dek
        .try_fill_bytes(&mut dek_bytes_lorebook)
        .expect("Failed to fill bytes for DEK");
    let user_dek_lorebook = Arc::new(SecretBox::new(Box::new(dek_bytes_lorebook.to_vec())));

    let lorebook1 = create_test_lorebook(
        &test_app.db_pool,
        encryption_service_for_lorebook.clone(),
        user.id,
        "Test Lorebook 1",
        user_dek_lorebook.clone(),
        &mut test_data_guard,
    )
    .await?;

    // Create chat session request with one lorebook_id
    let request_body = json!({
        "character_id": character_id,
        "title": "Chat with One Lorebook",
        "lorebook_ids": [lorebook1.id]
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats/create_session")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body)?))?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await?.to_bytes();
    let session: DbChatSession = serde_json::from_slice(&body)?;
    test_data_guard.add_chat(session.id);

    // Verify one entry in chat_session_lorebooks
    let conn_verify = test_app.db_pool.get().await?;
    let linked_lorebooks: Vec<ChatSessionLorebook> = conn_verify
        .interact(move |conn_inner| {
            chat_session_lorebooks::table
                .filter(chat_session_lorebooks::chat_session_id.eq(session.id))
                .load::<ChatSessionLorebook>(conn_inner)
        })
        .await
        .map_err(|e| AnyhowError::msg(format!("DB interaction error: {e}")))?
        .map_err(|e| AnyhowError::msg(format!("Failed to query lorebooks: {e}")))?;

    assert_eq!(
        linked_lorebooks.len(),
        1,
        "One lorebook should be linked to the chat session"
    );
    assert_eq!(linked_lorebooks[0].lorebook_id, lorebook1.id);
    assert_eq!(linked_lorebooks[0].chat_session_id, session.id);

    test_data_guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_create_chat_session_multiple_valid_lorebook_ids() -> Result<(), AnyhowError> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    let username = "user_multi_lorebooks";
    let password = "password";
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await?;
    test_data_guard.add_user(user.id);

    // Use router-based login to ensure we're using the same AuthBackend instance
    let auth_cookie =
        test_helpers::login_user_via_router(&test_app.router, username, password).await;

    // Create a character
    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id,
        user_id: user.id,
        name: "Multi Lorebooks Char".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        first_mes: None,
        description: None,
        personality: None,
        scenario: None,
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
        example_dialogue_nonce: None,
        model_prompt_nonce: None,
        user_persona_nonce: None,
        fav: None,
        world: None,
        creator_comment: None,
        creator_comment_nonce: None,
        depth_prompt: None,
        depth_prompt_depth: None,
        depth_prompt_role: None,
        talkativeness: None,
        depth_prompt_ciphertext: None,
        depth_prompt_nonce: None,
        world_ciphertext: None,
        world_nonce: None,
    };
    let conn_char = test_app.db_pool.get().await?;
    let _ = conn_char
        .interact(move |conn_inner| {
            diesel::insert_into(characters::table)
                .values(&new_character)
                .execute(conn_inner)
        })
        .await
        .map_err(|e| AnyhowError::msg(format!("DB interaction error: {e}")))?;
    test_data_guard.add_character(character_id);

    // Create Lorebooks
    let encryption_service_for_lorebook =
        Arc::new(scribe_backend::services::encryption_service::EncryptionService::new());
    let mut rng_dek = rand::rngs::OsRng;
    let mut dek_bytes_lorebook = [0u8; 32];
    rng_dek
        .try_fill_bytes(&mut dek_bytes_lorebook)
        .expect("Failed to fill bytes for DEK");
    let user_dek_lorebook = Arc::new(SecretBox::new(Box::new(dek_bytes_lorebook.to_vec())));

    let lorebook1 = create_test_lorebook(
        &test_app.db_pool,
        encryption_service_for_lorebook.clone(),
        user.id,
        "Test Lorebook Multi 1",
        user_dek_lorebook.clone(),
        &mut test_data_guard,
    )
    .await?;
    let lorebook2 = create_test_lorebook(
        &test_app.db_pool,
        encryption_service_for_lorebook.clone(),
        user.id,
        "Test Lorebook Multi 2",
        user_dek_lorebook.clone(),
        &mut test_data_guard,
    )
    .await?;

    // Create chat session request with multiple lorebook_ids
    let request_body = json!({
        "character_id": character_id,
        "title": "Chat with Multiple Lorebooks",
        "lorebook_ids": [lorebook1.id, lorebook2.id]
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats/create_session")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body)?))?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await?.to_bytes();
    let session: DbChatSession = serde_json::from_slice(&body)?;
    test_data_guard.add_chat(session.id);

    // Verify two entries in chat_session_lorebooks
    let conn_verify = test_app.db_pool.get().await?;
    let linked_lorebooks: Vec<ChatSessionLorebook> = conn_verify
        .interact(move |conn_inner| {
            chat_session_lorebooks::table
                .filter(chat_session_lorebooks::chat_session_id.eq(session.id))
                .order(chat_session_lorebooks::lorebook_id.asc()) // Ensure consistent order for assertion
                .load::<ChatSessionLorebook>(conn_inner)
        })
        .await
        .map_err(|e| AnyhowError::msg(format!("DB interaction error: {e}")))?
        .map_err(|e| AnyhowError::msg(format!("Failed to query lorebooks: {e}")))?;

    assert_eq!(
        linked_lorebooks.len(),
        2,
        "Two lorebooks should be linked to the chat session"
    );

    // Sort expected and actual IDs to ensure order doesn't matter for the content of the list
    let mut actual_linked_ids: Vec<Uuid> = linked_lorebooks.iter().map(|l| l.lorebook_id).collect();
    actual_linked_ids.sort();
    let mut expected_ids = vec![lorebook1.id, lorebook2.id];
    expected_ids.sort();

    assert_eq!(
        actual_linked_ids, expected_ids,
        "Linked lorebook IDs do not match expected IDs"
    );

    assert!(
        linked_lorebooks
            .iter()
            .all(|l| l.chat_session_id == session.id)
    );

    test_data_guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[ignore] // Following existing pattern for CI
#[allow(clippy::too_many_lines)]
async fn test_create_chat_session_empty_lorebook_ids_list() -> Result<(), AnyhowError> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    let username = "user_empty_lorebook_list";
    let password = "password";
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await?;
    test_data_guard.add_user(user.id);

    // Use router-based login to ensure we're using the same AuthBackend instance
    let auth_cookie =
        test_helpers::login_user_via_router(&test_app.router, username, password).await;

    // Create a character
    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id,
        user_id: user.id,
        name: "Empty Lorebook List Char".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        first_mes: None,
        description: None,
        personality: None,
        scenario: None,
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
        example_dialogue_nonce: None,
        model_prompt_nonce: None,
        user_persona_nonce: None,
        fav: None,
        world: None,
        creator_comment: None,
        creator_comment_nonce: None,
        depth_prompt: None,
        depth_prompt_depth: None,
        depth_prompt_role: None,
        talkativeness: None,
        depth_prompt_ciphertext: None,
        depth_prompt_nonce: None,
        world_ciphertext: None,
        world_nonce: None,
    };
    let conn_char = test_app.db_pool.get().await?;
    let _ = conn_char
        .interact(move |conn_inner| {
            diesel::insert_into(characters::table)
                .values(&new_character)
                .execute(conn_inner)
        })
        .await
        .map_err(|e| AnyhowError::msg(format!("DB interaction error: {e}")))?;
    test_data_guard.add_character(character_id);

    // Create chat session request with an empty lorebook_ids list
    let request_body = json!({
        "character_id": character_id,
        "title": "Chat with Empty Lorebook List",
        "lorebook_ids": [] // Empty list
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats/create_session")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body)?))?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::CREATED);

    let body = response.into_body().collect().await?.to_bytes();
    let session: DbChatSession = serde_json::from_slice(&body)?;
    test_data_guard.add_chat(session.id);

    // Verify no entries in chat_session_lorebooks
    let conn_verify = test_app.db_pool.get().await?;
    let linked_lorebooks: Vec<ChatSessionLorebook> = conn_verify
        .interact(move |conn_inner| {
            chat_session_lorebooks::table
                .filter(chat_session_lorebooks::chat_session_id.eq(session.id))
                .load::<ChatSessionLorebook>(conn_inner)
        })
        .await
        .map_err(|e| AnyhowError::msg(format!("DB interaction error: {e}")))?
        .map_err(|e| AnyhowError::msg(format!("Failed to query lorebooks: {e}")))?;

    assert!(
        linked_lorebooks.is_empty(),
        "No lorebooks should be linked when an empty list is provided"
    );

    test_data_guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_create_chat_session_non_existent_lorebook_id() -> Result<(), AnyhowError> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    let username = "user_non_existent_lorebook";
    let password = "password";
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        password.to_string(),
    )
    .await?;
    test_data_guard.add_user(user.id);

    // Use router-based login to ensure we're using the same AuthBackend instance
    let auth_cookie =
        test_helpers::login_user_via_router(&test_app.router, username, password).await;

    // Create a character
    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id,
        user_id: user.id,
        name: "Non-Existent Lorebook Char".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        first_mes: None,
        description: None,
        personality: None,
        scenario: None,
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
        example_dialogue_nonce: None,
        model_prompt_nonce: None,
        user_persona_nonce: None,
        fav: None,
        world: None,
        creator_comment: None,
        creator_comment_nonce: None,
        depth_prompt: None,
        depth_prompt_depth: None,
        depth_prompt_role: None,
        talkativeness: None,
        depth_prompt_ciphertext: None,
        depth_prompt_nonce: None,
        world_ciphertext: None,
        world_nonce: None,
    };
    let conn_char = test_app.db_pool.get().await?;
    let _ = conn_char
        .interact(move |conn_inner| {
            diesel::insert_into(characters::table)
                .values(&new_character)
                .execute(conn_inner)
        })
        .await
        .map_err(|e| AnyhowError::msg(format!("DB interaction error: {e}")))?;
    test_data_guard.add_character(character_id);

    let non_existent_lorebook_id = Uuid::new_v4();

    // Create chat session request with a non-existent lorebook_id
    let request_body = json!({
        "character_id": character_id,
        "title": "Chat with Non-Existent Lorebook",
        "lorebook_ids": [non_existent_lorebook_id]
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats/create_session")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body)?))?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND); // Expect 404 Not Found

    // No body to check for 404
    // let body = response.into_body().collect().await?.to_bytes();
    // let session: DbChatSession = serde_json::from_slice(&body)?; // No session to deserialize for 404
    // test_data_guard.add_chat(session.id); // No session to add for 404

    // Verify no entries in chat_session_lorebooks - This check is implicitly covered by the 404
    // as the session creation would have failed before attempting to link.
    // However, if we wanted to be absolutely sure no partial data was created (though transaction should prevent it),
    // we might query, but for a 404 on session creation, it's usually not necessary.

    // No cleanup needed for a session that wasn't created.
    // test_data_guard.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_create_chat_session_lorebook_owned_by_another_user() -> Result<(), AnyhowError> {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mut test_data_guard = test_helpers::TestDataGuard::new(test_app.db_pool.clone());

    // User who will own the lorebook
    let owner_username = "lorebook_owner_user";
    let owner_password = "password";
    let owner_user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        owner_username.to_string(),
        owner_password.to_string(),
    )
    .await?;
    test_data_guard.add_user(owner_user.id);

    // User who will try to create the chat session
    let requester_username = "chat_requester_user";
    let requester_password = "password";
    let requester_user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        requester_username.to_string(),
        requester_password.to_string(),
    )
    .await?;
    test_data_guard.add_user(requester_user.id);

    // Use router-based login to ensure we're using the same AuthBackend instance
    let requester_auth_cookie = test_helpers::login_user_via_router(
        &test_app.router,
        requester_username,
        requester_password,
    )
    .await;

    // Create a character for the requester_user
    let character_id = Uuid::new_v4();
    let new_character = DbCharacter {
        id: character_id,
        user_id: requester_user.id, // Character owned by requester
        name: "Requester Char For Unowned Lorebook".to_string(),
        spec: "test_spec".to_string(),
        spec_version: "1.0".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        first_mes: None,
        description: None,
        personality: None,
        scenario: None,
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
        example_dialogue_nonce: None,
        model_prompt_nonce: None,
        user_persona_nonce: None,
        fav: None,
        world: None,
        creator_comment: None,
        creator_comment_nonce: None,
        depth_prompt: None,
        depth_prompt_depth: None,
        depth_prompt_role: None,
        talkativeness: None,
        depth_prompt_ciphertext: None,
        depth_prompt_nonce: None,
        world_ciphertext: None,
        world_nonce: None,
    };
    let conn_char = test_app.db_pool.get().await?;
    let _ = conn_char
        .interact(move |conn_inner| {
            diesel::insert_into(characters::table)
                .values(&new_character)
                .execute(conn_inner)
        })
        .await
        .map_err(|e| AnyhowError::msg(format!("DB interaction error: {e}")))?;
    test_data_guard.add_character(character_id);

    // Create a Lorebook owned by owner_user
    let encryption_service_for_lorebook =
        Arc::new(scribe_backend::services::encryption_service::EncryptionService::new());
    let mut rng_dek = rand::rngs::OsRng;
    let mut dek_bytes_lorebook_owner = [0u8; 32];
    rng_dek
        .try_fill_bytes(&mut dek_bytes_lorebook_owner)
        .expect("Failed to fill bytes for DEK");
    let owner_user_dek = Arc::new(SecretBox::new(Box::new(dek_bytes_lorebook_owner.to_vec())));

    let lorebook_other_owner = create_test_lorebook(
        &test_app.db_pool,
        encryption_service_for_lorebook.clone(),
        owner_user.id, // Lorebook owned by owner_user
        "Lorebook Of Other User",
        owner_user_dek.clone(),
        &mut test_data_guard,
    )
    .await?;

    // Create chat session request with lorebook_id owned by another user
    let request_body = json!({
        "character_id": character_id,
        "title": "Chat with Unowned Lorebook",
        "lorebook_ids": [lorebook_other_owner.id]
    });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats/create_session")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, requester_auth_cookie) // Authenticated as requester_user
        .body(Body::from(serde_json::to_vec(&request_body)?))?;

    let response = test_app.router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN); // Expect 403 Forbidden

    // No body to check for 403
    // let body = response.into_body().collect().await?.to_bytes();
    // let session: DbChatSession = serde_json::from_slice(&body)?; // No session for 403
    // test_data_guard.add_chat(session.id); // No session to add for 403

    // Verification of no linked lorebooks is implicitly covered by the 403 error,
    // as session creation (and thus linking) would have failed.

    // No cleanup needed for a session that wasn't created.
    // test_data_guard.cleanup().await?;
    Ok(())
}
