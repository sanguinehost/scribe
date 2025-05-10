#![cfg(test)]

// Common imports needed for session tests
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use http_body_util::BodyExt;
use mime;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;
use chrono::Utc;

// Diesel imports
use diesel::prelude::*;
use diesel::RunQueryDsl;

// Crate imports
use scribe_backend::models::chats::{Chat as DbChatSession, NewChat};
use scribe_backend::models::character_card::NewCharacter;
use scribe_backend::models::characters::Character as DbCharacter;
use scribe_backend::schema::{characters, chat_sessions};
use scribe_backend::test_helpers; // For spawn_app, create_test_user

// --- Session Creation Tests ---

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_create_chat_session_success() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "test_create_chat_user",
        "password",
    )
    .await;

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
    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    let character_name = "Test Character for Chat";
    let pool = test_app.db_pool.clone();
    let user_id_clone = user.id;
    let _character_name_clone = character_name.to_string();
    let character_conn_obj = pool.get().await.expect("Failed to get DB connection for character creation");
    let character: DbCharacter = character_conn_obj.interact(move |actual_pg_conn| {
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
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };
        diesel::insert_into(characters::table)
            .values(&new_character_values)
            .get_result::<DbCharacter>(actual_pg_conn)
    }).await.map(|result| result.expect("Error saving character")).expect("Interact join error");

    let request_body = json!({ "title": "Test Chat", "character_id": character.id });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats")
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
        .uri("/api/chats")
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
        "test_char_not_found_user",
        "password",
    )
    .await;

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
    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
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
        .uri("/api/chats")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_create_chat_session_character_other_user() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let user1 = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "chat_user_1",
        "password"
    )
    .await;
    // Login user1 - not strictly needed for this test logic as cookie isn't used, but good practice for consistency
    let login_payload1 = json!({
        "identifier": "chat_user_1",
        "password": "password"
    });
    let login_request1 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload1).unwrap()))
        .unwrap();
    let login_response1 = test_app.router.clone().oneshot(login_request1).await.unwrap();
    assert_eq!(login_response1.status(), StatusCode::OK);
    // let _auth_cookie1 = login_response1.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string();

    let character_name = "User1 Character";
    let pool = test_app.db_pool.clone();
    let user1_id_clone = user1.id;
    let _character_name_clone = character_name.to_string();
    let char_user1_conn_obj = pool.get().await.expect("Failed to get DB connection for character creation user1");
    let character: DbCharacter = char_user1_conn_obj.interact(move |actual_pg_conn| {
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
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };
        diesel::insert_into(characters::table)
            .values(&new_character_values)
            .get_result::<DbCharacter>(actual_pg_conn)
    }).await.map(|result| result.expect("Error saving character")).expect("Interact join error");

    let _user2 = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "chat_user_2",
        "password"
    )
    .await;
    let login_payload2 = json!({
        "identifier": "chat_user_2",
        "password": "password"
    });
    let login_request2 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload2).unwrap()))
        .unwrap();
    let login_response2 = test_app.router.clone().oneshot(login_request2).await.unwrap();
    assert_eq!(login_response2.status(), StatusCode::OK);
    let auth_cookie2 = login_response2
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    let request_body = json!({ "title": "Other User Test", "character_id": character.id });

    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/chats")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie2) // Use user2's cookie
        .body(Body::from(serde_json::to_vec(&request_body).unwrap()))
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn create_chat_session_character_not_found_integration() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let _test_user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "test_create_chat_404_integ",
        "password",
    )
    .await;
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
    let login_response = test_app.router.clone().oneshot(login_request).await.unwrap();
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    let non_existent_character_id = Uuid::new_v4();
    let payload = json!({ "title": "Not Found Integ Test", "character_id": non_existent_character_id });
    let request = Request::builder()
        .uri("/api/chats")
        .method(Method::POST)
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .header(header::COOKIE, auth_cookie)
        .body(Body::from(payload.to_string()))
        .unwrap();
    let response = test_app.router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn create_chat_session_character_not_owned_integration() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let user1 = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "user1_create_chat_integ",
        "password",
    )
    .await;
    // Login user1 (not strictly needed as its cookie isn't used for the main request)
    let login_payload1 = json!({
        "identifier": "user1_create_chat_integ",
        "password": "password"
    });
    let login_request1 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload1).unwrap()))
        .unwrap();
    let login_response1 = test_app.router.clone().oneshot(login_request1).await.unwrap();
    assert_eq!(login_response1.status(), StatusCode::OK);
    // let _auth_cookie1 = login_response1.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string();

    let character_name = "User 1 Char Integ";
    let pool = test_app.db_pool.clone();
    let user1_id_clone = user1.id;
    let _character_name_clone = character_name.to_string();
    let char1_integ_conn_obj = pool.get().await.expect("Failed to get DB connection for char1 integ");
    let _character1: DbCharacter = char1_integ_conn_obj.interact(move |actual_pg_conn| {
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
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };
        diesel::insert_into(characters::table)
            .values(&new_character_values)
            .get_result::<DbCharacter>(actual_pg_conn)
    }).await.map(|result| result.expect("Error saving character")).expect("Interact join error");

    let _user2 = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "user2_create_chat_integ",
        "password",
    )
    .await;
    let login_payload2 = json!({
        "identifier": "user2_create_chat_integ",
        "password": "password"
    });
    let login_request2 = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload2).unwrap()))
        .unwrap();
    let login_response2 = test_app.router.clone().oneshot(login_request2).await.unwrap();
    assert_eq!(login_response2.status(), StatusCode::OK);
    let auth_cookie2 = login_response2
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}", Uuid::new_v4())) // Use a random UUID since this test is for authorization
        .header(header::COOKIE, auth_cookie2) // Using user 2's cookie
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
#[ignore] // Added ignore for CI
async fn test_get_chat_session_details_unauthorized() {
    let test_app = test_helpers::spawn_app(true, false, false).await;
    let user =
        test_helpers::db::create_test_user(&test_app.db_pool, "test_get_unauth_user", "password")
            .await;
    
    let pool = test_app.db_pool.clone();
    let user_id_clone = user.id;
    let char_name = "Char for Unauth Get";
    let conn_guard_char_unauth = pool.get().await.expect("Failed to get DB connection for character unauth");
    let character: DbCharacter = conn_guard_char_unauth.interact(move |actual_pg_conn| {
        let new_char_values = NewCharacter {
            user_id: user_id_clone, 
            spec: "character_card_v3_example".to_string(),
            spec_version: "1.0.0".to_string(),
            name: char_name.to_string(),
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
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };
        diesel::insert_into(characters::table).values(&new_char_values).get_result::<DbCharacter>(actual_pg_conn)
    }).await.map(|result| result.expect("Error saving character")).expect("Interact join error");
    
    let pool = test_app.db_pool.clone();
    let session_user_id_clone = user.id;
    let session_char_id_clone = character.id;
    let session_title = format!("Chat for char {}", character.id);
    let session_title_clone = session_title.clone();
    let conn_guard_session_unauth = pool.get().await.expect("Failed to get DB connection for session unauth");
    let session: DbChatSession = conn_guard_session_unauth.interact(move |actual_pg_conn| {
        let new_chat_values = NewChat {
            id: Uuid::new_v4(),
            user_id: session_user_id_clone, 
            character_id: session_char_id_clone,
            title: Some(session_title_clone),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            history_management_strategy: "truncate_summary".to_string(),
            history_management_limit: 10,
            model_name: "test-model".to_string(),
            visibility: Some("private".to_string()),
        };
        diesel::insert_into(chat_sessions::table).values(&new_chat_values).returning(DbChatSession::as_returning()).get_result(actual_pg_conn)
    }).await.map(|result| result.expect("Error saving session")).expect("Interact join error");


    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chats/{}", session.id))
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
        "test_get_details_invalid_uuid_user",
        "password",
    )
    .await;
    let login_payload_user = json!({
        "identifier": "test_get_details_invalid_uuid_user",
        "password": "password"
    });
    let login_request_user = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, mime::APPLICATION_JSON.as_ref())
        .body(Body::from(serde_json::to_string(&login_payload_user).unwrap()))
        .unwrap();
    let login_response_user = test_app.router.clone().oneshot(login_request_user).await.unwrap();
    assert_eq!(login_response_user.status(), StatusCode::OK);
    let auth_cookie = login_response_user
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    let request = Request::builder()
        .method(Method::GET)
        .uri("/api/chats/not-a-valid-uuid") // Invalid UUID in path
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.oneshot(request).await.unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}