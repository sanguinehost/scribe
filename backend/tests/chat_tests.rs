use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
};
use http_body_util::BodyExt; // For .collect()
use serde_json::Value;
use scribe_backend::models::{
    chat::{ChatSession, ChatMessage, MessageType},
};
use tower::ServiceExt; // for `app.oneshot()`
use uuid::Uuid;

// Reuse helper functions from other tests (assuming they exist and are made public/reusable)
// Might need to extract common test setup logic into a shared module later.
// For now, assume functions like `spawn_app`, `create_test_user_and_login`, 
// `create_test_character`, `create_test_chat_session` exist or adapt from existing tests.
mod helpers; // Assume helpers module exists or will be created
use helpers::{spawn_app};

#[tokio::test]
async fn list_chat_sessions_success() {
    // Arrange
    let app = spawn_app().await;

    // 1. Create User and Log In (using oneshot helper)
    let (auth_cookie, test_user) = helpers::create_test_user_and_login(&app, "test_list_chats", "password").await;
    
    // 2. Create a Character for the user
    let test_character = helpers::create_test_character(&app.db_pool, test_user.id, "Test Char for List").await;

    // 3. Create Chat Sessions for the user
    let session1 = helpers::create_test_chat_session(&app.db_pool, test_user.id, test_character.id).await;
    let session2 = helpers::create_test_chat_session(&app.db_pool, test_user.id, test_character.id).await;

    // 4. Create another user and session (to ensure we only get the logged-in user's sessions)
    let other_user = helpers::create_test_user(&app.db_pool, "other_user", "password").await;
    let other_character = helpers::create_test_character(&app.db_pool, other_user.id, "Other Char").await;
    let _other_session = helpers::create_test_chat_session(&app.db_pool, other_user.id, other_character.id).await;

    // Act
    let request = Request::builder()
        .uri(format!("{}/api/chats", &app.address))
        .method(Method::GET)
        .header("Cookie", auth_cookie) // Use the obtained auth cookie
        .body(Body::empty())
        .unwrap();

    let response = app.router.oneshot(request).await.unwrap();

    // Assert
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");

    // Expecting an array of chat sessions
    let sessions_array = body_json.as_array().expect("Response body should be a JSON array");

    assert_eq!(sessions_array.len(), 2, "Should return exactly 2 sessions for the logged-in user");

    // Deserialize and check ownership (optional, but good practice)
    let sessions: Vec<ChatSession> = serde_json::from_value(body_json).expect("Failed to deserialize sessions");
    assert!(sessions.iter().all(|s| s.user_id == test_user.id));
    assert!(sessions.iter().any(|s| s.id == session1.id));
    assert!(sessions.iter().any(|s| s.id == session2.id));
}

#[tokio::test]
async fn list_chat_sessions_unauthenticated() {
    // Arrange
    let app = spawn_app().await;

    // Act
    let request = Request::builder()
        .uri(format!("{}/api/chats", &app.address))
        .method(Method::GET)
        // No Cookie header
        .body(Body::empty())
        .unwrap();

    let response = app.router.oneshot(request).await.unwrap();

    // Assert
    // login_required redirects to login page by default
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    // Optionally check the Location header
    // assert_eq!(response.headers().get("Location").unwrap(), "/api/auth/login");
}

#[tokio::test]
async fn list_chat_sessions_empty() {
    // Arrange
    let app = spawn_app().await;
    let (auth_cookie, _test_user) = helpers::create_test_user_and_login(&app, "test_list_empty", "password").await;
    
    // Act
    let request = Request::builder()
        .uri(format!("{}/api/chats", &app.address))
        .method(Method::GET)
        .header("Cookie", auth_cookie) 
        .body(Body::empty())
        .unwrap();

    let response = app.router.oneshot(request).await.unwrap();

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");
    let sessions_array = body_json.as_array().expect("Response body should be a JSON array");
    assert!(sessions_array.is_empty(), "Should return an empty array for a user with no sessions");
}

// TODO: Add test case for DB error? (Might require mocking the DB interaction)
// TODO: Define the helper functions (spawn_app, create_test_user_and_login, etc.) 
//       likely by refactoring existing test helpers into backend/tests/helpers.rs

// --- Tests for GET /api/chats/{id}/messages ---

#[tokio::test]
async fn get_chat_messages_success() {
    // Arrange
    let app = spawn_app().await;
    let (auth_cookie, test_user) = helpers::create_test_user_and_login(&app, "test_get_msgs", "password").await;
    let test_character = helpers::create_test_character(&app.db_pool, test_user.id, "Test Char for Get Msgs").await;
    let session = helpers::create_test_chat_session(&app.db_pool, test_user.id, test_character.id).await;
    
    // Add messages to the session
    let msg1 = helpers::create_test_chat_message(&app.db_pool, session.id, MessageType::User, "Hello").await;
    let msg2 = helpers::create_test_chat_message(&app.db_pool, session.id, MessageType::Ai, "Hi there").await;

    // Act
    let request = Request::builder()
        .uri(format!("{}/api/chats/{}/messages", &app.address, session.id))
        .method(Method::GET)
        .header("Cookie", auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = app.router.oneshot(request).await.unwrap();

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");
    let messages_array = body_json.as_array().expect("Response body should be a JSON array");

    assert_eq!(messages_array.len(), 2, "Should return 2 messages");
    // Optional: Deserialize and check content/order
    let messages: Vec<ChatMessage> = serde_json::from_value(body_json).unwrap();
    // Assuming default order is creation time ascending
    assert_eq!(messages[0].id, msg1.id);
    assert_eq!(messages[1].id, msg2.id);
}

#[tokio::test]
async fn get_chat_messages_forbidden() {
    // Arrange
    let app = spawn_app().await;
    
    // User 1 (owns the session)
    let (_auth_cookie1, user1) = helpers::create_test_user_and_login(&app, "user1_get_msgs", "password").await;
    let character1 = helpers::create_test_character(&app.db_pool, user1.id, "Char User 1").await;
    let session1 = helpers::create_test_chat_session(&app.db_pool, user1.id, character1.id).await;
    let _msg1 = helpers::create_test_chat_message(&app.db_pool, session1.id, MessageType::User, "Msg 1").await;

    // User 2 (tries to access User 1's session)
    let (auth_cookie2, _user2) = helpers::create_test_user_and_login(&app, "user2_get_msgs", "password").await;

    // Act
    let request = Request::builder()
        .uri(format!("{}/api/chats/{}/messages", &app.address, session1.id)) // Request User 1's session ID
        .method(Method::GET)
        .header("Cookie", auth_cookie2) // Authenticated as User 2
        .body(Body::empty())
        .unwrap();

    let response = app.router.oneshot(request).await.unwrap();

    // Assert
    // We expect Forbidden because the session exists but doesn't belong to user2
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn get_chat_messages_not_found() {
    // Arrange
    let app = spawn_app().await;
    let (auth_cookie, _test_user) = helpers::create_test_user_and_login(&app, "test_get_msgs_404", "password").await;
    let non_existent_session_id = Uuid::new_v4();

    // Act
    let request = Request::builder()
        .uri(format!("{}/api/chats/{}/messages", &app.address, non_existent_session_id))
        .method(Method::GET)
        .header("Cookie", auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = app.router.oneshot(request).await.unwrap();

    // Assert
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_chat_messages_unauthenticated() {
     // Arrange
    let app = spawn_app().await;
    let test_user = helpers::create_test_user(&app.db_pool, "user_get_unauth", "password").await;
    let test_character = helpers::create_test_character(&app.db_pool, test_user.id, "Char Unauth").await;
    let session = helpers::create_test_chat_session(&app.db_pool, test_user.id, test_character.id).await;

    // Act
    let request = Request::builder()
        .uri(format!("{}/api/chats/{}/messages", &app.address, session.id))
        .method(Method::GET)
        // No Cookie header
        .body(Body::empty())
        .unwrap();

    let response = app.router.oneshot(request).await.unwrap();

    // Assert
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
}

#[tokio::test]
async fn get_chat_messages_empty_list() {
    // Arrange
    let app = spawn_app().await;
    let (auth_cookie, test_user) = helpers::create_test_user_and_login(&app, "test_get_msgs_empty", "password").await;
    let test_character = helpers::create_test_character(&app.db_pool, test_user.id, "Char Empty Msgs").await;
    let session = helpers::create_test_chat_session(&app.db_pool, test_user.id, test_character.id).await;
    // No messages added

    // Act
    let request = Request::builder()
        .uri(format!("{}/api/chats/{}/messages", &app.address, session.id))
        .method(Method::GET)
        .header("Cookie", auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = app.router.oneshot(request).await.unwrap();

    // Assert
    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_json: Value = serde_json::from_slice(&body_bytes).expect("Response body is not valid JSON");
    let messages_array = body_json.as_array().expect("Response body should be a JSON array");
    assert!(messages_array.is_empty(), "Should return an empty array");
}

// --- End Tests for GET /api/chats/{id}/messages ---

// --- Tests for POST /api/chats ---

#[tokio::test]
async fn create_chat_session_success() {
    // Arrange
    let app = spawn_app().await;
    let (auth_cookie, test_user) = helpers::create_test_user_and_login(&app, "test_create_chat", "password").await;
    let test_character = helpers::create_test_character(&app.db_pool, test_user.id, "Char Create Chat").await;

    let payload = serde_json::json!({ "character_id": test_character.id });

    // Act
    let request = Request::builder()
        .uri(format!("{}/api/chats", &app.address))
        .method(Method::POST)
        .header("Cookie", &auth_cookie)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = app.router.oneshot(request).await.unwrap();

    // Assert
    assert_eq!(response.status(), StatusCode::CREATED);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let created_session: ChatSession = serde_json::from_slice(&body_bytes).expect("Failed to deserialize created session");

    assert_eq!(created_session.user_id, test_user.id);
    assert_eq!(created_session.character_id, test_character.id);
    assert!(created_session.title.is_none()); // Assuming title isn't set on creation by default

    // Verify in DB (optional but good)
    let session_in_db = helpers::get_chat_session_from_db(&app.db_pool, created_session.id).await;
    assert!(session_in_db.is_some());
    assert_eq!(session_in_db.unwrap().id, created_session.id);
}

#[tokio::test]
async fn create_chat_session_unauthenticated() {
    // Arrange
    let app = spawn_app().await;
    let test_user = helpers::create_test_user(&app.db_pool, "unauth_create_chat", "password").await;
    let test_character = helpers::create_test_character(&app.db_pool, test_user.id, "Char Unauth Create").await;
    let payload = serde_json::json!({ "character_id": test_character.id });

    // Act
    let request = Request::builder()
        .uri(format!("{}/api/chats", &app.address))
        .method(Method::POST)
        // No Cookie header
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = app.router.oneshot(request).await.unwrap();

    // Assert
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT); // Expect redirect to login
}

#[tokio::test]
async fn create_chat_session_character_not_found() {
    // Arrange
    let app = spawn_app().await;
    let (auth_cookie, _test_user) = helpers::create_test_user_and_login(&app, "create_chat_404", "password").await;
    let non_existent_character_id = Uuid::new_v4();
    let payload = serde_json::json!({ "character_id": non_existent_character_id });

    // Act
    let request = Request::builder()
        .uri(format!("{}/api/chats", &app.address))
        .method(Method::POST)
        .header("Cookie", &auth_cookie)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = app.router.oneshot(request).await.unwrap();

    // Assert
    // The handler returns NotFound for both non-existent and not-owned characters
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_chat_session_character_not_owned() {
    // Arrange
    let app = spawn_app().await;

    // User 1 owns the character
    let (_auth_cookie1, user1) = helpers::create_test_user_and_login(&app, "user1_create_chat", "password").await;
    let character1 = helpers::create_test_character(&app.db_pool, user1.id, "Char User 1 Create").await;

    // User 2 tries to create a session with User 1's character
    let (auth_cookie2, _user2) = helpers::create_test_user_and_login(&app, "user2_create_chat", "password").await;

    let payload = serde_json::json!({ "character_id": character1.id }); // Use User 1's character ID

    // Act
    let request = Request::builder()
        .uri(format!("{}/api/chats", &app.address))
        .method(Method::POST)
        .header("Cookie", &auth_cookie2) // Authenticated as User 2
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = app.router.oneshot(request).await.unwrap();

    // Assert
    // The handler returns NotFound for both non-existent and not-owned characters
    assert_eq!(response.status(), StatusCode::NOT_FOUND); 
}

#[tokio::test]
async fn create_chat_session_invalid_payload() {
    // Arrange
    let app = spawn_app().await;
    let (auth_cookie, _test_user) = helpers::create_test_user_and_login(&app, "create_chat_bad_payload", "password").await;
    
    // Malformed payload (e.g., wrong field name or type)
    let payload = serde_json::json!({ "char_id": "not-a-uuid" }); 

    // Act
    let request = Request::builder()
        .uri(format!("{}/api/chats", &app.address))
        .method(Method::POST)
        .header("Cookie", &auth_cookie)
        .header("Content-Type", "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = app.router.oneshot(request).await.unwrap();

    // Assert
    // Axum typically returns 400 Bad Request or 422 Unprocessable Entity for bad JSON payloads
    assert!(response.status() == StatusCode::BAD_REQUEST || response.status() == StatusCode::UNPROCESSABLE_ENTITY);
}

// --- End Tests for POST /api/chats ---
