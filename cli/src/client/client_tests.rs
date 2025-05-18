// cli/src/client/client_tests.rs
#![cfg(test)]
use super::util::*;
use super::*; // Brings in items re-exported by cli/src/client/mod.rs // For build_url and handle_response

// External Crate Imports
use bigdecimal::BigDecimal;
use chrono::Utc;
use futures_util::{Stream, StreamExt}; // Added Stream
use httptest::{
    Expectation,
    ServerHandle,
    ServerPool,
    matchers::{all_of, contains, key, matches, request}, // Added matches
    responders::{json_encoded, status_code},
};
use reqwest::{Client as ReqwestClient, StatusCode, Url}; // Added StatusCode
use reqwest_eventsource::{Event, EventSource};
use secrecy::SecretString;
use serde_json::json;
use std::io::Write;
use std::str::FromStr;
use tempfile::NamedTempFile;
use uuid::Uuid;

// Project Crate Imports
use super::interface::HttpClient;
use super::types::{
    AdminUserDetailResponse, AdminUserListResponse, AuthUserResponse, ClientCharacterDataForClient,
    ClientChatMessageResponse, HealthStatus, RegisterPayload, SerializableLoginPayload,
    SerializableRegisterPayload, StreamEvent, UpdateUserRoleRequest,
};
use crate::error::CliError;
use scribe_backend::models::{
    auth::LoginPayload,
    characters::CharacterMetadata, // This was CharacterDataForClient in the old file, but CharacterMetadata is more likely for tests if it's a summary. Let's assume CharacterMetadata for now. If it causes issues, we can adjust.
    // The original test used CharacterDataForClient, but it was aliased from the main client file.
    // Since ClientCharacterDataForClient is now a distinct struct in types.rs and re-exported,
    // we should use that if the tests were indeed using the client's representation.
    // Let's stick to what was in the original test's direct use statements for now.
    chats::{
        ApiChatMessage, Chat, ChatMessage, ChatSettingsResponse, GenerateChatRequest, MessageRole,
        UpdateChatSettingsRequest,
    },
    users::User,
};

// Shared setup for tests needing a mock server
fn setup_test_server() -> (ServerHandle<'static>, ReqwestClientWrapper) {
    let server_pool = Box::leak(Box::new(ServerPool::new(1)));
    let server = server_pool.get_server();
    let base_url = Url::parse(&server.url_str("")).unwrap();
    let reqwest_client = ReqwestClient::builder().cookie_store(true).build().unwrap();
    let client_wrapper = ReqwestClientWrapper::new(reqwest_client, base_url);
    (server, client_wrapper)
}

#[test]
fn test_build_url_success() {
    let base = Url::parse("http://localhost:3000").unwrap();
    let expected = Url::parse("http://localhost:3000/api/users").unwrap();
    assert_eq!(build_url(&base, "/api/users").unwrap(), expected);

    let base_with_path = Url::parse("http://example.com/base/").unwrap();
    let expected_with_path = Url::parse("http://example.com/base/path").unwrap();
    assert_eq!(
        build_url(&base_with_path, "path").unwrap(),
        expected_with_path
    );

    let base_no_slash = Url::parse("http://example.com").unwrap();
    let expected_no_slash = Url::parse("http://example.com/path").unwrap();
    assert_eq!(
        build_url(&base_no_slash, "/path").unwrap(),
        expected_no_slash
    );
}

#[test]
fn test_build_url_invalid_path() {
    let base = Url::parse("http://localhost:3000").unwrap();
    let result = build_url(&base, "ftp:"); // Example invalid path component
    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::UrlParse(_) => {} // Expected error variant
        e => panic!("Expected UrlParse error, but got {:?}", e),
    }
}

#[tokio::test]
async fn test_login_success() {
    let (server, client_wrapper) = setup_test_server();
    let user_id = Uuid::new_v4();
    let mock_user = json!({
        "user_id": user_id,
        "username": "testuser",
        "email": "test@example.com",
        "created_at": Utc::now().to_rfc3339(),
        "updated_at": Utc::now().to_rfc3339(),
        "role": "User" // Added role field which is required in AuthUserResponse
    });

    server.expect(
        Expectation::matching(request::method_path("POST", "/api/auth/login"))
            .respond_with(json_encoded(mock_user)),
    );

    let credentials = LoginPayload {
        identifier: "testuser".to_string(),
        password: SecretString::new("password123".to_string().into()),
    };
    let result = client_wrapper.login(&credentials).await;

    eprintln!("Login test result: {:?}", result);
    assert!(result.is_ok(), "Login failed: {:?}", result.err());
    let user = result.unwrap();
    assert_eq!(user.id, user_id);
    assert_eq!(user.username, "testuser");
    assert_eq!(user.email, "test@example.com");
}

#[tokio::test]
async fn test_login_failure_unauthorized() {
    let (mut server, client) = setup_test_server();

    let credentials = LoginPayload {
        identifier: "testuser".to_string(),
        password: SecretString::new("wrongpassword".to_string().into()),
    };
    let error_body = json!({
        "error": {
            "message": "Invalid credentials"
        }
    });

    server.expect(
        Expectation::matching(request::method_path("POST", "/api/auth/login"))
            .respond_with(status_code(401).body(error_body.to_string())),
    );

    let result = client.login(&credentials).await;

    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::AuthFailed(msg) => {
            assert!(
                msg.contains("Invalid credentials"),
                "Error message was: {}",
                msg
            );
            assert!(msg.contains("401"), "Error message was: {}", msg);
        }
        e => panic!("Expected CliError::AuthFailed, got {:?}", e),
    }

    server.verify_and_clear();
}

#[tokio::test]
async fn test_login_failure_rate_limit() {
    let (mut server, client) = setup_test_server();

    let credentials = LoginPayload {
        identifier: "testuser".to_string(),
        password: SecretString::new("password".to_string().into()),
    };

    server.expect(
        Expectation::matching(request::method_path("POST", "/api/auth/login"))
            .respond_with(status_code(429)),
    );

    let result = client.login(&credentials).await;

    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::AuthFailed(msg) => {
            let expected_substring = "API rate limit exceeded";
            assert!(
                msg.contains(expected_substring),
                "Error message \"{}\" did not contain \"{}\"",
                msg,
                expected_substring
            );
        }
        e => panic!(
            "Expected CliError::AuthFailed indicating rate limit, got {:?}",
            e
        ),
    }

    server.verify_and_clear();
}

#[tokio::test]
async fn test_register_success() {
    let (server, client_wrapper) = setup_test_server();
    let user_id = Uuid::new_v4();
    let mock_user_response = json!({
        "user_id": user_id,
        "username": "newuser",
        "email": "new@example.com",
        "created_at": Utc::now().to_rfc3339(),
        "updated_at": Utc::now().to_rfc3339(),
        "role": "User" // Added role field
    });

    server.expect(
        Expectation::matching(request::method_path("POST", "/api/auth/register"))
            .respond_with(json_encoded(mock_user_response)),
    );

    let credentials = RegisterPayload {
        username: "newuser".to_string(),
        email: "new@example.com".to_string(),
        password: SecretString::new("password123".to_string().into()),
    };
    let result = client_wrapper.register(&credentials).await;

    eprintln!("Register test result: {:?}", result);
    assert!(result.is_ok(), "Registration failed: {:?}", result.err());
    let user = result.unwrap();
    assert_eq!(user.id, user_id);
    assert_eq!(user.username, "newuser");
    assert_eq!(user.email, "new@example.com");
}

#[tokio::test]
async fn test_register_failure_conflict() {
    let (mut server, client) = setup_test_server();

    let register_payload = RegisterPayload {
        username: "existinguser".to_string(),
        email: "existing@example.com".to_string(),
        password: SecretString::new("password123".to_string().into()),
    };

    let error_body = json!({
        "error": {
            "message": "Username already taken"
        }
    });

    server.expect(
        Expectation::matching(request::method_path("POST", "/api/auth/register"))
            .respond_with(status_code(409).body(error_body.to_string())),
    );

    let result = client.register(&register_payload).await;

    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::RegistrationFailed(msg) => {
            assert!(
                msg.contains("Username already taken"),
                "Error message was: {}",
                msg
            );
            assert!(msg.contains("409"), "Error message was: {}", msg);
        }
        e => panic!("Expected CliError::RegistrationFailed, got {:?}", e),
    }

    server.verify_and_clear();
}

#[tokio::test]
async fn test_list_characters_success() {
    let (mut server, client) = setup_test_server();

    let char1_id = Uuid::new_v4();
    let char2_id = Uuid::new_v4();
    let user_id_mock = Uuid::new_v4(); // Mock user ID
    let now = Utc::now();

    let char1_response = json!({
        "id": char1_id,
        "user_id": user_id_mock,
        "name": "Character One",
        "spec": "chara_card_v3",
        "spec_version": "1.0",
        "description": "Description One".to_string().into_bytes(), // Simulating backend byte array
        "first_mes": "Hello from Character One!".to_string().into_bytes(), // Simulating backend byte array
        "created_at": now,
        "updated_at": now
    });

    let char2_response = json!({
        "id": char2_id,
        "user_id": user_id_mock,
        "name": "Character Two",
        "spec": "chara_card_v3",
        "spec_version": "1.0",
        "description": null, // Simulating null from backend
        "first_mes": null,   // Simulating null from backend
        "created_at": now,
        "updated_at": now
    });

    let mock_response = json!([char1_response, char2_response]);

    server.expect(
        Expectation::matching(request::method_path("GET", "/api/characters"))
            .respond_with(json_encoded(mock_response)),
    );

    let result = client.list_characters().await;

    assert!(result.is_ok());
    let characters = result.unwrap();
    assert_eq!(characters.len(), 2);
    assert_eq!(characters[0].id, char1_id);
    assert_eq!(characters[1].name, "Character Two");
    assert_eq!(
        characters[0].description,
        Some("Description One".to_string())
    );
    assert_eq!(
        characters[0].first_mes,
        Some("Hello from Character One!".to_string())
    );
    assert_eq!(characters[1].description, None);
    assert_eq!(characters[1].first_mes, None);

    server.verify_and_clear();
}

#[tokio::test]
async fn test_list_characters_success_empty() {
    let (mut server, client) = setup_test_server();
    let mock_characters: Vec<ClientCharacterDataForClient> = vec![];

    server.expect(
        Expectation::matching(request::method_path("GET", "/api/characters"))
            .respond_with(json_encoded(mock_characters)),
    );

    let result = client.list_characters().await;

    assert!(result.is_ok());
    let characters = result.unwrap();
    assert!(characters.is_empty());

    server.verify_and_clear();
}

#[tokio::test]
async fn test_list_characters_api_error() {
    let (mut server, client) = setup_test_server();
    let error_body = json!({
        "error": {
            "message": "Database connection failed"
        }
    });

    server.expect(
        Expectation::matching(request::method_path("GET", "/api/characters"))
            .respond_with(status_code(500).body(error_body.to_string())),
    );

    let result = client.list_characters().await;

    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::ApiError { status, message } => {
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(message.contains("Database connection failed"));
        }
        e => panic!("Expected CliError::ApiError, got {:?}", e),
    }

    server.verify_and_clear();
}

#[tokio::test]
async fn test_upload_character_success() {
    let (mut server, client) = setup_test_server();

    let character_name = "Test Character Upload";
    let file_content = "PNG image data or character card content";
    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(file_content.as_bytes()).unwrap();
    let temp_file_path = temp_file.path().to_str().unwrap().to_string();

    let mock_response_id = Uuid::new_v4();
    let mock_response_user_id = Uuid::new_v4();
    let now = Utc::now();

    let mock_response = json!({
        "id": mock_response_id,
        "user_id": mock_response_user_id,
        "name": character_name,
        "spec": "chara_card_v3",
        "spec_version": "1.0",
        "description": "Uploaded via test".to_string().into_bytes(),
        "first_mes": "Hello from upload!".to_string().into_bytes(),
        "created_at": now,
        "updated_at": now
    });

    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/api/characters/upload"),
            request::headers(contains(key("content-type"))),
        ])
        .respond_with(json_encoded(mock_response)),
    );

    let result = client
        .upload_character(character_name, &temp_file_path)
        .await;

    assert!(result.is_ok());
    let uploaded_char = result.unwrap();
    assert_eq!(uploaded_char.id, mock_response_id);
    assert_eq!(uploaded_char.name, character_name);
    assert_eq!(
        uploaded_char.description,
        Some("Uploaded via test".to_string())
    );
    assert_eq!(
        uploaded_char.first_mes,
        Some("Hello from upload!".to_string())
    );

    server.verify_and_clear();
}

#[tokio::test]
async fn test_upload_character_file_not_found() {
    let (_server, client) = setup_test_server();

    let character_name = "Test Character Fail";
    let non_existent_path = "/path/to/non/existent/file.png";

    let result = client
        .upload_character(character_name, non_existent_path)
        .await;

    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::Io(io_error) => {
            assert_eq!(io_error.kind(), std::io::ErrorKind::NotFound);
        }
        e => panic!("Expected CliError::Io(NotFound), got {:?}", e),
    }
}

#[tokio::test]
async fn test_health_check_success() {
    let (mut server, client) = setup_test_server();

    let mock_status = HealthStatus {
        status: "OK".to_string(),
    };

    server.expect(
        Expectation::matching(request::method_path("GET", "/api/health"))
            .respond_with(json_encoded(mock_status.clone())),
    );

    let result = client.health_check().await;

    assert!(result.is_ok());
    let health = result.unwrap();
    assert_eq!(health.status, mock_status.status);

    server.verify_and_clear();
}

#[tokio::test]
async fn test_health_check_api_error() {
    let (mut server, client) = setup_test_server();
    let error_body = json!({
        "error": {
            "message": "Service Unavailable"
        }
    });

    server.expect(
        Expectation::matching(request::method_path("GET", "/api/health"))
            .respond_with(status_code(503).body(error_body.to_string())),
    );

    let result = client.health_check().await;

    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::ApiError { status, message } => {
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
            assert!(message.contains("Service Unavailable"));
        }
        e => panic!("Expected CliError::ApiError, got {:?}", e),
    }

    server.verify_and_clear();
}

#[tokio::test]
async fn test_logout_success() {
    let (mut server, client) = setup_test_server();

    server.expect(
        Expectation::matching(request::method_path("POST", "/api/auth/logout"))
            .respond_with(status_code(200)),
    );

    let result = client.logout().await;

    assert!(result.is_ok());

    server.verify_and_clear();
}

#[tokio::test]
async fn test_logout_api_error() {
    let (mut server, client) = setup_test_server();
    let error_body = json!({
        "error": {
            "message": "Logout failed internally"
        }
    });

    server.expect(
        Expectation::matching(request::method_path("POST", "/api/auth/logout"))
            .respond_with(status_code(500).body(error_body.to_string())),
    );

    let result = client.logout().await;

    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::ApiError { status, message } => {
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(message.contains("Logout failed internally"));
        }
        e => panic!("Expected CliError::ApiError, got {:?}", e),
    }

    server.verify_and_clear();
}

#[tokio::test]
async fn test_me_success() {
    let (server, client_wrapper) = setup_test_server();
    let user_id = Uuid::new_v4();
    let mock_user = json!({
        "user_id": user_id,
        "username": "currentuser",
        "email": "user@example.com",
        "created_at": Utc::now().to_rfc3339(),
        "updated_at": Utc::now().to_rfc3339(),
        "role": "User" // Added role field
    });

    server.expect(
        Expectation::matching(request::method_path("GET", "/api/auth/me"))
            .respond_with(json_encoded(mock_user)),
    );

    let result = client_wrapper.me().await;
    eprintln!("Me test result: {:?}", result);
    assert!(result.is_ok(), "Fetching /me failed: {:?}", result.err());
    let user = result.unwrap();
    assert_eq!(user.id, user_id);
    assert_eq!(user.username, "currentuser");
    assert_eq!(user.email, "user@example.com");
}

#[tokio::test]
async fn test_me_unauthorized() {
    let (mut server, client) = setup_test_server();
    let error_body = json!({
        "error": {
            "message": "Authentication token missing or invalid"
        }
    });

    server.expect(
        Expectation::matching(request::method_path("GET", "/api/auth/me"))
            .respond_with(status_code(401).body(error_body.to_string())),
    );

    let result = client.me().await;

    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::ApiError { status, message } => {
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert!(message.contains("Authentication token missing or invalid"));
        }
        e => panic!("Expected CliError::ApiError, got {:?}", e),
    }

    server.verify_and_clear();
}

#[tokio::test]
async fn test_get_character_success() {
    let (mut server, client) = setup_test_server();

    let character_id = Uuid::new_v4();
    let user_id_mock = Uuid::new_v4();
    let now = Utc::now();

    let mock_character = json!({
        "id": character_id,
        "user_id": user_id_mock,
        "name": "Specific Character",
        "spec": "chara_card_v3",
        "spec_version": "1.0",
        "description": "Details here".to_string().into_bytes(),
        "first_mes": "Specific greeting".to_string().into_bytes(),
        "created_at": now,
        "updated_at": now
    });

    let path_string = format!("/api/characters/fetch/{}", character_id);
    server.expect(
        Expectation::matching(all_of![
            request::method("GET"),
            request::path(matches(path_string))
        ])
        .respond_with(json_encoded(mock_character)),
    );

    let result = client.get_character(character_id).await;

    assert!(result.is_ok());
    let character = result.unwrap();
    assert_eq!(character.id, character_id);
    assert_eq!(character.name, "Specific Character");
    assert_eq!(character.description, Some("Details here".to_string()));
    assert_eq!(character.first_mes, Some("Specific greeting".to_string()));

    server.verify_and_clear();
}

#[tokio::test]
async fn test_get_character_not_found() {
    let (mut server, client) = setup_test_server();
    let character_id = Uuid::new_v4();
    let error_body = json!({
        "error": {
            "message": format!("Character {} not found", character_id)
        }
    });

    let path_string = format!("/api/characters/fetch/{}", character_id);
    server.expect(
        Expectation::matching(all_of![
            request::method("GET"),
            request::path(matches(path_string))
        ])
        .respond_with(status_code(404).body(error_body.to_string())),
    );

    let result = client.get_character(character_id).await;

    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::ApiError { status, message } => {
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert!(message.contains(&format!("Character {} not found", character_id)));
        }
        e => panic!("Expected CliError::ApiError with 404, got {:?}", e),
    }

    server.verify_and_clear();
}

#[tokio::test]
async fn test_list_chat_sessions_success() {
    let (mut server, client) = setup_test_server();

    let session1_id = Uuid::new_v4();
    let session2_id = Uuid::new_v4();
    let user_id_mock = Uuid::new_v4();
    let char_id_mock = Uuid::new_v4();
    let now = Utc::now();

    let mock_sessions = vec![
        Chat {
            id: session1_id,
            user_id: user_id_mock,
            character_id: char_id_mock,
            title: Some("First Chat".to_string()),
            created_at: now,
            updated_at: now,
            system_prompt: None,
            temperature: Some(BigDecimal::from_str("0.8").unwrap()),
            max_output_tokens: Some(512),
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: "window".to_string(),
            history_management_limit: 20,
            visibility: Some("private".to_string()),
            model_name: "default-model".to_string(),
            gemini_thinking_budget: None,
            gemini_enable_code_execution: None,
        },
        Chat {
            id: session2_id,
            user_id: user_id_mock,
            character_id: Uuid::new_v4(),
            title: Some("Second Chat".to_string()),
            created_at: now,
            updated_at: now,
            system_prompt: Some("You are helpful.".to_string()),
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: Some(BigDecimal::from_str("0.1").unwrap()),
            presence_penalty: Some(BigDecimal::from_str("0.2").unwrap()),
            top_k: Some(40),
            top_p: Some(BigDecimal::from_str("0.95").unwrap()),
            repetition_penalty: Some(BigDecimal::from_str("1.1").unwrap()),
            min_p: None,
            top_a: None,
            seed: Some(123),
            logit_bias: Some(json!({ "token_id": -1.0 })),
            history_management_strategy: "window".to_string(),
            history_management_limit: 20,
            visibility: Some("private".to_string()),
            model_name: "default-model".to_string(),
            gemini_thinking_budget: None,
            gemini_enable_code_execution: None,
        },
    ];

    server.expect(
        Expectation::matching(request::method_path("GET", "/api/chats-api/chats"))
            .respond_with(json_encoded(mock_sessions.clone())),
    );

    let result = client.list_chat_sessions().await;

    assert!(result.is_ok());
    let sessions = result.unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0].id, mock_sessions[0].id);
    assert_eq!(sessions[1].system_prompt, mock_sessions[1].system_prompt);
    assert_eq!(sessions[0].temperature, mock_sessions[0].temperature);
    assert_eq!(sessions[1].seed, mock_sessions[1].seed);

    server.verify_and_clear();
}

#[tokio::test]
async fn test_list_chat_sessions_success_empty() {
    let (mut server, client) = setup_test_server();
    let mock_sessions: Vec<Chat> = vec![];

    server.expect(
        Expectation::matching(request::method_path("GET", "/api/chats-api/chats"))
            .respond_with(json_encoded(mock_sessions)),
    );

    let result = client.list_chat_sessions().await;

    assert!(result.is_ok());
    let sessions = result.unwrap();
    assert!(sessions.is_empty());

    server.verify_and_clear();
}

#[tokio::test]
async fn test_list_chat_sessions_api_error() {
    let (mut server, client) = setup_test_server();
    let error_body = json!({
        "error": {
            "message": "Internal Server Error listing chats"
        }
    });

    server.expect(
        Expectation::matching(request::method_path("GET", "/api/chats-api/chats"))
            .respond_with(status_code(500).body(error_body.to_string())),
    );

    let result = client.list_chat_sessions().await;

    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::ApiError { status, message } => {
            assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(message.contains("Internal Server Error listing chats"));
        }
        e => panic!("Expected CliError::ApiError, got {:?}", e),
    }

    server.verify_and_clear();
}

#[tokio::test]
async fn test_get_chat_messages_success() {
    let (mut server, client) = setup_test_server();
    let session_id = Uuid::new_v4();
    let now = Utc::now();
    let msg_id1 = Uuid::new_v4();
    let msg_id2 = Uuid::new_v4();

    // Mock response should be Vec<ClientChatMessageResponse>
    let mock_api_response = json!([
        {
            "id": msg_id1,
            "session_id": session_id,
            "message_type": "User",
            "role": "user",
            "parts": [{"text": "Hello there"}],
            "attachments": [],
            "created_at": now.to_rfc3339(),
        },
        {
            "id": msg_id2,
            "session_id": session_id,
            "message_type": "Assistant",
            "role": "assistant",
            "parts": [{"text": "General Kenobi!"}],
            "attachments": [],
            "created_at": (now + chrono::Duration::seconds(1)).to_rfc3339(),
        }
    ]);

    let path_string = format!("/api/chats-api/chats/{}/messages", session_id);
    server.expect(
        Expectation::matching(all_of![
            request::method("GET"),
            request::path(matches(path_string))
        ])
        .respond_with(json_encoded(mock_api_response)), // Use the new mock_api_response
    );

    let result = client.get_chat_messages(session_id).await;

    assert!(
        result.is_ok(),
        "get_chat_messages failed: {:?}",
        result.err()
    );
    let messages = result.unwrap();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].id, msg_id1);
    assert_eq!(messages[0].role, "user");
    assert_eq!(
        messages[0].parts[0]["text"].as_str().unwrap(),
        "Hello there"
    );
    assert_eq!(messages[1].id, msg_id2);
    assert_eq!(messages[1].role, "assistant");
    assert_eq!(
        messages[1].parts[0]["text"].as_str().unwrap(),
        "General Kenobi!"
    );

    server.verify_and_clear();
}

#[tokio::test]
async fn test_get_chat_messages_success_empty() {
    let (mut server, client) = setup_test_server();
    let session_id = Uuid::new_v4();
    let mock_api_response: Vec<ClientChatMessageResponse> = vec![]; // Correct type

    let path_string = format!("/api/chats-api/chats/{}/messages", session_id);
    server.expect(
        Expectation::matching(all_of![
            request::method("GET"),
            request::path(matches(path_string))
        ])
        .respond_with(json_encoded(mock_api_response)),
    );

    let result = client.get_chat_messages(session_id).await;

    assert!(result.is_ok());
    let messages = result.unwrap();
    assert!(messages.is_empty());

    server.verify_and_clear();
}

#[tokio::test]
async fn test_get_chat_messages_not_found() {
    let (mut server, client) = setup_test_server();
    let session_id = Uuid::new_v4();
    let error_body = json!({
        "error": {
            "message": format!("Chat session {} not found", session_id)
        }
    });

    let path_string = format!("/api/chats-api/chats/{}/messages", session_id);
    server.expect(
        Expectation::matching(all_of![
            request::method("GET"),
            request::path(matches(path_string))
        ])
        .respond_with(status_code(404).body(error_body.to_string())),
    );

    let result = client.get_chat_messages(session_id).await;

    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::ApiError { status, message } => {
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert!(message.contains(&format!("Chat session {} not found", session_id)));
        }
        e => panic!("Expected CliError::ApiError with 404, got {:?}", e),
    }

    server.verify_and_clear();
}

#[tokio::test]
async fn test_create_chat_session_success() {
    let (mut server, client) = setup_test_server();
    let character_id = Uuid::new_v4();
    let user_id_mock = Uuid::new_v4();
    let session_id = Uuid::new_v4();
    let now = Utc::now();

    let mock_session = Chat {
        id: session_id,
        user_id: user_id_mock,
        character_id,
        title: Some("New Chat".to_string()),
        created_at: now,
        updated_at: now,
        system_prompt: None,
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        repetition_penalty: None,
        min_p: None,
        top_a: None,
        seed: None,
        logit_bias: None,
        history_management_strategy: "window".to_string(),
        history_management_limit: 20,
        visibility: Some("private".to_string()),
        model_name: "default-model".to_string(),
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
    };

    let request_payload = json!({ "character_id": character_id });

    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/api/chats"),
            request::body(request_payload.to_string()),
        ])
        .respond_with(json_encoded(mock_session.clone())),
    );

    let result = client.create_chat_session(character_id).await;

    assert!(result.is_ok());
    let created_session = result.unwrap();
    assert_eq!(created_session.id, mock_session.id);
    assert_eq!(created_session.character_id, character_id);

    server.verify_and_clear();
}

#[tokio::test]
async fn test_create_chat_session_char_not_found() {
    let (mut server, client) = setup_test_server();
    let character_id = Uuid::new_v4();
    let error_body = json!({
        "error": {
            "message": format!("Character {} not found", character_id)
        }
    });

    let request_payload = json!({ "character_id": character_id });

    server.expect(
        Expectation::matching(all_of![
            request::method_path("POST", "/api/chats"),
            request::body(request_payload.to_string()),
        ])
        .respond_with(status_code(404).body(error_body.to_string())),
    );

    let result = client.create_chat_session(character_id).await;

    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::ApiError { status, message } => {
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert!(message.contains(&format!("Character {} not found", character_id)));
        }
        e => panic!("Expected CliError::ApiError with 404, got {:?}", e),
    }

    server.verify_and_clear();
}

#[tokio::test]
async fn test_send_message_success() {
    let (mut server, client) = setup_test_server();
    let session_id = Uuid::new_v4();
    let message_content = "Hello, assistant!";
    let response_message_id = Uuid::new_v4();
    let response_content = "Hello, user!";

    // 1. Test with JSON response format
    let mock_api_response =
        json!({ "message_id": response_message_id, "content": response_content });

    server.expect(
        Expectation::matching(all_of![
            request::method("POST"),
            request::path(matches(format!("/api/chats/{}/generate.*", session_id)))
        ])
        .respond_with(json_encoded(mock_api_response)),
    );

    let result = client.send_message(session_id, message_content, None).await;

    assert!(
        result.is_ok(),
        "send_message with JSON response failed: {:?}",
        result.err()
    );
    let response_message = result.unwrap();
    assert_eq!(response_message.content, response_content.as_bytes());
    assert_eq!(response_message.message_type, MessageRole::Assistant);
    assert_eq!(response_message.id, response_message_id);
    assert_eq!(response_message.session_id, Uuid::nil());

    server.verify_and_clear();

    // 2. Test with SSE response format
    let sse_response = "event: content\ndata: Hello, user from SSE!\n\nevent: done\ndata: [DONE]\n";

    server.expect(
        Expectation::matching(all_of![
            request::method("POST"),
            request::path(matches(format!("/api/chats/{}/generate.*", session_id)))
        ])
        .respond_with(
            status_code(200)
                .append_header("content-type", "text/event-stream")
                .body(sse_response),
        ),
    );

    let result = client.send_message(session_id, message_content, None).await;

    assert!(
        result.is_ok(),
        "send_message with SSE response failed: {:?}",
        result.err()
    );
    let response_message = result.unwrap();
    assert_eq!(response_message.content, "Hello, user from SSE!".as_bytes());
    assert_eq!(response_message.message_type, MessageRole::Assistant);
    assert_eq!(response_message.session_id, Uuid::nil());

    server.verify_and_clear();
}

#[tokio::test]
async fn test_send_message_session_not_found() {
    let (mut server, client) = setup_test_server();
    let session_id = Uuid::new_v4();
    let message_content = "Does this exist?";
    let error_message_text = format!("Session {} not found", session_id);
    let error_body_json = json!({
        "error": {
            "message": error_message_text
        }
    });

    server.expect(
        Expectation::matching(all_of![
            request::method("POST"),
            request::path(matches(format!("/api/chats/{}/generate.*", session_id)))
        ])
        .respond_with(status_code(404).body(error_body_json.to_string())),
    );

    let result = client.send_message(session_id, message_content, None).await;

    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::ApiError { status, message } => {
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert!(
                message.contains(&error_message_text),
                "Expected message to contain '{}', but got: '{}'",
                error_message_text,
                message
            );
        }
        e => panic!("Expected CliError::ApiError, got {:?}", e),
    }

    server.verify_and_clear();

    // Test SSE error response format
    let sse_error_body = format!("event: error\ndata: Session {} not found", session_id);

    server.expect(
        Expectation::matching(all_of![
            request::method("POST"),
            request::path(matches(format!("/api/chats/{}/generate.*", session_id)))
        ])
        .respond_with(
            status_code(200)
                .append_header("content-type", "text/event-stream")
                .body(sse_error_body),
        ),
    );

    let result = client.send_message(session_id, message_content, None).await;

    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::Backend(message) => {
            assert!(message.contains("Session"));
            assert!(message.contains("not found"));
        }
        e => panic!("Expected CliError::Backend for SSE error, got {:?}", e),
    }

    server.verify_and_clear();
}

#[test]
fn test_generate_chat_request_serde() {
    let original = GenerateChatRequest {
        history: vec![ApiChatMessage {
            role: "user".to_string(),
            content: "Hello AI".to_string(),
        }],
        model: Some("gemini-2.5-flash-preview-04-17".to_string()),
    };

    let serialized = serde_json::to_string(&original).expect("Serialization failed");
    let deserialized: GenerateChatRequest =
        serde_json::from_str(&serialized).expect("Deserialization failed");

    assert_eq!(original.history.len(), deserialized.history.len());
    assert_eq!(original.history[0].role, deserialized.history[0].role);
    assert_eq!(original.history[0].content, deserialized.history[0].content);
    assert_eq!(original.model, deserialized.model);
}

#[tokio::test]
async fn test_delete_chat_success() {
    let (mut server, client) = setup_test_server();
    let chat_id = Uuid::new_v4();

    // Set up the correct expectation for the new endpoint following the character router pattern
    // Using explicit /remove/:id pattern to match backend's route.
    // The routes for getting and deleting were changed from /:id to /fetch/:id and /remove/:id
    // in the backend to avoid persistent 404 errors with Axum routing
    server.expect(
        Expectation::matching(all_of![
            request::method("DELETE"),
            request::path(matches(format!("/api/chats-api/chats/remove/{}", chat_id)))
        ])
        .respond_with(status_code(204)),
    );

    let result = client.delete_chat(chat_id).await;

    assert!(result.is_ok(), "Delete chat failed: {:?}", result.err());

    server.verify_and_clear();
}

#[tokio::test]
async fn test_delete_chat_not_found() {
    let (mut server, client) = setup_test_server();
    let chat_id = Uuid::new_v4();
    let error_body = json!({
        "error": {
            "message": format!("Chat session {} not found", chat_id)
        }
    });

    // Set up the correct expectation for the new endpoint following the character router pattern
    // Using explicit /remove/:id pattern to match backend's route to avoid 404 errors
    server.expect(
        Expectation::matching(all_of![
            request::method("DELETE"),
            request::path(matches(format!("/api/chats-api/chats/remove/{}", chat_id)))
        ])
        .respond_with(status_code(404).body(error_body.to_string())),
    );

    let result = client.delete_chat(chat_id).await;

    assert!(result.is_err());
    match result.err().unwrap() {
        CliError::ApiError { status, message } => {
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert!(message.contains(&format!("Chat session {} not found", chat_id)));
        }
        e => panic!("Expected CliError::ApiError with 404, got {:?}", e),
    }

    server.verify_and_clear();
}

// TODO: Add tests for stream_chat_response using a mock server (e.g., httptest or wiremock)
// TODO: Add tests for update_chat_settings
// TODO: Add tests for admin endpoints
