#[cfg(test)]
mod chat_overrides_api_tests {
    use scribe_backend::test_helpers::{self, TestApp, TestDataGuard};
    use scribe_backend::models::chat_override::CharacterOverrideDto;
    use scribe_backend::models::chats::Chat as ChatSession; // Renamed to avoid conflict with Character field
    use scribe_backend::models::characters::Character;
    use scribe_backend::models::users::User;
    use uuid::Uuid;
    use reqwest::StatusCode as ReqwestStatusCode; // Using reqwest for actual http client
    
     // for `oneshot`
    use serde_json::json;
     // for `collect`

    // Helper to create a chat session via API
    async fn create_chat_session_via_api(test_app: &TestApp, _user_id: Uuid, character_id: Uuid, auth_cookie: &str) -> ChatSession {
        let request_body = json!({ "character_id": character_id });

        let client = reqwest::Client::builder()
            .cookie_store(true) 
            .build()
            .expect("Failed to build reqwest client for create_chat_session_via_api");

        let request_url = format!("{}/api/chat/create_session", test_app.address);

        let response = client
            .post(&request_url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header(reqwest::header::COOKIE, auth_cookie)
            .json(&request_body)
            .send()
            .await
            .expect("Failed to send create_session request");
        
        let response_status = response.status();
        let response_body_bytes = response.bytes().await.expect("Failed to get response bytes for create_session");

        if response_status != ReqwestStatusCode::CREATED {
            let body_text = String::from_utf8_lossy(&response_body_bytes);
            panic!("Failed to create chat session via API for test setup. URL: {}. Status: {}. Body: {}", 
                    request_url, response_status, body_text);
        }
        
        serde_json::from_slice(&response_body_bytes).expect("Failed to deserialize chat session from API response")
    }


    async fn setup_test_environment(test_app: &TestApp) -> (TestDataGuard, User, Character, ChatSession, String) {
        let mut guard = TestDataGuard::new(test_app.db_pool.clone());
        let username = "override_user";
        let password = "override_password123";

        let user = test_helpers::db::create_test_user(&test_app.db_pool, username.to_string(), password.to_string()).await.unwrap();
        guard.add_user(user.id);
        
        let (_client, session_cookie_str) = test_helpers::login_user_via_api(test_app, username, password).await;

        let character = test_helpers::db::create_test_character(&test_app.db_pool, user.id, "Override Test Char".to_string()).await.unwrap();
        guard.add_character(character.id);

        let chat_session = create_chat_session_via_api(test_app, user.id, character.id, &session_cookie_str).await;
        guard.add_chat(chat_session.id); // Use add_chat

        (guard, user, character, chat_session, session_cookie_str)
    }

    #[tokio::test]
    async fn test_create_new_override_success() {
        let test_app = test_helpers::spawn_app(true, true, true).await;
        let (_guard, _user, _character, chat_session, session_cookie_str) = setup_test_environment(&test_app).await;

        let override_dto = CharacterOverrideDto {
            field_name: "description".to_string(),
            value: "This is a chat-specific description.".to_string(),
        };

        // Using reqwest client for this specific test to interact with the running app
        let client = reqwest::Client::builder()
            .cookie_store(true) // To handle session cookies if needed, though we pass it explicitly
            .build().unwrap();

        let request_url = format!(
            "{}/api/chats/{}/character/overrides", // Align with CLI and backend route
            test_app.address,
            chat_session.id
        );

        let response = client
            .post(&request_url)
            .header("Cookie", &session_cookie_str) // Pass the session cookie from login
            .json(&override_dto)
            .send()
            .await
            .expect("Failed to execute request.");

        assert_eq!(response.status(), ReqwestStatusCode::OK); 

        let override_response: serde_json::Value = response.json().await.expect("Failed to parse json response");
        assert_eq!(override_response["field_name"].as_str().unwrap(), "description");
        assert!(override_response["id"].as_str().is_some());
        assert_eq!(override_response["chat_session_id"].as_str().unwrap(), chat_session.id.to_string());
        assert_eq!(override_response["original_character_id"].as_str().unwrap(), _character.id.to_string());

        // TODO: Verify in DB that the override was created and encrypted correctly.
        // This would require fetching the override and decrypting it using the user's DEK.
        // The DEK is not currently returned by login_user_via_api, so this is a future improvement.
    }

    #[tokio::test]
    async fn test_update_existing_override_success() {
        let test_app = test_helpers::spawn_app(true, true, true).await;
        let (_guard, _user, character, chat_session, session_cookie_str) = setup_test_environment(&test_app).await;

        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build().unwrap();

        let initial_override_dto = CharacterOverrideDto {
            field_name: "description".to_string(),
            value: "Initial chat-specific description.".to_string(),
        };

        let request_url = format!(
            "{}/api/chats/{}/character/overrides", // Align with CLI and backend route
            test_app.address,
            chat_session.id
        );

        // 1. Create the initial override
        let response1 = client
            .post(&request_url)
            .header("Cookie", &session_cookie_str)
            .json(&initial_override_dto)
            .send()
            .await
            .expect("Failed to execute initial override request.");

        assert_eq!(response1.status(), ReqwestStatusCode::OK, "Initial override creation failed");
        let created_override: serde_json::Value = response1.json().await.expect("Failed to parse initial override response");
        let created_at_initial = created_override["created_at"].as_str().expect("created_at not found or not a string").to_string();
        let updated_at_initial = created_override["updated_at"].as_str().expect("updated_at not found or not a string").to_string();


        // Introduce a small delay to ensure updated_at will be different
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // 2. Update the override
        let updated_override_dto = CharacterOverrideDto {
            field_name: "description".to_string(), // Same field
            value: "UPDATED chat-specific description.".to_string(), // New value
        };

        let response2 = client
            .post(&request_url) // Same URL for upsert
            .header("Cookie", &session_cookie_str)
            .json(&updated_override_dto)
            .send()
            .await
            .expect("Failed to execute update override request.");

        assert_eq!(response2.status(), ReqwestStatusCode::OK, "Override update failed");
        
        let updated_override_response: serde_json::Value = response2.json().await.expect("Failed to parse updated override response");

        assert_eq!(updated_override_response["field_name"].as_str().unwrap(), "description");
        assert_eq!(updated_override_response["id"].as_str().unwrap(), created_override["id"].as_str().unwrap(), "ID should be the same on update");
        assert_eq!(updated_override_response["chat_session_id"].as_str().unwrap(), chat_session.id.to_string());
        assert_eq!(updated_override_response["original_character_id"].as_str().unwrap(), character.id.to_string());
        
        // Assertions for update
        assert_eq!(updated_override_response["created_at"].as_str().unwrap(), created_at_initial, "created_at should not change on update");
        assert_ne!(updated_override_response["updated_at"].as_str().unwrap(), updated_at_initial, "updated_at should change on update");
        
        // We can't directly check the updated value here as it's encrypted in the response.
        // A more thorough test would fetch the character, apply overrides, and check the effective value.
        // Or, fetch the override from DB and decrypt, if DEK was available.
    }

    #[tokio::test]
    async fn test_create_override_for_non_existent_chat_session() {
        let test_app = test_helpers::spawn_app(true, true, true).await;
        let (_guard, _user, _character, _chat_session, session_cookie_str) = setup_test_environment(&test_app).await;

        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build().unwrap();

        let non_existent_session_id = Uuid::new_v4();

        let override_dto = CharacterOverrideDto {
            field_name: "description".to_string(),
            value: "Override for non-existent session.".to_string(),
        };

        let request_url = format!(
            "{}/api/chats/{}/character/overrides", // Align with CLI and backend route
            test_app.address,
            non_existent_session_id // Use the fake ID
        );

        let response = client
            .post(&request_url)
            .header("Cookie", &session_cookie_str)
            .json(&override_dto)
            .send()
            .await
            .expect("Failed to execute request for non-existent session.");

        assert_eq!(response.status(), ReqwestStatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_create_override_for_unowned_chat_session() {
        let test_app = test_helpers::spawn_app(true, true, true).await;
        let mut guard = TestDataGuard::new(test_app.db_pool.clone());

        // User A: Owner of the chat session
        let user_a_username = "user_a_owner";
        let user_a_password = "password123A";
        let user_a = test_helpers::db::create_test_user(&test_app.db_pool, user_a_username.to_string(), user_a_password.to_string()).await.unwrap();
        guard.add_user(user_a.id);
        let (_client_a, user_a_cookie_str) = test_helpers::login_user_via_api(&test_app, user_a_username, user_a_password).await;
        let character_a = test_helpers::db::create_test_character(&test_app.db_pool, user_a.id, "UserA Char".to_string()).await.unwrap();
        guard.add_character(character_a.id);
        let chat_session_a = create_chat_session_via_api(&test_app, user_a.id, character_a.id, &user_a_cookie_str).await;
        guard.add_chat(chat_session_a.id);

        // User B: The one trying to make an unauthorized edit
        let user_b_username = "user_b_other";
        let user_b_password = "password123B";
        let user_b = test_helpers::db::create_test_user(&test_app.db_pool, user_b_username.to_string(), user_b_password.to_string()).await.unwrap();
        guard.add_user(user_b.id);
        let (_client_b, user_b_cookie_str) = test_helpers::login_user_via_api(&test_app, user_b_username, user_b_password).await;

        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build().unwrap();

        let override_dto = CharacterOverrideDto {
            field_name: "description".to_string(),
            value: "Attempted override by wrong user.".to_string(),
        };

        let request_url = format!(
            "{}/api/chats/{}/character/overrides", // Align with CLI and backend route
            test_app.address,
            chat_session_a.id // User B targets User A's session
        );

        let response = client
            .post(&request_url)
            .header("Cookie", &user_b_cookie_str) // Authenticated as User B
            .json(&override_dto)
            .send()
            .await
            .expect("Failed to execute request for unowned session.");

        assert_eq!(response.status(), ReqwestStatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_create_override_empty_value() {
        let test_app = test_helpers::spawn_app(true, true, true).await;
        let (_guard, _user, _character, chat_session, session_cookie_str) = setup_test_environment(&test_app).await;

        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build().unwrap();

        let override_dto = CharacterOverrideDto {
            field_name: "description".to_string(),
            value: "".to_string(), // Empty value
        };

        let request_url = format!(
            "{}/api/chats/{}/character/overrides", // Align with CLI and backend route
            test_app.address,
            chat_session.id
        );

        let response = client
            .post(&request_url)
            .header("Cookie", &session_cookie_str)
            .json(&override_dto)
            .send()
            .await
            .expect("Failed to execute request with empty value.");

        // Assuming CharacterOverrideDto has #[validate(length(min = 1))] on `value`
        assert_eq!(response.status(), ReqwestStatusCode::UNPROCESSABLE_ENTITY);

        let error_response: serde_json::Value = response.json().await.unwrap();
        assert!(error_response["error"].as_str().unwrap().contains("Validation error"));
        assert!(error_response["error_details"]["value"][0]["code"].as_str().unwrap().contains("length"));
    }

    #[tokio::test]
    async fn test_create_override_invalid_field_name() {
        let test_app = test_helpers::spawn_app(true, true, true).await;
        let (_guard, _user, _character, chat_session, session_cookie_str) = setup_test_environment(&test_app).await;

        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build().unwrap();

        let override_dto = CharacterOverrideDto {
            field_name: "".to_string(), // Empty field_name
            value: "Some value".to_string(),
        };

        let request_url = format!(
            "{}/api/chats/{}/character/overrides", // Align with CLI and backend route
            test_app.address,
            chat_session.id
        );

        let response = client
            .post(&request_url)
            .header("Cookie", &session_cookie_str)
            .json(&override_dto)
            .send()
            .await
            .expect("Failed to execute request with empty field_name.");

        assert_eq!(response.status(), ReqwestStatusCode::UNPROCESSABLE_ENTITY);

        let error_response: serde_json::Value = response.json().await.unwrap();
        assert!(error_response["error"].as_str().unwrap().contains("Validation error"));
        // Check that the error is for the 'field_name' field
        assert!(error_response["error_details"]["field_name"][0]["code"].as_str().unwrap().contains("length"));
    }

    #[tokio::test]
    async fn test_create_override_response_has_message_field() {
        let test_app = test_helpers::spawn_app(true, true, true).await;
        let (_guard, _user, _character, chat_session, session_cookie_str) = setup_test_environment(&test_app).await;

        let override_dto = CharacterOverrideDto {
            field_name: "description".to_string(),
            value: "This is a test override description.".to_string(),
        };

        let client = reqwest::Client::builder()
            .cookie_store(true)
            .build().unwrap();

        let request_url = format!(
            "{}/api/chats/{}/character/overrides",
            test_app.address,
            chat_session.id
        );

        let response = client
            .post(&request_url)
            .header("Cookie", &session_cookie_str)
            .json(&override_dto)
            .send()
            .await
            .expect("Failed to execute request.");

        assert_eq!(response.status(), ReqwestStatusCode::OK);

        // Parse the response as JSON value to check fields
        let response_json: serde_json::Value = response.json().await.expect("Failed to parse response as JSON");
        
        // The test that would fail currently - the response doesn't have a "message" field
        assert!(response_json.get("message").is_some(), "Response should include a 'message' field");
        
        // Check other expected fields
        assert!(response_json.get("field_name").is_some(), "Response should include a 'field_name' field");
        assert!(response_json.get("session_id").is_some() || response_json.get("chat_session_id").is_some(), 
                "Response should include 'session_id' or 'chat_session_id'");
    }

} 