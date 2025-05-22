// backend/tests/user_persona_api_tests.rs

use scribe_backend::models::user_personas::{
    CreateUserPersonaDto, UpdateUserPersonaDto, UserPersonaDataForClient,
};
use scribe_backend::test_helpers::{
    db::create_test_user, login_user_via_api, spawn_app,
};
use reqwest; // For making HTTP calls
use uuid::Uuid;
// serde_json::json is not used

// Helper to create a default CreateUserPersonaDto
fn default_create_dto() -> CreateUserPersonaDto {
    CreateUserPersonaDto {
        name: "Test Persona".to_string(),
        description: "A persona for testing purposes.".to_string(),
        spec: Some("user_persona_spec_v1".to_string()),
        spec_version: Some("1.0.0".to_string()),
        personality: Some("Curious and inquisitive.".to_string()),
        scenario: Some("Exploring new APIs.".to_string()),
        first_mes: Some("Hello there!".to_string()),
        mes_example: Some("User: How does this work?\nAI: Like this!".to_string()),
        system_prompt: Some("You are a helpful assistant.".to_string()),
        post_history_instructions: Some("Summarize the key points.".to_string()),
        tags: Some(vec![Some("test".to_string()), Some("api".to_string())]), // Corrected tags
        avatar: Some("avatar_url_or_data".to_string()),
    }
}

#[tokio::test]
async fn create_user_persona_success() {
    let app = spawn_app(false, false, false).await;
    let client = reqwest::Client::new();
    let username = "testuser_create_persona";
    let password = "Password123!";

    // Create user directly in DB
    let _user = create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .expect("Failed to create test user");

    // Login via API to get session cookie
    let auth_cookie = login_user_via_api(&app, username, password).await;

    let create_dto = default_create_dto();

    let response = client
        .post(&format!("{}/api/personas", &app.address))
        .header("Cookie", auth_cookie) // Use cookie for auth
        .json(&create_dto)
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status().as_u16(), 201, "Expected 201 Created");

    let created_persona: UserPersonaDataForClient = response
        .json()
        .await
        .expect("Failed to parse JSON response");

    assert_eq!(created_persona.name, create_dto.name);
    assert_eq!(created_persona.description, create_dto.description);
    assert_eq!(created_persona.personality, create_dto.personality);
    // Add more assertions for other fields as needed
}

#[tokio::test]
async fn create_user_persona_unauthorized() {
    let app = spawn_app(false, false, false).await;
    let client = reqwest::Client::new();
    let create_dto = default_create_dto();

    let response = client
        .post(&format!("{}/api/personas", &app.address))
        // No auth token
        .json(&create_dto)
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status().as_u16(), 401, "Expected 401 Unauthorized");
}

#[tokio::test]
async fn list_user_personas_success() {
    let app = spawn_app(false, false, false).await;
    let client = reqwest::Client::new();
    let username = "testuser_list_personas";
    let password = "Password123!";

    let _user = create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .expect("Failed to create test user");
    let auth_cookie = login_user_via_api(&app, username, password).await;

    // Create a persona first
    let create_dto = default_create_dto();
    client
        .post(&format!("{}/api/personas", &app.address))
        .header("Cookie", auth_cookie.clone())
        .json(&create_dto)
        .send()
        .await
        .expect("Failed to create persona for listing test.");

    let response = client
        .get(&format!("{}/api/personas", &app.address))
        .header("Cookie", auth_cookie)
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status().as_u16(), 200, "Expected 200 OK");

    let personas: Vec<UserPersonaDataForClient> = response
        .json()
        .await
        .expect("Failed to parse JSON response");

    assert!(!personas.is_empty(), "Expected at least one persona");
    assert_eq!(personas[0].name, create_dto.name);
}

#[tokio::test]
async fn get_user_persona_success() {
    let app = spawn_app(false, false, false).await;
    let client = reqwest::Client::new();
    let username = "testuser_get_persona";
    let password = "Password123!";

    let _user = create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .expect("Failed to create test user");
    let auth_cookie = login_user_via_api(&app, username, password).await;

    let create_dto = default_create_dto();
    let create_response = client
        .post(&format!("{}/api/personas", &app.address))
        .header("Cookie", auth_cookie.clone())
        .json(&create_dto)
        .send()
        .await
        .expect("Failed to create persona for get test.");
    let created_persona: UserPersonaDataForClient = create_response
        .json()
        .await
        .expect("Failed to parse created persona");
    let persona_id = created_persona.id;

    let response = client
        .get(&format!(
            "{}/api/personas/fetch/{}",
            &app.address, persona_id
        ))
        .header("Cookie", auth_cookie)
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status().as_u16(), 200, "Expected 200 OK");
    let fetched_persona: UserPersonaDataForClient = response
        .json()
        .await
        .expect("Failed to parse JSON response");
    assert_eq!(fetched_persona.id, persona_id);
    assert_eq!(fetched_persona.name, create_dto.name);
}

#[tokio::test]
async fn get_user_persona_not_found() {
    let app = spawn_app(false, false, false).await;
    let client = reqwest::Client::new();
    let username = "testuser_get_persona_nf";
    let password = "Password123!";

    let _user = create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .expect("Failed to create test user");
    let auth_cookie = login_user_via_api(&app, username, password).await;
    let non_existent_id = Uuid::new_v4();

    let response = client
        .get(&format!(
            "{}/api/personas/fetch/{}",
            &app.address, non_existent_id
        ))
        .header("Cookie", auth_cookie)
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status().as_u16(), 404, "Expected 404 Not Found");
}

#[tokio::test]
async fn get_user_persona_forbidden() {
    let app = spawn_app(false, false, false).await;
    let client = reqwest::Client::new();
    let username1 = "testuser_get_forbidden1";
    let password = "Password123!";
    let username2 = "testuser_get_forbidden2";

    let _user1 = create_test_user(&app.db_pool, username1.to_string(), password.to_string())
        .await
        .expect("Failed to create user1");
    let auth_cookie1 = login_user_via_api(&app, username1, password).await;

    let _user2 = create_test_user(&app.db_pool, username2.to_string(), password.to_string())
        .await
        .expect("Failed to create user2");
    let auth_cookie2 = login_user_via_api(&app, username2, password).await;

    // User1 creates a persona
    let create_dto = default_create_dto();
    let create_response = client
        .post(&format!("{}/api/personas", &app.address))
        .header("Cookie", auth_cookie1.clone())
        .json(&create_dto)
        .send()
        .await
        .expect("Failed to create persona for user1.");
    let created_persona: UserPersonaDataForClient = create_response
        .json()
        .await
        .expect("Failed to parse created persona");
    let persona_id_user1 = created_persona.id;

    // User2 tries to get User1's persona
    let response = client
        .get(&format!(
            "{}/api/personas/fetch/{}",
            &app.address, persona_id_user1
        ))
        .header("Cookie", auth_cookie2) // Authenticated as User2
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status().as_u16(), 403, "Expected 403 Forbidden");
}


#[tokio::test]
async fn update_user_persona_success() {
    let app = spawn_app(false, false, false).await;
    let client = reqwest::Client::new();
    let username = "testuser_update_persona";
    let password = "Password123!";

    let _user = create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .expect("Failed to create test user");
    let auth_cookie = login_user_via_api(&app, username, password).await;

    let create_dto = default_create_dto();
    let create_response = client
        .post(&format!("{}/api/personas", &app.address))
        .header("Cookie", auth_cookie.clone())
        .json(&create_dto)
        .send()
        .await
        .expect("Failed to create persona for update test.");
    let created_persona: UserPersonaDataForClient = create_response
        .json()
        .await
        .expect("Failed to parse created persona");
    let persona_id = created_persona.id;

    let update_dto = UpdateUserPersonaDto {
        name: Some("Updated Persona Name".to_string()),
        description: Some("Updated description.".to_string()),
        personality: None, // Test clearing a field
        scenario: Some("Updated scenario.".to_string()),
        first_mes: None,
        mes_example: None,
        system_prompt: None,
        post_history_instructions: None,
        tags: Some(vec![Some("updated".to_string())]), // Corrected tags
        avatar: None,
        spec: None,
        spec_version: None,
    };

    let response = client
        .put(&format!("{}/api/personas/{}", &app.address, persona_id))
        .header("Cookie", auth_cookie)
        .json(&update_dto)
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status().as_u16(), 200, "Expected 200 OK");
    let updated_persona: UserPersonaDataForClient = response
        .json()
        .await
        .expect("Failed to parse JSON response");

    assert_eq!(updated_persona.id, persona_id);
    assert_eq!(updated_persona.name, update_dto.name.unwrap());
    assert_eq!(updated_persona.description, update_dto.description.unwrap());
    assert!(updated_persona.personality.is_none(), "Personality should be cleared");
    assert_eq!(updated_persona.scenario, update_dto.scenario);
}

#[tokio::test]
async fn delete_user_persona_success() {
    let app = spawn_app(false, false, false).await;
    let client = reqwest::Client::new();
    let username = "testuser_delete_persona";
    let password = "Password123!";

    let _user = create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .expect("Failed to create test user");
    let auth_cookie = login_user_via_api(&app, username, password).await;

    let create_dto = default_create_dto();
    let create_response = client
        .post(&format!("{}/api/personas", &app.address))
        .header("Cookie", auth_cookie.clone())
        .json(&create_dto)
        .send()
        .await
        .expect("Failed to create persona for delete test.");
    let created_persona: UserPersonaDataForClient = create_response
        .json()
        .await
        .expect("Failed to parse created persona");
    let persona_id = created_persona.id;

    let response = client
        .delete(&format!(
            "{}/api/personas/remove/{}",
            &app.address, persona_id
        ))
        .header("Cookie", auth_cookie.clone())
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status().as_u16(), 204, "Expected 204 No Content");

    // Verify it's actually deleted
    let get_response = client
        .get(&format!(
            "{}/api/personas/fetch/{}",
            &app.address, persona_id
        ))
        .header("Cookie", auth_cookie)
        .send()
        .await
        .expect("Failed to execute get request after delete.");
    assert_eq!(get_response.status().as_u16(), 404, "Expected 404 Not Found after delete");
}

#[tokio::test]
async fn delete_user_persona_forbidden() {
    let app = spawn_app(false, false, false).await;
    let client = reqwest::Client::new();
    let username1 = "testuser_delete_forbidden1";
    let password = "Password123!";
    let username2 = "testuser_delete_forbidden2";

    let _user1 = create_test_user(&app.db_pool, username1.to_string(), password.to_string())
        .await
        .expect("Failed to create user1");
    let auth_cookie1 = login_user_via_api(&app, username1, password).await;

    let _user2 = create_test_user(&app.db_pool, username2.to_string(), password.to_string())
        .await
        .expect("Failed to create user2");
    let auth_cookie2 = login_user_via_api(&app, username2, password).await;

    // User1 creates a persona
    let create_dto = default_create_dto();
    let create_response = client
        .post(&format!("{}/api/personas", &app.address))
        .header("Cookie", auth_cookie1.clone())
        .json(&create_dto)
        .send()
        .await
        .expect("Failed to create persona for user1.");
    let created_persona: UserPersonaDataForClient = create_response
        .json()
        .await
        .expect("Failed to parse created persona");
    let persona_id_user1 = created_persona.id;

    // User2 tries to delete User1's persona
    let response = client
        .delete(&format!(
            "{}/api/personas/remove/{}",
            &app.address, persona_id_user1
        ))
        .header("Cookie", auth_cookie2) // Authenticated as User2
        .send()
        .await
        .expect("Failed to execute request.");

    assert_eq!(response.status().as_u16(), 403, "Expected 403 Forbidden");
}

// TODO: Add more tests:
// - Validation errors for create/update (e.g., missing required fields like name/description)
// - Test encryption/decryption:
//   - Create a persona, fetch it, verify decrypted fields match.
//   - List personas, verify decrypted fields.
// - Test behavior with empty optional fields in DTOs.
// - Test updating only specific fields.
// - Test clearing optional fields by sending `None` or omitting them in update DTO.
