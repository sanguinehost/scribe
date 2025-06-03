use axum::http::StatusCode;
use uuid::Uuid;

use reqwest::header::COOKIE;
use scribe_backend::models::auth::AuthResponse;
use scribe_backend::models::user_personas::{CreateUserPersonaDto, UserPersonaDataForClient}; // Changed UserPersona to UserPersonaDataForClient
use scribe_backend::test_helpers::{TestDataGuard, db, login_user_via_api, spawn_app};

#[tokio::test]
async fn get_me_includes_default_persona_id() {
    let app = spawn_app(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone());

    let username = "testuser_settings";
    let password = "password123";
    let user_db = db::create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .unwrap();
    tdg.add_user(user_db.id);
    let (client, auth_cookie_str) = login_user_via_api(&app, username, password).await;

    // 1. Initially, no default persona
    let response = client
        .get(format!("{}/api/auth/me", app.address))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let auth_response: AuthResponse = response.json().await.unwrap();
    assert_eq!(auth_response.user_id, user_db.id);
    assert!(
        auth_response.default_persona_id.is_none(),
        "Initially, default_persona_id should be None"
    );

    // 2. Create a persona
    let persona_create = CreateUserPersonaDto {
        name: "Test Persona For Default".to_string(),
        description: "A persona for testing default settings".to_string(),
        system_prompt: Some("You are a test persona.".to_string()),
        ..Default::default()
    };
    let response = client
        .post(format!("{}/api/personas", app.address)) // Corrected path to /api/personas
        .json(&persona_create)
        .header(COOKIE, &auth_cookie_str) // Added auth cookie
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created_persona: UserPersonaDataForClient = response.json().await.unwrap(); // Changed to UserPersonaDataForClient
    tdg.add_user_persona(created_persona.id);

    // 3. Set the persona as default
    let response = client
        .put(format!(
            "{}/api/user-settings/set_default_persona/{}", // Corrected path segment
            app.address, created_persona.id
        ))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 4. Get /me again, should include default_persona_id
    let response = client
        .get(format!("{}/api/auth/me", app.address))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let auth_response: AuthResponse = response.json().await.unwrap();
    assert_eq!(auth_response.user_id, user_db.id);
    assert_eq!(
        auth_response.default_persona_id,
        Some(created_persona.id),
        "default_persona_id should be the ID of the set persona"
    );

    // 5. Clear the default persona
    let response = client
        .delete(format!(
            "{}/api/user-settings/clear_default_persona",
            app.address
        )) // Corrected path segment
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // 6. Get /me again, should be None
    let response = client
        .get(format!("{}/api/auth/me", app.address))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let auth_response: AuthResponse = response.json().await.unwrap();
    assert_eq!(auth_response.user_id, user_db.id);
    assert!(
        auth_response.default_persona_id.is_none(),
        "After clearing, default_persona_id should be None"
    );

    tdg.cleanup().await.unwrap();
}

#[tokio::test]
async fn set_default_persona_success() {
    let app = spawn_app(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone());

    let username = "testuser_set_default";
    let password = "password123";
    let user_db = db::create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .unwrap();
    tdg.add_user(user_db.id);
    let (client, auth_cookie_str) = login_user_via_api(&app, username, password).await;

    // Create a persona
    let persona_create = CreateUserPersonaDto {
        name: "Default Candidate Persona".to_string(),
        description: "This persona will be set as default.".to_string(),
        system_prompt: Some("You are a candidate for default.".to_string()),
        ..Default::default()
    };
    let response = client
        .post(format!("{}/api/personas", app.address)) // Corrected path
        .json(&persona_create)
        .header(COOKIE, &auth_cookie_str) // Added auth cookie
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created_persona: UserPersonaDataForClient = response.json().await.unwrap(); // Changed to UserPersonaDataForClient
    tdg.add_user_persona(created_persona.id);

    // Set the persona as default
    let response = client
        .put(format!(
            "{}/api/user-settings/set_default_persona/{}", // Corrected path segment
            app.address, created_persona.id
        ))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // Verify by getting /me
    let response = client
        .get(format!("{}/api/auth/me", app.address))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let auth_response: AuthResponse = response.json().await.unwrap();
    assert_eq!(auth_response.default_persona_id, Some(created_persona.id));

    tdg.cleanup().await.unwrap();
}

#[tokio::test]
async fn clear_default_persona_success() {
    let app = spawn_app(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone());

    let username = "testuser_clear_default";
    let password = "password123";
    let user_db = db::create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .unwrap();
    tdg.add_user(user_db.id);
    let (client, auth_cookie_str) = login_user_via_api(&app, username, password).await;

    // Create and set a persona as default
    let persona_create = CreateUserPersonaDto {
        name: "Default To Be Cleared".to_string(),
        description: "This persona will be cleared as default.".to_string(),
        system_prompt: Some("You are a temporary default.".to_string()),
        ..Default::default()
    };
    let response = client
        .post(format!("{}/api/personas", app.address)) // Corrected path
        .json(&persona_create)
        .header(COOKIE, &auth_cookie_str) // Added auth cookie
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let created_persona: UserPersonaDataForClient = response.json().await.unwrap(); // Changed to UserPersonaDataForClient
    tdg.add_user_persona(created_persona.id);

    client
        .put(format!(
            "{}/api/user-settings/set_default_persona/{}", // Corrected path segment
            app.address, created_persona.id
        ))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    // Sanity check it was set
    let response = client
        .get(format!("{}/api/auth/me", app.address))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    let auth_response: AuthResponse = response.json().await.unwrap();
    assert_eq!(auth_response.default_persona_id, Some(created_persona.id));

    // Clear the default persona
    let response = client
        .delete(format!(
            "{}/api/user-settings/clear_default_persona",
            app.address
        )) // Corrected path segment
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    // Verify by getting /me
    let response = client
        .get(format!("{}/api/auth/me", app.address))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let auth_response: AuthResponse = response.json().await.unwrap();
    assert!(auth_response.default_persona_id.is_none());

    tdg.cleanup().await.unwrap();
}

#[tokio::test]
async fn set_default_persona_not_owned_fails() {
    let app = spawn_app(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone());

    let alice_username = "alice_set_foreign_default";
    let alice_password = "password123";
    let user_alice_db = db::create_test_user(
        &app.db_pool,
        alice_username.to_string(),
        alice_password.to_string(),
    )
    .await
    .unwrap();
    tdg.add_user(user_alice_db.id);
    let (client_alice, alice_auth_cookie_str) =
        login_user_via_api(&app, alice_username, alice_password).await;

    let bob_username = "bob_owns_persona";
    let bob_password = "password123";
    let user_bob_db = db::create_test_user(
        &app.db_pool,
        bob_username.to_string(),
        bob_password.to_string(),
    )
    .await
    .unwrap();
    tdg.add_user(user_bob_db.id);
    let (client_bob, bob_auth_cookie_str) =
        login_user_via_api(&app, bob_username, bob_password).await;

    // Bob creates a persona
    let persona_create_bob = CreateUserPersonaDto {
        name: "Bob's Persona".to_string(),
        description: "Only Bob should be able to set this as default for himself.".to_string(),
        system_prompt: Some("I belong to Bob.".to_string()),
        ..Default::default()
    };
    let response = client_bob
        .post(format!("{}/api/personas", app.address)) // Corrected path
        .json(&persona_create_bob)
        .header(COOKIE, &bob_auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let bobs_persona: UserPersonaDataForClient = response.json().await.unwrap(); // Changed to UserPersonaDataForClient
    tdg.add_user_persona(bobs_persona.id);

    // Alice tries to set Bob's persona as her default
    let response = client_alice
        .put(format!(
            "{}/api/user-settings/set_default_persona/{}", // Corrected path segment
            app.address, bobs_persona.id
        ))
        .header(COOKIE, &alice_auth_cookie_str)
        .send()
        .await
        .unwrap();

    // Expecting 404 Not Found, as the persona_service checks ownership.
    // If it was 403 Forbidden, it would imply the user *could* see it but isn't allowed to set it.
    // But `get_user_persona_by_id_and_user_id` would return NotFound for Alice.
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    // Verify Alice's default_persona_id is still None
    let response = client_alice
        .get(format!("{}/api/auth/me", app.address))
        .header(COOKIE, &alice_auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let auth_response_alice: AuthResponse = response.json().await.unwrap();
    assert!(auth_response_alice.default_persona_id.is_none());

    tdg.cleanup().await.unwrap();
}

#[tokio::test]
async fn set_default_persona_requires_auth() {
    let app = spawn_app(false, false, false).await;
    let tdg = TestDataGuard::new(app.db_pool.clone()); // tdg needed for potential cleanup if test fails early, removed mut
    let unauth_client = reqwest::Client::new();
    let persona_id = Uuid::new_v4(); // Dummy ID, request won't get far

    let response = unauth_client
        .put(format!(
            "{}/api/user-settings/set_default_persona/{}", // Corrected path segment
            app.address, persona_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    tdg.cleanup().await.unwrap(); // Ensure cleanup even if test logic changes
}

#[tokio::test]
async fn clear_default_persona_requires_auth() {
    let app = spawn_app(false, false, false).await;
    let tdg = TestDataGuard::new(app.db_pool.clone()); // Removed mut
    let unauth_client = reqwest::Client::new();

    let response = unauth_client
        .delete(format!(
            "{}/api/user-settings/clear_default_persona",
            app.address
        )) // Corrected path segment
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    tdg.cleanup().await.unwrap();
}

// Additional tests for setting and clearing default persona will go here

#[tokio::test]
async fn change_default_persona_success() {
    let app = spawn_app(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone());

    let username = "testuser_change_default";
    let password = "password123";
    let user_db = db::create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .unwrap();
    tdg.add_user(user_db.id);
    let (client, auth_cookie_str) = login_user_via_api(&app, username, password).await;

    // 1. Create Persona A
    let first_persona_create = CreateUserPersonaDto {
        name: "Persona A - Initial Default".to_string(),
        description: "This is Persona A.".to_string(),
        system_prompt: Some("I am Persona A.".to_string()),
        ..Default::default()
    };
    let response_a = client
        .post(format!("{}/api/personas", app.address)) // Corrected path
        .json(&first_persona_create)
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(response_a.status(), StatusCode::CREATED);
    let persona_a: UserPersonaDataForClient = response_a.json().await.unwrap(); // Changed to UserPersonaDataForClient
    tdg.add_user_persona(persona_a.id);

    // 2. Create Persona B
    let second_persona_create = CreateUserPersonaDto {
        name: "Persona B - New Default".to_string(),
        description: "This is Persona B.".to_string(),
        system_prompt: Some("I am Persona B.".to_string()),
        ..Default::default()
    };
    let response_b = client
        .post(format!("{}/api/personas", app.address)) // Corrected path
        .json(&second_persona_create)
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(response_b.status(), StatusCode::CREATED);
    let persona_b: UserPersonaDataForClient = response_b.json().await.unwrap(); // Changed to UserPersonaDataForClient
    tdg.add_user_persona(persona_b.id);

    // 3. Set Persona A as default
    let set_a_response = client
        .put(format!(
            "{}/api/user-settings/set_default_persona/{}", // Corrected path segment
            app.address, persona_a.id
        ))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(set_a_response.status(), StatusCode::OK);

    // 4. Verify Persona A is default
    let get_me_response_1 = client
        .get(format!("{}/api/auth/me", app.address))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(get_me_response_1.status(), StatusCode::OK);
    let auth_response_1: AuthResponse = get_me_response_1.json().await.unwrap();
    assert_eq!(
        auth_response_1.default_persona_id,
        Some(persona_a.id),
        "Persona A should be the default."
    );

    // 5. Set Persona B as default (changing from A to B)
    let set_b_response = client
        .put(format!(
            "{}/api/user-settings/set_default_persona/{}", // Corrected path segment
            app.address, persona_b.id
        ))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(set_b_response.status(), StatusCode::OK);

    // 6. Verify Persona B is now default
    let get_me_response_2 = client
        .get(format!("{}/api/auth/me", app.address))
        .header(COOKIE, &auth_cookie_str)
        .send()
        .await
        .unwrap();
    assert_eq!(get_me_response_2.status(), StatusCode::OK);
    let auth_response_2: AuthResponse = get_me_response_2.json().await.unwrap();
    assert_eq!(
        auth_response_2.default_persona_id,
        Some(persona_b.id),
        "Persona B should now be the default."
    );

    tdg.cleanup().await.unwrap();
}
