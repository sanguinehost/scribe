#![allow(clippy::unwrap_used)]
use std::sync::Arc;
use secrecy::ExposeSecret; // Added import

use diesel::prelude::*;
use secrecy::SecretBox;
use uuid::Uuid;
use reqwest::header::COOKIE; // Added

use scribe_backend::{
    models::{
        // characters::Character, // Character is used from test_helpers::db or directly via schema
        user_personas::{UserPersonaDataForClient, CreateUserPersonaDto}, // Changed UserPersona to UserPersonaDataForClient
        users::{User, UserDbQuery},
    },
    schema::{self, chat_sessions, user_personas, users, characters}, // Added schema::characters
    services::chat_service,
    state::AppState, // Added
    test_helpers::{spawn_app, TestDataGuard, db, login_user_via_api, TestAppStateBuilder}, // Changed TestUser
};

#[tokio::test]
async fn create_session_uses_default_persona_when_active_persona_is_none() {
    let app = spawn_app(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone());

    let username = "user_with_default_persona";
    let password = "password123";
    let user_db = db::create_test_user(&app.db_pool, username.to_string(), password.to_string()).await.unwrap();
    tdg.add_user(user_db.id);
    let auth_cookie = login_user_via_api(&app, username, password).await;
    let client = reqwest::Client::new();

    // 1. Create a character for the user
    let character_name = "Test Character for Default Persona";
    let character_system_prompt_val = "Character's original system prompt".to_string();
    let mut character = db::create_test_character(&app.db_pool, user_db.id, character_name.to_string()).await.unwrap();
    tdg.add_character(character.id);

    // Manually update character's system prompt as db::create_test_character doesn't set it.
    // This requires the character's DEK which is not readily available here.
    // For this test, we'll assume the character's system_prompt is not encrypted or use a placeholder.
    // OR, modify create_test_character to accept and encrypt it.
    // For now, let's assume the test logic will fetch the character again and its prompt will be None or default.
    // If the test *relies* on this specific prompt, this part needs more work.
    // Given the test asserts against persona_system_prompt, character's prompt might not be critical here.
    // However, if default persona is NOT found, it falls back to character's prompt.
    // Let's update it directly in the DB (unencrypted for simplicity in test setup, or use placeholder if encrypted)
    let char_id_for_update = character.id;
    let character_prompt_bytes = Some(character_system_prompt_val.as_bytes().to_vec());
    app.db_pool.get().await.unwrap().interact(move |conn| {
        diesel::update(characters::table.find(char_id_for_update))
            .set(characters::system_prompt.eq(character_prompt_bytes))
            .execute(conn)
    }).await.unwrap().unwrap();
    // Re-fetch character to have the updated prompt if needed by later logic, though this test focuses on persona.
    character = app.db_pool.get().await.unwrap().interact(move |conn| {
        characters::table.find(char_id_for_update).first::<scribe_backend::models::characters::Character>(conn)
    }).await.unwrap().unwrap();


    // 2. Create a persona for the user
    let persona_name = "My Default Test Persona".to_string();
    let persona_system_prompt = "You are the default test persona.".to_string();
    let persona_create = CreateUserPersonaDto {
        name: persona_name.clone(),
        description: "This is my default persona.".to_string(),
        system_prompt: Some(persona_system_prompt.clone()),
        ..Default::default()
    };

    let response = client
        .post(format!("{}/api/personas", app.address)) // Corrected path
        .json(&persona_create)
        .header(COOKIE, &auth_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::CREATED);
    let created_persona: UserPersonaDataForClient = response.json().await.unwrap();
    tdg.add_user_persona(created_persona.id);

    // 3. Set this persona as the user's default via API
    let response = client
        .put(format!(
            "{}/api/user-settings/set_default_persona/{}",
            app.address, created_persona.id
        ))
        .header(COOKIE, &auth_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);

    // Verify user's default_persona_id is set in DB
    let user_id_clone = user_db.id;
    let db_user_check: User = app
        .db_pool // Use app.db_pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            users::table
                .filter(users::id.eq(user_id_clone))
                .select(UserDbQuery::as_select())
                .first(conn)
                .map(User::from) // Convert UserDbQuery to User
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(db_user_check.default_persona_id, Some(created_persona.id));

    // 4. Call create_session_and_maybe_first_message with active_custom_persona_id = None
    let user_dek_secret_box: Option<Arc<SecretBox<Vec<u8>>>> = user_db.dek.as_ref().map(|user_dek_struct| Arc::new(SecretBox::new(Box::new(user_dek_struct.0.expose_secret().clone()))));
    
    let app_state_for_service = TestAppStateBuilder::new(
        app.db_pool.clone(),
        app.config.clone(),
        app.ai_client.clone(),
        app.mock_embedding_client.clone(),
        app.qdrant_service.clone(),
    )
    .with_embedding_pipeline_service(app.mock_embedding_pipeline_service.clone())
    .build();
    let app_state_arc = Arc::new(app_state_for_service);

    let created_chat_session = chat_service::create_session_and_maybe_first_message(
        app_state_arc, // Use constructed AppState
        user_db.id,
        character.id,
        None, // active_custom_persona_id is None
        user_dek_secret_box,
    )
    .await
    .unwrap();
    tdg.add_chat(created_chat_session.id);


    // 5. Verify the chat session
    assert_eq!(
        created_chat_session.active_custom_persona_id,
        Some(created_persona.id),
        "Chat session should use the user's default persona ID"
    );

    assert_eq!(
        created_chat_session.system_prompt.as_deref(),
        Some(persona_system_prompt.as_str()),
        "Chat session system prompt should match the default persona's system prompt"
    );
    tdg.cleanup().await.unwrap();
}

#[tokio::test]
async fn create_session_no_default_persona_falls_back_to_character_prompt() {
    let app = spawn_app(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone());

    let username = "user_no_default_persona";
    let password = "password123";
    let user_db = db::create_test_user(&app.db_pool, username.to_string(), password.to_string()).await.unwrap();
    tdg.add_user(user_db.id);
    // No API client needed for this test as it directly calls the service

    // 1. Create a character for the user with a specific system prompt
    let character_system_prompt_val = "You are the character's original prompt.".to_string();
    let mut character = db::create_test_character(&app.db_pool, user_db.id, "Character For No Default Test".to_string()).await.unwrap();
    tdg.add_character(character.id);
    
    let char_id_for_update = character.id;
    let character_prompt_bytes = Some(character_system_prompt_val.as_bytes().to_vec());
    app.db_pool.get().await.unwrap().interact(move |conn| {
        diesel::update(characters::table.find(char_id_for_update))
            .set(characters::system_prompt.eq(character_prompt_bytes))
            .execute(conn)
    }).await.unwrap().unwrap();
    character = app.db_pool.get().await.unwrap().interact(move |conn| {
        characters::table.find(char_id_for_update).first::<scribe_backend::models::characters::Character>(conn)
    }).await.unwrap().unwrap();


    // 2. Ensure user has no default persona
    let user_id_clone = user_db.id;
    let db_user_check: User = app
        .db_pool // Use app.db_pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            users::table
                .filter(users::id.eq(user_id_clone))
                .select(UserDbQuery::as_select())
                .first(conn)
                .map(User::from)
        })
        .await
        .unwrap()
        .unwrap();
    assert!(db_user_check.default_persona_id.is_none());

    // 3. Call create_session_and_maybe_first_message with active_custom_persona_id = None
    let user_dek_secret_box: Option<Arc<SecretBox<Vec<u8>>>> = user_db.dek.as_ref().map(|user_dek_struct| Arc::new(SecretBox::new(Box::new(user_dek_struct.0.expose_secret().clone()))));

    let app_state_for_service = TestAppStateBuilder::new(
        app.db_pool.clone(),
        app.config.clone(),
        app.ai_client.clone(),
        app.mock_embedding_client.clone(),
        app.qdrant_service.clone(),
    )
    .with_embedding_pipeline_service(app.mock_embedding_pipeline_service.clone())
    .build();
    let app_state_arc = Arc::new(app_state_for_service);

    let created_chat_session = chat_service::create_session_and_maybe_first_message(
        app_state_arc,
        user_db.id,
        character.id,
        None, // active_custom_persona_id is None
        user_dek_secret_box,
    )
    .await
    .unwrap();
    tdg.add_chat(created_chat_session.id);

    // 4. Verify the chat session
    assert!(
        created_chat_session.active_custom_persona_id.is_none(),
        "Chat session should have no active_custom_persona_id"
    );

    assert_eq!(
        created_chat_session.system_prompt.as_deref(),
        Some(character_system_prompt_val.as_str()),
        "Chat session system prompt should match the character's system prompt"
    );
    tdg.cleanup().await.unwrap();
}

#[tokio::test]
async fn create_session_default_persona_deleted_falls_back_to_character_prompt() {
    let app = spawn_app(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone());

    let username = "user_deleted_default_persona";
    let password = "password123";
    let user_db = db::create_test_user(&app.db_pool, username.to_string(), password.to_string()).await.unwrap();
    tdg.add_user(user_db.id);
    let auth_cookie = login_user_via_api(&app, username, password).await;
    let client = reqwest::Client::new();


    // 1. Create a character
    let character_system_prompt_val = "Character prompt for deleted persona test.".to_string();
    let mut character = db::create_test_character(&app.db_pool, user_db.id, "Char For Deleted Persona Test".to_string()).await.unwrap();
    tdg.add_character(character.id);

    let char_id_for_update = character.id;
    let character_prompt_bytes = Some(character_system_prompt_val.as_bytes().to_vec());
     app.db_pool.get().await.unwrap().interact(move |conn| {
        diesel::update(characters::table.find(char_id_for_update))
            .set(characters::system_prompt.eq(character_prompt_bytes))
            .execute(conn)
    }).await.unwrap().unwrap();
    character = app.db_pool.get().await.unwrap().interact(move |conn| {
        characters::table.find(char_id_for_update).first::<scribe_backend::models::characters::Character>(conn)
    }).await.unwrap().unwrap();


    // 2. Create a persona and set it as default
    let persona_create = CreateUserPersonaDto {
        name: "Persona To Be Deleted".to_string(),
        description: "This persona will be deleted.".to_string(),
        system_prompt: Some("I am about to be deleted.".to_string()),
        ..Default::default()
    };
    let response = client
        .post(format!("{}/api/personas", app.address)) // Corrected path
        .json(&persona_create)
        .header(COOKIE, &auth_cookie)
        .send()
        .await
        .unwrap();
    let created_persona: UserPersonaDataForClient = response.json().await.unwrap();
    tdg.add_user_persona(created_persona.id);

    client
        .put(format!(
            "{}/api/user-settings/set_default_persona/{}",
            app.address, created_persona.id
        ))
        .header(COOKIE, &auth_cookie)
        .send()
        .await
        .unwrap();

    // Verify user's default_persona_id is set
    let user_id_clone = user_db.id; // Use user_db.id
    let db_user_before_delete: User = app.db_pool.get().await.unwrap()
        .interact(move |conn| users::table.filter(users::id.eq(user_id_clone)).select(UserDbQuery::as_select()).first(conn).map(User::from)).await.unwrap().unwrap();
    assert_eq!(db_user_before_delete.default_persona_id, Some(created_persona.id));


    // 3. Delete the persona directly from the database (simulating an orphaned default_persona_id)
    let persona_id_to_delete = created_persona.id;
    app.db_pool // Use app.db_pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::delete(user_personas::table.filter(user_personas::id.eq(persona_id_to_delete)))
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();

    // 4. Call create_session_and_maybe_first_message
    let user_dek_secret_box: Option<Arc<SecretBox<Vec<u8>>>> = user_db.dek.as_ref().map(|user_dek_struct| Arc::new(SecretBox::new(Box::new(user_dek_struct.0.expose_secret().clone()))));

    let app_state_for_service = TestAppStateBuilder::new(
        app.db_pool.clone(),
        app.config.clone(),
        app.ai_client.clone(),
        app.mock_embedding_client.clone(),
        app.qdrant_service.clone(),
    )
    .with_embedding_pipeline_service(app.mock_embedding_pipeline_service.clone())
    .build();
    let app_state_arc = Arc::new(app_state_for_service);

    let created_chat_session = chat_service::create_session_and_maybe_first_message(
        app_state_arc,
        user_db.id, // Use user_db.id
        character.id,
        None, // active_custom_persona_id is None
        user_dek_secret_box,
    )
    .await
    .unwrap();
    tdg.add_chat(created_chat_session.id);

    // 5. Verify the chat session
    // active_custom_persona_id should still be the (now orphaned) ID from user.default_persona_id
    // because the service tries to use it, but it won't find the persona.
    assert_eq!(
        created_chat_session.active_custom_persona_id,
        None,
        "Chat session active_custom_persona_id should be None after default persona is deleted"
    );

    assert_eq!(
        created_chat_session.system_prompt.as_deref(),
        Some(character_system_prompt_val.as_str()),
        "Chat session system prompt should fall back to the character's system prompt"
    );
    tdg.cleanup().await.unwrap();
}