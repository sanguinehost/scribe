use secrecy::ExposeSecret;
use std::sync::Arc; // Added import

use diesel::prelude::*;
use reqwest::header::COOKIE;
use secrecy::SecretBox;
use uuid::Uuid;

use scribe_backend::{
    models::{
        // characters::Character, // Character is used from test_helpers::db or directly via schema
        chats::ChatMode,
        user_personas::{CreateUserPersonaDto, UserPersonaDataForClient}, // Changed UserPersona to UserPersonaDataForClient
        users::{User, UserDbQuery},
    },
    schema::{characters, user_personas, users}, // Added schema::characters
    services::chat::session_management::create_session_and_maybe_first_message,
    test_helpers::{TestAppStateBuilder, TestDataGuard, db, login_user_via_router, spawn_app}, // Changed TestUser
};

// Helper struct for common test setup
struct TestSetup {
    tdg: TestDataGuard,
    app: scribe_backend::test_helpers::TestApp,
    user_db: User,
    user_dek_secret_box: Option<Arc<SecretBox<Vec<u8>>>>,
    app_state_arc: Arc<scribe_backend::state::AppState>,
}

async fn setup_common_test_env(username: &str) -> TestSetup {
    let app = spawn_app(false, false, false).await;
    let tdg = TestDataGuard::new(app.db_pool.clone());

    let user_db = db::create_test_user(
        &app.db_pool,
        username.to_string(),
        "password123".to_string(),
    )
    .await
    .unwrap();

    let user_dek_secret_box: Option<Arc<SecretBox<Vec<u8>>>> =
        user_db.dek.as_ref().map(|user_dek_struct| {
            Arc::new(SecretBox::new(Box::new(
                user_dek_struct.0.expose_secret().clone(),
            )))
        });

    let auth_backend = Arc::new(scribe_backend::auth::user_store::Backend::new(
        app.db_pool.clone(),
    ));
    let app_state_for_service = TestAppStateBuilder::new(
        app.db_pool.clone(),
        app.config.clone(),
        app.ai_client.clone(),
        app.mock_embedding_client.clone(),
        app.qdrant_service.clone(),
        auth_backend,
    )
    .with_embedding_pipeline_service(app.mock_embedding_pipeline_service.clone())
    .build()
    .await
    .expect("Failed to build app state for test");
    let app_state_arc = Arc::new(app_state_for_service);

    TestSetup {
        tdg,
        app,
        user_db,
        user_dek_secret_box,
        app_state_arc,
    }
}

// Helper to update character system prompt
async fn update_character_system_prompt(
    pool: &deadpool_diesel::postgres::Pool,
    character_id: Uuid,
    system_prompt: String,
) -> scribe_backend::models::characters::Character {
    let char_id_for_update = character_id;
    pool.get()
        .await
        .unwrap()
        .interact(move |conn| {
            diesel::update(characters::table.find(char_id_for_update))
                .set((
                    characters::system_prompt.eq(Some(system_prompt.as_bytes().to_vec())),
                    characters::system_prompt_nonce.eq(Some(vec![0u8; 12])), // Dummy nonce
                ))
                .execute(conn)
        })
        .await
        .unwrap()
        .unwrap();
    pool.get()
        .await
        .unwrap()
        .interact(move |conn| {
            characters::table
                .find(char_id_for_update)
                .first::<scribe_backend::models::characters::Character>(conn)
        })
        .await
        .unwrap()
        .unwrap()
}

// Helper to decrypt system prompt from chat session
fn decrypt_system_prompt(
    system_prompt_ciphertext: Option<&Vec<u8>>,
    system_prompt_nonce: Option<&Vec<u8>>,
    user_dek_secret_box: Option<&Arc<SecretBox<Vec<u8>>>>,
) -> Option<String> {
    match (
        system_prompt_ciphertext.as_ref(),
        system_prompt_nonce.as_ref(),
        user_dek_secret_box.as_ref(),
    ) {
        (Some(ciphertext), Some(nonce), Some(dek_arc)) => {
            scribe_backend::crypto::decrypt_gcm(ciphertext, nonce, dek_arc.as_ref())
                .ok()
                .and_then(|ps| String::from_utf8(ps.expose_secret().clone()).ok())
        }
        _ => None,
    }
}

#[tokio::test]
async fn create_session_uses_default_persona_when_active_persona_is_none() {
    let mut setup = setup_common_test_env("user_with_default_persona").await;
    setup.tdg.add_user(setup.user_db.id);

    let auth_cookie = login_user_via_router(
        &setup.app.router,
        "user_with_default_persona",
        "password123",
    )
    .await;

    let client = reqwest::Client::new();

    let character_name = "Test Character for Default Persona";
    let character_system_prompt_val = "Character's original system prompt".to_string();
    let mut character = db::create_test_character(
        &setup.app.db_pool,
        setup.user_db.id,
        character_name.to_string(),
    )
    .await
    .unwrap();
    setup.tdg.add_character(character.id);

    character = update_character_system_prompt(
        &setup.app.db_pool,
        character.id,
        character_system_prompt_val.clone(),
    )
    .await;

    let persona_name = "My Default Test Persona".to_string();
    let persona_system_prompt = "You are the default test persona.".to_string();
    let persona_create = CreateUserPersonaDto {
        name: persona_name.clone(),
        description: "This is my default persona.".to_string(),
        system_prompt: Some(persona_system_prompt.clone()),
        ..Default::default()
    };

    let response = client
        .post(format!("{}/api/personas", setup.app.address))
        .json(&persona_create)
        .header(COOKIE, &auth_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::CREATED);
    let created_persona: UserPersonaDataForClient = response.json().await.unwrap();
    setup.tdg.add_user_persona(created_persona.id);

    let response = client
        .put(format!(
            "{}/api/user-settings/set_default_persona/{}",
            setup.app.address, created_persona.id
        ))
        .header(COOKIE, &auth_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);

    let user_id_clone = setup.user_db.id;
    let db_user_check: User = setup
        .app
        .db_pool
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
    assert_eq!(db_user_check.default_persona_id, Some(created_persona.id));

    let created_chat_session = create_session_and_maybe_first_message(
        setup.app_state_arc.clone(),
        setup.user_db.id,
        Some(character.id),
        ChatMode::Character,
        None,
        None,
        setup.user_dek_secret_box.clone(),
    )
    .await
    .unwrap();
    setup.tdg.add_chat(created_chat_session.id);

    assert_eq!(
        created_chat_session.active_custom_persona_id,
        Some(created_persona.id),
        "Chat session should use the user's default persona ID"
    );

    let decrypted_prompt = decrypt_system_prompt(
        created_chat_session.system_prompt_ciphertext.as_ref(),
        created_chat_session.system_prompt_nonce.as_ref(),
        setup.user_dek_secret_box.as_ref(),
    );
    assert_eq!(
        decrypted_prompt.as_deref(),
        Some(persona_system_prompt.as_str()),
        "Chat session system prompt should match the default persona's system prompt"
    );
    setup.tdg.cleanup().await.unwrap();
}

#[tokio::test]
async fn create_session_no_default_persona_falls_back_to_character_prompt() {
    let mut setup = setup_common_test_env("user_no_default_persona").await;
    setup.tdg.add_user(setup.user_db.id);

    let character_system_prompt_val = "You are the character's original prompt.".to_string();
    let mut character = db::create_test_character(
        &setup.app.db_pool,
        setup.user_db.id,
        "Character For No Default Test".to_string(),
    )
    .await
    .unwrap();
    setup.tdg.add_character(character.id);

    character = update_character_system_prompt(
        &setup.app.db_pool,
        character.id,
        character_system_prompt_val.clone(),
    )
    .await;

    let user_id_clone = setup.user_db.id;
    let db_user_check: User = setup
        .app
        .db_pool
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

    let created_chat_session = create_session_and_maybe_first_message(
        setup.app_state_arc.clone(),
        setup.user_db.id,
        Some(character.id),
        ChatMode::Character,
        None,
        None,
        setup.user_dek_secret_box.clone(),
    )
    .await
    .unwrap();
    setup.tdg.add_chat(created_chat_session.id);

    assert!(
        created_chat_session.active_custom_persona_id.is_none(),
        "Chat session should have no active_custom_persona_id"
    );

    let decrypted_prompt = decrypt_system_prompt(
        created_chat_session.system_prompt_ciphertext.as_ref(),
        created_chat_session.system_prompt_nonce.as_ref(),
        setup.user_dek_secret_box.as_ref(),
    );
    assert_eq!(
        decrypted_prompt.as_deref(),
        Some(character_system_prompt_val.as_str()),
        "Chat session system prompt should match the character's system prompt"
    );
    setup.tdg.cleanup().await.unwrap();
}

async fn create_and_set_default_persona(
    app_address: &str,
    auth_cookie: &str,
    persona_name: String,
    persona_description: String,
    persona_system_prompt: Option<String>,
    tdg: &mut TestDataGuard,
) -> UserPersonaDataForClient {
    let client = reqwest::Client::new();
    let persona_create = CreateUserPersonaDto {
        name: persona_name,
        description: persona_description,
        system_prompt: persona_system_prompt,
        ..Default::default()
    };
    let response = client
        .post(format!("{app_address}/api/personas"))
        .json(&persona_create)
        .header(COOKIE, auth_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::CREATED);
    let created_persona: UserPersonaDataForClient = response.json().await.unwrap();
    tdg.add_user_persona(created_persona.id);

    client
        .put(format!(
            "{}/api/user-settings/set_default_persona/{}",
            app_address, created_persona.id
        ))
        .header(COOKIE, auth_cookie)
        .send()
        .await
        .unwrap();
    created_persona
}

#[tokio::test]
async fn create_session_default_persona_deleted_falls_back_to_character_prompt() {
    let mut setup = setup_common_test_env("user_deleted_default_persona").await;
    setup.tdg.add_user(setup.user_db.id);
    let auth_cookie = login_user_via_router(
        &setup.app.router,
        "user_deleted_default_persona",
        "password123",
    )
    .await;

    let character_system_prompt_val = "Character prompt for deleted persona test.".to_string();
    let mut character = db::create_test_character(
        &setup.app.db_pool,
        setup.user_db.id,
        "Char For Deleted Persona Test".to_string(),
    )
    .await
    .unwrap();
    setup.tdg.add_character(character.id);

    character = update_character_system_prompt(
        &setup.app.db_pool,
        character.id,
        character_system_prompt_val.clone(),
    )
    .await;

    let created_persona = create_and_set_default_persona(
        &setup.app.address,
        &auth_cookie,
        "Persona To Be Deleted".to_string(),
        "This persona will be deleted.".to_string(),
        Some("I am about to be deleted.".to_string()),
        &mut setup.tdg,
    )
    .await;

    let user_id_clone = setup.user_db.id;
    let db_user_before_delete: User = setup
        .app
        .db_pool
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
    assert_eq!(
        db_user_before_delete.default_persona_id,
        Some(created_persona.id)
    );

    let persona_id_to_delete = created_persona.id;
    setup
        .app
        .db_pool
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

    let created_chat_session = create_session_and_maybe_first_message(
        setup.app_state_arc.clone(),
        setup.user_db.id,
        Some(character.id),
        ChatMode::Character,
        None,
        None,
        setup.user_dek_secret_box.clone(),
    )
    .await
    .unwrap();
    setup.tdg.add_chat(created_chat_session.id);

    assert_eq!(
        created_chat_session.active_custom_persona_id, None,
        "Chat session active_custom_persona_id should be None after default persona is deleted"
    );

    let decrypted_prompt = decrypt_system_prompt(
        created_chat_session.system_prompt_ciphertext.as_ref(),
        created_chat_session.system_prompt_nonce.as_ref(),
        setup.user_dek_secret_box.as_ref(),
    );
    assert_eq!(
        decrypted_prompt.as_deref(),
        Some(character_system_prompt_val.as_str()),
        "Chat session system prompt should fall back to the character's system prompt"
    );
    setup.tdg.cleanup().await.unwrap();
}
