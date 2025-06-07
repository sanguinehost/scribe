use std::sync::Arc;

use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper};
use secrecy::SecretBox; // Removed SecretString

use scribe_backend::{
    auth::user_store::Backend as AuthBackend, // Added
    llm::EmbeddingClient,                     // Removed AiClient, Added EmbeddingClient
    models::{
        user_settings::{NewUserSettings, UserSettings},
    },
    schema::user_settings,
    services::{
        chat_override_service::ChatOverrideService, // Added
        embedding_pipeline::EmbeddingPipelineServiceTrait, // Added
        encryption_service::EncryptionService,      // Added
        gemini_token_client::GeminiTokenClient,     // Added
        hybrid_token_counter::HybridTokenCounter,   // Added
        lorebook_service::LorebookService,          // Added
        tokenizer_service::TokenizerService,        // Added
        user_persona_service::UserPersonaService,   // Added
        UserSettingsService,
    },
    state::{AppState, AppStateServices}, // Added AppStateServices
    test_helpers::{db, spawn_app, TestDataGuard}, // Removed QdrantClientServiceTrait from here
};

/// Test that user settings service auto-creates defaults when none exist
#[tokio::test]
async fn test_user_settings_auto_creation() {
    let app = spawn_app(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone());

    // Create a test user WITHOUT user settings
    let username = "testuser_auto_create";
    let password = "password123";
    let user_db = db::create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .unwrap();
    tdg.add_user(user_db.id);

    // Call get_user_settings - this should auto-create defaults
    let user_settings = UserSettingsService::get_user_settings(&app.db_pool, user_db.id, &app.config)
        .await
        .expect("Failed to get/create user settings");

    // Verify the settings were created with system defaults
    assert_eq!(
        user_settings.default_model_name.as_ref().unwrap(),
        &app.config.token_counter_default_model,
        "Auto-created settings should use system default model"
    );
    assert_eq!(
        user_settings.default_context_total_token_limit.unwrap(),
        app.config.context_total_token_limit as i32,
        "Auto-created settings should use system default context limit"
    );
    assert_eq!(
        user_settings.auto_save_chats.unwrap(),
        true,
        "Auto-created settings should have auto_save_chats enabled"
    );

    // Verify the settings were actually saved to the database
    let conn = &mut app.db_pool.get().await.unwrap();
    conn.interact(move |conn| {
        let db_settings: UserSettings = user_settings::table
            .filter(user_settings::user_id.eq(user_db.id))
            .first(conn)
            .expect("Settings should be saved to database");

        assert_eq!(
            db_settings.default_model_name.as_ref().unwrap(),
            &app.config.token_counter_default_model,
            "Database settings should match auto-created settings"
        );
        
        Result::<(), diesel::result::Error>::Ok(())
    })
    .await
    .unwrap()
    .unwrap();

    // Cleanup handled by TestDataGuard
}

/// Test that new chat sessions use user's default model from user settings via direct service call
#[tokio::test]
async fn test_chat_session_uses_user_default_model() {
    let app = spawn_app(false, false, false).await;
    let mut tdg = TestDataGuard::new(app.db_pool.clone());

    // Create a test user
    let username = "testuser_model";
    let password = "password123";
    let user_db = db::create_test_user(&app.db_pool, username.to_string(), password.to_string())
        .await
        .unwrap();
    tdg.add_user(user_db.id);

    // Create user settings with a custom default model directly in the database
    let custom_model = "gemini-2.5-pro".to_string();
    let user_settings = NewUserSettings {
        user_id: user_db.id,
        default_model_name: Some(custom_model.clone()),
        default_temperature: None,
        default_max_output_tokens: None,
        default_frequency_penalty: None,
        default_presence_penalty: None,
        default_top_p: None,
        default_top_k: None,
        default_seed: None,
        default_gemini_thinking_budget: None,
        default_gemini_enable_code_execution: None,
        default_context_total_token_limit: None,
        default_context_recent_history_budget: None,
        default_context_rag_budget: None,
        auto_save_chats: None,
        theme: None,
        notifications_enabled: None,
    };

    // Insert user settings in database using interact 
    app.db_pool.get().await.unwrap()
        .interact(move |conn| {
            let _inserted_settings: UserSettings = diesel::insert_into(user_settings::table)
                .values(&user_settings)
                .returning(UserSettings::as_returning())
                .get_result(conn)?;
            Result::<(), diesel::result::Error>::Ok(())
        })
        .await
        .unwrap()
        .unwrap();

    // Create a test character
    let character = scribe_backend::test_helpers::db::create_test_character(
        &app.db_pool, 
        user_db.id, 
        "Test Character".to_string()
    ).await.unwrap();
    tdg.add_character(character.id);

    // Create AppState for session creation
    let db_pool = app.db_pool.clone();
    let config = app.config.clone();
    let ai_client = app.ai_client.clone();
    let embedding_client =
        app.mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>;
    let qdrant_service = app.qdrant_service.clone();
    let embedding_pipeline_service = app.mock_embedding_pipeline_service.clone()
        as Arc<dyn EmbeddingPipelineServiceTrait + Send + Sync>;

    let encryption_service = Arc::new(EncryptionService::new());
    let auth_backend = Arc::new(AuthBackend::new(db_pool.clone()));
    let chat_override_service =
        Arc::new(ChatOverrideService::new(db_pool.clone(), encryption_service.clone()));
    let user_persona_service =
        Arc::new(UserPersonaService::new(db_pool.clone(), encryption_service.clone()));
    
    let tokenizer_service = TokenizerService::new(&config.tokenizer_model_path)
        .expect("Failed to load tokenizer for test AppState construction");

    let gemini_token_client = config
        .gemini_api_key
        .as_ref()
        .map(|api_key_secret_string| {
            // Assuming api_key_secret_string is SecretString
            // GeminiTokenClient::new expects SecretString
            GeminiTokenClient::new(api_key_secret_string.clone())
        });

    let token_counter = Arc::new(HybridTokenCounter::new(
        tokenizer_service,
        gemini_token_client,
        config.token_counter_default_model.clone(),
    ));
    let lorebook_service = Arc::new(LorebookService::new(
        db_pool.clone(),
        encryption_service.clone(),
        qdrant_service.clone(),
    ));
    let file_storage_service = Arc::new(
        scribe_backend::services::file_storage_service::FileStorageService::new("./test_uploads")
            .expect("Failed to create test file storage service")
    );

    let app_services = AppStateServices {
        ai_client,
        embedding_client,
        qdrant_service,
        embedding_pipeline_service,
        chat_override_service,
        user_persona_service,
        token_counter,
        encryption_service,
        lorebook_service,
        auth_backend,
        file_storage_service,
    };

    let app_state_for_session = Arc::new(AppState::new(db_pool, config, app_services));

    // Create a mock DEK for encryption
    // The SessionDek is SecretBox<Vec<u8>>
    // create_test_user already sets up a DEK and it's available on user_db.dek
    // We need to extract it and pass it.
    // user_db.dek is Option<SerializableSecretDek(SecretBox<Vec<u8>>)>
    // create_session_and_maybe_first_message expects Option<Arc<SessionDek>> which is Option<Arc<SecretBox<Vec<u8>>>>
    
    let user_dek_for_session: Option<Arc<SecretBox<Vec<u8>>>> = user_db.dek.map(|serializable_dek| Arc::new(serializable_dek.0));


    // Create a chat session using the session management service
    let chat_session = scribe_backend::services::chat::session_management::create_session_and_maybe_first_message(
        app_state_for_session, // Use the correctly constructed AppState
        user_db.id,
        character.id,
        None, // No custom persona
        None, // No lorebooks
        user_dek_for_session, // Use the DEK from the test user
    )
    .await
    .expect("Failed to create chat session");

    // Verify the chat session uses the user's default model
    assert_eq!(
        chat_session.model_name, // Type String
        custom_model.as_str(),   // Type &str, String implements PartialEq<&str>
        "Chat session should use user's default model from settings"
    );

    // Cleanup handled by TestDataGuard
}

