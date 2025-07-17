#![cfg(test)]

// Common imports needed for settings tests
use axum::{
    body::Body,
    http::{Method, Request, StatusCode, header},
};
use bigdecimal::BigDecimal;
use chrono::Utc;
use http_body_util::BodyExt;
use secrecy::SecretBox;
use std::str::FromStr;
use tower::ServiceExt;
use uuid::Uuid;

// Diesel and model imports
use diesel::prelude::*;
use scribe_backend::models::character_card::NewCharacter;
use scribe_backend::models::characters::Character as DbCharacter;
use scribe_backend::models::chats::{
    Chat as DbChat, ChatMode, ChatSettingsResponse, NewChat, UpdateChatSettingsRequest,
};
use scribe_backend::schema::{characters, chat_sessions};
use scribe_backend::services::chat::session_management::create_session_and_maybe_first_message;
use scribe_backend::services::chat::settings::get_session_settings;
use scribe_backend::services::lorebook::LorebookService; // Added LorebookService
use scribe_backend::state::{AppState, AppStateServices};
use scribe_backend::test_helpers;
use std::sync::Arc; // Added for Result in set_history_settings

// --- Helper functions for forbidden access tests ---

/// Helper to create a user and log them in, returning the auth cookie
async fn create_user_and_login(
    test_app: &test_helpers::TestApp,
    username: &str,
) -> anyhow::Result<String> {
    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        "password".to_string(),
    )
    .await?;

    let login_payload = serde_json::json!({ "identifier": username, "password": "password" });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&login_payload)?))
        .unwrap();

    let login_response = test_app
        .router
        .clone()
        .oneshot(login_request)
        .await
        .unwrap();

    if login_response.status() != StatusCode::OK {
        anyhow::bail!("Login failed for user {}", username);
    }

    let auth_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()
        .unwrap()
        .to_string();

    Ok(auth_cookie)
}

/// Helper to create a minimal character for testing
async fn create_test_character(
    conn_pool: &deadpool_diesel::Pool<deadpool_diesel::Manager<diesel::PgConnection>>,
    user_id: Uuid,
    name: &str,
) -> anyhow::Result<DbCharacter> {
    let new_character_data = NewCharacter {
        user_id,
        spec: "character_card_v2".to_string(),
        spec_version: "2.0.0".to_string(),
        name: name.to_string(),
        visibility: Some("private".to_string()),
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
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
    };

    let character = conn_pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get DB connection: {}", e))?
        .interact(move |actual_conn| {
            diesel::insert_into(characters::table)
                .values(&new_character_data)
                .get_result::<DbCharacter>(actual_conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Database interaction failed: {}", e))?
        .map_err(|e| anyhow::anyhow!("Database query failed: {}", e))?;

    Ok(character)
}

/// Helper to create a minimal chat session for testing
async fn create_test_chat_session(
    conn_pool: &deadpool_diesel::Pool<deadpool_diesel::Manager<diesel::PgConnection>>,
    user_id: Uuid,
    character_id: Uuid,
) -> anyhow::Result<DbChat> {
    let new_chat_data = NewChat {
        id: Uuid::new_v4(),
        user_id,
        character_id,
        title_ciphertext: None,
        title_nonce: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        history_management_strategy: "token_limit".to_string(),
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
        player_chronicle_id: None,
    };

    let chat_session = conn_pool
        .get()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get DB connection: {}", e))?
        .interact(move |actual_conn| {
            diesel::insert_into(chat_sessions::table)
                .values(&new_chat_data)
                .returning(DbChat::as_returning())
                .get_result(actual_conn)
        })
        .await
        .map_err(|e| anyhow::anyhow!("Database interaction failed: {}", e))?
        .map_err(|e| anyhow::anyhow!("Database query failed: {}", e))?;

    Ok(chat_session)
}

// --- Tests for GET /api/chat/{id}/settings ---

/// Helper to set up a common test environment for chat settings tests.
/// Creates a user, logs them in, creates a character, and an initial chat session.
async fn setup_chat_settings_test_env(
    test_app: &test_helpers::TestApp,
    username_prefix: &str,
    character_name: &str,
    initial_chat_data: Option<NewChat>,
) -> anyhow::Result<(
    scribe_backend::models::users::User,
    String, // auth_cookie
    DbCharacter,
    DbChat,
)> {
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        format!("{username_prefix}_user"),
        "password".to_string(),
    )
    .await?;

    let login_payload = serde_json::json!({
        "identifier": format!("{}_user", username_prefix),
        "password": "password"
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&login_payload)?))?;

    let login_response = test_app.router.clone().oneshot(login_request).await?;
    assert_eq!(login_response.status(), StatusCode::OK);
    let auth_cookie = login_response
        .headers()
        .get(header::SET_COOKIE)
        .expect("Set-Cookie header should be present")
        .to_str()?
        .to_string();

    let new_character_data = NewCharacter {
        user_id: user.id,
        spec: format!("character_card_v2_{username_prefix}"),
        spec_version: "2.0.0".to_string(),
        name: character_name.to_string(),
        visibility: Some("private".to_string()),
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
        ..Default::default()
    };

    let character: DbCharacter = test_app
        .db_pool
        .get()
        .await?
        .interact(move |actual_conn| {
            diesel::insert_into(characters::table)
                .values(&new_character_data)
                .get_result::<DbCharacter>(actual_conn)
        })
        .await
        .expect("Interact failed for character insert")?;

    let chat_data = match initial_chat_data {
        Some(mut provided_data) => {
            // Always override user_id and character_id with the actual created entities
            provided_data.user_id = user.id;
            provided_data.character_id = character.id;
            provided_data
        }
        None => NewChat {
            id: Uuid::new_v4(),
            user_id: user.id,
            character_id: character.id,
            title_ciphertext: Some(format!("Chat for {username_prefix}").as_bytes().to_vec()),
            title_nonce: Some(vec![0u8; 12]), // Dummy nonce
            created_at: Utc::now(),
            updated_at: Utc::now(),
            history_management_strategy: "truncate_summary".to_string(),
            history_management_limit: 20,
            model_name: "initial-model".to_string(),
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
            player_chronicle_id: None,
        },
    };

    let chat_data_clone = chat_data.clone();
    let session: DbChat = test_app
        .db_pool
        .get()
        .await?
        .interact(move |actual_conn| {
            diesel::insert_into(chat_sessions::table)
                .values(&chat_data_clone)
                .returning(DbChat::as_returning())
                .get_result(actual_conn)
        })
        .await
        .expect("Interact failed for chat insert")?;

    Ok((user, auth_cookie, character, session))
}

#[tokio::test]
async fn get_chat_settings_success() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let (_user, auth_cookie, _character, session) = setup_chat_settings_test_env(
        &test_app,
        "get_settings_success",
        "Get Settings Success Char",
        None,
    )
    .await
    .expect("Failed to setup test environment");

    let session_id_for_update = session.id;
    let update_conn_pool = test_app.db_pool.clone();
    update_conn_pool
        .get()
        .await
        .unwrap()
        .interact(move |actual_conn| {
            diesel::update(chat_sessions::table.find(session_id_for_update))
                .set((
                    (
                        chat_sessions::system_prompt_ciphertext.eq(None::<Vec<u8>>),
                        chat_sessions::system_prompt_nonce.eq(None::<Vec<u8>>),
                    ),
                    chat_sessions::temperature.eq(Some(BigDecimal::from_str("0.9").unwrap())),
                    chat_sessions::max_output_tokens.eq(Some(1024_i32)),
                    chat_sessions::frequency_penalty.eq(Some(BigDecimal::from_str("0.3").unwrap())),
                    chat_sessions::presence_penalty.eq(Some(BigDecimal::from_str("0.2").unwrap())),
                    chat_sessions::top_k.eq(Some(40_i32)),
                    chat_sessions::top_p.eq(Some(BigDecimal::from_str("0.95").unwrap())),
                    chat_sessions::seed.eq(Some(12345_i32)),
                    chat_sessions::model_name.eq("gemini-2.5-flash".to_string()),
                    chat_sessions::history_management_strategy.eq("truncate_summary".to_string()),
                    chat_sessions::history_management_limit.eq(20),
                    chat_sessions::gemini_thinking_budget.eq(Some(30_i32)),
                    chat_sessions::gemini_enable_code_execution.eq(Some(true)),
                ))
                .execute(actual_conn)
        })
        .await
        .expect("Interact failed for chat update")
        .expect("Diesel query failed for chat update");

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chat/{}/settings", session.id))
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&body).expect("Failed to deserialize settings response");

    assert_eq!(settings_resp.system_prompt, None);
    assert_eq!(
        settings_resp.temperature,
        Some(BigDecimal::from_str("0.9").unwrap())
    );
    assert_eq!(settings_resp.max_output_tokens, Some(1024_i32));
    assert_eq!(
        settings_resp.frequency_penalty,
        Some(BigDecimal::from_str("0.3").unwrap())
    );
    assert_eq!(
        settings_resp.presence_penalty,
        Some(BigDecimal::from_str("0.2").unwrap())
    );
    assert_eq!(settings_resp.top_k, Some(40_i32));
    assert_eq!(
        settings_resp.top_p,
        Some(BigDecimal::from_str("0.95").unwrap())
    );
    assert_eq!(settings_resp.seed, Some(12345_i32));
    assert_eq!(
        settings_resp.model_name,
        "gemini-2.5-flash".to_string()
    );
    assert_eq!(
        settings_resp.history_management_strategy,
        "truncate_summary"
    );
    assert_eq!(settings_resp.history_management_limit, 20);
    assert_eq!(settings_resp.gemini_thinking_budget, Some(30_i32));
    assert_eq!(settings_resp.gemini_enable_code_execution, Some(true));
}

fn create_app_state_for_settings_test(test_app: &test_helpers::TestApp) -> Arc<AppState> {
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
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone(),
        chat_override_service: chat_override_service_for_test,
        user_persona_service: user_persona_service_for_test,
        token_counter: hybrid_token_counter_for_test,
        encryption_service: encryption_service_for_test,
        lorebook_service: lorebook_service_for_test,
        auth_backend: auth_backend_for_test,
        file_storage_service: file_storage_service_for_test,
        email_service: Arc::new(
            scribe_backend::services::email_service::LoggingEmailService::new(
                "http://localhost:3000".to_string(),
            ),
        ),
        // ECS Services - minimal test instances
        redis_client: Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
        feature_flags: Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
        ecs_entity_manager: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ))
        },
        ecs_graceful_degradation: Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
            Default::default(),
            Arc::new(scribe_backend::config::NarrativeFeatureFlags::default()),
            None,
            None,
        )),
        ecs_enhanced_rag_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                degradation,
                concrete_embedding_service,
            ))
        },
        hybrid_query_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            let rag_service = Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                concrete_embedding_service,
            ));
            Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                rag_service,
                degradation,
            ))
        },
        // Chronicle ECS services for test
        chronicle_service: Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone())),
        chronicle_ecs_translator: Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
            Arc::new(test_app.db_pool.clone())
        )),
        chronicle_event_listener: {
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
            let chronicle_ecs_translator = Arc::new(scribe_backend::services::ChronicleEcsTranslator::new(
                Arc::new(test_app.db_pool.clone())
            ));
            Arc::new(scribe_backend::services::ChronicleEventListener::new(
                Default::default(),
                feature_flags,
                chronicle_ecs_translator,
                entity_manager,
                chronicle_service,
            ))
        },
        // Create WorldModelService for ECS world state snapshots
        world_model_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            let rag_service = Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                concrete_embedding_service,
            ));
            let hybrid_query_service = Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager.clone(),
                rag_service,
                degradation,
            ));
            let chronicle_service = Arc::new(scribe_backend::services::ChronicleService::new(test_app.db_pool.clone()));
            Arc::new(scribe_backend::services::WorldModelService::new(
                Arc::new(test_app.db_pool.clone()),
                entity_manager,
                hybrid_query_service.clone(),
                chronicle_service,
            ))
        },
        // Create agentic orchestrator with all required services
        agentic_orchestrator: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            let feature_flags = Arc::new(scribe_backend::config::NarrativeFeatureFlags::default());
            let entity_manager = Arc::new(scribe_backend::services::EcsEntityManager::new(
                Arc::new(test_app.db_pool.clone()),
                redis_client,
                None,
            ));
            let degradation = Arc::new(scribe_backend::services::EcsGracefulDegradation::new(
                Default::default(),
                feature_flags.clone(),
                Some(entity_manager.clone()),
                None,
            ));
            let concrete_embedding_service = Arc::new(scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::chunking::ChunkConfig {
                    metric: scribe_backend::text_processing::chunking::ChunkingMetric::Word,
                    max_size: 500,
                    overlap: 50,
                }
            ));
            let rag_service = Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                concrete_embedding_service,
            ));
            let hybrid_query_service = Arc::new(scribe_backend::services::HybridQueryService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags,
                entity_manager,
                rag_service,
                degradation,
            ));
            let agentic_state_update_service = Arc::new(scribe_backend::services::AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap()),
                    None,
                )),
            ));
            Arc::new(scribe_backend::services::AgenticOrchestrator::new(
                test_app.ai_client.clone(),
                hybrid_query_service,
                Arc::new(test_app.db_pool.clone()),
                agentic_state_update_service.clone(),
            ))
        },
        agentic_state_update_service: {
            let redis_client = Arc::new(redis::Client::open("redis://127.0.0.1:6379/").unwrap());
            Arc::new(scribe_backend::services::AgenticStateUpdateService::new(
                test_app.ai_client.clone(),
                Arc::new(scribe_backend::services::EcsEntityManager::new(
                    Arc::new(test_app.db_pool.clone()),
                    redis_client,
                    None,
                )),
            ))
        },
        hierarchical_context_assembler: None,
        tactical_agent: None,
        strategic_agent: None,
    };

    Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ))
}

#[tokio::test]
async fn get_chat_settings_defaults() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let character_default_description = "This is the character\'s default description.".to_string();
    let (_user, _auth_cookie, mut character, session) = setup_chat_settings_test_env(
        &test_app,
        "get_defaults",
        "Get Defaults Char",
        Some(NewChat {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(), // Will be overwritten by setup_chat_settings_test_env
            character_id: Uuid::new_v4(), // Will be overwritten
            title_ciphertext: Some(b"Chat for get_chat_settings_defaults".to_vec()),
            title_nonce: Some(vec![0u8; 12]), // Dummy nonce
            created_at: Utc::now(),
            updated_at: Utc::now(),
            history_management_strategy: "token_limit".to_string(),
            history_management_limit: 1000,
            model_name: "scribe-default-model".to_string(),
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
            player_chronicle_id: None,
        }),
    )
    .await
    .expect("Failed to setup test environment");

    // Update the character with a description
    character.description = Some(character_default_description.as_bytes().to_vec());
    let character_clone = character.clone();
    let description_clone = character_default_description.clone();
    test_app
        .db_pool
        .get()
        .await
        .expect("Failed to get DB connection")
        .interact(move |conn| {
            use scribe_backend::schema::characters::dsl::*;
            diesel::update(characters.find(character_clone.id))
                .set(description.eq(Some(description_clone.as_bytes().to_vec())))
                .execute(conn)
        })
        .await
        .expect("Failed to update character")
        .expect("Failed to update character in DB");

    let app_state_for_service = create_app_state_for_settings_test(&test_app);

    let dummy_dek_bytes = vec![0u8; 32];
    let user_dek_for_service_call = Some(Arc::new(SecretBox::new(Box::new(dummy_dek_bytes))));

    let created_chat_session = create_session_and_maybe_first_message(
        app_state_for_service,
        session.user_id, // Use user ID from the session created by helper
        Some(character.id), // character_id is now Option<Uuid>
        ChatMode::Character, // chat_mode
        None,                              // active_custom_persona_id
        None,                              // lorebook_ids
        user_dek_for_service_call.clone(), // Pass the created DEK
    )
    .await
    .expect("Failed to create chat session via service");

    let settings_resp: ChatSettingsResponse = get_session_settings(
        &test_app.db_pool,
        session.user_id, // Use user ID from the session created by helper
        created_chat_session.id,
        user_dek_for_service_call.as_deref(), // Pass the dummy DEK used for encryption
    )
    .await
    .expect("Failed to get session settings via service call");

    assert_eq!(
        settings_resp.system_prompt,
        Some(character_default_description)
    );

    assert_eq!(settings_resp.temperature, None);
    assert_eq!(settings_resp.max_output_tokens, None);
    assert_eq!(settings_resp.frequency_penalty, None);
    assert_eq!(settings_resp.presence_penalty, None);
    assert_eq!(settings_resp.top_k, None);
    assert_eq!(settings_resp.top_p, None);
    assert_eq!(settings_resp.seed, None);

    assert_eq!(settings_resp.model_name, "gemini-2.5-flash");
    assert_eq!(settings_resp.history_management_strategy, "message_window");
    assert_eq!(settings_resp.history_management_limit, 20);

    assert_eq!(settings_resp.gemini_thinking_budget, None);
    assert_eq!(settings_resp.gemini_enable_code_execution, None);
}

#[tokio::test]
async fn test_get_chat_settings_not_found() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "get_settings_404_user".to_string(),
        "password".to_string(),
    )
    .await
    .expect("Failed to create test user for 404 test");

    let login_payload = serde_json::json!({
        "identifier": "get_settings_404_user",
        "password": "password"
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
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

    let non_existent_session_id = Uuid::new_v4();
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chat/{non_existent_session_id}/settings"))
        .header(header::COOKIE, auth_cookie)
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    // For non-existent chat IDs (test case), the API returns NOT_FOUND
    // (For existing chat IDs owned by someone else, it returns FORBIDDEN)
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_get_chat_settings_forbidden() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let conn_pool = test_app.db_pool.clone();

    // Create user A who owns the chat session
    let user_a = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "get_settings_forbid_usera".to_string(),
        "password".to_string(),
    )
    .await
    .expect("Failed to create user_a");

    // Create user B who will try to access user A's chat session
    let auth_cookie_b = create_user_and_login(&test_app, "get_settings_forbid_userb")
        .await
        .expect("Failed to create and login user B");

    // Create character for user A
    let char_a = create_test_character(&conn_pool, user_a.id, "Get Settings Forbidden Char A")
        .await
        .expect("Failed to create character for user A");

    // Create chat session for user A
    let session_a = create_test_chat_session(&conn_pool, user_a.id, char_a.id)
        .await
        .expect("Failed to create chat session for user A");

    // User B tries to access user A's chat session settings
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chat/{}/settings", session_a.id))
        .header(header::COOKIE, auth_cookie_b)
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    // For existing chat IDs owned by someone else, the endpoint returns FORBIDDEN
    // (For non-existent chat IDs, it returns NOT_FOUND)
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

// --- Tests for PUT /api/chat/{id}/settings ---

async fn setup_update_test_env(
    test_app: &test_helpers::TestApp,
    username: &str,
    char_name: &str,
    chat_title_suffix: &str,
    initial_model_name: &str,
    initial_hist_strat: &str,
    initial_hist_limit: i32,
) -> anyhow::Result<(
    scribe_backend::models::users::User,
    String, // auth_cookie
    DbCharacter,
    DbChat,
)> {
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        username.to_string(),
        "password".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let login_payload = serde_json::json!({ "identifier": username, "password": "password" });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
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

    let new_character_data = NewCharacter {
        user_id: user.id,
        spec: format!("character_card_v2_{username}"),
        spec_version: "2.0.0".to_string(),
        name: char_name.to_string(),
        visibility: Some("private".to_string()),
        created_at: Some(Utc::now()),
        updated_at: Some(Utc::now()),
        ..Default::default()
    };
    let character: DbCharacter = test_app
        .db_pool
        .get()
        .await
        .unwrap()
        .interact(move |actual_conn| {
            diesel::insert_into(characters::table)
                .values(&new_character_data)
                .get_result::<DbCharacter>(actual_conn)
        })
        .await
        .expect("Interact char insert failed")
        .expect("Diesel char insert failed");

    let new_chat_data = NewChat {
        id: Uuid::new_v4(),
        user_id: user.id,
        character_id: character.id,
        title_ciphertext: Some(format!("Chat for {chat_title_suffix}").as_bytes().to_vec()),
        title_nonce: Some(vec![0u8; 12]), // Dummy nonce
        created_at: Utc::now(),
        updated_at: Utc::now(),
        history_management_strategy: initial_hist_strat.to_string(),
        history_management_limit: initial_hist_limit,
        model_name: initial_model_name.to_string(),
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
        player_chronicle_id: None,
    };
    let session: DbChat = test_app
        .db_pool
        .get()
        .await
        .unwrap()
        .interact(move |actual_conn| {
            diesel::insert_into(chat_sessions::table)
                .values(&new_chat_data)
                .returning(DbChat::as_returning())
                .get_result(actual_conn)
        })
        .await
        .expect("Interact chat insert failed")
        .expect("Diesel chat insert failed");

    Ok((user, auth_cookie, character, session))
}

#[tokio::test]
async fn update_chat_settings_success_full() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let (_user, auth_cookie, _character, session) = setup_update_test_env(
        &test_app,
        "update_settings_user",
        "Update Full Settings Char",
        "update_chat_settings_success_full",
        "initial-model",
        "token_limit",
        10,
    )
    .await
    .expect("Failed to setup test environment");

    let update_data = UpdateChatSettingsRequest {
        system_prompt: Some("Updated System Prompt".to_string()),
        temperature: Some(BigDecimal::from_str("0.75").unwrap()),
        max_output_tokens: Some(512_i32),
        frequency_penalty: Some(BigDecimal::from_str("0.15").unwrap()),
        presence_penalty: Some(BigDecimal::from_str("0.12").unwrap()),
        top_k: Some(30_i32),
        top_p: Some(BigDecimal::from_str("0.88").unwrap()),
        seed: Some(54321_i32),
        stop_sequences: None,
        model_name: Some("updated-model-name".to_string()),
        history_management_strategy: Some("token_limit".to_string()),
        history_management_limit: Some(100),
        gemini_thinking_budget: Some(60_i32),
        gemini_enable_code_execution: Some(false),
        chronicle_id: None,
    };

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chat/{}/settings", session.id))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(serde_json::to_string(&update_data).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&body).expect("Failed to deserialize settings response");

    assert_eq!(
        settings_resp.system_prompt,
        Some("Updated System Prompt".to_string())
    );
    assert_eq!(
        settings_resp.temperature,
        Some(BigDecimal::from_str("0.75").unwrap())
    );
    assert_eq!(settings_resp.max_output_tokens, Some(512_i32));
    assert_eq!(settings_resp.model_name, "updated-model-name".to_string());
    assert_eq!(settings_resp.history_management_strategy, "token_limit");
    assert_eq!(settings_resp.history_management_limit, 100);
    assert_eq!(settings_resp.gemini_thinking_budget, Some(60_i32));
    assert_eq!(settings_resp.gemini_enable_code_execution, Some(false));
}

#[tokio::test]
async fn update_chat_settings_success_partial() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let conn_pool = test_app.db_pool.clone();
    let (_user, auth_cookie, _character, session) = setup_update_test_env(
        &test_app,
        "update_partial_user",
        "Update Partial Settings Char",
        "update_chat_settings_success_partial",
        "initial-partial-model",
        "none",
        0,
    )
    .await
    .expect("Failed to setup test environment");

    let session_id_for_update = session.id;
    let update_conn_pool = conn_pool.clone();
    let initial_temp_val = BigDecimal::from_str("0.5").unwrap();
    let initial_temp_val_for_closure = initial_temp_val.clone();

    update_conn_pool
        .get()
        .await
        .unwrap()
        .interact(move |actual_conn| {
            diesel::update(chat_sessions::table.find(session_id_for_update))
                .set((
                    (
                        chat_sessions::system_prompt_ciphertext.eq(None::<Vec<u8>>),
                        chat_sessions::system_prompt_nonce.eq(None::<Vec<u8>>),
                    ),
                    chat_sessions::temperature.eq(Some(initial_temp_val_for_closure)),
                    chat_sessions::max_output_tokens.eq(Some(100_i32)),
                ))
                .execute(actual_conn)
        })
        .await
        .expect("Interact for initial chat settings update failed")
        .expect("Diesel update for initial settings failed");

    let update_data = UpdateChatSettingsRequest {
        system_prompt: Some("Partially Updated System Prompt".to_string()),
        temperature: None,
        max_output_tokens: Some(200),
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        model_name: None,
        history_management_strategy: None,
        history_management_limit: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: None,
    };

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chat/{}/settings", session.id))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(serde_json::to_string(&update_data).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&body).expect("Failed to deserialize settings response");

    assert_eq!(
        settings_resp.system_prompt,
        Some("Partially Updated System Prompt".to_string())
    );
    assert_eq!(settings_resp.max_output_tokens, Some(200));
    assert_eq!(settings_resp.temperature, Some(initial_temp_val));
    assert_eq!(
        settings_resp.model_name,
        "initial-partial-model".to_string()
    );
    assert_eq!(settings_resp.history_management_strategy, "none");
    assert_eq!(settings_resp.history_management_limit, 0);
}

#[tokio::test]
async fn update_chat_settings_invalid_data() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let (_user, auth_cookie, _character, session) = setup_update_test_env(
        &test_app,
        "update_invalid_user",
        "Update Invalid Data Char",
        "update_chat_settings_invalid_data",
        "invalid-data-model",
        "token_limit",
        10,
    )
    .await
    .expect("Failed to setup test environment");

    let invalid_update_data = serde_json::json!({
        "temperature": "not_a_number"
    });

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chat/{}/settings", session.id))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(
            serde_json::to_string(&invalid_update_data).unwrap(),
        ))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn update_chat_settings_forbidden() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let conn_pool = test_app.db_pool.clone();

    // Create user1 who owns the chat session
    let user1 = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "update_settings_user1".to_string(),
        "password".to_string(),
    )
    .await
    .expect("user1 creation failed");

    // Create user2 who will try to update user1's chat session
    let auth_cookie2 = create_user_and_login(&test_app, "update_settings_user2")
        .await
        .expect("Failed to create and login user2");

    // Create character for user1
    let character_user1 =
        create_test_character(&conn_pool, user1.id, "Update Forbidden Settings Char")
            .await
            .expect("Failed to create character for user1");

    // Create chat session for user1
    let session_user1 = create_test_chat_session(&conn_pool, user1.id, character_user1.id)
        .await
        .expect("Failed to create chat session for user1");

    // Prepare update data
    let update_data = UpdateChatSettingsRequest {
        system_prompt: Some("Attempted Update by User2".to_string()),
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        history_management_strategy: None,
        history_management_limit: None,
        model_name: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: None,
    };

    // User2 tries to update user1's chat session settings
    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chat/{}/settings", session_user1.id))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, auth_cookie2)
        .body(Body::from(serde_json::to_string(&update_data).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn update_chat_settings_not_found() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let _user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "update_notfound_user".to_string(),
        "password".to_string(),
    )
    .await
    .expect("user creation failed");

    let login_payload =
        serde_json::json!({ "identifier": "update_notfound_user", "password": "password" });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
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
        .expect("Set-Cookie header")
        .to_str()
        .unwrap()
        .to_string();

    let non_existent_session_id = Uuid::new_v4();
    let update_data = UpdateChatSettingsRequest {
        system_prompt: Some("Update for Non-existent Session".to_string()),
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        model_name: None,
        history_management_strategy: None,
        history_management_limit: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: None,
    };

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chat/{non_existent_session_id}/settings"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(serde_json::to_string(&update_data).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_chat_settings_unauthorized() {
    let test_app = test_helpers::spawn_app(false, false, false).await;

    let session_id_for_unauth = Uuid::new_v4();

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chat/{session_id_for_unauth}/settings"))
        .body(Body::empty())
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// Helper to set history management settings via API

#[tokio::test]
async fn update_chat_settings_unauthorized() {
    let test_app = test_helpers::spawn_app(false, false, false).await;

    let session_id_for_unauth = Uuid::new_v4();
    let update_data = UpdateChatSettingsRequest {
        system_prompt: Some("Unauthorized Update Attempt".to_string()),
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        model_name: None,
        history_management_strategy: None,
        history_management_limit: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: None,
    };

    let request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chat/{session_id_for_unauth}/settings"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&update_data).unwrap()))
        .unwrap();

    let response = test_app.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn debug_system_prompt_encryption_decryption() {
    let test_app = test_helpers::spawn_app(false, false, false).await;

    // Create a test user
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "debug_user".to_string(),
        "password".to_string(),
    )
    .await
    .expect("Failed to create test user");

    // Create a DEK for the user
    let dek_bytes = vec![0u8; 32]; // Use a dummy 32-byte key
    let user_dek = SecretBox::new(Box::new(dek_bytes));

    // Create a character (minimal)
    let character: DbCharacter = test_app
        .db_pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            use chrono::Utc;
            use scribe_backend::models::character_card::NewCharacter;
            use scribe_backend::schema::characters;

            let new_character = NewCharacter {
                user_id: user.id,
                spec: "character_card_v2".to_string(),
                spec_version: "2.0.0".to_string(),
                name: "Debug Character".to_string(),
                visibility: Some("private".to_string()),
                created_at: Some(Utc::now()),
                updated_at: Some(Utc::now()),
                ..Default::default()
            };

            diesel::insert_into(characters::table)
                .values(&new_character)
                .get_result::<DbCharacter>(conn)
        })
        .await
        .unwrap()
        .unwrap();

    // Create a chat session
    let session = test_app
        .db_pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            use chrono::Utc;
            use scribe_backend::models::chats::NewChat;
            use scribe_backend::schema::chat_sessions;

            let new_chat = NewChat {
                id: Uuid::new_v4(),
                user_id: user.id,
                character_id: character.id,
                title_ciphertext: None,
                title_nonce: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                history_management_strategy: "message_window".to_string(),
                history_management_limit: 20,
                model_name: "gemini-2.5-flash".to_string(),
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
                player_chronicle_id: None,
            };

            diesel::insert_into(chat_sessions::table)
                .values(&new_chat)
                .returning(scribe_backend::models::chats::Chat::as_returning())
                .get_result(conn)
        })
        .await
        .unwrap()
        .unwrap();

    println!("Created session: {:?}", session.id);

    // Test 1: Update the system prompt
    let system_prompt_text = "You are a helpful assistant for debugging encryption.";
    let update_request = UpdateChatSettingsRequest {
        system_prompt: Some(system_prompt_text.to_string()),
        temperature: Some(BigDecimal::from_str("0.8").unwrap()),
        max_output_tokens: Some(1000),
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        model_name: None,
        history_management_strategy: None,
        history_management_limit: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: None,
    };

    println!(
        "Updating session settings with system prompt: {:?}",
        system_prompt_text
    );

    let updated_settings = scribe_backend::services::chat::settings::update_session_settings(
        &test_app.db_pool,
        user.id,
        session.id,
        update_request,
        Some(&user_dek),
    )
    .await
    .expect("Failed to update session settings");

    println!(
        "Update response system_prompt: {:?}",
        updated_settings.system_prompt
    );

    // Test 2: Fetch the settings back
    println!("Fetching session settings...");

    let fetched_settings = scribe_backend::services::chat::settings::get_session_settings(
        &test_app.db_pool,
        user.id,
        session.id,
        Some(&user_dek),
    )
    .await
    .expect("Failed to get session settings");

    println!(
        "Fetched system_prompt: {:?}",
        fetched_settings.system_prompt
    );

    // Test 3: Check what's actually stored in the database
    let (stored_ciphertext, stored_nonce) = test_app
        .db_pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session.id))
                .select((
                    chat_sessions::system_prompt_ciphertext,
                    chat_sessions::system_prompt_nonce,
                ))
                .first::<(Option<Vec<u8>>, Option<Vec<u8>>)>(conn)
        })
        .await
        .unwrap()
        .unwrap();

    println!(
        "Stored ciphertext: {:?}",
        stored_ciphertext.as_ref().map(|c| c.len())
    );
    println!("Stored nonce: {:?}", stored_nonce.as_ref().map(|n| n.len()));

    // Test 4: Manual decryption
    if let (Some(ciphertext), Some(nonce)) = (&stored_ciphertext, &stored_nonce) {
        match scribe_backend::crypto::decrypt_gcm(ciphertext, nonce, &user_dek) {
            Ok(plaintext_secret) => {
                use secrecy::ExposeSecret;
                let decrypted_string = String::from_utf8(plaintext_secret.expose_secret().clone())
                    .expect("Failed to convert to UTF-8");
                println!("Manual decryption successful: {:?}", decrypted_string);
            }
            Err(e) => {
                println!("Manual decryption failed: {:?}", e);
            }
        }
    }

    // Assertions
    assert!(
        fetched_settings.system_prompt.is_some(),
        "System prompt should be present"
    );
    assert_eq!(
        fetched_settings.system_prompt.as_ref().unwrap(),
        system_prompt_text,
        "Decrypted system prompt should match original"
    );
}

#[tokio::test]
async fn test_actual_api_route_for_system_prompt() {
    let test_app = test_helpers::spawn_app(false, false, false).await;

    // Create a test user and login to get auth cookie
    let user = test_helpers::db::create_test_user(
        &test_app.db_pool,
        "api_debug_user".to_string(),
        "password".to_string(),
    )
    .await
    .expect("Failed to create test user");

    let login_payload = serde_json::json!({
        "identifier": "api_debug_user",
        "password": "password"
    });
    let login_request = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
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

    // Create a character
    let character: DbCharacter = test_app
        .db_pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            use chrono::Utc;
            use scribe_backend::models::character_card::NewCharacter;
            use scribe_backend::schema::characters;

            let new_character = NewCharacter {
                user_id: user.id,
                spec: "character_card_v2".to_string(),
                spec_version: "2.0.0".to_string(),
                name: "API Debug Character".to_string(),
                visibility: Some("private".to_string()),
                created_at: Some(Utc::now()),
                updated_at: Some(Utc::now()),
                ..Default::default()
            };

            diesel::insert_into(characters::table)
                .values(&new_character)
                .get_result::<DbCharacter>(conn)
        })
        .await
        .unwrap()
        .unwrap();

    // Create a chat session
    let session = test_app
        .db_pool
        .get()
        .await
        .unwrap()
        .interact(move |conn| {
            use chrono::Utc;
            use scribe_backend::models::chats::NewChat;
            use scribe_backend::schema::chat_sessions;

            let new_chat = NewChat {
                id: Uuid::new_v4(),
                user_id: user.id,
                character_id: character.id,
                title_ciphertext: None,
                title_nonce: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                history_management_strategy: "message_window".to_string(),
                history_management_limit: 20,
                model_name: "gemini-2.5-flash".to_string(),
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
                player_chronicle_id: None,
            };

            diesel::insert_into(chat_sessions::table)
                .values(&new_chat)
                .returning(scribe_backend::models::chats::Chat::as_returning())
                .get_result(conn)
        })
        .await
        .unwrap()
        .unwrap();

    // First, set a system prompt via the UPDATE API route
    let system_prompt_text = "You are a debugging assistant for API testing.";
    let update_request = UpdateChatSettingsRequest {
        system_prompt: Some(system_prompt_text.to_string()),
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        model_name: None,
        history_management_strategy: None,
        history_management_limit: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: None,
    };

    println!(
        "Testing UPDATE via API route: PUT /api/chat/{}/settings",
        session.id
    );
    let update_api_request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chat/{}/settings", session.id))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(serde_json::to_string(&update_request).unwrap()))
        .unwrap();

    let update_response = test_app
        .router
        .clone()
        .oneshot(update_api_request)
        .await
        .unwrap();
    println!("Update response status: {}", update_response.status());
    assert_eq!(update_response.status(), StatusCode::OK);

    let update_body = update_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let update_settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&update_body).expect("Failed to deserialize update response");

    println!(
        "Update response system_prompt: {:?}",
        update_settings_resp.system_prompt
    );

    // Now, fetch the settings via the GET API route that the frontend uses
    println!(
        "Testing GET via API route: GET /api/chat/{}/settings",
        session.id
    );
    let get_api_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chat/{}/settings", session.id))
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::empty())
        .unwrap();

    let get_response = test_app
        .router
        .clone()
        .oneshot(get_api_request)
        .await
        .unwrap();
    println!("Get response status: {}", get_response.status());
    assert_eq!(get_response.status(), StatusCode::OK);

    let get_body = get_response.into_body().collect().await.unwrap().to_bytes();
    let get_settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&get_body).expect("Failed to deserialize get response");

    println!(
        "Get response system_prompt: {:?}",
        get_settings_resp.system_prompt
    );
    println!("Get response system_prompt (raw bytes): {:?}", get_body);

    // Assertions
    assert!(
        get_settings_resp.system_prompt.is_some(),
        "System prompt should be present in GET response"
    );
    assert_eq!(
        get_settings_resp.system_prompt.as_ref().unwrap(),
        system_prompt_text,
        "GET response system prompt should match original text"
    );
}

#[tokio::test]
async fn test_chat_chronicle_association() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let (_user, auth_cookie, _character, session) = setup_update_test_env(
        &test_app,
        "chronicle_assoc_user",
        "Chronicle Association Test Char",
        "test_chat_chronicle_association",
        "initial-model",
        "token_limit",
        10,
    )
    .await
    .expect("Failed to setup test environment");

    // First, create a chronicle
    let chronicle_payload = serde_json::json!({
        "name": "Test Chronicle",
        "description": "A test chronicle for association testing"
    });

    let create_chronicle_request = Request::builder()
        .method(Method::POST)
        .uri("/api/chronicles")
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(serde_json::to_string(&chronicle_payload).unwrap()))
        .unwrap();

    let chronicle_response = test_app
        .router
        .clone()
        .oneshot(create_chronicle_request)
        .await
        .unwrap();
    assert_eq!(chronicle_response.status(), StatusCode::CREATED);

    let chronicle_body = chronicle_response.into_body().collect().await.unwrap().to_bytes();
    let chronicle_data: serde_json::Value = serde_json::from_slice(&chronicle_body).unwrap();
    let chronicle_id = chronicle_data["id"].as_str().unwrap();
    let chronicle_uuid = Uuid::parse_str(chronicle_id).unwrap();

    // Now update the chat session to associate it with the chronicle
    let update_data = UpdateChatSettingsRequest {
        system_prompt: None,
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        model_name: None,
        history_management_strategy: None,
        history_management_limit: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: Some(chronicle_uuid),
    };

    let update_request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chat/{}/settings", session.id))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(serde_json::to_string(&update_data).unwrap()))
        .unwrap();

    let update_response = test_app.router.clone().oneshot(update_request).await.unwrap();
    assert_eq!(update_response.status(), StatusCode::OK);

    let update_body = update_response.into_body().collect().await.unwrap().to_bytes();
    let settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&update_body).expect("Failed to deserialize settings response");

    // Verify the chronicle association was saved
    assert_eq!(settings_resp.chronicle_id, Some(chronicle_uuid));

    // Now get the settings again to verify persistence
    let get_request = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/chat/{}/settings", session.id))
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::empty())
        .unwrap();

    let get_response = test_app.router.clone().oneshot(get_request).await.unwrap();
    assert_eq!(get_response.status(), StatusCode::OK);

    let get_body = get_response.into_body().collect().await.unwrap().to_bytes();
    let get_settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&get_body).expect("Failed to deserialize get settings response");

    // Verify the chronicle association persisted
    assert_eq!(get_settings_resp.chronicle_id, Some(chronicle_uuid));

    // Test removing the association by setting chronicle_id to None
    let remove_update_data = UpdateChatSettingsRequest {
        system_prompt: None,
        temperature: None,
        max_output_tokens: None,
        frequency_penalty: None,
        presence_penalty: None,
        top_k: None,
        top_p: None,
        seed: None,
        stop_sequences: None,
        model_name: None,
        history_management_strategy: None,
        history_management_limit: None,
        gemini_thinking_budget: None,
        gemini_enable_code_execution: None,
        chronicle_id: None, // This should clear the association
    };

    let remove_request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/api/chat/{}/settings", session.id))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::COOKIE, auth_cookie.clone())
        .body(Body::from(serde_json::to_string(&remove_update_data).unwrap()))
        .unwrap();

    let remove_response = test_app.router.clone().oneshot(remove_request).await.unwrap();
    assert_eq!(remove_response.status(), StatusCode::OK);

    let remove_body = remove_response.into_body().collect().await.unwrap().to_bytes();
    let remove_settings_resp: ChatSettingsResponse =
        serde_json::from_slice(&remove_body).expect("Failed to deserialize remove settings response");

    // Verify the chronicle association was removed - should be None
    assert_eq!(remove_settings_resp.chronicle_id, None);
}
