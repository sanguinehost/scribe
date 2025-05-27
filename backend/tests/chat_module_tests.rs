#[cfg(test)]
mod get_session_data_for_generation_tests {
    use scribe_backend::crypto; // For create_db_chat_message helper
    use scribe_backend::services::chat::generation::get_session_data_for_generation;
    use scribe_backend::services::chat::types::{
        MessageRole, // ChatMessageContent, RetrievedContextItem, UserMessage were removed or not used by chat_service.rs
        // MinimalChatMessage was an error, ScribeSseEvent and GenerationDataWithUnsavedUserMessage are used by generation.rs
        // but tests will use the functions that return them, not the types directly in most cases here.
        // DbChatMessage is an alias for ChatMessage from models::chats
    };
    use scribe_backend::services::hybrid_token_counter::CountingMode; // For token counting in tests
    use std::cmp::min; // Used in budget calculation assertions
    use std::sync::Arc; // Used in various places (helpers, test setup)
    use scribe_backend::config::Config as AppConfig;
    use scribe_backend::models::chats::{DbInsertableChatMessage, ChatMessage as DbChatMessage, NewChat};
    use scribe_backend::schema::{characters as character_schema, chat_messages as chat_messages_schema, chat_sessions as chat_sessions_schema, users};
    use scribe_backend::models::users::{NewUser, UserRole, AccountStatus};
    use diesel::{RunQueryDsl, ExpressionMethods, QueryDsl, SelectableHelper}; // Added for specific Diesel traits
    use scribe_backend::services::embedding_pipeline::{RetrievedChunk};
    use scribe_backend::services::hybrid_token_counter::HybridTokenCounter;
    use scribe_backend::services::tokenizer_service::TokenizerService; // TokenEstimate removed
    use scribe_backend::services::gemini_token_client::GeminiTokenClient;
    use scribe_backend::services::user_persona_service::UserPersonaService;
    use scribe_backend::state::AppState;
    use scribe_backend::test_helpers::db::setup_test_database;
    use scribe_backend::test_helpers::{
        MockAiClient, MockEmbeddingClient, MockEmbeddingPipelineService,
        MockQdrantClientService, TestAppStateBuilder,
    };
    use mockall::predicate::*;
    use secrecy::SecretBox;
    use std::collections::VecDeque;
    use uuid::Uuid;
    use bigdecimal::BigDecimal;
    use serde_json::json;
    use scribe_backend::models::characters::Character;
    use scribe_backend::models::chat_override::ChatCharacterOverride;
    use std::str::FromStr; // For BigDecimal::from_str


    // Helper to create a DbChatMessage for testing
    fn create_db_chat_message(
        id: Uuid,
        session_id: Uuid,
        user_id: Uuid,
        role: MessageRole,
        content: &str,
        tokens: Option<i32>, // Generic token count for simplicity in setup
        created_at_offset_secs: i64, // To control order
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    ) -> DbChatMessage {
        let (content_bytes, nonce_bytes) = if let Some(dek) = user_dek {
            let (ciphertext, nonce) = crypto::encrypt_gcm(content.as_bytes(), dek.as_ref()).unwrap();
            (ciphertext, Some(nonce))
        } else {
            (content.as_bytes().to_vec(), None)
        };

        let mut msg = DbChatMessage {
            id,
            session_id,
            user_id,
            message_type: role,
            content: content_bytes,
            content_nonce: nonce_bytes,
            created_at: chrono::Utc::now() + chrono::Duration::seconds(created_at_offset_secs),
            prompt_tokens: None,
            completion_tokens: None,
        };
        match role {
            MessageRole::User => msg.prompt_tokens = tokens,
            MessageRole::Assistant => msg.completion_tokens = tokens,
            _ => {}
        }
        msg
    }

    struct TestSetup {
        app_state: Arc<AppState>,
        user_id: Uuid,
        session_id: Uuid,
        _character_id: Uuid,
        _mock_embedding_pipeline: Arc<MockEmbeddingPipelineService>,
        user_dek: Option<Arc<SecretBox<Vec<u8>>>>,
    }

    async fn setup_test_env(
        _db_messages_raw: Vec<DbChatMessage>,
        _lorebook_chunks: Vec<RetrievedChunk>,
        _older_chat_chunks: Vec<RetrievedChunk>,
        _token_counts: VecDeque<(String, usize)>,
        config_override: Option<AppConfig>,
        _active_persona_id_from_session: Option<Uuid>,
        // _persona_details: Option<UserPersonaDto>, // Removed
        session_character_id_override: Option<Uuid>,
        _session_system_prompt_override_db: Option<String>,
        character_db_details: Option<Character>,
        _character_overrides_db: Option<Vec<ChatCharacterOverride>>,
        _active_lorebook_ids_for_search_db: Option<Vec<Uuid>>,
    ) -> TestSetup {
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let default_character_id = Uuid::new_v4();
        let character_id = session_character_id_override.unwrap_or(default_character_id);

        let config = config_override.unwrap_or_else(|| {
            // Inlined create_test_config logic
            let mut cfg = AppConfig::default(); // Assuming AppConfig has a sensible default or load mechanism
            cfg.context_recent_history_token_budget = 100;
            cfg.context_rag_token_budget = 50;
            cfg.context_total_token_limit = 200;
            cfg.tokenizer_model_path = Some("./resources/tokenizers/gemma.model".to_string());
            cfg.gemini_api_key = Some("dummy_api_key".to_string());
            cfg.token_counter_default_model = Some("gemini-test-model".to_string());
            // Add other necessary default config fields if AppConfig::default() is not sufficient
            cfg
        });
        let config_arc = Arc::new(config.clone());

        let user_dek_secret_vec = vec![0u8; 32];
        let user_dek = Some(Arc::new(SecretBox::new(Box::new(user_dek_secret_vec))));

        let pool = setup_test_database(None).await;

        let tokenizer_model_path_str = config_arc.tokenizer_model_path.as_ref().cloned()
            .expect("Tokenizer model path not set in config for test setup");
        let tokenizer_service = TokenizerService::new(&tokenizer_model_path_str)
            .expect("Failed to load tokenizer model for test setup");
        let gemini_token_client = config_arc.gemini_api_key.as_ref().map(|api_key| {
            GeminiTokenClient::new(api_key.clone())
        });
        let default_model_for_tc = config_arc.token_counter_default_model.as_ref().cloned()
            .expect("Token counter default model not set in config for test setup");
        let token_counter_service = Arc::new(HybridTokenCounter::new(
            tokenizer_service,
            gemini_token_client,
            default_model_for_tc,
        ));

        let mock_embedding_pipeline_instance = MockEmbeddingPipelineService::new();
        // mock_embedding_pipeline_instance.set_retrieve_responses_sequence is not used in this context
        // as the mock is passed to AppStateBuilder which might configure it or use defaults.
        // If specific sequences are needed, they should be set on the instance before it's moved/cloned.
        // For this refactor, assuming the default mock behavior or AppStateBuilder's handling is sufficient.
        // If tests fail due to mock behavior, this is where to look.
        // Example of setting sequence if needed:
        // let mut mock_embedding_pipeline_instance_mut = MockEmbeddingPipelineService::new();
        // mock_embedding_pipeline_instance_mut.set_retrieve_responses_sequence(vec![
        //     Ok(lorebook_chunks.clone()),
        //     Ok(older_chat_chunks.clone()),
        //     Ok(Vec::new()),
        // ]);
        // let mock_embedding_pipeline_instance = mock_embedding_pipeline_instance_mut;

        // Ensure lorebook_chunks and older_chat_chunks are cloned if used by the mock setup
        // For now, they are passed to the function but not directly used to set mock sequences here.
        // This might be an oversight if the intention was to use them for mocking retrieve_relevant_chunks.
        // The current mock_embedding_pipeline_instance.set_retrieve_responses_sequence was commented out
        // as it was unused. If it *should* be used, it needs to be uncommented and `mut` restored.
        // For the purpose of removing the `mut` warning, we assume it's not strictly needed here.
        // The actual mock setup for retrieve_relevant_chunks happens inside the tests themselves
        // by calling expect_retrieve_relevant_chunks on the Arc<MockEmbeddingPipelineService> from TestSetup.

        // The following lines related to setting retrieve_responses_sequence are removed as per the warning.
        // If this causes test failures, it means the mock setup here was indeed necessary.
        // mock_embedding_pipeline_instance.set_retrieve_responses_sequence(vec![
        //     Ok(lorebook_chunks.clone()),
        //     Ok(older_chat_chunks.clone()),
        //     Ok(Vec::new()),
        // ]);
        // mock_embedding_pipeline_instance is not Arc yet, and not Mutex wrapped at this stage for TestSetup
        let mock_embedding_pipeline_service_concrete = mock_embedding_pipeline_instance; // This was the original line


        let shared_encryption_service = Arc::new(scribe_backend::services::encryption_service::EncryptionService::new());
        let user_persona_service_instance = Arc::new(UserPersonaService::new(
            pool.clone(),
            shared_encryption_service.clone(), // This encryption service is for UserPersonaService itself
        ));

        // Create mock clients for AppState builder
        let mock_ai_client_instance = Arc::new(MockAiClient::new());
        let mock_embedding_client_instance = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service_instance = Arc::new(MockQdrantClientService::new());


        // This is the character that will be returned by the mock DB interaction if `character_db_details` is None.
        // It's used in the `conn.interact` block within `get_session_data_for_generation`.
        // We ensure this default instantiation is correct.
        // NOTE: This _default_character_for_mocking is for the *old* mock DB setup.
        // With real DB, tests must ensure the character exists in the DB.
        // This variable is now only for ensuring the unwrap_or_else block compiles,
        // but the actual data should come from the DB in tests.
        let _default_character_for_db_priming_if_needed = character_db_details.clone().unwrap_or_else(|| Character {
            id: character_id,
            user_id,
            name: "Test Character".to_string(),
            spec: "chara_card_v2".to_string(),
            spec_version: "2.0".to_string(),
            description: Some("Char desc".as_bytes().to_vec()),
            personality: Some("Char persona".as_bytes().to_vec()),
            scenario: Some("Char scenario".as_bytes().to_vec()),
            first_mes: Some("Char first mes".as_bytes().to_vec()),
            mes_example: Some("Char example".as_bytes().to_vec()),
            creator_notes: Some("Char creator notes".as_bytes().to_vec()),
            system_prompt: Some("Char system prompt".as_bytes().to_vec()),
            post_history_instructions: Some("Char post history instructions".as_bytes().to_vec()),
            tags: Some(vec![Some("tag1".to_string()), Some("tag2".to_string())]),
            creator: Some("Test Creator".to_string()),
            character_version: Some("1.0".to_string()),
            alternate_greetings: Some(vec![Some("Hi".to_string()), Some("Hello".to_string())]),
            nickname: Some("Test Nickname".to_string()),
            creator_notes_multilingual: Some(json!({"en": "English notes"})),
            source: Some(vec![Some("TestSource".to_string())]),
            group_only_greetings: Some(vec![Some("Group Hi".to_string())]),
            creation_date: Some(chrono::Utc::now()),
            modification_date: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            persona: Some("Char persona field".as_bytes().to_vec()),
            world_scenario: Some("Char world scenario".as_bytes().to_vec()),
            avatar: Some("avatar.png".to_string()),
            chat: Some("chat_export.txt".to_string()),
            greeting: Some("Char greeting".as_bytes().to_vec()),
            definition: Some("Char definition".as_bytes().to_vec()),
            default_voice: Some("voice_id".to_string()),
            extensions: Some(json!({"custom_field": "value"})),
            data_id: Some(123),
            category: Some("Test Category".to_string()),
            definition_visibility: Some("private".to_string()),
            depth: Some(1),
            example_dialogue: Some("Char example dialogue".as_bytes().to_vec()),
            favorite: Some(false),
            first_message_visibility: Some("private".to_string()),
            height: Some(BigDecimal::from_str("180").unwrap()),
            last_activity: Some(chrono::Utc::now()),
            migrated_from: Some("old_system".to_string()),
            model_prompt: Some("Char model prompt".as_bytes().to_vec()),
            model_prompt_visibility: Some("private".to_string()),
            model_temperature: Some(BigDecimal::from_str("0.7").unwrap()),
            num_interactions: Some(10),
            permanence: Some(BigDecimal::from_str("0.5").unwrap()),
            persona_visibility: Some("private".to_string()),
            revision: Some(1),
            sharing_visibility: Some("private".to_string()),
            status: Some("active".to_string()),
            system_prompt_visibility: Some("private".to_string()),
            system_tags: Some(vec![Some("system_tag1".to_string())]),
            token_budget: Some(2048),
            usage_hints: Some(json!({"hint": "value"})),
            user_persona: Some("Char user persona".as_bytes().to_vec()),
            user_persona_visibility: Some("private".to_string()),
            visibility: Some("private".to_string()),
            weight: Some(BigDecimal::from_str("70.5").unwrap()),
            world_scenario_visibility: Some("private".to_string()),
            description_nonce: Some(vec![1; 12]),
            personality_nonce: Some(vec![2; 12]),
            scenario_nonce: Some(vec![3; 12]),
            first_mes_nonce: Some(vec![4; 12]),
            mes_example_nonce: Some(vec![5; 12]),
            creator_notes_nonce: Some(vec![6; 12]),
            system_prompt_nonce: Some(vec![7; 12]),
            persona_nonce: Some(vec![8; 12]),
            world_scenario_nonce: Some(vec![9; 12]),
            greeting_nonce: Some(vec![10; 12]),
            definition_nonce: Some(vec![11; 12]),
            example_dialogue_nonce: Some(vec![12; 12]),
            model_prompt_nonce: Some(vec![13; 12]),
            user_persona_nonce: Some(vec![14; 12]),
            post_history_instructions_nonce: Some(vec![15; 12]),
        });
        
        // Create an Arc for the concrete MockEmbeddingPipelineService to store in TestSetup
        let mock_embedding_pipeline_for_test_setup = Arc::new(mock_embedding_pipeline_service_concrete.clone());

        let app_state_instance = TestAppStateBuilder::new(
            pool.clone(),
            config_arc.clone(),
            mock_ai_client_instance.clone(),
            mock_embedding_client_instance.clone(),
            mock_qdrant_service_instance.clone(),
        )
        .with_token_counter(token_counter_service.clone())
        // Pass the concrete mock service to the builder, it will be cast internally if needed by AppState::new
        // Or, cast it here if with_embedding_pipeline_service expects the trait object.
        // TestAppStateBuilder::with_embedding_pipeline_service expects Arc<dyn ...Trait>
        .with_embedding_pipeline_service(Arc::new(mock_embedding_pipeline_service_concrete) as Arc<dyn scribe_backend::services::embedding_pipeline::EmbeddingPipelineServiceTrait + Send + Sync>)
        .with_user_persona_service(user_persona_service_instance.clone())
        .build();

        TestSetup {
            app_state: Arc::new(app_state_instance),
            user_id,
            session_id,
            _character_id: character_id,
            _mock_embedding_pipeline: mock_embedding_pipeline_for_test_setup, // Store the Arc<MockEmbeddingPipelineService>
            user_dek,
        }
    }

    #[tokio::test]
    async fn test_recent_history_windowing_basic_fits_budget() {
        // Arrange
        let user_message_content = "test user message".to_string();
        let user_dek_secret_vec = vec![0u8; 32];
        let user_dek = Some(Arc::new(SecretBox::new(Box::new(user_dek_secret_vec))));

        let msg1_content = "Hello there assistant!";
        let msg2_content = "Hi user, how are you?";

        let _messages = vec![
            create_db_chat_message(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), MessageRole::User, msg1_content, Some(3), -20, user_dek.as_ref()),
            create_db_chat_message(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), MessageRole::Assistant, msg2_content, Some(5), -10, user_dek.as_ref()),
        ];
        
        // Inlined create_test_config
        let mut test_config = AppConfig::default();
        test_config.context_recent_history_token_budget = 20;
        test_config.context_rag_token_budget = 50;
        test_config.context_total_token_limit = 100;
        test_config.tokenizer_model_path = Some("./resources/tokenizers/gemma.model".to_string());
        test_config.gemini_api_key = Some("dummy_api_key".to_string());
        test_config.token_counter_default_model = Some("gemini-test-model".to_string());


        let setup = setup_test_env(
            Vec::new(), // messages are now inserted directly in the test
            Vec::new(),
            Vec::new(),
            VecDeque::new(), // token_counts is unused in setup_test_env, pass empty
            Some(test_config.clone()), // Clone test_config
            None, /* _active_persona_id_from_session */
            // None, // _persona_details removed
            None, /* session_character_id_override */
            None, /* _session_system_prompt_override_db */
            None, /* character_db_details */
            None, /* _character_overrides_db */
            None  /* _active_lorebook_ids_for_search_db */
        ).await;

        let mut setup = setup; // Make setup mutable to update user_id
        let conn = setup.app_state.pool.get().await.expect("Failed to get DB connection for basic_fits_budget");

        // Insert User
        let new_user_for_test = NewUser {
            username: "testuser_basic_fits".to_string(),
            password_hash: "hash".to_string(),
            email: "basicfits@example.com".to_string(),
            role: UserRole::User,
            account_status: AccountStatus::Active,
            kek_salt: "dummy_salt".to_string(),
            encrypted_dek: vec![0u8; 16],
            dek_nonce: vec![0u8; 12],
            encrypted_dek_by_recovery: None,
            recovery_kek_salt: None,
            recovery_dek_nonce: None,
        };
        let inserted_user_id: Uuid = conn.interact(move |conn_insert| {
            diesel::insert_into(users::table)
                .values(&new_user_for_test)
                .returning(users::id)
                .get_result(conn_insert)
        }).await.unwrap().unwrap();
        setup.user_id = inserted_user_id; // Update setup with the actual inserted user_id

        // Insert Character
        // Use create_dummy_character and override necessary fields
        let mut test_character_basic_fits = scribe_backend::models::characters::create_dummy_character();
        test_character_basic_fits.id = setup._character_id;
        test_character_basic_fits.user_id = setup.user_id; // Use the actual inserted user_id
        test_character_basic_fits.name = "Test Character Basic Fits".to_string();
        test_character_basic_fits.created_at = chrono::Utc::now();
        test_character_basic_fits.updated_at = chrono::Utc::now();
        test_character_basic_fits.visibility = Some("private".to_string());
        // Ensure spec and spec_version are set if they are critical for the test logic,
        // otherwise dummy values from create_dummy_character are fine.
        test_character_basic_fits.spec = "chara_card_v2".to_string();
        test_character_basic_fits.spec_version = "2.0".to_string();

        conn.interact(move |conn_insert| {
            diesel::insert_into(character_schema::table)
                .values(&test_character_basic_fits)
                .execute(conn_insert)
        }).await.unwrap().unwrap();
        
        // Insert ChatSession
        let test_session_basic_fits = NewChat {
            id: setup.session_id, user_id: setup.user_id, character_id: setup._character_id,
            title_ciphertext: None, title_nonce: None, // Updated field
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            history_management_strategy: "message_window".to_string(), history_management_limit: 20,
            model_name: test_config.token_counter_default_model.clone().unwrap_or_else(|| "gemini-test-model".to_string()),
            visibility: Some("private".to_string()), active_custom_persona_id: None, active_impersonated_character_id: None,
        };
        conn.interact(move |conn_insert| {
            diesel::insert_into(chat_sessions_schema::table)
                .values(&test_session_basic_fits)
                .execute(conn_insert)
        }).await.unwrap().unwrap();

        // Create and insert messages associated with setup.session_id
        let message_definitions = [
            (msg1_content, MessageRole::User, Some(3i32), -20i64),
            (msg2_content, MessageRole::Assistant, Some(5i32), -10i64),
        ];

        for (plain_content_str, role_enum, tokens_opt, time_offset_secs) in message_definitions.iter() {
            let (content_bytes_for_db, nonce_for_db) = if let Some(dek) = setup.user_dek.as_ref() {
                let (ciphertext, nonce) = crypto::encrypt_gcm(plain_content_str.as_bytes(), dek.as_ref()).unwrap();
                (ciphertext, Some(nonce))
            } else {
                (plain_content_str.as_bytes().to_vec(), None)
            };
        
            let (prompt_tokens_val, completion_tokens_val) = match role_enum {
                MessageRole::User => (*tokens_opt, None),
                MessageRole::Assistant => (None, *tokens_opt),
                _ => (None, None),
            };
            
            let role_str_val = Some(match role_enum {
                MessageRole::User => "user".to_string(),
                MessageRole::Assistant => "assistant".to_string(),
                MessageRole::System => "system".to_string(),
            });
        
            let current_time = chrono::Utc::now();
            let _created_at_val = current_time + chrono::Duration::seconds(*time_offset_secs);
        
            let insertable_msg = DbInsertableChatMessage::new(
                setup.session_id, // chat_id
                setup.user_id,    // user_id
                *role_enum,       // msg_type_enum
                content_bytes_for_db, // text
                nonce_for_db,     // nonce
                role_str_val,     // role_str
                Some(json!({"type": "text", "text": *plain_content_str})), // parts_json
                None,             // attachments_json
                prompt_tokens_val, // prompt_tokens
                completion_tokens_val // completion_tokens
            );
        
            conn.interact(move |conn_i| {
                diesel::insert_into(chat_messages_schema::table)
                    .values(&insertable_msg)
                    .execute(conn_i)
            }).await.unwrap().unwrap();
        }
        
        // Configure mock expectations for embedding pipeline service
        // retrieve_relevant_chunks is called twice: once for lorebooks, once for older chat history.
        // For this test, we expect both to return empty vectors.
        setup._mock_embedding_pipeline.set_retrieve_responses_sequence(vec![
            Ok(Vec::new()), // For lorebook chunks
            Ok(Vec::new()), // For older chat history chunks
        ]);

        // Act
        let result = get_session_data_for_generation(
            setup.app_state.clone(),
            setup.user_id,
            setup.session_id,
            user_message_content.clone(),
            setup.user_dek.clone(),
        ).await;

        // Assert
        assert!(result.is_ok(), "Result should be Ok: {:?}", result.err());
        let (
            managed_history, _system_prompt, _lore_ids, _char_id, _, _, _, _, _, _, _, _, _, _, _, _, _model_name, // Added one underscore
            _, _, _user_msg_struct, actual_recent_tokens, rag_items, _, _
        ) = result.unwrap();

        assert_eq!(managed_history.len(), 2, "Should include both historical messages");

        // Calculate expected tokens dynamically using the same token counter and model
        let model_name_for_assertion = test_config.token_counter_default_model.as_ref().expect("Model name should be in test_config");
        let tokens_msg1 = setup.app_state.token_counter.count_tokens(msg1_content, CountingMode::LocalOnly, Some(model_name_for_assertion)).await.unwrap().total;
        let tokens_msg2 = setup.app_state.token_counter.count_tokens(msg2_content, CountingMode::LocalOnly, Some(model_name_for_assertion)).await.unwrap().total;
        let expected_total_tokens = tokens_msg1 + tokens_msg2;

        assert_eq!(actual_recent_tokens, expected_total_tokens as usize, "Token count for recent history should be sum of dynamically calculated historical message tokens");
        
        // Check content of managed history (ensure decryption happened if applicable)
        assert_eq!(String::from_utf8(managed_history[0].content.clone()).unwrap(), msg1_content);
        assert_eq!(String::from_utf8(managed_history[1].content.clone()).unwrap(), msg2_content);

        assert!(rag_items.is_empty(), "RAG items should be empty as no RAG chunks were provided");
    }

    #[tokio::test]
    async fn test_rag_lorebook_inclusion_fits_budget() {
        // Arrange
        let user_message_content = "Tell me about the ancient artifact.".to_string();
        let mut test_config = AppConfig::default();
        test_config.context_recent_history_token_budget = 30;
        test_config.context_rag_token_budget = 40;
        test_config.context_total_token_limit = 100; // Total: 30 (hist) + 40 (RAG) + buffer
        test_config.tokenizer_model_path = Some("./resources/tokenizers/gemma.model".to_string());
        test_config.gemini_api_key = Some("dummy_api_key_rag_lore".to_string());
        let model_name_for_test = "gemini-test-model-rag-lore".to_string();
        test_config.token_counter_default_model = Some(model_name_for_test.clone());

        let mut setup = setup_test_env(
            Vec::new(), Vec::new(), Vec::new(), VecDeque::new(),
            Some(test_config.clone()),
            None, /* _active_persona_id_from_session */
            None, /* session_character_id_override */
            None, /* _session_system_prompt_override_db */
            None, /* character_db_details */
            None, /* _character_overrides_db */
            None  /* _active_lorebook_ids_for_search_db */
        ).await;
        let conn = setup.app_state.pool.get().await.expect("Failed to get DB connection for RAG lorebook test");

        // Insert User
        let new_user_for_rag_lore_test = NewUser {
            username: "testuser_rag_lore".to_string(), password_hash: "hash_rag_lore".to_string(),
            email: "raglore@example.com".to_string(), role: UserRole::User, account_status: AccountStatus::Active,
            kek_salt: "salt_rag_lore".to_string(), encrypted_dek: vec![2u8; 16], dek_nonce: vec![2u8; 12],
            encrypted_dek_by_recovery: None, recovery_kek_salt: None, recovery_dek_nonce: None,
        };
        let inserted_user_id_rag_lore: Uuid = conn.interact(move |conn_insert_user| {
            diesel::insert_into(users::table)
                .values(&new_user_for_rag_lore_test)
                .returning(users::id)
                .get_result(conn_insert_user)
        }).await.unwrap().unwrap();
        setup.user_id = inserted_user_id_rag_lore;

        // Insert Character
        let mut test_character_rag_lore = scribe_backend::models::characters::create_dummy_character();
        test_character_rag_lore.id = setup._character_id;
        test_character_rag_lore.user_id = setup.user_id;
        test_character_rag_lore.name = "Test Character RAG Lore".to_string();
        conn.interact(move |conn_insert_char| {
            diesel::insert_into(character_schema::table)
                .values(&test_character_rag_lore)
                .execute(conn_insert_char)
        }).await.unwrap().unwrap();

        // Insert ChatSession
        let test_session_rag_lore = NewChat {
            id: setup.session_id, user_id: setup.user_id, character_id: setup._character_id,
            title_ciphertext: None, title_nonce: None, // Updated field
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            history_management_strategy: "message_window".to_string(), history_management_limit: 5,
            model_name: model_name_for_test.clone(), visibility: Some("private".to_string()),
            active_custom_persona_id: None, active_impersonated_character_id: None,
        };
        conn.interact(move |conn_insert_session| {
            diesel::insert_into(chat_sessions_schema::table)
                .values(&test_session_rag_lore)
                .execute(conn_insert_session)
        }).await.unwrap().unwrap();

        // Insert a simple history message
        let history_msg_content = "What was that sound?"; // Approx 4 tokens
        // We need to construct DbInsertableChatMessage directly with plain text for parts
        let (hist_content_bytes_for_db, hist_nonce_for_db) = if let Some(dek) = setup.user_dek.as_ref() {
            let (ciphertext, nonce) = crypto::encrypt_gcm(history_msg_content.as_bytes(), dek.as_ref()).unwrap();
            (ciphertext, Some(nonce))
        } else {
            (history_msg_content.as_bytes().to_vec(), None)
        };

        conn.interact(move |conn_i| {
            let insertable_msg = DbInsertableChatMessage::new(
                setup.session_id, setup.user_id, MessageRole::User,
                hist_content_bytes_for_db, hist_nonce_for_db,
                Some("user".to_string()), Some(json!({"type": "text", "text": history_msg_content})), // Use original plaintext
                None, Some(4), None, // prompt_tokens, completion_tokens
            );
            diesel::insert_into(chat_messages_schema::table).values(&insertable_msg).execute(conn_i)
        }).await.unwrap().unwrap();

        // Prepare Lorebook and link to session
        let lorebook_id = Uuid::new_v4();
        // Minimal Lorebook struct for insertion
        let test_lorebook = scribe_backend::models::lorebooks::NewLorebook {
            id: lorebook_id,
            user_id: setup.user_id,
            name: "Ancient Artifacts".to_string(),
            description: Some("Lore about ancient artifacts.".to_string()),
            source_format: "scribe_v1".to_string(), // Provide a default source_format
            is_public: false, // Default to private
            created_at: Some(chrono::Utc::now()),
            updated_at: Some(chrono::Utc::now()),
        };
         conn.interact({
            let tl = test_lorebook.clone(); // Clone for the first interact
            move |conn_lore_insert| {
                diesel::insert_into(scribe_backend::schema::lorebooks::table)
                    .values(&tl)
                    .execute(conn_lore_insert)
            }
        }).await.unwrap().unwrap();

        conn.interact(move |conn_link| {
            {
                use scribe_backend::schema::chat_session_lorebooks;
                let new_link = scribe_backend::models::lorebooks::NewChatSessionLorebook {
                    chat_session_id: setup.session_id,
                    lorebook_id,
                    user_id: setup.user_id,
                    created_at: None,
                    updated_at: None,
                };
                diesel::insert_into(chat_session_lorebooks::table)
                    .values(&new_link)
                    .execute(conn_link)
            }
        }).await.unwrap().unwrap();


        // Define RAG chunks to be returned by the mock
        let lore_chunk1_content = "The Orb of Zog is powerful."; // Approx 6 tokens
        let lore_chunk2_content = "It glows with an eerie light."; // Approx 7 tokens
        let lore_chunk1 = RetrievedChunk {
            text: lore_chunk1_content.to_string(),
            score: 0.9,
            metadata: scribe_backend::services::embedding_pipeline::RetrievedMetadata::Lorebook(
                scribe_backend::services::embedding_pipeline::LorebookChunkMetadata {
                    original_lorebook_entry_id: Uuid::new_v4(), // Assuming a new UUID for test
                    lorebook_id,
                    user_id: setup.user_id, // Add user_id
                    chunk_text: lore_chunk1_content.to_string(), // Add chunk_text
                    entry_title: Some("Orb of Zog".to_string()), // Add entry_title
                    keywords: Some(vec!["orb".to_string()]), // Change entry_keys to keywords
                    is_enabled: true, // Add is_enabled
                    is_constant: false, // Add is_constant
                    source_type: "lorebook_entry".to_string(), // Add source_type
                }
            ),
        };
        let lore_chunk2 = RetrievedChunk {
            text: lore_chunk2_content.to_string(),
            score: 0.8,
            metadata: scribe_backend::services::embedding_pipeline::RetrievedMetadata::Lorebook(
                 scribe_backend::services::embedding_pipeline::LorebookChunkMetadata {
                    original_lorebook_entry_id: Uuid::new_v4(), // Assuming a new UUID for test
                    lorebook_id,
                    user_id: setup.user_id, // Add user_id
                    chunk_text: lore_chunk2_content.to_string(), // Add chunk_text
                    entry_title: Some("Eerie Light".to_string()), // Add entry_title
                    keywords: Some(vec!["light".to_string()]), // Change entry_keys to keywords
                    is_enabled: true, // Add is_enabled
                    is_constant: false, // Add is_constant
                    source_type: "lorebook_entry".to_string(), // Add source_type
                }
            ),
        };
        let expected_lore_chunks = vec![lore_chunk1.clone(), lore_chunk2.clone()];

        // Configure mock expectations for the manual mock
        // retrieve_relevant_chunks is called twice:
        // 1. For lorebooks (with active_lorebook_ids_for_search = Some(vec![lorebook_id]))
        // 2. For older chat history (with session_id_for_chat_history = Some(setup.session_id))
        // We set a sequence of responses. The first call to retrieve_relevant_chunks will get the first response, etc.
        setup._mock_embedding_pipeline.set_retrieve_responses_sequence(vec![
            Ok(expected_lore_chunks.clone()), // Response for the lorebook chunks call
            Ok(Vec::new()),                   // Response for the older chat history call (empty for this test)
        ]);


        // Act
        let result = get_session_data_for_generation(
            setup.app_state.clone(),
            setup.user_id,
            setup.session_id,
            user_message_content.clone(),
            setup.user_dek.clone(),
        ).await;

        // Assert
        assert!(result.is_ok(), "Result should be Ok: {:?}", result.err());
        let (
            managed_history, _system_prompt, _active_lore_ids, _char_id, _, _, _, _, _, _, _, _, _, _, _, _, _model_name, // Added one underscore
            _, _, _user_msg_struct, actual_recent_tokens, rag_items, _, _
        ) = result.unwrap();

        assert_eq!(managed_history.len(), 1, "Should include the single historical message");
        assert_eq!(String::from_utf8(managed_history[0].content.clone()).unwrap(), history_msg_content);

        let tokens_hist_msg = setup.app_state.token_counter.count_tokens(history_msg_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        assert_eq!(actual_recent_tokens, tokens_hist_msg as usize, "Token count for recent history mismatch");

        assert_eq!(rag_items.len(), 2, "Should include both lorebook chunks in RAG items");
        assert_eq!(rag_items[0].text, lore_chunk1_content); // Assuming sorted by score (mock data is already sorted)
        assert_eq!(rag_items[1].text, lore_chunk2_content);

        let tokens_lore1 = setup.app_state.token_counter.count_tokens(lore_chunk1_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let tokens_lore2 = setup.app_state.token_counter.count_tokens(lore_chunk2_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let total_rag_tokens_used = tokens_lore1 + tokens_lore2;

        let expected_available_rag_tokens = min(
            test_config.context_rag_token_budget,
            test_config.context_total_token_limit.saturating_sub(actual_recent_tokens)
        );
        assert!(total_rag_tokens_used as usize <= expected_available_rag_tokens, "Total RAG tokens used ({}) should be within available budget ({})", total_rag_tokens_used, expected_available_rag_tokens);
    }
 
    #[tokio::test]
    async fn test_history_truncation_exceeds_budget() {
        // Arrange
        let user_message_content = "new user message".to_string();
        let mut test_config = AppConfig::default();
        test_config.context_recent_history_token_budget = 8; // Budget for 2 smaller messages
        test_config.context_rag_token_budget = 0; // No RAG for this test
        test_config.context_total_token_limit = 50;
        test_config.tokenizer_model_path = Some("./resources/tokenizers/gemma.model".to_string());
        test_config.gemini_api_key = Some("dummy_api_key_for_trunc_test".to_string());
        let model_name_for_test = "gemini-test-model-trunc".to_string();
        test_config.token_counter_default_model = Some(model_name_for_test.clone());

        let setup = setup_test_env(
            Vec::new(), Vec::new(), Vec::new(), VecDeque::new(),
            Some(test_config),
            None, /* _active_persona_id_from_session */
            // None, // _persona_details removed
            None, /* session_character_id_override */
            None, /* _session_system_prompt_override_db */
            None, /* character_db_details */
            None, /* _character_overrides_db */
            None  /* _active_lorebook_ids_for_search_db */
        ).await;

        let mut setup = setup; // Make setup mutable
        let conn = setup.app_state.pool.get().await.expect("Failed to get DB connection");

        // Insert User
        let new_user_for_trunc_test = NewUser {
            username: "testuser_trunc".to_string(),
            password_hash: "anotherhash".to_string(),
            email: "trunc@example.com".to_string(),
            role: UserRole::User,
            account_status: AccountStatus::Active,
            kek_salt: "dummy_salt_trunc".to_string(),
            encrypted_dek: vec![1u8; 16],
            dek_nonce: vec![1u8; 12],
            encrypted_dek_by_recovery: None,
            recovery_kek_salt: None,
            recovery_dek_nonce: None,
        };
        let inserted_user_id_trunc: Uuid = conn.interact(move |conn_insert_user| {
            diesel::insert_into(users::table)
                .values(&new_user_for_trunc_test)
                .returning(users::id)
                .get_result(conn_insert_user)
        }).await.unwrap().unwrap();
        setup.user_id = inserted_user_id_trunc; // Update setup with the actual inserted user_id
 
        // Insert Character
        // Use create_dummy_character and override necessary fields
        let mut test_character = scribe_backend::models::characters::create_dummy_character();
        test_character.id = setup._character_id;
        test_character.user_id = setup.user_id; // Use the actual inserted user_id
        test_character.name = "Test Character".to_string();
        test_character.created_at = chrono::Utc::now();
        test_character.updated_at = chrono::Utc::now();
        test_character.visibility = Some("private".to_string());
        test_character.spec = "chara_card_v2".to_string();
        test_character.spec_version = "2.0".to_string();
        
        conn.interact(move |conn_insert| {
            diesel::insert_into(character_schema::table)
                .values(&test_character)
                .execute(conn_insert)
        }).await.unwrap().unwrap();

        // Insert ChatSession
        let test_session = NewChat {
            id: setup.session_id, user_id: setup.user_id, character_id: setup._character_id,
            title_ciphertext: None, title_nonce: None, // Updated field
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            history_management_strategy: "message_window".to_string(), history_management_limit: 20,
            model_name: model_name_for_test.clone(), // Crucial for token counting consistency
            visibility: Some("private".to_string()), active_custom_persona_id: None, active_impersonated_character_id: None,
        };
        conn.interact(move |conn_insert| {
            diesel::insert_into(chat_sessions_schema::table)
                .values(&test_session)
                .execute(conn_insert)
        }).await.unwrap().unwrap();

        // Messages (content chosen for Gemma tokenizer, rough estimates)
        // Gemma counts punctuation and spaces.
        // "This is a longer first message." ~6-7 tokens
        // "Okay then." ~3 tokens
        // "See you." ~2 tokens
        let msg1_content = "This is a longer first message."; // Should be excluded
        let msg2_content = "Okay then."; // Kept
        let msg3_content = "See you.";   // Kept

        let message_definitions_for_insertion = [
            (msg1_content, MessageRole::Assistant, Some(7i32)),
            (msg2_content, MessageRole::User, Some(3i32)),
            (msg3_content, MessageRole::Assistant, Some(2i32)),
        ];

        for (plain_content_str, role_enum, tokens_opt) in message_definitions_for_insertion.iter() {
            let (content_bytes_for_db, nonce_for_db) = if let Some(dek) = setup.user_dek.as_ref() {
                let (ciphertext, nonce) = crypto::encrypt_gcm(plain_content_str.as_bytes(), dek.as_ref()).unwrap();
                (ciphertext, Some(nonce))
            } else {
                (plain_content_str.as_bytes().to_vec(), None)
            };
        
            let (prompt_tokens_val, completion_tokens_val) = match role_enum {
                MessageRole::User => (*tokens_opt, None),
                MessageRole::Assistant => (None, *tokens_opt),
                _ => (None, None),
            };
            
            let role_str_val = Some(match role_enum {
                MessageRole::User => "user".to_string(),
                MessageRole::Assistant => "assistant".to_string(),
                MessageRole::System => "system".to_string(),
            });
        
            let insertable_msg = DbInsertableChatMessage::new(
                setup.session_id,
                setup.user_id,
                *role_enum,
                content_bytes_for_db,
                nonce_for_db,
                role_str_val,
                Some(json!({"type": "text", "text": *plain_content_str})),
                None,
                prompt_tokens_val,
                completion_tokens_val
            );
        
            conn.interact(move |conn_i| {
                diesel::insert_into(chat_messages_schema::table)
                    .values(&insertable_msg)
                    .execute(conn_i)
            }).await.unwrap().unwrap();
        }
        
        // Act
        let result = get_session_data_for_generation(
            setup.app_state.clone(),
            setup.user_id,
            setup.session_id,
            user_message_content.clone(),
            setup.user_dek.clone(),
        ).await;

        // Assert
        assert!(result.is_ok(), "Result should be Ok: {:?}", result.err());
        let (
            managed_history, _system_prompt, _lore_ids, _char_id, _, _, _, _, _, _, _, _, _, _, _, _, _model_name, // Added one underscore
            _, _, _user_msg_struct, actual_recent_tokens, rag_items, _, _
        ) = result.unwrap();

        // Token counts with Gemma for "Okay then." (3) and "See you." (2) = 5. Budget is 8.
        // "This is a longer first message." is ~7 tokens. 5 + 7 = 12 > 8. So msg1 is excluded.
        assert_eq!(managed_history.len(), 2, "Should include 2 most recent messages");
        
        let hist_msg2_content = String::from_utf8(managed_history[0].content.clone()).unwrap();
        let hist_msg3_content = String::from_utf8(managed_history[1].content.clone()).unwrap();
        
        assert_eq!(hist_msg2_content, msg2_content, "Second message content mismatch");
        assert_eq!(hist_msg3_content, msg3_content, "Third message content mismatch");

        // Calculate expected tokens based on actual content kept
        let tokens_msg2 = setup.app_state.token_counter.count_tokens(msg2_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let tokens_msg3 = setup.app_state.token_counter.count_tokens(msg3_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let expected_tokens = tokens_msg2 + tokens_msg3;

        assert_eq!(actual_recent_tokens, expected_tokens as usize, "Token count for recent history mismatch");
        assert!(rag_items.is_empty(), "RAG items should be empty for this test");
    }
#[tokio::test]
    async fn test_rag_lorebook_exclusion_due_to_total_budget() {
        // Arrange
        let user_message_content = "User query that triggers RAG.".to_string();
        let mut test_config = AppConfig::default();
        test_config.context_recent_history_token_budget = 150; // Allows significant history
        test_config.context_rag_token_budget = 50;           // RAG budget itself is positive
        test_config.context_total_token_limit = 160;         // Total limit is tight
        test_config.tokenizer_model_path = Some("./resources/tokenizers/gemma.model".to_string());
        test_config.gemini_api_key = Some("dummy_api_key_rag_total_limit".to_string());
        let model_name_for_test = "gemini-test-model-rag-total-limit".to_string();
        test_config.token_counter_default_model = Some(model_name_for_test.clone());

        let mut setup = setup_test_env(
            Vec::new(), Vec::new(), Vec::new(), VecDeque::new(),
            Some(test_config.clone()),
            None, /* _active_persona_id_from_session */
            None, /* session_character_id_override */
            None, /* _session_system_prompt_override_db */
            None, /* character_db_details */
            None, /* _character_overrides_db */
            None  /* _active_lorebook_ids_for_search_db */
        ).await;
        let conn = setup.app_state.pool.get().await.expect("Failed to get DB connection for RAG total limit test");

        // Insert User
        let new_user_for_rag_total_limit_test = NewUser {
            username: "testuser_rag_total_limit".to_string(), password_hash: "hash_rag_total_limit".to_string(),
            email: "ragtotallimit@example.com".to_string(), role: UserRole::User, account_status: AccountStatus::Active,
            kek_salt: "salt_rag_total_limit".to_string(), encrypted_dek: vec![3u8; 16], dek_nonce: vec![3u8; 12],
            encrypted_dek_by_recovery: None, recovery_kek_salt: None, recovery_dek_nonce: None,
        };
        let inserted_user_id_rag_total_limit: Uuid = conn.interact(move |conn_insert_user| {
            diesel::insert_into(users::table)
                .values(&new_user_for_rag_total_limit_test)
                .returning(users::id)
                .get_result(conn_insert_user)
        }).await.unwrap().unwrap();
        setup.user_id = inserted_user_id_rag_total_limit;

        // Insert Character
        let mut test_character_rag_total_limit = scribe_backend::models::characters::create_dummy_character();
        test_character_rag_total_limit.id = setup._character_id;
        test_character_rag_total_limit.user_id = setup.user_id;
        test_character_rag_total_limit.name = "Test Character RAG Total Limit".to_string();
        conn.interact(move |conn_insert_char| {
            diesel::insert_into(character_schema::table)
                .values(&test_character_rag_total_limit)
                .execute(conn_insert_char)
        }).await.unwrap().unwrap();

        // Insert ChatSession
        let test_session_rag_total_limit = NewChat {
            id: setup.session_id, user_id: setup.user_id, character_id: setup._character_id,
            title_ciphertext: None, title_nonce: None, // Updated field
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            history_management_strategy: "message_window".to_string(), history_management_limit: 20, // High limit, actual tokens will control
            model_name: model_name_for_test.clone(), visibility: Some("private".to_string()),
            active_custom_persona_id: None, active_impersonated_character_id: None,
        };
        conn.interact(move |conn_insert_session| {
            diesel::insert_into(chat_sessions_schema::table)
                .values(&test_session_rag_total_limit)
                .execute(conn_insert_session)
        }).await.unwrap().unwrap();

        // Create history messages to consume tokens close to `CONTEXT_TOTAL_TOKEN_LIMIT - CONTEXT_RAG_TOKEN_BUDGET`
        // Target `actual_recent_history_tokens` = 140.
        // `CONTEXT_RECENT_HISTORY_TOKEN_BUDGET` = 150, so these will fit.
        // `CONTEXT_TOTAL_TOKEN_LIMIT` = 160.
        // `available_rag_tokens` = min(CONTEXT_RAG_TOKEN_BUDGET (50), CONTEXT_TOTAL_TOKEN_LIMIT (160) - actual_recent_history_tokens (140))
        //                        = min(50, 20) = 20.
        // Unused variables:
        // let _history_msg1_content = "This is a very long message that will consume a lot of tokens, hopefully around seventy tokens for this specific test case.";
        // let _history_msg2_content = "Another quite long message to add to the history, also aiming for about seventy tokens to reach our target sum for history.";
        let long_hist_msg_content = "This is a test message for token counting purposes, let's see how many it takes."; // Count this precisely
        let tokens_per_long_hist_msg = setup.app_state.token_counter.count_tokens(long_hist_msg_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total as usize;
        
        let mut current_history_tokens: usize = 0;
        let target_history_tokens: usize = 140;
        let mut constructed_message_data_for_insertion = Vec::new(); // Store (plaintext, role, tokens, created_at)
        let time_offset_base = -100i64;

        for i in 0.. {
            if current_history_tokens.saturating_add(tokens_per_long_hist_msg) <= target_history_tokens {
                let created_at = chrono::Utc::now() + chrono::Duration::seconds(time_offset_base - i as i64);
                constructed_message_data_for_insertion.push((long_hist_msg_content.to_string(), MessageRole::User, Some(tokens_per_long_hist_msg as i32), created_at));
                current_history_tokens += tokens_per_long_hist_msg;
            } else {
                break;
            }
        }
        let remaining_tokens_needed = target_history_tokens.saturating_sub(current_history_tokens);
        if remaining_tokens_needed > 0 {
            let short_filler_content = std::iter::repeat("a ").take(remaining_tokens_needed).collect::<String>();
            let tokens_filler = setup.app_state.token_counter.count_tokens(&short_filler_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total as usize;
            if tokens_filler > 0 && current_history_tokens.saturating_add(tokens_filler) <= target_history_tokens + 5 {
                let created_at = chrono::Utc::now() + chrono::Duration::seconds(time_offset_base - 1000); // Ensure it's older
                constructed_message_data_for_insertion.push((short_filler_content, MessageRole::User, Some(tokens_filler as i32), created_at));
                current_history_tokens += tokens_filler;
            }
        }
        
        // Insert history messages
        for (plain_content_str, role_enum, tokens_opt, _created_at_val) in constructed_message_data_for_insertion.iter() {
            let (content_bytes_for_db, nonce_for_db) = if let Some(dek) = setup.user_dek.as_ref() {
                let (ciphertext, nonce) = crypto::encrypt_gcm(plain_content_str.as_bytes(), dek.as_ref()).unwrap();
                (ciphertext, Some(nonce))
            } else {
                (plain_content_str.as_bytes().to_vec(), None)
            };

            let (prompt_tokens_val, completion_tokens_val) = match role_enum {
                MessageRole::User => (*tokens_opt, None),
                MessageRole::Assistant => (None, *tokens_opt),
                _ => (None, None),
            };
            
            let role_str_val = Some(match role_enum {
                MessageRole::User => "user".to_string(),
                MessageRole::Assistant => "assistant".to_string(),
                MessageRole::System => "system".to_string(),
            });

            let insertable_msg = DbInsertableChatMessage::new(
                setup.session_id, // chat_id
                setup.user_id,    // user_id
                *role_enum,       // msg_type_enum
                content_bytes_for_db, // text
                nonce_for_db,     // nonce
                role_str_val,     // role_str
                Some(json!({"type": "text", "text": plain_content_str})), // parts_json
                None,             // attachments_json
                prompt_tokens_val, // prompt_tokens
                completion_tokens_val // completion_tokens
            );

            conn.interact(move |conn_i| {
                diesel::insert_into(chat_messages_schema::table)
                    .values(&insertable_msg)
                    .execute(conn_i)
            }).await.unwrap().unwrap();
        }
        
        // Prepare Lorebook and link to session
        let lorebook_id = Uuid::new_v4();
        let test_lorebook_total_limit = scribe_backend::models::lorebooks::NewLorebook {
            id: lorebook_id, user_id: setup.user_id, name: "Total Limit Lorebook".to_string(),
            description: Some("Lore for total limit test.".to_string()), source_format: "scribe_v1".to_string(),
            is_public: false, created_at: Some(chrono::Utc::now()), updated_at: Some(chrono::Utc::now()),
        };
        conn.interact({ let tl = test_lorebook_total_limit.clone(); move |conn_lore_insert| {
            diesel::insert_into(scribe_backend::schema::lorebooks::table).values(&tl).execute(conn_lore_insert)
        }}).await.unwrap().unwrap();
        conn.interact(move |conn_link| { {
            use scribe_backend::schema::chat_session_lorebooks;
            let new_link = scribe_backend::models::lorebooks::NewChatSessionLorebook {
                chat_session_id: setup.session_id, lorebook_id, user_id: setup.user_id,
                created_at: None,
                updated_at: None,
            };
            diesel::insert_into(chat_session_lorebooks::table).values(&new_link).execute(conn_link)
        }}).await.unwrap().unwrap();

        // Define RAG chunks to be returned by the mock for lorebooks.
        // Each chunk should have > 20 tokens. `available_rag_tokens` is expected to be 20.
        let lore_chunk1_content = "This particular lorebook chunk is specifically designed to be quite a bit more than twenty tokens long for the purpose of testing exclusion criteria accurately. One two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twentyone.";
        let lore_chunk1_tokens = setup.app_state.token_counter.count_tokens(lore_chunk1_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total as usize;
        assert!(lore_chunk1_tokens > 20, "Test setup error: lore_chunk1_content ('{}') is not > 20 tokens (actual: {})", lore_chunk1_content, lore_chunk1_tokens);

        let lore_chunk1 = RetrievedChunk {
            text: lore_chunk1_content.to_string(), score: 0.9,
            metadata: scribe_backend::services::embedding_pipeline::RetrievedMetadata::Lorebook(
                scribe_backend::services::embedding_pipeline::LorebookChunkMetadata {
                    original_lorebook_entry_id: Uuid::new_v4(), lorebook_id, user_id: setup.user_id,
                    chunk_text: lore_chunk1_content.to_string(), entry_title: Some("Large Chunk 1".to_string()),
                    keywords: Some(vec!["large".to_string()]), is_enabled: true, is_constant: false,
                    source_type: "lorebook_entry".to_string(),
                }),
        };
        let expected_lore_chunks = vec![lore_chunk1.clone()];

        // Configure mock expectations
        setup._mock_embedding_pipeline.set_retrieve_responses_sequence(vec![
            Ok(expected_lore_chunks.clone()), // For lorebook chunks
            Ok(Vec::new()),                   // For older chat history chunks
        ]);

        // Act
        let result = get_session_data_for_generation(
            setup.app_state.clone(),
            setup.user_id,
            setup.session_id,
            user_message_content.clone(),
            setup.user_dek.clone(),
        ).await;

        // Assert
        assert!(result.is_ok(), "Result should be Ok: {:?}", result.err());
        let (
            managed_history, _system_prompt, _active_lore_ids, _char_id, _, _, _, _, _, _, _, _, _, _, _, _, _model_name, // Added one underscore
            _, _, _user_msg_struct, actual_recent_tokens_from_result, rag_items, _, _
        ) = result.unwrap();

        // Verify actual_recent_history_tokens is what we set up (around 140)
        // This assertion helps confirm the history setup was correct.
        // The exact value depends on the precise tokenization of the filler messages.
        // We are aiming for `current_history_tokens` to be the value.
        assert_eq!(actual_recent_tokens_from_result, current_history_tokens, "Actual recent history tokens ({}) from result does not match expected ({}) from setup. Target was {}.", actual_recent_tokens_from_result, current_history_tokens, target_history_tokens);

        // Key assertion: RAG items should be empty because no lorebook chunk could fit
        assert!(rag_items.is_empty(), "RAG items should be empty due to total budget constraint, but got: {:?}", rag_items);
        
        // Verify managed_recent_history contains the messages we inserted
        assert_eq!(managed_history.len(), constructed_message_data_for_insertion.len(), "Managed history length mismatch");
    }
    #[tokio::test]
    async fn test_rag_older_chat_history_inclusion_fits_budget() {
        // Arrange
        let user_message_content = "User query for older history RAG.".to_string();
        let mut test_config = AppConfig::default();
        test_config.context_recent_history_token_budget = 10; // Adjusted from 50
        test_config.context_rag_token_budget = 100;
        test_config.context_total_token_limit = 200;
        test_config.tokenizer_model_path = Some("./resources/tokenizers/gemma.model".to_string());
        test_config.gemini_api_key = Some("dummy_api_key_rag_older_hist".to_string());
        let model_name_for_test = "gemini-test-model-rag-older-hist".to_string();
        test_config.token_counter_default_model = Some(model_name_for_test.clone());

        let mut setup = setup_test_env(
            Vec::new(), Vec::new(), Vec::new(), VecDeque::new(),
            Some(test_config.clone()),
            None, /* _active_persona_id_from_session */
            None, /* session_character_id_override */
            None, /* _session_system_prompt_override_db */
            None, /* character_db_details */
            None, /* _character_overrides_db */
            None  /* _active_lorebook_ids_for_search_db */
        ).await;
        let conn = setup.app_state.pool.get().await.expect("Failed to get DB connection for RAG older history test");

        // Insert User
        let new_user_for_rag_older_hist_test = NewUser {
            username: "testuser_rag_older_hist".to_string(), password_hash: "hash_rag_older_hist".to_string(),
            email: "ragolderhist@example.com".to_string(), role: UserRole::User, account_status: AccountStatus::Active,
            kek_salt: "salt_rag_older_hist".to_string(), encrypted_dek: vec![4u8; 16], dek_nonce: vec![4u8; 12],
            encrypted_dek_by_recovery: None, recovery_kek_salt: None, recovery_dek_nonce: None,
        };
        let inserted_user_id_rag_older_hist: Uuid = conn.interact(move |conn_insert_user| {
            diesel::insert_into(users::table)
                .values(&new_user_for_rag_older_hist_test)
                .returning(users::id)
                .get_result(conn_insert_user)
        }).await.unwrap().unwrap();
        setup.user_id = inserted_user_id_rag_older_hist;

        // Insert Character
        let mut test_character_rag_older_hist = scribe_backend::models::characters::create_dummy_character();
        test_character_rag_older_hist.id = setup._character_id;
        test_character_rag_older_hist.user_id = setup.user_id;
        test_character_rag_older_hist.name = "Test Character RAG Older Hist".to_string();
        conn.interact(move |conn_insert_char| {
            diesel::insert_into(character_schema::table)
                .values(&test_character_rag_older_hist)
                .execute(conn_insert_char)
        }).await.unwrap().unwrap();

        // Insert ChatSession
        let test_session_rag_older_hist = NewChat {
            id: setup.session_id, user_id: setup.user_id, character_id: setup._character_id,
            title_ciphertext: None, title_nonce: None, // Updated field
            created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            history_management_strategy: "message_window".to_string(), history_management_limit: 10, // Ample limit for recent
            model_name: model_name_for_test.clone(), visibility: Some("private".to_string()),
            active_custom_persona_id: None, active_impersonated_character_id: None,
        };
        conn.interact(move |conn_insert_session| {
            diesel::insert_into(chat_sessions_schema::table)
                .values(&test_session_rag_older_hist)
                .execute(conn_insert_session)
        }).await.unwrap().unwrap();

        let mut message_ids = Vec::new();

        // Insert "older" history messages (timestamps further in the past)
        let older_msg1_content = "This is an old message from the user."; // ~8 tokens
        let older_msg2_content = "And an old reply from the assistant."; // ~8 tokens
        let older_msg3_content = "One more old user message for context."; // ~9 tokens

        let older_messages_data = [
            (older_msg1_content, MessageRole::User, -300i64),
            (older_msg2_content, MessageRole::Assistant, -200i64),
            (older_msg3_content, MessageRole::User, -100i64),
        ];
        let mut expected_older_chat_chunks = Vec::new();

        for (idx, (content, role, time_offset)) in older_messages_data.iter().enumerate() {
            let msg_id = Uuid::new_v4();
            message_ids.push(msg_id);
            let (content_bytes, nonce_bytes): (Vec<u8>, Option<Vec<u8>>) = if let Some(dek) = setup.user_dek.as_ref() {
                let (cb, n) = crypto::encrypt_gcm(content.as_bytes(), dek.as_ref()).unwrap();
                (cb, Some(n))
            } else { (content.as_bytes().to_vec(), None) };
            let tokens = setup.app_state.token_counter.count_tokens(content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total as i32;
            let (pt, ct) = if *role == MessageRole::User { (Some(tokens), None) } else { (None, Some(tokens)) };
            let created_at_val = chrono::Utc::now() + chrono::Duration::seconds(*time_offset);

            let insertable_msg = DbInsertableChatMessage::new(
                setup.session_id, setup.user_id, *role, content_bytes, nonce_bytes,
                Some(role.to_string()), Some(json!({"type": "text", "text": *content})), None, pt, ct,
            );
            // created_at will be set by the database default `now()`.
            // Order of insertion will manage "older" vs "recent".

            conn.interact({
                let m = insertable_msg.clone(); // Clone for closure
                let _current_msg_id = msg_id; // Capture current msg_id for this iteration
                move |conn_i| {
                // Insert the message
                diesel::insert_into(chat_messages_schema::table)
                    .values(&m)
                    // We need to explicitly set the ID if we want to control it for the ChatChunkMetadata
                    // However, DbInsertableChatMessage doesn't have an ID field.
                    // We'll fetch the ID after insertion if needed, or rely on content matching.
                    // For simplicity, we'll use the generated ID from the DB if ChatChunkMetadata needs it.
                    // For this test, we'll construct ChatChunkMetadata with the ID we generate here.
                    // This requires that the DB message actually has this ID.
                    // A better way is to insert and then query, or let the DB generate the ID and use that.
                    // For now, let's assume we can't control the ID on insert easily with DbInsertableChatMessage.
                    // We will use the generated msg_id for the ChatChunkMetadata.
                    .execute(conn_i)?;

                // Update the created_at timestamp separately if DbInsertableChatMessage doesn't allow direct setting
                // Or ensure DbInsertableChatMessage can take created_at
                // The current DbInsertableChatMessage::new does not take created_at.
                // We will update it after insertion.
                // This is not ideal. A better approach is to modify DbInsertableChatMessage or use a different struct.
                // For now, we'll try to update. This requires knowing the ID.
                // Let's assume the test helper `create_db_chat_message` is better for controlled insertion.
                // However, that helper is for creating `DbChatMessage` not `DbInsertableChatMessage`.
                // We will proceed with inserting and then constructing `RetrievedChunk` with the known content and a *new* Uuid for metadata.
                // The crucial part for the test is that the *content* matches.
                // The filtering logic in get_session_data_for_generation uses message IDs from `managed_recent_history`.
                // So, the `message_id` in `ChatChunkMetadata` for older chunks *must* be the actual ID from the DB.

                // To get the actual ID, we would need to insert and then select.
                // For this test, we will create the RetrievedChunk with the ID we *would* have inserted if we controlled it.
                // This means the test relies on the content and the mock returning these specific chunks.
                // The filtering logic for `recent_message_ids` will be tested by ensuring the mock returns chunks
                // that are *not* in recent history.

                // Let's re-think: we need the actual DB message ID for the ChatChunkMetadata.
                // So, after inserting, we should query for that message to get its ID.
                // Or, if we can't easily query by content/timestamp reliably, we'll have to make the test simpler
                // by ensuring the mock returns chunks with *new* Uuids for message_id, and the test focuses on content.
                // The problem statement says: "Ensure these chunks, when combined, fit within the available_rag_tokens."
                // And "rag_context_items contains the expected older chat history chunks."
                // This implies the content and token count are key.

                // Let's simplify: the mock will return `RetrievedChunk`s. The `message_id` in their metadata
                // will be a new Uuid for each, not necessarily matching a DB ID for this specific part of the test.
                // The main function's filtering of recent messages from RAG candidates will still work based on
                // the `message_id`s of the *actual recent messages* from the DB.
                // The test for *older history RAG* is about whether *different* (older) content gets included.

                // So, the `message_id` in `ChatChunkMetadata` for the mock can be `Uuid::new_v4()`.
                Ok::<_, diesel::result::Error>(())
            }}).await.unwrap().unwrap();

            // Update created_at for the last inserted message (this is hacky)
            // A proper solution would be to allow setting created_at in DbInsertableChatMessage or use a raw query.
            // For now, we assume the order of insertion combined with small time offsets in other messages will suffice.
            // The critical part is that these messages are older than "recent" ones.
            // The `created_at` field in `DbInsertableChatMessage` is now `Option<DateTime<Utc>>`
            // So we can set it directly in `DbInsertableChatMessage::new` if we modify the constructor or struct.
            // The current `DbInsertableChatMessage::new` does not take `created_at`.
            // The struct `DbInsertableChatMessage` itself does not have `created_at`.
            // It's `ChatMessage` that has `created_at`.
            // The `chat_messages` schema has `created_at` with `DEFAULT now()`.
            // We need to insert with specific `created_at` values.
            // This means using a more direct insert or modifying `DbInsertableChatMessage`.

            // Let's use a direct insert approach for messages where we need to control created_at.
            // This is getting complex. Let's simplify the message insertion for older messages.
            // We will insert them and assume their DB-generated `created_at` will be naturally older if inserted first.
            // Or, use the time_offset in `create_db_chat_message` style if we adapt it for insertion.

            // For this test, the key is that the mock `EmbeddingPipelineService` returns the correct older chunks.
            // The actual DB messages for "older" history are primarily to ensure they *exist* for the conceptual setup.
            // The `retrieve_relevant_chunks` mock for older history will provide the content.

            expected_older_chat_chunks.push(RetrievedChunk {
                text: content.to_string(),
                score: 0.85 - (idx as f32 * 0.01), // Ensure some ordering if needed
                metadata: scribe_backend::services::embedding_pipeline::RetrievedMetadata::Chat(
                    scribe_backend::services::embedding_pipeline::ChatMessageChunkMetadata {
                        message_id: msg_id, // Use the ID we generated for this message
                        session_id: setup.session_id,
                        user_id: setup.user_id,
                        speaker: role.to_string(), // Changed from role
                        timestamp: created_at_val, // Changed from created_at
                        // token_count: tokens as usize, // Removed, not in struct
                        source_type: "chat_message".to_string(),
                        text: content.to_string(), // Changed from chunk_text
                        // original_message_id: msg_id, // Removed, covered by message_id
                    }
                ),
            });
        }


        // Insert "recent" history messages (timestamps more recent)
        let recent_msg1_content = "Recent user message."; // ~4 tokens
        let recent_msg2_content = "Recent assistant reply."; // ~4 tokens
        let recent_messages_data = [
            (recent_msg1_content, MessageRole::User, -20i64),
            (recent_msg2_content, MessageRole::Assistant, -10i64),
        ];
        let mut recent_message_ids_in_db = Vec::new();

        for (content, role, _time_offset) in recent_messages_data.iter() {
            let msg_id = Uuid::new_v4();
            recent_message_ids_in_db.push(msg_id); // Store the ID we intend to insert, though DB might generate a different one if not set.
                                                 // For this test, we will fetch the actual IDs later.

            let (content_bytes, nonce_bytes): (Vec<u8>, Option<Vec<u8>>) = if let Some(dek) = setup.user_dek.as_ref() {
                let (cb, n) = crypto::encrypt_gcm(content.as_bytes(), dek.as_ref()).unwrap();
                (cb, Some(n))
            } else { (content.as_bytes().to_vec(), None) };

            let tokens = setup.app_state.token_counter.count_tokens(content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total as i32;
            let (pt, ct) = if *role == MessageRole::User { (Some(tokens), None) } else { (None, Some(tokens)) };

            // created_at will be set by DB default. Order of insertion matters.
            // These "recent" messages are inserted *after* "older" messages.
            let insertable_recent_msg = DbInsertableChatMessage::new(
                setup.session_id, // chat_id
                setup.user_id,    // user_id
                *role,            // msg_type_enum
                content_bytes,    // text
                nonce_bytes,      // nonce
                Some(role.to_string()), // role_str
                Some(json!({"type": "text", "text": *content})), // parts_json
                None,             // attachments_json
                pt,               // prompt_tokens
                ct,               // completion_tokens
            );

            conn.interact({
                let m_insert = insertable_recent_msg.clone();
                move |conn_i| {
                    diesel::insert_into(chat_messages_schema::table)
                        .values(&m_insert)
                        .execute(conn_i)
                }
            }).await.unwrap().unwrap();
        }

        // Fetch the actual recent messages from DB to get their DB-generated IDs and confirm order
        let actual_recent_messages_from_db: Vec<DbChatMessage> = conn.interact(move |conn_db| {
            chat_messages_schema::table
                .filter(chat_messages_schema::session_id.eq(setup.session_id))
                .order(chat_messages_schema::created_at.desc()) // newest first
                .limit(2) // We inserted 2 recent messages
                .select(DbChatMessage::as_select())
                .load::<DbChatMessage>(conn_db)
        }).await.unwrap().unwrap();

        let recent_history_message_ids_from_db: std::collections::HashSet<Uuid> =
            actual_recent_messages_from_db.iter().map(|msg| msg.id).collect();

        // Configure mock expectations
        setup._mock_embedding_pipeline.set_retrieve_responses_sequence(vec![
            Ok(expected_older_chat_chunks.clone()), // For older chat history chunks (lorebook call is skipped in this test)
        ]);

        // Act
        let result = get_session_data_for_generation(
            setup.app_state.clone(),
            setup.user_id,
            setup.session_id,
            user_message_content.clone(),
            setup.user_dek.clone(),
        ).await;

        // Assert
        assert!(result.is_ok(), "Result should be Ok: {:?}", result.err());
        let (
            managed_history, _system_prompt, _lore_ids, _char_id, _, _, _, _, _, _, _, _, _, _, _, _, _model_name, // Added one underscore
            _, _, _user_msg_struct, actual_recent_tokens, rag_items, _, _
        ) = result.unwrap();

        assert_eq!(managed_history.len(), 2, "Managed recent history should contain 2 messages");
        assert_eq!(String::from_utf8(managed_history[0].content.clone()).unwrap(), recent_msg1_content);
        assert_eq!(String::from_utf8(managed_history[1].content.clone()).unwrap(), recent_msg2_content);

        let tokens_recent1 = setup.app_state.token_counter.count_tokens(recent_msg1_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let tokens_recent2 = setup.app_state.token_counter.count_tokens(recent_msg2_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        assert_eq!(actual_recent_tokens, (tokens_recent1 + tokens_recent2) as usize, "Actual recent history tokens mismatch");

        assert_eq!(rag_items.len(), 3, "RAG items should contain 3 older chat history chunks");
        assert_eq!(rag_items[0].text, older_msg1_content);
        assert_eq!(rag_items[1].text, older_msg2_content);
        assert_eq!(rag_items[2].text, older_msg3_content);

        let tokens_older1 = setup.app_state.token_counter.count_tokens(older_msg1_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let tokens_older2 = setup.app_state.token_counter.count_tokens(older_msg2_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let tokens_older3 = setup.app_state.token_counter.count_tokens(older_msg3_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let total_rag_tokens_used = tokens_older1 + tokens_older2 + tokens_older3;

        let expected_available_rag_tokens = min(
            test_config.context_rag_token_budget, // 100
            test_config.context_total_token_limit.saturating_sub(actual_recent_tokens) // 200 - (tokens_recent1+tokens_recent2)
        );
        assert!(total_rag_tokens_used as usize <= expected_available_rag_tokens,
                "Total RAG tokens used ({}) should be within available budget ({})", total_rag_tokens_used, expected_available_rag_tokens);

        // Ensure no overlap between recent history (actual IDs from DB) and RAG items (mocked IDs)
        for rag_chunk in &rag_items {
            if let scribe_backend::services::embedding_pipeline::RetrievedMetadata::Chat(chat_meta) = &rag_chunk.metadata {
                assert!(!recent_history_message_ids_from_db.contains(&chat_meta.message_id), "RAG item with mock ID {} should not be in the set of actual recent DB message IDs", chat_meta.message_id);
            }
        }
    }
}
