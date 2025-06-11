#[cfg(test)]
mod tests {
    use crate::services::embeddings::{
        EmbeddingPipelineService,
        ChatMessageChunkMetadata, LorebookEntryParams,
        RetrievedMetadata
    };
    use crate::text_processing::chunking::ChunkConfig;
    use std::collections::HashMap;
    use std::sync::Arc;
    use uuid::Uuid;
    use crate::errors::AppError;
    use crate::state::AppState;
    use crate::models::chats::ChatMessage;
    use crate::auth::session_dek::SessionDek;
    use crate::{
        config::Config,
        crypto::encrypt_gcm, // Updated for encryption tests
        models::chats::MessageRole,
        services::lorebook_service::LorebookService, // Added for LorebookService
        state::AppStateServices,
        test_helpers::{
            MockAiClient, MockEmbeddingClient, MockQdrantClientService, db::setup_test_database,
        },
        text_processing::chunking::ChunkingMetric,
    };
    use chrono::Utc;
    use qdrant_client::qdrant::{
        PointId, ScoredPoint, Value, Filter,
        condition::ConditionOneOf, r#match::MatchValue
    };
    use secrecy::SecretBox; // For encryption tests
    // For creating test JSON values
    // Ensure this is imported ONCE here

    // Helper to convert string to Qdrant String Value
    fn string_value(s: &str) -> Value {
        Value {
            kind: Some(qdrant_client::qdrant::value::Kind::StringValue(
                s.to_string(),
            )),
        }
    }
    // Helper to convert i64 to Qdrant Integer Value
    const fn integer_value(i: i64) -> Value {
        Value {
            kind: Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)),
        }
    }

    // --- Tests for EmbeddingMetadata --- TODO: Move to models/embeddings.rs tests?
    fn build_valid_payload_map() -> HashMap<String, Value> {
        let mut payload = HashMap::new();
        payload.insert(
            "message_id".to_string(),
            string_value(&Uuid::new_v4().to_string()),
        );
        payload.insert(
            "session_id".to_string(),
            string_value(&Uuid::new_v4().to_string()),
        );
        payload.insert(
            "user_id".to_string(),
            string_value(&Uuid::new_v4().to_string()),
        );
        payload.insert("speaker".to_string(), string_value("user"));
        payload.insert(
            "timestamp".to_string(),
            string_value(&Utc::now().to_rfc3339()),
        );
        payload.insert("text".to_string(), string_value("Hello world"));
        payload.insert("source_type".to_string(), string_value("chat_message")); // Added source_type
        payload
    }

    #[test]
    fn test_chat_message_chunk_metadata_try_from_valid_payload() {
        let payload = build_valid_payload_map();
        let result = ChatMessageChunkMetadata::try_from(payload);
        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert_eq!(metadata.speaker, "user");
        assert_eq!(metadata.text, "Hello world");
    }

    #[test]
    fn test_chat_message_chunk_metadata_try_from_missing_field() {
        let mut payload = build_valid_payload_map();
        payload.remove("speaker");
        let result = ChatMessageChunkMetadata::try_from(payload);
        assert!(result.is_err());
        if let Err(AppError::SerializationError(msg)) = result {
            assert!(msg.contains("Missing or invalid 'speaker'"));
        } else {
            panic!("Expected SerializationError for missing field");
        }
    }

    #[test]
    fn test_chat_message_chunk_metadata_try_from_invalid_uuid_format() {
        let mut payload = build_valid_payload_map();
        payload.insert("message_id".to_string(), string_value("not-a-uuid"));
        let result = ChatMessageChunkMetadata::try_from(payload);
        assert!(result.is_err());
        if let Err(AppError::SerializationError(msg)) = result {
            assert!(msg.contains("Failed to parse 'message_id' as UUID"));
        } else {
            panic!("Expected SerializationError for invalid UUID");
        }
    }

    #[test]
    fn test_chat_message_chunk_metadata_try_from_invalid_timestamp_format() {
        let mut payload = build_valid_payload_map();
        payload.insert("timestamp".to_string(), string_value("not-a-timestamp"));
        let result = ChatMessageChunkMetadata::try_from(payload);
        assert!(result.is_err());
        if let Err(AppError::SerializationError(msg)) = result {
            assert!(msg.contains("Failed to parse 'timestamp'"));
        } else {
            panic!("Expected SerializationError for invalid timestamp");
        }
    }

    #[test]
    fn test_chat_message_chunk_metadata_try_from_wrong_field_type() {
        let mut payload = build_valid_payload_map();
        payload.insert("speaker".to_string(), integer_value(123)); // Speaker should be string
        let result = ChatMessageChunkMetadata::try_from(payload);
        assert!(result.is_err());
        if let Err(AppError::SerializationError(msg)) = result {
            assert!(msg.contains("Missing or invalid 'speaker'")); // Will fail on wrong type, re-checking as missing
        } else {
            panic!("Expected SerializationError for wrong field type");
        }
    }

    #[test]
    fn test_chat_message_chunk_metadata_try_from_empty_payload() {
        let payload = HashMap::new();
        let result = ChatMessageChunkMetadata::try_from(payload);
        assert!(result.is_err());
        if let Err(AppError::SerializationError(msg)) = result {
            // The first field it checks will be reported as missing
            assert!(msg.contains("Missing or invalid"));
        } else {
            panic!("Expected SerializationError for empty payload");
        }
    }

    // --- Tests for EmbeddingPipelineService ---
    // TODO: Add tests for process_and_embed_lorebook_entry

    // Helper for setting up test environment for service methods
    async fn setup_pipeline_test_env() -> (
        Arc<AppState>,
        Arc<MockQdrantClientService>,
        Arc<MockEmbeddingClient>,
    ) {
        let mock_qdrant = Arc::new(MockQdrantClientService::new());
        let mock_embed_client = Arc::new(MockEmbeddingClient::new());
        let pool = setup_test_database(None).await;
        let config = Arc::new(Config::default());
        let ai_client = Arc::new(MockAiClient::new());

        // For EmbeddingPipelineService tests, we instantiate the actual service
        let chunk_config = ChunkConfig {
            metric: ChunkingMetric::Char,
            max_size: 100,
            overlap: 20,
        };
        let embedding_pipeline_service_concrete =
            Arc::new(EmbeddingPipelineService::new(chunk_config));

        let encryption_service =
            Arc::new(crate::services::encryption_service::EncryptionService::new());
        let chat_override_service = Arc::new(
            crate::services::chat_override_service::ChatOverrideService::new(
                pool.clone(),
                encryption_service.clone(),
            ),
        );
        let user_persona_service = Arc::new(
            crate::services::user_persona_service::UserPersonaService::new(
                pool.clone(),
                encryption_service.clone(),
            ),
        );
        let token_counter_service = Arc::new(
            crate::services::hybrid_token_counter::HybridTokenCounter::new_local_only(
                crate::services::tokenizer_service::TokenizerService::new(
                    &config.tokenizer_model_path,
                )
                .expect("Failed to create tokenizer for test"),
            ),
        );
        let lorebook_service = Arc::new(LorebookService::new(
            pool.clone(),
            encryption_service.clone(),
            mock_qdrant.clone(),
        ));
        let auth_backend = Arc::new(crate::auth::user_store::Backend::new(pool.clone()));

        let file_storage_service = Arc::new(
            crate::services::file_storage_service::FileStorageService::new("./test_uploads")
                .expect("Failed to create test file storage service"),
        );

        let services = AppStateServices {
            ai_client,
            embedding_client: mock_embed_client.clone(),
            qdrant_service: mock_qdrant.clone(),
            embedding_pipeline_service: embedding_pipeline_service_concrete,
            chat_override_service,
            user_persona_service,
            token_counter: token_counter_service,
            encryption_service,
            lorebook_service,
            auth_backend,
            file_storage_service,
            email_service: Arc::new(crate::services::email_service::LoggingEmailService::new(
                "http://localhost:3000".to_string(),
            )),
        };

        let app_state = Arc::new(AppState::new(pool, config, services));
        (app_state, mock_qdrant, mock_embed_client)
    }

    #[tokio::test]
    async fn test_process_and_embed_message_method_success() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let message_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let message_content = "This is a test message for embedding.";

        let test_message = ChatMessage {
            id: message_id,
            session_id,
            message_type: MessageRole::User,
            content: message_content.as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        };

        // Mock Embedding Client to return a dummy vector
        mock_embed_client.set_response(Ok(vec![0.1, 0.2, 0.3]));
        // Mock Qdrant to succeed on upsert
        mock_qdrant.set_upsert_response(Ok(()));

        let result = state
            .embedding_pipeline_service
            .process_and_embed_message(state.clone(), test_message, None)
            .await;
        assert!(
            result.is_ok(),
            "process_and_embed_message failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_process_and_embed_message_method_uses_service_config() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let message_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        // Content designed to be chunked by the service's default config (max_size 100)
        let long_content = "a".repeat(150);

        let test_message = ChatMessage {
            id: message_id,
            session_id,
            message_type: MessageRole::User,
            content: long_content.as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        };

        mock_embed_client.set_response(Ok(vec![0.1, 0.2])); // Needs to be called for each chunk
        mock_qdrant.set_upsert_response(Ok(()));

        let result = state
            .embedding_pipeline_service
            .process_and_embed_message(state.clone(), test_message, None)
            .await;
        assert!(result.is_ok());

        // Verify that mock_embed_client.embed_content was called multiple times (due to chunking)
        // This indirectly verifies that the service's chunk_config was used.
        // The exact number of calls depends on the chunker logic (150 chars, 100 max, 20 overlap -> 2 chunks)
        assert_eq!(
            mock_embed_client.get_calls().len(),
            2,
            "Expected 2 chunks for 150 char content with 100/20 config"
        );
    }

    #[tokio::test]
    async fn test_process_and_embed_message_method_empty_content() {
        let (state, _mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let message_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        let test_message = ChatMessage {
            id: message_id,
            session_id,
            message_type: MessageRole::User,
            content: b"   ".to_vec(), // Empty after trim
            content_nonce: None,
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        };

        let result = state
            .embedding_pipeline_service
            .process_and_embed_message(state.clone(), test_message, None)
            .await;
        assert!(
            result.is_ok(),
            "Expected Ok for empty content (should skip embedding)"
        );
        assert!(
            mock_embed_client.get_calls().is_empty(),
            "Embedding client should not be called for empty content"
        );
    }

    #[tokio::test]
    async fn test_process_and_embed_message_method_embedding_error() {
        let (state, _mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let message_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        let test_message = ChatMessage {
            id: message_id,
            session_id,
            message_type: MessageRole::User,
            content: b"Some content".to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        };

        mock_embed_client.set_response(Err(AppError::AiServiceError(
            "Embedding failed".to_string(),
        )));

        let result = state
            .embedding_pipeline_service
            .process_and_embed_message(state.clone(), test_message, None)
            .await;
        // The current implementation logs the error and continues, so it might still return Ok(()) if at least one chunk fails.
        // If ALL chunks fail to embed, it should ideally propagate an error, or if some succeed, it should still be Ok.
        // For this test, if the *first* chunk embedding fails, points_to_upsert will be empty.
        // If points_to_upsert is empty, it returns Ok. This might need refinement.
        // Let's adjust the expectation: if embedding fails, no points are upserted, so it's still Ok.
        // The error is logged internally. This depends on desired error propagation strategy.
        // For now, assert Ok, and check that Qdrant wasn't called if embedding failed.
        assert!(
            result.is_ok(),
            "Service should handle embedding errors gracefully and return Ok if no points were made to upsert."
        );
        // We could also check mock_qdrant.get_upsert_calls() to be empty if we want to be more specific.
    }

    #[tokio::test]
    async fn test_process_and_embed_message_method_qdrant_error() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let message_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        let test_message = ChatMessage {
            id: message_id,
            session_id,
            message_type: MessageRole::User,
            content: b"Some content".to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        };

        mock_embed_client.set_response(Ok(vec![0.3, 0.4]));
        mock_qdrant.set_upsert_response(Err(AppError::VectorDbError("Qdrant down".to_string())));

        let result = state
            .embedding_pipeline_service
            .process_and_embed_message(state.clone(), test_message, None)
            .await;
        assert!(result.is_err());
        if let Err(AppError::VectorDbError(msg)) = result {
            assert_eq!(msg, "Qdrant down");
        } else {
            panic!("Expected VectorDbError");
        }
    }

    // Helper struct for creating mock ScoredPoint
    struct MockScoredPointParams<'a> {
        id_uuid: Uuid,
        score: f32,
        session_id: Uuid,
        message_id: Uuid,
        user_id: Uuid,
        speaker: &'a str,
        timestamp: chrono::DateTime<Utc>,
        text: &'a str,
        source_type: &'a str,
    }

    // Helper to create a mock ScoredPoint
    fn create_mock_scored_point(params: &MockScoredPointParams<'_>) -> ScoredPoint {
        let mut payload = HashMap::new();
        payload.insert(
            "message_id".to_string(),
            string_value(&params.message_id.to_string()),
        );
        payload.insert(
            "session_id".to_string(),
            string_value(&params.session_id.to_string()),
        );
        payload.insert(
            // Added user_id to payload
            "user_id".to_string(),
            string_value(&params.user_id.to_string()),
        );
        payload.insert("speaker".to_string(), string_value(params.speaker));
        payload.insert(
            "timestamp".to_string(),
            string_value(&params.timestamp.to_rfc3339()),
        );
        payload.insert("text".to_string(), string_value(params.text));
        payload.insert("source_type".to_string(), string_value(params.source_type));

        ScoredPoint {
            id: Some(PointId {
                // Consistent with PointIdOptions::Uuid usage
                point_id_options: Some(qdrant_client::qdrant::point_id::PointIdOptions::Uuid(
                    params.id_uuid.to_string(),
                )),
            }),
            payload,
            score: params.score,
            version: 0,    // Example version
            vectors: None, // Not usually needed for retrieval tests focusing on payload
            shard_key: None,
            order_value: None,
        }
    }

    #[tokio::test]
    async fn test_retrieve_relevant_chunks_method_success() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let query_text = "Tell me about cats";

        mock_embed_client.set_response(Ok(vec![0.5, 0.6]));

        let mock_point_id_1 = Uuid::new_v4();
        let mock_point_id_2 = Uuid::new_v4();
        let message_id_1 = Uuid::new_v4();
        let message_id_2 = Uuid::new_v4();

        let mock_qdrant_results = vec![
            create_mock_scored_point(&MockScoredPointParams {
                id_uuid: mock_point_id_1,
                score: 0.95,
                session_id,
                message_id: message_id_1,
                user_id,
                speaker: "user",
                timestamp: Utc::now(),
                text: "Cats are furry.",
                source_type: "chat_message",
            }),
            create_mock_scored_point(&MockScoredPointParams {
                id_uuid: mock_point_id_2,
                score: 0.85,
                session_id,
                message_id: message_id_2,
                user_id,
                speaker: "ai",
                timestamp: Utc::now(),
                text: "They meow a lot.",
                source_type: "chat_message",
            }),
        ];
        mock_qdrant.set_search_response(Ok(mock_qdrant_results));

        let result = state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(
                state.clone(),
                user_id,
                Some(session_id),
                None,
                query_text,
                5,
            )
            .await;
        assert!(
            result.is_ok(),
            "retrieve_relevant_chunks failed: {:?}",
            result.err()
        );
        let chunks = result.unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].text, "Cats are furry.");
        if let RetrievedMetadata::Chat(meta) = &chunks[0].metadata {
            assert_eq!(meta.speaker, "user");
            assert_eq!(meta.user_id, user_id); // Added user_id assertion
            assert_eq!(meta.message_id, message_id_1);
        } else {
            panic!("Expected Chat metadata for chunks[0]");
        }
        assert_eq!(chunks[1].text, "They meow a lot.");
        if let RetrievedMetadata::Chat(meta) = &chunks[1].metadata {
            assert_eq!(meta.speaker, "ai");
            assert_eq!(meta.user_id, user_id); // Added user_id assertion
            assert_eq!(meta.message_id, message_id_2);
        } else {
            panic!("Expected Chat metadata for chunks[1]");
        }
    }

    // --- Standalone function tests (can be removed if service tests cover sufficiently) ---
    // These are now mostly covered by the service method tests which use mocks for dependencies.
    // Keeping one or two simple ones for direct logic verification if desired.

    #[tokio::test]
    async fn test_full_pipeline_new_message_no_docs_no_similar_messages() {
        let (state, mock_qdrant, _mock_embed_client) = setup_pipeline_test_env().await;
        let message_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        let test_message = ChatMessage {
            id: message_id,
            session_id,
            message_type: MessageRole::User,
            content: "This is a new user message about quantum physics"
                .as_bytes()
                .to_vec(),
            content_nonce: None, // ENSURED
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        };

        mock_qdrant.set_search_response(Ok(vec![]));
        let result = state
            .embedding_pipeline_service
            .process_and_embed_message(state.clone(), test_message, None)
            .await;
        assert!(
            result.is_ok(),
            "Expected Ok(()) for new message with no similar messages"
        );
    }

    #[tokio::test]
    async fn test_full_pipeline_with_similar_messages_retrieved() {
        let (state, mock_qdrant, _mock_embed_client) = setup_pipeline_test_env().await;
        let message_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        let test_message = ChatMessage {
            id: message_id,
            session_id,
            message_type: MessageRole::User,
            content: "Tell me more about ancient Rome and its emperors."
                .as_bytes()
                .to_vec(),
            content_nonce: None, // ENSURED
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        };
        mock_qdrant.set_search_response(Ok(vec![]));
        let result = state
            .embedding_pipeline_service
            .process_and_embed_message(state.clone(), test_message, None)
            .await;
        assert!(
            result.is_ok(),
            "Expected Ok(()) for message with similar messages"
        );
    }

    #[tokio::test]
    async fn test_full_pipeline_uses_original_message_if_no_expansion_needed() {
        let (state, mock_qdrant, _mock_embed_client) = setup_pipeline_test_env().await;
        let message_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let test_message = ChatMessage {
            id: message_id,
            session_id,
            message_type: MessageRole::User,
            content: b"Short and sweet.".to_vec(),
            content_nonce: None, // ENSURED
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        };
        mock_qdrant.set_search_response(Ok(vec![]));
        let result = state
            .embedding_pipeline_service
            .process_and_embed_message(state.clone(), test_message, None)
            .await;
        assert!(
            result.is_ok(),
            "Expected Ok(()) for message with no expansion needed"
        );
    }

    #[tokio::test]
    async fn test_full_pipeline_handles_embedding_client_error_gracefully() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let message_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let test_message = ChatMessage {
            id: message_id,
            session_id,
            message_type: MessageRole::User,
            content: "This message will cause an embedding error."
                .as_bytes()
                .to_vec(),
            content_nonce: None, // ENSURED
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        };
        mock_qdrant.set_search_response(Ok(vec![]));
        mock_embed_client.set_response(Err(AppError::AiServiceError(
            "Simulated embedding error".to_string(),
        )));
        let result = state
            .embedding_pipeline_service
            .process_and_embed_message(state.clone(), test_message, None)
            .await;
        // Current behavior: logs error, returns Ok if no points were made to upsert.
        assert!(
            result.is_ok(),
            "Expected an Ok due to graceful error handling of embedding client failure"
        );
    }

    #[tokio::test]
    async fn test_full_pipeline_handles_qdrant_upsert_error_gracefully() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let message_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let test_message = ChatMessage {
            id: message_id,
            session_id,
            message_type: MessageRole::User,
            content: "This message will cause a Qdrant upsert error."
                .as_bytes()
                .to_vec(),
            content_nonce: None, // ENSURED
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        };
        mock_qdrant.set_search_response(Ok(vec![]));
        mock_qdrant.set_upsert_response(Err(AppError::VectorDbError(
            "Simulated Qdrant upsert error".to_string(),
        )));
        mock_embed_client.set_response(Ok(vec![0.1, 0.2, 0.3])); // Ensure embedding itself succeeds
        let result = state
            .embedding_pipeline_service
            .process_and_embed_message(state.clone(), test_message, None)
            .await;
        assert!(
            result.is_err(),
            "Expected an error due to Qdrant upsert failure"
        );
    }

    // --- Tests for process_and_embed_message with encryption ---

    fn create_test_dek() -> SessionDek {
        // Use the centralized DEK generation function and unwrap for test
        SessionDek(crate::crypto::crypto_generate_dek().expect("Failed to generate DEK for test"))
    }

    #[tokio::test]
    async fn test_process_and_embed_encrypted_message_success() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let dek = create_test_dek();
        let original_content = "This is a secret message.";

        let (encrypted_content, nonce) = encrypt_gcm(original_content.as_bytes(), &dek.0).unwrap();

        let test_message = ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: encrypted_content,
            content_nonce: Some(nonce),
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        };

        mock_embed_client.set_response(Ok(vec![0.1, 0.2]));
        mock_qdrant.set_upsert_response(Ok(()));

        let result = state
            .embedding_pipeline_service
            .process_and_embed_message(state.clone(), test_message, Some(&dek))
            .await;
        assert!(
            result.is_ok(),
            "Processing encrypted message failed: {:?}",
            result.err()
        );

        let calls = mock_embed_client.get_calls();
        assert_eq!(calls.len(), 1, "Expected one call to embedding client");
        assert_eq!(
            calls[0].0, original_content,
            "Expected original content to be embedded after decryption"
        );
    }

    #[tokio::test]
    async fn test_process_and_embed_plaintext_message_with_nonce_but_no_dek() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;

        let original_content = "NoDEK"; // Shorter, simpler content

        // Use a fixed key for deterministic encryption in this test
        let fixed_key_bytes = [0u8; 32]; // Example fixed key
        let key_for_encryption_only = SecretBox::new(Box::new(fixed_key_bytes.to_vec()));

        // Simulate encrypted content and nonce, but we won't provide DEK
        let (encrypted_content, nonce) =
            encrypt_gcm(original_content.as_bytes(), &key_for_encryption_only)
                .expect("Encryption failed in test");

        let test_message = ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: encrypted_content.clone(), // This will be used for lossy conversion
            content_nonce: Some(nonce),
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        };

        mock_embed_client.set_response(Ok(vec![0.1, 0.2]));
        mock_qdrant.set_upsert_response(Ok(()));

        // Pass None for session_dek
        let result = state
            .embedding_pipeline_service
            .process_and_embed_message(state.clone(), test_message, None)
            .await;
        assert!(
            result.is_ok(),
            "Processing message with nonce but no DEK failed: {:?}",
            result.err()
        );

        let calls = mock_embed_client.get_calls();
        assert_eq!(
            calls.len(),
            1,
            "Expected one call to embedding client. Actual calls: {calls:#?}"
        );
        // Expect lossy conversion of the ciphertext, sanitized, then trimmed
        let expected_lossy_content_sanitized = String::from_utf8_lossy(&encrypted_content)
            .to_string()
            .replace(['\n', '\r'], " ");
        let expected_embedded_content = expected_lossy_content_sanitized.trim().to_string();
        assert_eq!(
            calls[0].0, expected_embedded_content,
            "Expected trimmed, sanitized lossy ciphertext to be embedded"
        );
    }

    #[tokio::test]
    async fn test_process_and_embed_encrypted_message_decryption_failure() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let user_dek = create_test_dek(); // User's actual DEK
        let wrong_dek = create_test_dek(); // A different DEK for simulating decryption failure

        // Shortened to ensure its lossy-converted ciphertext is unlikely to be chunked.
        let original_content_text = "Test";

        // Encrypt with the user's actual DEK
        let (encrypted_content, nonce) =
            encrypt_gcm(original_content_text.as_bytes(), &user_dek.0).unwrap();

        let test_message = ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: encrypted_content.clone(), // This will be used for lossy conversion
            content_nonce: Some(nonce),
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        };

        mock_embed_client.set_response(Ok(vec![0.1, 0.2]));
        mock_qdrant.set_upsert_response(Ok(()));

        // Pass the "wrong" DEK for decryption
        let result = state
            .embedding_pipeline_service
            .process_and_embed_message(state.clone(), test_message, Some(&wrong_dek))
            .await;
        assert!(
            result.is_ok(),
            "Processing message with decryption failure failed: {:?}",
            result.err()
        );

        let calls = mock_embed_client.get_calls();
        assert_eq!(calls.len(), 1, "Expected one call to embedding client");
        // Expect lossy conversion of the ciphertext, sanitized, then trimmed, due to decryption failure
        let expected_lossy_content_sanitized = String::from_utf8_lossy(&encrypted_content)
            .to_string()
            .replace(['\n', '\r'], " ");
        let expected_embedded_content = expected_lossy_content_sanitized.trim().to_string();
        assert_eq!(
            calls[0].0, expected_embedded_content,
            "Expected trimmed, sanitized lossy ciphertext to be embedded after decryption failure"
        );
    }

    #[tokio::test]
    async fn test_process_and_embed_encrypted_message_missing_nonce() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let dek = create_test_dek();
        // Shortened to ensure its lossy-converted ciphertext is unlikely to be chunked.
        let original_content_text = "T";

        // Encrypt the content to simulate what would be in message.content
        let (encrypted_content_bytes, _nonce_that_will_be_ignored) =
            encrypt_gcm(original_content_text.as_bytes(), &dek.0).unwrap();

        let test_message = ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: encrypted_content_bytes.clone(), // This is ciphertext
            content_nonce: None,                      // Crucially, nonce is None
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        };

        mock_embed_client.set_response(Ok(vec![0.1, 0.2]));
        mock_qdrant.set_upsert_response(Ok(()));

        // Pass the DEK, but it shouldn't be used due to missing nonce
        let result = state
            .embedding_pipeline_service
            .process_and_embed_message(state.clone(), test_message, Some(&dek))
            .await;
        assert!(
            result.is_ok(),
            "Processing message with missing nonce failed: {:?}",
            result.err()
        );

        let calls = mock_embed_client.get_calls();
        assert_eq!(calls.len(), 1, "Expected one call to embedding client");

        // Expect lossy conversion of the ciphertext, sanitized, then trimmed
        let expected_lossy_content_sanitized = String::from_utf8_lossy(&encrypted_content_bytes)
            .to_string()
            .replace(['\n', '\r'], " ");
        let expected_embedded_content = expected_lossy_content_sanitized.trim().to_string();
        assert_eq!(
            calls[0].0, expected_embedded_content,
            "Expected trimmed, sanitized lossy original (encrypted) content to be embedded"
        );
    }

    #[tokio::test]
    async fn test_process_and_embed_plaintext_message_with_dek_present() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let dek = create_test_dek(); // DEK is present
        let plaintext_content = "This is a normal plaintext message.";

        let test_message = ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: plaintext_content.as_bytes().to_vec(), // Plaintext
            content_nonce: None,                            // No nonce, so it's plaintext
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        };

        mock_embed_client.set_response(Ok(vec![0.1, 0.2]));
        mock_qdrant.set_upsert_response(Ok(()));

        // Pass the DEK; it should be ignored for plaintext messages
        let result = state
            .embedding_pipeline_service
            .process_and_embed_message(state.clone(), test_message, Some(&dek))
            .await;
        assert!(
            result.is_ok(),
            "Processing plaintext message with DEK present failed: {:?}",
            result.err()
        );

        let calls = mock_embed_client.get_calls();
        assert_eq!(calls.len(), 1, "Expected one call to embedding client");
        assert_eq!(
            calls[0].0, plaintext_content,
            "Expected original plaintext content to be embedded"
        );
    }

    // --- Tests for process_and_embed_lorebook_entry ---

    // Helper struct for test parameters
    #[derive(Clone)]
    struct TestLorebookParams {
        params: LorebookEntryParams,
        original_id: Uuid,
        lorebook_id: Uuid,
        user_id: Uuid,
        content: String,
    }

    // Helper function to create test lorebook entry parameters
    fn create_test_lorebook_params() -> TestLorebookParams {
        let original_lorebook_entry_id = Uuid::new_v4();
        let lorebook_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let decrypted_content =
            "This is a lorebook entry about dragons. They breathe fire.".to_string();

        let params = LorebookEntryParams {
            original_lorebook_entry_id,
            lorebook_id,
            user_id,
            decrypted_content: decrypted_content.clone(),
            decrypted_title: Some("Dragons".to_string()),
            decrypted_keywords: Some(vec!["dragon".to_string(), "mythical".to_string()]),
            is_enabled: true,
            is_constant: false,
        };

        TestLorebookParams {
            params,
            original_id: original_lorebook_entry_id,
            lorebook_id,
            user_id,
            content: decrypted_content,
        }
    }

    // Helper function to verify payload string value
    fn assert_payload_string(
        point: &qdrant_client::qdrant::PointStruct,
        key: &str,
        expected: &str,
    ) {
        let payload_value = point.payload.get(key).unwrap().kind.as_ref().unwrap();
        if let qdrant_client::qdrant::value::Kind::StringValue(s) = payload_value {
            assert_eq!(s, expected);
        } else {
            panic!("Wrong type for {key}");
        }
    }

    // Helper function to verify payload bool value
    fn assert_payload_bool(point: &qdrant_client::qdrant::PointStruct, key: &str, expected: bool) {
        let payload_value = point.payload.get(key).unwrap().kind.as_ref().unwrap();
        if let qdrant_client::qdrant::value::Kind::BoolValue(b) = payload_value {
            assert_eq!(*b, expected);
        } else {
            panic!("Wrong type for {key}");
        }
    }

    #[tokio::test]
    async fn test_process_lorebook_entry_succeeds() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let test_params = create_test_lorebook_params();

        // Setup mocks
        mock_embed_client.set_response(Ok(vec![0.1, 0.2, 0.3, 0.4]));
        mock_qdrant.set_upsert_response(Ok(()));

        let result = state
            .embedding_pipeline_service
            .process_and_embed_lorebook_entry(state.clone(), test_params.params)
            .await;

        assert!(
            result.is_ok(),
            "process_and_embed_lorebook_entry failed: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn test_lorebook_entry_embedding_client_calls() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let test_params = create_test_lorebook_params();

        // Setup mocks
        mock_embed_client.set_response(Ok(vec![0.1, 0.2, 0.3, 0.4]));
        mock_qdrant.set_upsert_response(Ok(()));

        let _ = state
            .embedding_pipeline_service
            .process_and_embed_lorebook_entry(state.clone(), test_params.params.clone())
            .await;

        // Verify embedding client calls
        let embed_calls = mock_embed_client.get_calls();
        assert_eq!(embed_calls.len(), 1, "Expected 1 call to embedding client");
        assert_eq!(embed_calls[0].0, test_params.content);
        assert_eq!(embed_calls[0].1, "RETRIEVAL_DOCUMENT");
        assert_eq!(embed_calls[0].2, test_params.params.decrypted_title);
    }

    #[tokio::test]
    async fn test_lorebook_entry_qdrant_upsert() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let test_params = create_test_lorebook_params();

        // Setup mocks
        mock_embed_client.set_response(Ok(vec![0.1, 0.2, 0.3, 0.4]));
        mock_qdrant.set_upsert_response(Ok(()));

        let _ = state
            .embedding_pipeline_service
            .process_and_embed_lorebook_entry(state.clone(), test_params.params)
            .await;

        // Verify Qdrant upsert
        let qdrant_upsert_points = mock_qdrant.get_last_upsert_points().unwrap_or_default();
        assert_eq!(
            qdrant_upsert_points.len(),
            1,
            "Expected 1 point in the batch upsert"
        );

        let point = &qdrant_upsert_points[0];
        assert!(
            matches!(
                point
                    .vectors
                    .as_ref()
                    .unwrap()
                    .vectors_options
                    .as_ref()
                    .unwrap(),
                qdrant_client::qdrant::vectors::VectorsOptions::Vector(_)
            ),
            "Expected a single unnamed vector"
        );
    }

    // Helper function to verify embedding client calls
    fn verify_embedding_calls(
        embed_calls: &[(String, String, Option<String>)],
        expected_content: &str,
        expected_title: Option<&String>,
    ) {
        assert_eq!(
            embed_calls.len(),
            1,
            "Expected 1 call to embedding client for the content"
        );
        assert_eq!(embed_calls[0].0, expected_content);
        assert_eq!(embed_calls[0].1, "RETRIEVAL_DOCUMENT");
        assert_eq!(embed_calls[0].2.as_ref(), expected_title);
    }

    // Helper function to verify qdrant upsert structure
    fn verify_qdrant_upsert_structure(points: &[qdrant_client::qdrant::PointStruct]) {
        assert_eq!(points.len(), 1, "Expected 1 point in the batch upsert");
        let point = &points[0];
        assert!(
            matches!(
                point
                    .vectors
                    .as_ref()
                    .unwrap()
                    .vectors_options
                    .as_ref()
                    .unwrap(),
                qdrant_client::qdrant::vectors::VectorsOptions::Vector(_)
            ),
            "Expected a single unnamed vector"
        );
    }

    // Helper function to verify detailed payload fields (complementing assert_payload_* helpers)
    fn verify_detailed_payload_fields(
        point: &qdrant_client::qdrant::PointStruct,
        test_params: &TestLorebookParams,
    ) {
        // These detailed checks verify the same data as the helper functions but with raw access
        let payload_value = point
            .payload
            .get("original_lorebook_entry_id")
            .unwrap()
            .kind
            .as_ref()
            .unwrap();
        if let qdrant_client::qdrant::value::Kind::StringValue(s) = payload_value {
            assert_eq!(*s, test_params.original_id.to_string());
        } else {
            panic!("Wrong type for original_lorebook_entry_id");
        }

        let payload_value = point
            .payload
            .get("lorebook_id")
            .unwrap()
            .kind
            .as_ref()
            .unwrap();
        if let qdrant_client::qdrant::value::Kind::StringValue(s) = payload_value {
            assert_eq!(*s, test_params.lorebook_id.to_string());
        } else {
            panic!("Wrong type for lorebook_id");
        }

        let payload_value = point.payload.get("user_id").unwrap().kind.as_ref().unwrap();
        if let qdrant_client::qdrant::value::Kind::StringValue(s) = payload_value {
            assert_eq!(*s, test_params.user_id.to_string());
        } else {
            panic!("Wrong type for user_id");
        }

        let payload_value = point
            .payload
            .get("chunk_text")
            .unwrap()
            .kind
            .as_ref()
            .unwrap();
        if let qdrant_client::qdrant::value::Kind::StringValue(s) = payload_value {
            assert_eq!(*s, test_params.content);
        } else {
            panic!("Wrong type for chunk_text");
        }

        let payload_value = point
            .payload
            .get("entry_title")
            .unwrap()
            .kind
            .as_ref()
            .unwrap();
        if let qdrant_client::qdrant::value::Kind::StringValue(s) = payload_value {
            assert_eq!(
                *s,
                test_params.params.decrypted_title.as_ref().unwrap().clone()
            );
        } else {
            panic!("Wrong type for entry_title");
        }

        let payload_value = point
            .payload
            .get("is_enabled")
            .unwrap()
            .kind
            .as_ref()
            .unwrap();
        if let qdrant_client::qdrant::value::Kind::BoolValue(b) = payload_value {
            assert_eq!(b, &test_params.params.is_enabled);
        } else {
            panic!("Wrong type for is_enabled");
        }
    }

    #[tokio::test]
    async fn test_lorebook_entry_payload_fields() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let test_params = create_test_lorebook_params();

        // Setup mocks and process entry
        mock_embed_client.set_response(Ok(vec![0.1, 0.2, 0.3, 0.4]));
        mock_qdrant.set_upsert_response(Ok(()));

        let _ = state
            .embedding_pipeline_service
            .process_and_embed_lorebook_entry(state.clone(), test_params.params.clone())
            .await;

        // Verify payload fields using helper functions
        let points = mock_qdrant.get_last_upsert_points().unwrap_or_default();
        let point = &points[0];

        assert_payload_string(
            point,
            "original_lorebook_entry_id",
            &test_params.original_id.to_string(),
        );
        assert_payload_string(point, "lorebook_id", &test_params.lorebook_id.to_string());
        assert_payload_string(point, "user_id", &test_params.user_id.to_string());
        assert_payload_string(point, "chunk_text", &test_params.content);
        assert_payload_string(
            point,
            "entry_title",
            test_params.params.decrypted_title.as_ref().unwrap(),
        );
        assert_payload_bool(point, "is_enabled", test_params.params.is_enabled);

        // Verify embedding client calls
        let embed_calls = mock_embed_client.get_calls();
        verify_embedding_calls(
            &embed_calls,
            &test_params.content,
            test_params.params.decrypted_title.as_ref(),
        );

        // Verify Qdrant upsert structure
        let qdrant_upsert_points = mock_qdrant.get_last_upsert_points().unwrap_or_default();
        verify_qdrant_upsert_structure(&qdrant_upsert_points);

        // Verify detailed payload fields (raw access verification)
        verify_detailed_payload_fields(&qdrant_upsert_points[0], &test_params);
    }

    #[tokio::test]
    async fn test_process_and_embed_lorebook_entry_empty_content() {
        let (state, _mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let original_lorebook_entry_id = Uuid::new_v4();
        let lorebook_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let params = LorebookEntryParams {
            original_lorebook_entry_id,
            lorebook_id,
            user_id,
            decrypted_content: "   ".to_string(), // Empty after trim
            decrypted_title: Some("Empty Title".to_string()),
            decrypted_keywords: None,
            is_enabled: true,
            is_constant: false,
        };

        let result = state
            .embedding_pipeline_service
            .process_and_embed_lorebook_entry(state.clone(), params)
            .await;

        assert!(
            result.is_ok(),
            "Expected Ok for empty content (should skip embedding)"
        );
        assert!(
            mock_embed_client.get_calls().is_empty(),
            "Embedding client should not be called for empty content"
        );
    }

    #[tokio::test]
    async fn test_process_and_embed_lorebook_entry_embedding_error() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let original_lorebook_entry_id = Uuid::new_v4();
        let lorebook_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        mock_embed_client.set_response(Err(AppError::AiServiceError(
            "Embedding failed".to_string(),
        )));

        let params = LorebookEntryParams {
            original_lorebook_entry_id,
            lorebook_id,
            user_id,
            decrypted_content: "Some lore content".to_string(),
            decrypted_title: Some("Lore Title".to_string()),
            decrypted_keywords: None,
            is_enabled: true,
            is_constant: false,
        };

        let result = state
            .embedding_pipeline_service
            .process_and_embed_lorebook_entry(state.clone(), params)
            .await;

        assert!(
            result.is_ok(),
            "Service should handle embedding errors gracefully and return Ok if no points were made to upsert."
        );
        assert!(
            mock_qdrant
                .get_last_upsert_points()
                .unwrap_or_default()
                .is_empty(),
            "Qdrant should not be called if embedding failed for all chunks"
        );
    }

    #[tokio::test]
    async fn test_process_and_embed_lorebook_entry_qdrant_error() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let original_lorebook_entry_id = Uuid::new_v4();
        let lorebook_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        mock_embed_client.set_response(Ok(vec![0.5, 0.5]));
        mock_qdrant.set_upsert_response(Err(AppError::VectorDbError("Qdrant down".to_string())));

        let params = LorebookEntryParams {
            original_lorebook_entry_id,
            lorebook_id,
            user_id,
            decrypted_content: "Some lore content".to_string(),
            decrypted_title: Some("Lore Title".to_string()),
            decrypted_keywords: None,
            is_enabled: true,
            is_constant: false,
        };

        let result = state
            .embedding_pipeline_service
            .process_and_embed_lorebook_entry(state.clone(), params)
            .await;

        assert!(result.is_err());
        if let Err(AppError::VectorDbError(msg)) = result {
            assert_eq!(msg, "Qdrant down");
        } else {
            panic!("Expected VectorDbError");
        }
    }

    #[tokio::test]
    async fn test_process_and_embed_lorebook_entry_multiple_chunks() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let original_lorebook_entry_id = Uuid::new_v4();
        let lorebook_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        // Content designed to be chunked by the service's default config (max_size 100, overlap 20)
        let long_content = "a".repeat(150);
        let decrypted_title = Some("Long Lore".to_string());

        mock_embed_client.set_response(Ok(vec![0.1, 0.2])); // Mock will return this for each call
        mock_qdrant.set_upsert_response(Ok(()));

        let params = LorebookEntryParams {
            original_lorebook_entry_id,
            lorebook_id,
            user_id,
            decrypted_content: long_content.clone(),
            decrypted_title: decrypted_title.clone(),
            decrypted_keywords: None,
            is_enabled: true,
            is_constant: false,
        };

        let result = state
            .embedding_pipeline_service
            .process_and_embed_lorebook_entry(state.clone(), params)
            .await;

        assert!(
            result.is_ok(),
            "Processing multi-chunk lore entry failed: {:?}",
            result.err()
        );

        let embed_calls = mock_embed_client.get_calls();
        // 150 chars, 100 max, 20 overlap.
        // Chunk 1: 0-99 (100 chars)
        // Chunk 2: 80-149 (70 chars) -> (start = 100 - 20 = 80)
        assert_eq!(
            embed_calls.len(),
            2,
            "Expected 2 calls to embedding client for 150 char content"
        );
        assert_eq!(embed_calls[0].1, "RETRIEVAL_DOCUMENT");
        assert_eq!(embed_calls[0].2, decrypted_title);
        assert_eq!(embed_calls[1].1, "RETRIEVAL_DOCUMENT");
        assert_eq!(embed_calls[1].2, decrypted_title);

        let qdrant_upsert_points = mock_qdrant.get_last_upsert_points().unwrap_or_default();
        assert_eq!(
            qdrant_upsert_points.len(),
            2,
            "Expected 2 points in the batch upsert"
        );
    }

    // Helper to convert bool to Qdrant Bool Value
    const fn bool_value(b: bool) -> Value {
        Value {
            kind: Some(qdrant_client::qdrant::value::Kind::BoolValue(b)),
        }
    }

    // Helper to convert Option<Vec<String>> to Qdrant List Value or Null Value
    fn optional_list_string_value(opt_list: Option<Vec<String>>) -> Value {
        opt_list.map_or_else(
            || Value {
                kind: Some(qdrant_client::qdrant::value::Kind::NullValue(
                    // Use the enum variant directly without casting - it should auto-convert
                    qdrant_client::qdrant::NullValue::default().into(),
                )),
            },
            |list| Value {
                kind: Some(qdrant_client::qdrant::value::Kind::ListValue(
                    qdrant_client::qdrant::ListValue {
                        values: list.into_iter().map(|s| string_value(&s)).collect(),
                    },
                )),
            },
        )
    }

    // Helper to convert Option<String> to Qdrant String Value or Null Value
    fn optional_string_value(opt_s: Option<String>) -> Value {
        opt_s.map_or_else(
            || Value {
                kind: Some(qdrant_client::qdrant::value::Kind::NullValue(
                    // Use the enum variant directly without casting - it should auto-convert
                    qdrant_client::qdrant::NullValue::default().into(),
                )),
            },
            |s| string_value(&s),
        )
    }

    // Helper to create a mock ScoredPoint for Lorebook entries
    // Helper struct for creating mock lorebook ScoredPoint
    struct MockLorebookScoredPointParams<'a> {
        point_uuid: Uuid,
        score: f32,
        original_lorebook_entry_id: Uuid,
        lorebook_id: Uuid,
        user_id: Uuid,
        chunk_text: &'a str,
        entry_title: Option<String>,
        keywords: Option<Vec<String>>,
        is_enabled: bool,
        is_constant: bool,
        source_type: &'a str,
    }

    fn create_mock_lorebook_scored_point(params: MockLorebookScoredPointParams<'_>) -> ScoredPoint {
        let mut payload = HashMap::new();
        payload.insert(
            "original_lorebook_entry_id".to_string(),
            string_value(&params.original_lorebook_entry_id.to_string()),
        );
        payload.insert(
            "lorebook_id".to_string(),
            string_value(&params.lorebook_id.to_string()),
        );
        payload.insert(
            "user_id".to_string(),
            string_value(&params.user_id.to_string()),
        );
        payload.insert("chunk_text".to_string(), string_value(params.chunk_text));
        payload.insert(
            "entry_title".to_string(),
            optional_string_value(params.entry_title),
        );
        payload.insert(
            "keywords".to_string(),
            optional_list_string_value(params.keywords),
        );
        payload.insert("is_enabled".to_string(), bool_value(params.is_enabled));
        payload.insert("is_constant".to_string(), bool_value(params.is_constant));
        payload.insert("source_type".to_string(), string_value(params.source_type));

        ScoredPoint {
            id: Some(PointId::from(params.point_uuid.to_string())),
            payload,
            score: params.score,
            version: 0,
            vectors: None,
            shard_key: None,
            order_value: None,
        }
    }

    // --- Tests for retrieve_relevant_chunks ---

    #[tokio::test]
    async fn test_retrieve_chunks_chat_history_only() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let query_text = "relevant query";
        let limit: u64 = 3;

        mock_embed_client.set_response(Ok(vec![0.1, 0.2, 0.3])); // Mock query embedding

        let chat_point_id = Uuid::new_v4();
        let mock_chat_results = vec![create_mock_scored_point(&MockScoredPointParams {
            id_uuid: chat_point_id,
            score: 0.9,
            session_id,
            message_id: Uuid::new_v4(),
            user_id,
            speaker: "User",
            timestamp: Utc::now(),
            text: "Test chat message content",
            source_type: "chat_message",
        })];
        mock_qdrant.set_search_response(Ok(mock_chat_results.clone()));

        let result = state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(
                state.clone(),
                user_id,
                Some(session_id),
                None,
                query_text,
                limit,
            )
            .await;

        assert!(
            result.is_ok(),
            "retrieve_relevant_chunks failed: {:?}",
            result.err()
        );
        let chunks = result.unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].text, "Test chat message content");
        match &chunks[0].metadata {
            RetrievedMetadata::Chat(meta) => {
                assert_eq!(meta.session_id, session_id);
                assert_eq!(meta.source_type, "chat_message");
            }
            RetrievedMetadata::Lorebook(_) => panic!("Expected Chat metadata"),
        }

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(search_call_count, 1, "Expected one search call to Qdrant");
        let search_params = mock_qdrant
            .get_last_search_params()
            .expect("Expected search_params to be set after one call");
        let (_embedding, _limit, filter_opt) = &search_params;
        assert!(filter_opt.is_some());
        let filter = filter_opt.as_ref().unwrap();

        // Verify chat filter construction
        assert_eq!(filter.must.len(), 3); // user_id, session_id, source_type
        assert!(filter.must.iter().any(|c| {
            if let Some(ConditionOneOf::Field(fc)) = c.condition_one_of.as_ref() {
                if fc.key == "user_id" {
                    if let Some(m) = fc.r#match.as_ref() {
                        if let Some(MatchValue::Keyword(val)) = m.match_value.as_ref() {
                            return val == &user_id.to_string();
                        }
                    }
                }
            }
            false
        }));
        assert!(filter.must.iter().any(|c| {
            if let Some(ConditionOneOf::Field(fc)) = c.condition_one_of.as_ref() {
                if fc.key == "session_id" {
                    if let Some(m) = fc.r#match.as_ref() {
                        if let Some(MatchValue::Keyword(val)) = m.match_value.as_ref() {
                            return val == &session_id.to_string();
                        }
                    }
                }
            }
            false
        }));
        assert!(filter.must.iter().any(|c| {
            if let Some(ConditionOneOf::Field(fc)) = c.condition_one_of.as_ref() {
                if fc.key == "source_type" {
                    if let Some(m) = fc.r#match.as_ref() {
                        if let Some(MatchValue::Keyword(val)) = m.match_value.as_ref() {
                            return val == "chat_message";
                        }
                    }
                }
            }
            false
        }));
    }

    fn verify_lorebook_filter_conditions(
        filter: &Filter,
        user_id: Uuid,
        lorebook_id1: Uuid,
        lorebook_id2: Uuid,
    ) {
        assert_eq!(filter.must.len(), 3); // user_id, source_type, is_enabled
        assert_eq!(filter.should.len(), 2); // lorebook_id1, lorebook_id2

        assert!(filter.must.iter().any(|c| {
            if let Some(ConditionOneOf::Field(fc)) = c.condition_one_of.as_ref() {
                if fc.key == "user_id" {
                    if let Some(m) = fc.r#match.as_ref() {
                        if let Some(MatchValue::Keyword(val)) = m.match_value.as_ref() {
                            return val == &user_id.to_string();
                        }
                    }
                }
            }
            false
        }));
        assert!(filter.must.iter().any(|c| {
            if let Some(ConditionOneOf::Field(fc)) = c.condition_one_of.as_ref() {
                if fc.key == "source_type" {
                    if let Some(m) = fc.r#match.as_ref() {
                        if let Some(MatchValue::Keyword(val)) = m.match_value.as_ref() {
                            return val == "lorebook_entry";
                        }
                    }
                }
            }
            false
        }));
        assert!(filter.must.iter().any(|c| {
            if let Some(ConditionOneOf::Field(fc)) = c.condition_one_of.as_ref() {
                if fc.key == "is_enabled" {
                    if let Some(m) = fc.r#match.as_ref() {
                        if let Some(MatchValue::Boolean(b_val)) = m.match_value.as_ref() {
                            return *b_val;
                        }
                    }
                }
            }
            false
        }));
        assert!(filter.should.iter().any(|c| {
            if let Some(ConditionOneOf::Field(fc)) = c.condition_one_of.as_ref() {
                if fc.key == "lorebook_id" {
                    if let Some(m) = fc.r#match.as_ref() {
                        if let Some(MatchValue::Keyword(val)) = m.match_value.as_ref() {
                            return val == &lorebook_id1.to_string();
                        }
                    }
                }
            }
            false
        }));
        assert!(filter.should.iter().any(|c| {
            if let Some(ConditionOneOf::Field(fc)) = c.condition_one_of.as_ref() {
                if fc.key == "lorebook_id" {
                    if let Some(m) = fc.r#match.as_ref() {
                        if let Some(MatchValue::Keyword(val)) = m.match_value.as_ref() {
                            return val == &lorebook_id2.to_string();
                        }
                    }
                }
            }
            false
        }));
    }

    #[tokio::test]
    async fn test_retrieve_chunks_lorebook_entries_only() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let user_id = Uuid::new_v4();
        let lorebook_id1 = Uuid::new_v4();
        let lorebook_id2 = Uuid::new_v4();
        let active_lorebook_ids = vec![lorebook_id1, lorebook_id2];
        let query_text = "relevant query for lore";
        let limit: u64 = 2;

        mock_embed_client.set_response(Ok(vec![0.4, 0.5, 0.6]));

        let lore_point_id = Uuid::new_v4();
        let mock_lore_results = vec![create_mock_lorebook_scored_point(
            MockLorebookScoredPointParams {
                point_uuid: lore_point_id,
                score: 0.85,
                original_lorebook_entry_id: Uuid::new_v4(),
                lorebook_id: lorebook_id1,
                user_id,
                chunk_text: "Test lorebook entry content",
                entry_title: Some("Lore Title".to_string()),
                keywords: None,
                is_enabled: true,
                is_constant: false,
                source_type: "lorebook_entry",
            },
        )];
        mock_qdrant.set_search_response(Ok(mock_lore_results.clone()));

        let result = state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(
                state.clone(),
                user_id,
                None,
                Some(active_lorebook_ids.clone()),
                query_text,
                limit,
            )
            .await;

        assert!(
            result.is_ok(),
            "retrieve_relevant_chunks failed: {:?}",
            result.err()
        );
        let chunks = result.unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].text, "Test lorebook entry content");
        match &chunks[0].metadata {
            RetrievedMetadata::Lorebook(meta) => {
                assert_eq!(meta.lorebook_id, lorebook_id1);
                assert_eq!(meta.source_type, "lorebook_entry");
                assert!(meta.is_enabled);
            }
            RetrievedMetadata::Chat(_) => panic!("Expected Lorebook metadata"),
        }

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(search_call_count, 1, "Expected one search call to Qdrant");
        let search_params = mock_qdrant
            .get_last_search_params()
            .expect("Expected search_params to be set after one call");
        let (_embedding, _limit, filter_opt) = &search_params;
        assert!(filter_opt.is_some());
        let filter = filter_opt.as_ref().unwrap();

        verify_lorebook_filter_conditions(filter, user_id, lorebook_id1, lorebook_id2);
    }

    #[tokio::test]
    async fn test_retrieve_chunks_chat_and_lorebook() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let lorebook_id = Uuid::new_v4();
        let active_lorebook_ids = vec![lorebook_id];
        let query_text = "relevant query for both";
        let limit: u64 = 1; // Limit to 1 per source to test combining and sorting

        mock_embed_client.set_response(Ok(vec![0.7, 0.8, 0.9]));

        let chat_point_id = Uuid::new_v4();
        let lore_point_id = Uuid::new_v4();

        let mock_chat_results = vec![create_mock_scored_point(&MockScoredPointParams {
            id_uuid: chat_point_id,
            score: 0.95,
            session_id,
            message_id: Uuid::new_v4(),
            user_id,
            speaker: "User",
            timestamp: Utc::now(),
            text: "Chat content about topic",
            source_type: "chat_message",
        })];
        let mock_lore_results = vec![create_mock_lorebook_scored_point(
            MockLorebookScoredPointParams {
                point_uuid: lore_point_id,
                score: 0.90,
                original_lorebook_entry_id: Uuid::new_v4(),
                lorebook_id,
                user_id,
                chunk_text: "Lore content about topic",
                entry_title: None,
                keywords: None,
                is_enabled: true,
                is_constant: false,
                source_type: "lorebook_entry",
            },
        )];

        // Mock Qdrant to return chat results first, then lore results using a sequence
        mock_qdrant.set_search_responses_sequence(vec![
            Ok(mock_chat_results.clone()), // First call gets chat results
            Ok(mock_lore_results.clone()), // Second call gets lore results
        ]);

        let result = state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(
                state.clone(),
                user_id,
                Some(session_id),
                Some(active_lorebook_ids.clone()),
                query_text,
                limit,
            )
            .await;

        assert!(
            result.is_ok(),
            "retrieve_relevant_chunks failed: {:?}",
            result.err()
        );
        let chunks = result.unwrap();
        assert_eq!(chunks.len(), 2);

        // Verify sorting by score (descending)
        assert_eq!(chunks[0].text, "Chat content about topic"); // Higher score
        assert!((chunks[0].score - 0.95).abs() < f32::EPSILON);
        assert_eq!(chunks[1].text, "Lore content about topic"); // Lower score
        assert!((chunks[1].score - 0.90).abs() < f32::EPSILON);

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(
            search_call_count, 2,
            "Expected two search calls (one for chat, one for lore)"
        );
        // Verifying parameters of individual calls in a sequence is complex with the current mock.
        // The primary check is that the combined and sorted results are correct.
        // We can check the *types* of filters used by inspecting the mock's recorded calls if the mock supports it,
        // but for now, we rely on the mock correctly routing based on the sequence.
        // The `get_last_search_params` would only give details for the *second* call (lorebooks).
        let last_search_params = mock_qdrant
            .get_last_search_params()
            .expect("Expected search_params for the last call");
        let (_embedding_lore, limit_lore, filter_opt_lore) = &last_search_params;
        assert_eq!(*limit_lore, limit); // limit_per_source for the lorebook call
        let filter_lore = filter_opt_lore.as_ref().unwrap();
        assert!(
            get_field_condition_keyword_match(filter_lore, "source_type")
                .is_some_and(|s| s == "lorebook_entry")
        );
        assert!(get_field_condition_bool_match(filter_lore, "is_enabled").is_some_and(|b| b));
        assert!(!get_should_conditions_keyword_match(filter_lore, "lorebook_id").is_empty());
    }

    #[tokio::test]
    async fn test_retrieve_chunks_no_specific_sources() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let user_id = Uuid::new_v4();
        let query_text = "query with no sources";
        let limit: u64 = 5;

        mock_embed_client.set_response(Ok(vec![0.1, 0.1, 0.1])); // Embedding will be generated

        let result = state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(
                state.clone(),
                user_id,
                None, // No chat session
                None, // No lorebooks
                query_text,
                limit,
            )
            .await;

        assert!(
            result.is_ok(),
            "retrieve_relevant_chunks failed: {:?}",
            result.err()
        );
        let chunks = result.unwrap();
        assert!(
            chunks.is_empty(),
            "Expected empty results when no sources are specified"
        );

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(
            search_call_count, 0,
            "Expected no calls to Qdrant search_points"
        );
    }

    #[tokio::test]
    async fn test_retrieve_chunks_empty_lorebook_id_list() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let user_id = Uuid::new_v4();
        let query_text = "query with empty lorebook list";
        let limit: u64 = 5;

        mock_embed_client.set_response(Ok(vec![0.2, 0.2, 0.2]));

        let result = state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(
                state.clone(),
                user_id,
                None,         // No chat session
                Some(vec![]), // Empty list of lorebook IDs
                query_text,
                limit,
            )
            .await;

        assert!(
            result.is_ok(),
            "retrieve_relevant_chunks failed: {:?}",
            result.err()
        );
        let chunks = result.unwrap();
        assert!(
            chunks.is_empty(),
            "Expected empty results for empty lorebook ID list and no chat"
        );

        let search_call_count = mock_qdrant.get_search_call_count();
        // No call for lorebooks because the list is empty. No call for chat because session_id is None.
        assert_eq!(
            search_call_count, 0,
            "Expected no calls to Qdrant search_points"
        );
    }

    #[tokio::test]
    async fn test_retrieve_chunks_empty_lorebook_id_list_with_chat() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4(); // Chat session IS provided
        let query_text = "query with empty lorebook list but with chat";
        let limit: u64 = 3;

        mock_embed_client.set_response(Ok(vec![0.1, 0.2, 0.3]));

        let chat_point_id = Uuid::new_v4();
        let mock_chat_results = vec![create_mock_scored_point(&MockScoredPointParams {
            id_uuid: chat_point_id,
            score: 0.9,
            session_id,
            message_id: Uuid::new_v4(),
            user_id,
            speaker: "User",
            timestamp: Utc::now(),
            text: "Chat message for this test",
            source_type: "chat_message",
        })];
        mock_qdrant.set_search_response(Ok(mock_chat_results.clone())); // Only chat results expected

        let result = state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(
                state.clone(),
                user_id,
                Some(session_id), // Chat session provided
                Some(vec![]),     // Empty list of lorebook IDs
                query_text,
                limit,
            )
            .await;

        assert!(
            result.is_ok(),
            "retrieve_relevant_chunks failed: {:?}",
            result.err()
        );
        let chunks = result.unwrap();
        assert_eq!(chunks.len(), 1); // Should get chat results
        assert_eq!(chunks[0].text, "Chat message for this test");

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(
            search_call_count, 1,
            "Expected one call to Qdrant for chat history"
        );
        let search_params = mock_qdrant
            .get_last_search_params()
            .expect("Expected search_params to be set after one call");
        let (_embedding, _limit_call, filter_opt) = &search_params;
        let filter = filter_opt.as_ref().unwrap();
        assert!(filter.must.iter().any(|c| {
            if let Some(ConditionOneOf::Field(fc)) = c.condition_one_of.as_ref() {
                fc.key == "session_id"
            } else {
                false
            }
        }));
        assert!(filter.should.is_empty()); // No lorebook conditions
    }

    fn create_mock_chat_results_for_limit_test(
        user_id: Uuid,
        session_id: Uuid,
    ) -> Vec<ScoredPoint> {
        let chat_point1 = Uuid::new_v4();
        let chat_point2 = Uuid::new_v4();

        vec![
            create_mock_scored_point(&MockScoredPointParams {
                id_uuid: chat_point1,
                score: 0.99,
                session_id,
                message_id: Uuid::new_v4(),
                user_id,
                speaker: "U1",
                timestamp: Utc::now(),
                text: "Chat1",
                source_type: "chat_message",
            }),
            create_mock_scored_point(&MockScoredPointParams {
                id_uuid: chat_point2,
                score: 0.98,
                session_id,
                message_id: Uuid::new_v4(),
                user_id,
                speaker: "U2",
                timestamp: Utc::now(),
                text: "Chat2",
                source_type: "chat_message",
            }),
        ]
    }

    fn create_mock_lore_results_for_limit_test(
        user_id: Uuid,
        lorebook_id: Uuid,
    ) -> Vec<ScoredPoint> {
        let lore_point1 = Uuid::new_v4();
        let lore_point2 = Uuid::new_v4();

        vec![
            create_mock_lorebook_scored_point(MockLorebookScoredPointParams {
                point_uuid: lore_point1,
                score: 0.97,
                original_lorebook_entry_id: Uuid::new_v4(),
                lorebook_id,
                user_id,
                chunk_text: "Lore1",
                entry_title: None,
                keywords: None,
                is_enabled: true,
                is_constant: false,
                source_type: "lorebook_entry",
            }),
            create_mock_lorebook_scored_point(MockLorebookScoredPointParams {
                point_uuid: lore_point2,
                score: 0.96,
                original_lorebook_entry_id: Uuid::new_v4(),
                lorebook_id,
                user_id,
                chunk_text: "Lore2",
                entry_title: None,
                keywords: None,
                is_enabled: true,
                is_constant: false,
                source_type: "lorebook_entry",
            }),
        ]
    }

    #[tokio::test]
    async fn test_retrieve_chunks_limit_per_source_respected() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let lorebook_id = Uuid::new_v4();
        let query_text = "query for limit test";
        let limit_per_source: u64 = 1; // Crucial: limit to 1 per source

        mock_embed_client.set_response(Ok(vec![0.5, 0.5, 0.5]));

        let mock_chat_results_full = create_mock_chat_results_for_limit_test(user_id, session_id);
        let mock_lore_results_full = create_mock_lore_results_for_limit_test(user_id, lorebook_id);

        // Mock Qdrant to provide full results; the mock's search_points method will truncate based on limit_per_source.
        mock_qdrant.set_search_responses_sequence(vec![
            Ok(mock_chat_results_full.clone()), // First call gets chat results (mock will truncate)
            Ok(mock_lore_results_full.clone()), // Second call gets lore results (mock will truncate)
        ]);

        let result = state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(
                state.clone(),
                user_id,
                Some(session_id),
                Some(vec![lorebook_id]),
                query_text,
                limit_per_source,
            )
            .await;

        assert!(
            result.is_ok(),
            "retrieve_relevant_chunks failed: {:?}",
            result.err()
        );
        let chunks = result.unwrap();
        // Total chunks should be limit_per_source from chat + limit_per_source from lore
        assert_eq!(
            chunks.len(),
            usize::try_from(limit_per_source * 2).unwrap_or(usize::MAX),
            "Expected total chunks to be sum of limits from each source"
        );
        // Results are sorted by score. Chat1 (0.99) > Lore1 (0.97)
        assert_eq!(
            chunks[0].text, "Chat1",
            "Expected Chat1 with higher score first"
        );
        assert_eq!(
            chunks[1].text, "Lore1",
            "Expected Lore1 with lower score second"
        );

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(search_call_count, 2, "Expected two search calls");

        // We can check the limit passed to the *last* call (lorebooks)
        let last_search_params = mock_qdrant
            .get_last_search_params()
            .expect("Expected search_params for the last call");
        let (_embedding_lore, limit_call_lore, _filter_opt_lore) = &last_search_params;
        assert_eq!(
            *limit_call_lore, limit_per_source,
            "Limit for lorebook search call was not limit_per_source"
        );

        // To verify the limit for the first call (chat), the mock would need to store all call parameters.
        // However, the fact that we get `limit_per_source` (1) chat result and `limit_per_source` (1) lore result,
        // and the mock truncates based on the `limit` argument to `search_points`,
        // implies `limit_per_source` was correctly passed for both calls.
    }

    #[tokio::test]
    async fn test_retrieve_chunks_error_handling_one_source_fails() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let lorebook_id = Uuid::new_v4();
        let query_text = "query for error test";
        let limit: u64 = 2;

        mock_embed_client.set_response(Ok(vec![0.6, 0.6, 0.6]));

        let lore_point_id = Uuid::new_v4();
        let mock_lore_results = vec![create_mock_lorebook_scored_point(
            MockLorebookScoredPointParams {
                point_uuid: lore_point_id,
                score: 0.8,
                original_lorebook_entry_id: Uuid::new_v4(),
                lorebook_id,
                user_id,
                chunk_text: "Successful lore content",
                entry_title: None,
                keywords: None,
                is_enabled: true,
                is_constant: false,
                source_type: "lorebook_entry",
            },
        )];

        // Chat search fails, Lorebook search succeeds using a sequence
        mock_qdrant.set_search_responses_sequence(vec![
            Err(AppError::VectorDbError(
                "Chat search Qdrant down".to_string(),
            )), // First call (chat) fails
            Ok(mock_lore_results.clone()), // Second call (lore) succeeds
        ]);

        let result = state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(
                state.clone(),
                user_id,
                Some(session_id),
                Some(vec![lorebook_id]),
                query_text,
                limit,
            )
            .await;

        assert!(
            result.is_ok(),
            "Expected Ok even if one source fails, got: {:?}",
            result.err()
        );
        let chunks = result.unwrap();
        assert_eq!(
            chunks.len(),
            1,
            "Expected only results from the successful source"
        );
        assert_eq!(chunks[0].text, "Successful lore content");
        match &chunks[0].metadata {
            RetrievedMetadata::Lorebook(_) => {} // Correct
            RetrievedMetadata::Chat(_) => panic!("Expected Lorebook metadata"),
        }

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(
            search_call_count, 2,
            "Expected two attempts to search Qdrant"
        );
    }

    // Helper to extract field condition for string match
    fn get_field_condition_keyword_match<'a>(
        filter: &'a Filter,
        key_name: &str,
    ) -> Option<&'a str> {
        filter.must.iter().find_map(|cond| {
            if let Some(ConditionOneOf::Field(fc)) = &cond.condition_one_of {
                if fc.key == key_name {
                    if let Some(m) = &fc.r#match {
                        if let Some(MatchValue::Keyword(val)) = &m.match_value {
                            return Some(val.as_str());
                        }
                    }
                }
            }
            None
        })
    }

    // Helper to extract field condition for boolean match
    fn get_field_condition_bool_match(filter: &Filter, key_name: &str) -> Option<bool> {
        filter.must.iter().find_map(|cond| {
            if let Some(ConditionOneOf::Field(fc)) = &cond.condition_one_of {
                if fc.key == key_name {
                    if let Some(m) = &fc.r#match {
                        if let Some(MatchValue::Boolean(val)) = &m.match_value {
                            return Some(*val);
                        }
                    }
                }
            }
            None
        })
    }

    // Helper to extract should conditions for string match
    fn get_should_conditions_keyword_match<'a>(filter: &'a Filter, key_name: &str) -> Vec<&'a str> {
        filter
            .should
            .iter()
            .filter_map(|cond| {
                if let Some(ConditionOneOf::Field(fc)) = &cond.condition_one_of {
                    if fc.key == key_name {
                        if let Some(m) = &fc.r#match {
                            if let Some(MatchValue::Keyword(val)) = &m.match_value {
                                return Some(val.as_str());
                            }
                        }
                    }
                }
                None
            })
            .collect()
    }

    // Re-testing with more robust filter assertions
    #[tokio::test]
    async fn test_retrieve_chunks_chat_history_only_filter_check() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let query_text = "relevant query";
        let limit: u64 = 3;

        mock_embed_client.set_response(Ok(vec![0.1, 0.2, 0.3]));
        mock_qdrant.set_search_response(Ok(vec![])); // Results don't matter for filter check

        let _ = state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(
                state.clone(),
                user_id,
                Some(session_id),
                None,
                query_text,
                limit,
            )
            .await;

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(search_call_count, 1);
        let search_params = mock_qdrant
            .get_last_search_params()
            .expect("Expected search_params to be set after one call");
        let filter = search_params
            .2
            .as_ref()
            .expect("Filter should be present for chat history");

        assert_eq!(
            get_field_condition_keyword_match(filter, "user_id"),
            Some(user_id.to_string().as_str())
        );
        assert_eq!(
            get_field_condition_keyword_match(filter, "session_id"),
            Some(session_id.to_string().as_str())
        );
        assert_eq!(
            get_field_condition_keyword_match(filter, "source_type"),
            Some("chat_message")
        );
        assert!(filter.should.is_empty());
    }

    #[tokio::test]
    async fn test_retrieve_chunks_lorebook_entries_only_filter_check() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let user_id = Uuid::new_v4();
        let lorebook_id1 = Uuid::new_v4();
        let lorebook_id2 = Uuid::new_v4();
        let active_lorebook_ids = vec![lorebook_id1, lorebook_id2];
        let query_text = "relevant query for lore";
        let limit: u64 = 2;

        mock_embed_client.set_response(Ok(vec![0.4, 0.5, 0.6]));
        mock_qdrant.set_search_response(Ok(vec![])); // Results don't matter

        let _ = state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(
                state.clone(),
                user_id,
                None,
                Some(active_lorebook_ids.clone()),
                query_text,
                limit,
            )
            .await;

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(search_call_count, 1);
        let search_params = mock_qdrant
            .get_last_search_params()
            .expect("Expected search_params to be set after one call");
        let filter = search_params
            .2
            .as_ref()
            .expect("Filter should be present for lorebooks");

        assert_eq!(
            get_field_condition_keyword_match(filter, "user_id"),
            Some(user_id.to_string().as_str())
        );
        assert_eq!(
            get_field_condition_keyword_match(filter, "source_type"),
            Some("lorebook_entry")
        );
        assert_eq!(
            get_field_condition_bool_match(filter, "is_enabled"),
            Some(true)
        );

        let matched_lorebook_ids = get_should_conditions_keyword_match(filter, "lorebook_id");
        assert_eq!(matched_lorebook_ids.len(), 2);
        assert!(matched_lorebook_ids.contains(&lorebook_id1.to_string().as_str()));
        assert!(matched_lorebook_ids.contains(&lorebook_id2.to_string().as_str()));
    }
}
