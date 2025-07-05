#![allow(clippy::too_many_lines)]
#![allow(clippy::ignored_unit_patterns)]
use chrono::Utc;
use mockall::predicate::*;
use qdrant_client::qdrant::{PointId, Value, point_id::PointIdOptions};
use scribe_backend::{
    models::chats::{ChatMessage, MessageRole},
    services::{
        chat_override_service::ChatOverrideService,
        embeddings::{
            ChatMessageChunkMetadata, EmbeddingPipelineService, LorebookEntryParams,
            RetrievedMetadata,
        },
        encryption_service::EncryptionService,
        hybrid_token_counter::HybridTokenCounter,
        lorebook::LorebookService,
        tokenizer_service::TokenizerService,
        user_persona_service::UserPersonaService,
    },
    state::{AppState, AppStateServices},
    state_builder::AppStateServicesBuilder, // Use the new builder
    test_helpers::{self, MockQdrantClientService}, // Removed AppStateBuilder, config. Added self for spawn_app
    text_processing::chunking::ChunkConfig,
    vector_db::qdrant_client::{QdrantClientServiceTrait, ScoredPoint, create_message_id_filter},
};
use serial_test::serial;
// Removed unused std::convert::TryFrom
use std::time::Duration;
use std::{collections::HashMap, sync::Arc}; // Removed env
use uuid::Uuid; // For mock assertions

// Helper to assert content and metadata of retrieved chunks
fn assert_retrieved_chunks_content(
    retrieved_chunks: &[scribe_backend::services::embeddings::RetrievedChunk],
    test_session_id: Uuid,
    message_id_1: Uuid,
    message_id_2: Uuid,
    test_user_id: Uuid,
) {
    assert_eq!(
        retrieved_chunks.len(),
        2,
        "Expected 2 chunks to be retrieved"
    );

    // Verify content of the first chunk
    assert!(
        (retrieved_chunks[0].score - 0.95).abs() < f32::EPSILON,
        "Expected score ~0.95, got {}",
        retrieved_chunks[0].score
    );
    assert_eq!(retrieved_chunks[0].text, "Chunk 1 text");
    if let RetrievedMetadata::Chat(meta) = &retrieved_chunks[0].metadata {
        assert_eq!(meta.session_id, test_session_id);
        assert_eq!(meta.message_id, message_id_1);
        assert_eq!(meta.user_id, test_user_id);
        assert_eq!(meta.speaker, "User");
        assert_eq!(meta.text, "Chunk 1 text");
        assert_eq!(meta.source_type, "chat_message");
    } else {
        panic!("Expected Chat metadata for retrieved_chunks[0]");
    }

    // Verify content of the second chunk
    assert!(
        (retrieved_chunks[1].score - 0.88).abs() < f32::EPSILON,
        "Expected score ~0.88, got {}",
        retrieved_chunks[1].score
    );
    assert_eq!(retrieved_chunks[1].text, "Chunk 2 text");
    if let RetrievedMetadata::Chat(meta) = &retrieved_chunks[1].metadata {
        assert_eq!(meta.session_id, test_session_id);
        assert_eq!(meta.message_id, message_id_2);
        assert_eq!(meta.user_id, test_user_id);
        assert_eq!(meta.speaker, "Assistant");
        assert_eq!(meta.text, "Chunk 2 text");
        assert_eq!(meta.source_type, "chat_message");
    } else {
        panic!("Expected Chat metadata for retrieved_chunks[1]");
    }
}

async fn create_test_app_state(test_app: test_helpers::TestApp) -> Arc<AppState> {
    // Use the new builder pattern - much simpler!
    let services = AppStateServicesBuilder::new(test_app.db_pool.clone(), test_app.config.clone())
        .with_ai_client(
            test_app
                .mock_ai_client
                .clone()
                .expect("Mock AI client should be present"),
        )
        .with_embedding_client(test_app.mock_embedding_client.clone())
        .with_qdrant_service(test_app.qdrant_service.clone())
        .build()
        .await
        .expect("Failed to build services for test");

    Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config,
        services,
    ))
}

// Helper to check Qdrant URL and skip integration tests if not set
fn check_qdrant_url_and_skip(config: &scribe_backend::config::Config, test_name: &str) -> bool {
    if config.qdrant_url.is_none() || config.qdrant_url.as_deref().unwrap_or("").is_empty() {
        log::warn!("Skipping Qdrant integration test '{test_name}': QDRANT_URL not set in config.");
        assert!(
            option_env!("CI").is_some(),
            "QDRANT_URL is not set in config for an un-ignored integration test."
        );
        true
    } else {
        log::info!(
            "Qdrant URL from test_app.config for {}: {}",
            test_name,
            config.qdrant_url.as_deref().unwrap_or("None")
        );
        false
    }
}

// Helper to verify Qdrant points after embedding
async fn verify_qdrant_points(
    qdrant_service_trait: Arc<dyn QdrantClientServiceTrait + Send + Sync>,
    test_message_id: Uuid,
    test_session_id: Uuid,
    test_message_user_id: Uuid,
    test_message_type: MessageRole,
    test_content: &str,
    test_app_config: &scribe_backend::config::Config,
) {
    tokio::time::sleep(std::time::Duration::from_millis(500)).await; // Allow indexing

    let filter = create_message_id_filter(test_message_id);
    let retrieved_points: Vec<ScoredPoint> = qdrant_service_trait
        .retrieve_points(Some(filter), 10)
        .await
        .expect("Failed to retrieve points from Qdrant");

    assert!(
        !retrieved_points.is_empty(),
        "No points found in Qdrant for the message ID"
    );

    let verification_chunk_config = ChunkConfig::from(test_app_config);
    let expected_chunks = scribe_backend::text_processing::chunking::chunk_text(
        test_content,
        &verification_chunk_config,
        None,
        0,
    )
    .expect("Failed to chunk test content for verification");
    let expected_num_chunks = expected_chunks.len();

    assert_eq!(
        retrieved_points.len(),
        expected_num_chunks,
        "Expected {} chunks based on chunking logic, but found {} points in Qdrant",
        expected_num_chunks,
        retrieved_points.len()
    );

    let mut found_chunk_texts: Vec<String> = Vec::new();
    for point in retrieved_points {
        let payload_map: HashMap<String, Value> = point.payload;
        let metadata = ChatMessageChunkMetadata::try_from(payload_map)
            .expect("Failed to parse ChatMessageChunkMetadata from Qdrant payload");

        assert_eq!(
            metadata.source_type, "chat_message",
            "Metadata source_type mismatch"
        );
        assert_eq!(
            metadata.message_id, test_message_id,
            "Metadata message_id mismatch"
        );
        assert_eq!(
            metadata.session_id, test_session_id,
            "Metadata session_id mismatch"
        );
        assert_eq!(
            metadata.user_id, test_message_user_id,
            "Metadata user_id mismatch"
        );
        assert_eq!(
            metadata.speaker,
            format!("{test_message_type:?}"),
            "Metadata speaker mismatch"
        );
        // Note: timestamp verification requires the actual message object, skipping for now

        assert!(
            expected_chunks
                .iter()
                .any(|chunk| chunk.content == metadata.text),
            "Stored text '{}' did not match any expected chunk",
            metadata.text
        );

        found_chunk_texts.push(metadata.text);
    }

    assert_eq!(
        found_chunk_texts.len(),
        expected_num_chunks,
        "Number of verified chunks doesn't match expected"
    );
    for expected_chunk in expected_chunks {
        assert!(
            found_chunk_texts.contains(&expected_chunk.content),
            "Expected chunk missing: {}",
            expected_chunk.content
        );
    }
}

#[tokio::test]
async fn test_process_and_embed_message_integration() {
    let test_app = test_helpers::spawn_app(false, false, true).await;
    if check_qdrant_url_and_skip(
        &test_app.config,
        "test_process_and_embed_message_integration",
    ) {
        return;
    }

    let mock_embedding_client = test_app.mock_embedding_client.clone();
    let qdrant_service_trait = test_app.qdrant_service.clone();
    let app_state = create_test_app_state(test_app.clone()).await;

    let test_message_id = Uuid::new_v4();
    let test_session_id = Uuid::new_v4();
    let test_content = "This is a test message with multiple sentences. It should be chunked into pieces for storage.".to_string();
    let test_user_id = Uuid::new_v4();
    let test_message = ChatMessage {
        id: test_message_id,
        session_id: test_session_id,
        message_type: MessageRole::User,
        content: test_content.clone().into(),
        content_nonce: None,
        created_at: Utc::now(),
        user_id: test_user_id,
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: "gemini-1.5-pro".to_string(),
    };

    let embedding_dimension = 768;
    let mock_embedding = vec![0.1; embedding_dimension];
    mock_embedding_client.set_response(Ok(mock_embedding.clone()));

    let result = app_state
        .embedding_pipeline_service
        .process_and_embed_message(app_state.clone(), test_message.clone(), None)
        .await;
    assert!(
        result.is_ok(),
        "process_and_embed_message failed: {:?}",
        result.err()
    );

    verify_qdrant_points(
        qdrant_service_trait,
        test_message_id,
        test_session_id,
        test_user_id,
        test_message.message_type,
        &test_content,
        &test_app.config,
    )
    .await;
}

#[tokio::test]
async fn test_process_and_embed_message_all_chunks_fail_embedding() {
    // 1. Setup dependencies using spawn_app
    let test_app = test_helpers::spawn_app(false, false, false).await; // multi_thread = false, use_real_ai = false, use_real_qdrant = false

    // Get mock clients from test_app
    let mock_embedding_client = test_app.mock_embedding_client.clone();
    let mock_qdrant_service_concrete = test_app
        .mock_qdrant_service
        .clone()
        .expect("Mock Qdrant service should be present");

    let app_state = create_test_app_state(test_app.clone()).await;

    // 2. Prepare test data
    let test_message_id = Uuid::new_v4();
    let test_session_id = Uuid::new_v4();
    let test_content = "This content will produce multiple chunks. Chunk two.".to_string();
    let test_message = ChatMessage {
        id: test_message_id,
        session_id: test_session_id,
        message_type: MessageRole::User,
        content: test_content.clone().into(), // Convert String to Vec<u8>
        content_nonce: None,
        created_at: Utc::now(),
        user_id: Uuid::new_v4(), // Add dummy user_id for test data
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: "gemini-1.5-pro".to_string(),
    };

    // Configure mock embedding client to always return an error
    let embedding_error =
        scribe_backend::errors::AppError::EmbeddingError("Simulated embedding failure".to_string());
    mock_embedding_client.set_response(Err(embedding_error));

    // Mock Qdrant upsert (it should NOT be called)
    mock_qdrant_service_concrete.set_upsert_response(Ok(()));
    // The test logic ensures upsert isn't called if embeddings fail.

    // 3. Call the function under test directly on the real EmbeddingPipelineService
    let result = app_state
        .embedding_pipeline_service
        .process_and_embed_message(
            app_state.clone(), // Pass AppState
            test_message.clone(),
            None, // No session DEK needed for tests
        )
        .await;

    // 4. Assertions
    assert!(
        result.is_ok(),
        "process_and_embed_message should return Ok even if all embeddings fail, but got: {:?}",
        result.err()
    );

    // Verify embedding client was called for each chunk
    // Use chunk config from test_app.config for verification
    let verification_chunk_config = ChunkConfig::from(test_app.config.as_ref());
    let expected_chunks = scribe_backend::text_processing::chunking::chunk_text(
        &test_content,
        &verification_chunk_config,
        None,
        0,
    )
    .expect("Failed to chunk test content for verification")
    .into_iter()
    .map(|c| (c.content, "RETRIEVAL_DOCUMENT".to_string(), None)) // Match expected call format (text, task_type, title)
    .collect::<Vec<_>>();

    let embed_calls = mock_embedding_client.get_calls();
    assert_eq!(
        embed_calls.len(),
        expected_chunks.len(),
        "Embedding client should be called for each chunk"
    );

    // Explicitly check call count
    assert_eq!(
        mock_qdrant_service_concrete.get_upsert_call_count(),
        0,
        "Qdrant upsert should not have been called"
    );
    // Verify the exact calls made to embedding client
    assert_eq!(
        embed_calls, expected_chunks,
        "Embedding client calls mismatch"
    );
}
// --- Unit Tests for retrieve_relevant_chunks ---

// Parameters for creating mock ScoredPoint
#[derive(Clone)]
struct MockScoredPointParams {
    id_uuid: Uuid,
    score: f32,
    session_id: Uuid,
    message_id: Uuid,
    user_id: Uuid,
    speaker: String,
    timestamp: chrono::DateTime<Utc>,
    text: String,
    source_type: String,
}

// Helper to create a mock ScoredPoint
fn create_mock_scored_point_simple(params: &MockScoredPointParams) -> ScoredPoint {
    let mut payload = HashMap::new();
    payload.insert(
        "session_id".to_string(),
        Value::from(params.session_id.to_string()),
    );
    payload.insert(
        "message_id".to_string(),
        Value::from(params.message_id.to_string()),
    );
    payload.insert(
        "user_id".to_string(), // Added user_id to payload
        Value::from(params.user_id.to_string()),
    );
    payload.insert("speaker".to_string(), Value::from(params.speaker.clone()));
    payload.insert(
        "timestamp".to_string(),
        Value::from(params.timestamp.to_rfc3339()),
    );
    payload.insert("text".to_string(), Value::from(params.text.clone()));
    payload.insert(
        "source_type".to_string(),
        Value::from(params.source_type.clone()),
    );

    // Set vectors to None for simplicity in mock helper
    // let vector_data: Vec<f32> = vec![0.1; 3072]; // Corrected dimension
    // let vectors_output = qdrant_client::qdrant::VectorsOutput { ... };

    ScoredPoint {
        id: Some(PointId {
            point_id_options: Some(PointIdOptions::Uuid(params.id_uuid.to_string())),
        }),
        version: 1,
        score: params.score,
        payload,
        // Set vectors to None
        vectors: None,
        shard_key: None,
        order_value: None,
    }
}

#[tokio::test]
async fn test_retrieve_relevant_chunks_success() {
    // 1. Setup dependencies
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let _mock_qdrant_service_concrete = test_app
        .mock_qdrant_service
        .clone()
        .expect("Mock Qdrant service");

    let _app_state = create_test_app_state(test_app).await;

    // 2. Prepare mock responses and expectations
    let _test_session_id = Uuid::new_v4();
    let _test_user_id = Uuid::new_v4(); // Added user_id for the test
    let _message_id_1 = Uuid::new_v4();
    let _message_id_2 = Uuid::new_v4();

    // TODO: Complete the test implementation
}

#[tokio::test]
async fn test_retrieve_relevant_chunks_success_with_real_execution() {
    // 1. Setup dependencies
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mock_qdrant_service_concrete = test_app
        .mock_qdrant_service
        .clone()
        .expect("Mock Qdrant service");

    let app_state = create_test_app_state(test_app.clone()).await;

    // 2. Prepare mock responses and expectations
    let test_session_id = Uuid::new_v4();
    let test_user_id = Uuid::new_v4();
    let message_id_1 = Uuid::new_v4();
    let message_id_2 = Uuid::new_v4();

    let embedding_dimension = 3072;
    let mock_query_embedding = vec![0.5; embedding_dimension];

    test_app
        .mock_embedding_client
        .set_response(Ok(mock_query_embedding.clone()));

    mock_qdrant_service_concrete.set_search_response(Ok(vec![
        create_mock_scored_point_simple(&MockScoredPointParams {
            id_uuid: Uuid::new_v4(),
            score: 0.95,
            session_id: test_session_id,
            message_id: message_id_1,
            user_id: test_user_id,
            speaker: "User".to_string(),
            timestamp: Utc::now(),
            text: "Chunk 1 text".to_string(),
            source_type: "chat_message".to_string(),
        }),
        create_mock_scored_point_simple(&MockScoredPointParams {
            id_uuid: Uuid::new_v4(),
            score: 0.88,
            session_id: test_session_id,
            message_id: message_id_2,
            user_id: test_user_id,
            speaker: "Assistant".to_string(),
            timestamp: Utc::now(),
            text: "Chunk 2 text".to_string(),
            source_type: "chat_message".to_string(),
        }),
    ]));

    let query = "What is the meaning of life?";

    let result = app_state
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state.clone(),
            test_user_id,
            Some(test_session_id),
            None,
            None, // chronicle_id_for_search
            query,
            5,
        )
        .await;

    assert!(
        result.is_ok(),
        "retrieve_relevant_chunks failed: {:?}",
        result.err()
    );
    let retrieved_chunks = result.unwrap();

    assert_retrieved_chunks_content(
        &retrieved_chunks,
        test_session_id,
        message_id_1,
        message_id_2,
        test_user_id,
    );

    let embed_calls = test_app.mock_embedding_client.get_calls();
    assert_eq!(embed_calls.len(), 1, "Expected 1 call to embedding client");
    assert_eq!(embed_calls[0].0, query, "Embedding query mismatch");

    assert_eq!(
        mock_qdrant_service_concrete.get_search_call_count(),
        1,
        "Expected 1 call to Qdrant search"
    );
    let last_search_params = mock_qdrant_service_concrete
        .get_last_search_params()
        .expect("No search params recorded");
    assert_eq!(
        last_search_params.0, mock_query_embedding,
        "Search vector mismatch"
    );
    assert_eq!(last_search_params.1, 5_u64, "Search limit mismatch");
    let filter = last_search_params.2.expect("Search filter was None");
    assert!(
        format!("{filter:?}").contains(&test_session_id.to_string()),
        "Filter does not contain session_id"
    );
}

#[tokio::test]
async fn test_retrieve_relevant_chunks_no_results() {
    // 1. Setup
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mock_qdrant_service_concrete = test_app
        .mock_qdrant_service
        .clone()
        .expect("Mock Qdrant service");

    let app_state = create_test_app_state(test_app.clone()).await;

    // 2. Configure mock Qdrant service to return no results
    mock_qdrant_service_concrete.set_search_response(Ok(Vec::new()));

    // Call the method using the real embedding pipeline service from app_state
    let result = app_state
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state.clone(),
            Uuid::new_v4(),       // user_id
            Some(Uuid::new_v4()), // session_id_for_chat_history
            None,                 // active_lorebook_ids_for_search
            None,                 // chronicle_id_for_search
            "A query that finds nothing",
            5,
        )
        .await;

    // 3. Assertions
    assert!(
        result.is_ok(),
        "retrieve_relevant_chunks failed: {:?}",
        result.err()
    );
    let retrieved_chunks = result.unwrap();
    assert!(
        retrieved_chunks.is_empty(),
        "Expected no chunks to be retrieved"
    );
}

#[tokio::test]
async fn test_retrieve_relevant_chunks_qdrant_error() {
    // 1. Setup
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mock_qdrant_service_concrete = test_app
        .mock_qdrant_service
        .clone()
        .expect("Mock Qdrant service");

    let embeddings_service =
        EmbeddingPipelineService::new(ChunkConfig::from(test_app.config.as_ref()));

    // Create dependent services for AppState
    let encryption_service_for_test_5 = Arc::new(EncryptionService::new());
    let chat_override_service_for_test_5 = Arc::new(ChatOverrideService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_5.clone(),
    ));
    let tokenizer_service_for_test_5 = TokenizerService::new(
        "/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model",
    )
    .expect("Failed to create tokenizer for test");
    let hybrid_token_counter_for_test_5 = Arc::new(HybridTokenCounter::new_local_only(
        tokenizer_service_for_test_5,
    ));
    let user_persona_service_for_test_5 = Arc::new(UserPersonaService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_5.clone(),
    ));
    let lorebook_service_for_test_5 = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_5.clone(),
        test_app.qdrant_service.clone(),
    ));
    let auth_backend_5 = Arc::new(scribe_backend::auth::user_store::Backend::new(
        test_app.db_pool.clone(),
    ));
    let file_storage_service_5 = Arc::new(
        scribe_backend::services::file_storage_service::FileStorageService::new("./test_uploads")
            .expect("Failed to create test file storage service"),
    );

    let services = AppStateServices {
        ai_client: test_app
            .mock_ai_client
            .clone()
            .expect("Mock AI client should be present"),
        embedding_client: test_app.mock_embedding_client.clone(),
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: Arc::new(embeddings_service),
        chat_override_service: chat_override_service_for_test_5,
        user_persona_service: user_persona_service_for_test_5,
        token_counter: hybrid_token_counter_for_test_5,
        encryption_service: encryption_service_for_test_5.clone(),
        lorebook_service: lorebook_service_for_test_5,
        auth_backend: auth_backend_5,
        file_storage_service: file_storage_service_5,
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
        },        // Chronicle ECS services for test
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
    };

    let app_state = Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ));

    // 2. Configure mock Qdrant service to return an error
    let qdrant_error = scribe_backend::errors::AppError::VectorDbError(
        "Simulated Qdrant search failure".to_string(),
    );
    mock_qdrant_service_concrete.set_search_response(Err(qdrant_error));

    // Call the method on the real service
    let result = app_state
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state.clone(),
            Uuid::new_v4(),
            Some(Uuid::new_v4()),
            None,
            None, // chronicle_id_for_search
            "Query leading to Qdrant error",
            2,
        )
        .await;

    // 3. Assertions
    assert!(
        result.is_ok(),
        "Expected retrieve_relevant_chunks to return Ok even with Qdrant error"
    );
    let retrieved_chunks = result.unwrap();
    assert!(
        retrieved_chunks.is_empty(),
        "Expected empty chunks when Qdrant search fails"
    );
}

#[tokio::test]

async fn test_retrieve_relevant_chunks_metadata_invalid_uuid() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mock_qdrant_service_concrete = test_app
        .mock_qdrant_service
        .clone()
        .expect("Mock Qdrant service");

    // Create dependent services for AppState
    let encryption_service_for_test_6 = Arc::new(EncryptionService::new());
    let chat_override_service_for_test_6 = Arc::new(ChatOverrideService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_6.clone(),
    ));
    let tokenizer_service_for_test_6 = TokenizerService::new(
        "/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model",
    )
    .expect("Failed to create tokenizer for test");
    let hybrid_token_counter_for_test_6 = Arc::new(HybridTokenCounter::new_local_only(
        tokenizer_service_for_test_6,
    ));
    let user_persona_service_for_test_6 = Arc::new(UserPersonaService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_6.clone(),
    ));
    let lorebook_service_for_test_6 = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_6.clone(),
        test_app.qdrant_service.clone(),
    ));
    let auth_backend_6 = Arc::new(scribe_backend::auth::user_store::Backend::new(
        test_app.db_pool.clone(),
    ));
    let file_storage_service_6 = Arc::new(
        scribe_backend::services::file_storage_service::FileStorageService::new("./test_uploads")
            .expect("Failed to create test file storage service"),
    );

    let services = AppStateServices {
        ai_client: test_app
            .mock_ai_client
            .clone()
            .expect("Mock AI client should be present"),
        embedding_client: test_app.mock_embedding_client.clone(),
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone(),
        chat_override_service: chat_override_service_for_test_6,
        user_persona_service: user_persona_service_for_test_6,
        token_counter: hybrid_token_counter_for_test_6,
        encryption_service: encryption_service_for_test_6.clone(),
        lorebook_service: lorebook_service_for_test_6,
        auth_backend: auth_backend_6,
        file_storage_service: file_storage_service_6,
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
    };

    let app_state_arc = Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services,
    ));

    // Mock Qdrant to return a point with an invalid UUID in metadata
    let query_text = "Query for invalid UUID metadata";
    let session_id = Uuid::new_v4();
    let limit = 3;
    let _mock_query_embedding = vec![0.6; 3072]; // Prefixed with _ as it's unused with mock_embeddings_service

    mock_qdrant_service_concrete.set_search_response(Ok(vec![
        create_mock_scored_point_simple(&MockScoredPointParams {
            id_uuid: Uuid::new_v4(),
            score: 0.9,
            session_id,
            message_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            speaker: "User".to_string(),
            timestamp: Utc::now(),
            text: "Valid text".to_string(),
            source_type: "chat_message".to_string(),
        }),
        create_mock_scored_point_simple(&MockScoredPointParams {
            // This point will have the invalid UUID in its message_id field
            id_uuid: Uuid::new_v4(),
            score: 0.9,
            session_id,
            message_id: Uuid::new_v4(), // message_id - this should be the one made invalid for the test's purpose
            user_id: Uuid::new_v4(),
            speaker: "User".to_string(),
            timestamp: Utc::now(),
            text: "Valid text with invalid message_id in payload".to_string(),
            source_type: "chat_message".to_string(),
        }),
    ]));

    // To make the second point's message_id invalid, we need to modify the mock_qdrant_service_concrete's response
    // This is a bit tricky as set_search_response takes ownership. We'll set it, then modify.
    // This test's intent is to check how the *real* EmbeddingPipelineService handles bad data from Qdrant.
    // So, the mock_embeddings_service should not be used here.
    // The panic "MockEmbeddingPipelineService::retrieve_relevant_chunks called but no more responses were queued"
    // indicates that the mock service was called, which is not the intent for testing metadata parsing.

    // Let's re-evaluate the setup for these metadata tests.
    // They should use the *real* EmbeddingPipelineService and a mock Qdrant that returns malformed data.
    let real_embeddings_service =
        EmbeddingPipelineService::new(ChunkConfig::from(test_app.config.as_ref()));

    // Create a new AppState with the real service
    let services_for_metadata_test = AppStateServices {
        ai_client: test_app
            .mock_ai_client
            .clone()
            .expect("Mock AI client should be present"),
        embedding_client: test_app.mock_embedding_client.clone(),
        qdrant_service: test_app.qdrant_service.clone(), // This is the MockQdrantClientService
        embedding_pipeline_service: Arc::new(real_embeddings_service), // Use the real service
        chat_override_service: app_state_arc.chat_override_service.clone(), // Reuse from previous app_state_arc
        user_persona_service: app_state_arc.user_persona_service.clone(),
        token_counter: app_state_arc.token_counter.clone(),
        encryption_service: app_state_arc.encryption_service.clone(),
        lorebook_service: app_state_arc.lorebook_service.clone(),
        auth_backend: app_state_arc.auth_backend.clone(), // Reuse auth_backend from app_state_arc
        file_storage_service: app_state_arc.file_storage_service.clone(),
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
    };
    let app_state_for_metadata_test = Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services_for_metadata_test,
    ));

    // Modify the second point in the mock Qdrant response to have an invalid message_id
    let mut mock_response = vec![create_mock_scored_point_simple(&MockScoredPointParams {
        id_uuid: Uuid::new_v4(),
        score: 0.9,
        session_id,
        message_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        speaker: "User".to_string(),
        timestamp: Utc::now(),
        text: "Valid text 1".to_string(),
        source_type: "chat_message".to_string(),
    })];
    let mut invalid_payload_point = create_mock_scored_point_simple(&MockScoredPointParams {
        id_uuid: Uuid::new_v4(),
        score: 0.8,
        session_id,
        message_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        speaker: "User".to_string(),
        timestamp: Utc::now(),
        text: "Text for invalid point".to_string(),
        source_type: "chat_message".to_string(),
    });
    // Directly manipulate the payload to make message_id invalid
    invalid_payload_point
        .payload
        .insert("message_id".to_string(), Value::from("not-a-valid-uuid"));
    mock_response.push(invalid_payload_point);
    mock_qdrant_service_concrete.set_search_response(Ok(mock_response));

    // Call the method using the AppState with the real EmbeddingPipelineService
    let result = app_state_for_metadata_test
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state_for_metadata_test.clone(), // Use the correct app_state
            Uuid::new_v4(),                      // user_id
            Some(session_id),                    // session_id_for_chat_history
            None,                                // active_lorebook_ids_for_search
            None,                                // chronicle_id_for_search
            query_text,
            limit,
        )
        .await;

    // 3. Assertions
    assert!(
        result.is_ok(),
        "retrieve_relevant_chunks should succeed even with metadata errors: {:?}",
        result.err()
    );
    let retrieved_chunks = result.unwrap();
    assert_eq!(
        retrieved_chunks.len(),
        1,
        "Expected 1 chunk, the one with invalid metadata should be skipped"
    );
    assert_eq!(retrieved_chunks[0].text, "Valid text 1");
}

#[tokio::test]

async fn test_retrieve_relevant_chunks_metadata_invalid_timestamp() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mock_qdrant_service_concrete = test_app
        .mock_qdrant_service
        .clone()
        .expect("Mock Qdrant service");

    // Create dependent services for AppState
    let encryption_service_for_test_7 = Arc::new(EncryptionService::new());
    let chat_override_service_for_test_7 = Arc::new(ChatOverrideService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_7.clone(),
    ));
    let tokenizer_service_for_test_7 = TokenizerService::new(
        "/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model",
    )
    .expect("Failed to create tokenizer for test");
    let hybrid_token_counter_for_test_7 = Arc::new(HybridTokenCounter::new_local_only(
        tokenizer_service_for_test_7,
    ));
    let user_persona_service_for_test_7 = Arc::new(UserPersonaService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_7.clone(),
    ));
    let lorebook_service_for_test_7 = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_7.clone(),
        test_app.qdrant_service.clone(),
    ));
    let auth_backend_7 = Arc::new(scribe_backend::auth::user_store::Backend::new(
        test_app.db_pool.clone(),
    ));
    let file_storage_service_7 = Arc::new(
        scribe_backend::services::file_storage_service::FileStorageService::new("./test_uploads")
            .expect("Failed to create test file storage service"),
    );

    let services_for_test_7 = AppStateServices {
        ai_client: test_app
            .mock_ai_client
            .clone()
            .expect("Mock AI client should be present"),
        embedding_client: test_app.mock_embedding_client.clone(),
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: test_app.mock_embedding_pipeline_service.clone(),
        chat_override_service: chat_override_service_for_test_7,
        user_persona_service: user_persona_service_for_test_7, // Added user_persona_service
        token_counter: hybrid_token_counter_for_test_7,
        encryption_service: encryption_service_for_test_7.clone(),
        lorebook_service: lorebook_service_for_test_7,
        auth_backend: auth_backend_7,
        file_storage_service: file_storage_service_7,
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
    };
    let app_state_arc = Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services_for_test_7,
    ));

    // Mock Qdrant to return a point with an invalid timestamp in metadata
    let query_text = "Query for invalid timestamp metadata";
    let session_id = Uuid::new_v4();
    let limit = 3;
    let _mock_query_embedding = vec![0.7; 3072]; // Prefixed with _

    mock_qdrant_service_concrete.set_search_response(Ok(vec![
        create_mock_scored_point_simple(&MockScoredPointParams {
            id_uuid: Uuid::new_v4(),
            score: 0.85,
            session_id,
            message_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            speaker: "Assistant".to_string(),
            timestamp: Utc::now(),
            text: "More text".to_string(),
            source_type: "chat_message".to_string(),
        }),
        // This point will have an invalid timestamp
        {
            let mut point_with_invalid_ts =
                create_mock_scored_point_simple(&MockScoredPointParams {
                    id_uuid: Uuid::new_v4(),
                    score: 0.85,
                    session_id,
                    message_id: Uuid::new_v4(),
                    user_id: Uuid::new_v4(),
                    speaker: "Assistant".to_string(),
                    timestamp: Utc::now(),
                    text: "Text for invalid TS".to_string(),
                    source_type: "chat_message".to_string(),
                });
            point_with_invalid_ts
                .payload
                .insert("timestamp".to_string(), Value::from("not-a-timestamp"));
            point_with_invalid_ts
        },
    ]));

    let real_embeddings_service =
        EmbeddingPipelineService::new(ChunkConfig::from(test_app.config.as_ref()));
    let services_for_metadata_test_2 = AppStateServices {
        ai_client: test_app
            .mock_ai_client
            .clone()
            .expect("Mock AI client should be present"),
        embedding_client: test_app.mock_embedding_client.clone(),
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: Arc::new(real_embeddings_service),
        chat_override_service: app_state_arc.chat_override_service.clone(),
        user_persona_service: app_state_arc.user_persona_service.clone(),
        token_counter: app_state_arc.token_counter.clone(),
        encryption_service: app_state_arc.encryption_service.clone(),
        lorebook_service: app_state_arc.lorebook_service.clone(),
        auth_backend: app_state_arc.auth_backend.clone(),
        file_storage_service: app_state_arc.file_storage_service.clone(),
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
            let concrete_embedding_service = scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::ChunkConfig::from(test_app.config.as_ref())
            );
            Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                Arc::new(concrete_embedding_service),
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
            let concrete_embedding_service = scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::ChunkConfig::from(test_app.config.as_ref())
            );
            let rag_service = Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                Arc::new(concrete_embedding_service),
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
    };
    let app_state_for_metadata_test = Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services_for_metadata_test_2,
    ));

    let result = app_state_for_metadata_test
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state_for_metadata_test.clone(),
            Uuid::new_v4(),
            Some(session_id),
            None,
            None, // chronicle_id_for_search
            query_text,
            limit,
        )
        .await;

    // 3. Assertions
    // Expect Ok, but only one valid chunk should be returned.
    assert!(
        result.is_ok(),
        "retrieve_relevant_chunks should succeed even with metadata errors: {:?}",
        result.err()
    );
    let retrieved_chunks = result.unwrap();
    assert_eq!(
        retrieved_chunks.len(),
        1,
        "Expected 1 chunk, the one with invalid metadata should be skipped"
    );
    assert_eq!(retrieved_chunks[0].text, "More text");
}

#[tokio::test]

async fn test_retrieve_relevant_chunks_metadata_missing_field() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mock_qdrant_service_concrete = test_app
        .mock_qdrant_service
        .clone()
        .expect("Mock Qdrant service");

    // Create dependent services for AppState
    let encryption_service_for_test_8 = Arc::new(EncryptionService::new());
    let chat_override_service_for_test_8 = Arc::new(ChatOverrideService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_8.clone(),
    ));
    let tokenizer_service_for_test_8 = TokenizerService::new(
        "/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model",
    )
    .expect("Failed to create tokenizer for test");
    let hybrid_token_counter_for_test_8 = Arc::new(HybridTokenCounter::new_local_only(
        tokenizer_service_for_test_8,
    ));
    let user_persona_service_for_test_8 = Arc::new(UserPersonaService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_8.clone(),
    ));
    let lorebook_service_for_test_8 = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_8.clone(),
        test_app.qdrant_service.clone(),
    ));
    let auth_backend_8 = Arc::new(scribe_backend::auth::user_store::Backend::new(
        test_app.db_pool.clone(),
    ));

    // This app_state_arc is not needed here as we are creating app_state_for_metadata_test below
    // let app_state_arc = Arc::new(AppState::new(
    //     test_app.db_pool.clone(),
    //     test_app.config.clone(),
    //     test_app.mock_ai_client.clone().expect("Mock AI client should be present"),
    //     test_app.mock_embedding_client.clone(),
    //     test_app.qdrant_service.clone(),
    //     test_app.mock_embedding_pipeline_service.clone(), // This was the issue, using mock service
    //     chat_override_service_for_test_8,
    //     user_persona_service_for_test_8, // Added user_persona_service
    //     hybrid_token_counter_for_test_8,
    //     encryption_service_for_test_8.clone(),
    //     lorebook_service_for_test_8
    // ));

    // Mock Qdrant to return a point with a missing required field in metadata
    let query_text = "Query for missing metadata field";
    let session_id = Uuid::new_v4();
    let limit = 3;
    let _mock_query_embedding = vec![0.8; 3072]; // Prefixed with _

    mock_qdrant_service_concrete.set_search_response(Ok(vec![
        create_mock_scored_point_simple(&MockScoredPointParams {
            id_uuid: Uuid::new_v4(),
            score: 0.8,
            session_id,
            message_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            speaker: "User".to_string(),
            timestamp: Utc::now(),
            text: "Some text".to_string(),
            source_type: "chat_message".to_string(),
        }),
        // This point will have a missing field (e.g., speaker)
        {
            let mut point_with_missing_field =
                create_mock_scored_point_simple(&MockScoredPointParams {
                    id_uuid: Uuid::new_v4(),
                    score: 0.8,
                    session_id,
                    message_id: Uuid::new_v4(),
                    user_id: Uuid::new_v4(),
                    speaker: "User".to_string(),
                    timestamp: Utc::now(),
                    text: "Text for missing field".to_string(),
                    source_type: "chat_message".to_string(),
                });
            point_with_missing_field.payload.remove("speaker");
            point_with_missing_field
        },
    ]));

    let real_embeddings_service =
        EmbeddingPipelineService::new(ChunkConfig::from(test_app.config.as_ref()));
    let file_storage_service_8 = Arc::new(
        scribe_backend::services::file_storage_service::FileStorageService::new("./test_uploads")
            .expect("Failed to create test file storage service"),
    );
    let services_for_metadata_test_3 = AppStateServices {
        ai_client: test_app
            .mock_ai_client
            .clone()
            .expect("Mock AI client should be present"),
        embedding_client: test_app.mock_embedding_client.clone(),
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: Arc::new(real_embeddings_service),
        chat_override_service: chat_override_service_for_test_8, // Use services created in this test
        user_persona_service: user_persona_service_for_test_8,
        token_counter: hybrid_token_counter_for_test_8,
        encryption_service: encryption_service_for_test_8.clone(),
        lorebook_service: lorebook_service_for_test_8,
        auth_backend: auth_backend_8,
        file_storage_service: file_storage_service_8,
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
            let concrete_embedding_service = scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::ChunkConfig::from(test_app.config.as_ref())
            );
            Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                Arc::new(concrete_embedding_service),
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
            let concrete_embedding_service = scribe_backend::services::embeddings::EmbeddingPipelineService::new(
                scribe_backend::text_processing::ChunkConfig::from(test_app.config.as_ref())
            );
            let rag_service = Arc::new(scribe_backend::services::EcsEnhancedRagService::new(
                Arc::new(test_app.db_pool.clone()),
                Default::default(),
                feature_flags.clone(),
                entity_manager.clone(),
                degradation.clone(),
                Arc::new(concrete_embedding_service),
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
    };
    let app_state_for_metadata_test = Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services_for_metadata_test_3,
    ));

    let result = app_state_for_metadata_test
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state_for_metadata_test.clone(),
            Uuid::new_v4(),
            Some(session_id),
            None,
            None, // chronicle_id_for_search
            query_text,
            limit,
        )
        .await;

    // 3. Assertions
    // Expect Ok, but only one valid chunk should be returned.
    assert!(
        result.is_ok(),
        "retrieve_relevant_chunks should succeed even with metadata errors: {:?}",
        result.err()
    );
    let retrieved_chunks = result.unwrap();
    assert_eq!(
        retrieved_chunks.len(),
        1,
        "Expected 1 chunk, the one with invalid metadata should be skipped"
    );
    assert_eq!(retrieved_chunks[0].text, "Some text");
}

#[tokio::test]

async fn test_retrieve_relevant_chunks_metadata_wrong_type() {
    let test_app = test_helpers::spawn_app(false, false, false).await;
    let mock_qdrant_service_concrete = test_app
        .mock_qdrant_service
        .clone()
        .expect("Mock Qdrant service");
    let mock_embedding_client = test_app.mock_embedding_client.clone();

    // Create dependent services for AppState
    let encryption_service_for_test_9 = Arc::new(EncryptionService::new());
    let chat_override_service_for_test_9 = Arc::new(ChatOverrideService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_9.clone(),
    ));
    let tokenizer_service_for_test_9 = TokenizerService::new(
        "/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model",
    )
    .expect("Failed to create tokenizer for test");
    let hybrid_token_counter_for_test_9 = Arc::new(HybridTokenCounter::new_local_only(
        tokenizer_service_for_test_9,
    ));
    let user_persona_service_for_test_9 = Arc::new(UserPersonaService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_9.clone(),
    ));
    let lorebook_service_for_test_9 = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_9.clone(),
        test_app.qdrant_service.clone(),
    ));
    let auth_backend_9 = Arc::new(scribe_backend::auth::user_store::Backend::new(
        test_app.db_pool.clone(),
    ));

    // This _app_state is not needed here as we are creating app_state_for_metadata_test below
    // let _app_state = Arc::new(AppState::new( // Renamed to avoid conflict, though it's unused now
    //     test_app.db_pool.clone(),
    //     test_app.config.clone(),
    //     test_app.mock_ai_client.clone().expect("Mock AI client should be present"),
    //     mock_embedding_client.clone(),
    //     test_app.qdrant_service.clone(),
    //     test_app.mock_embedding_pipeline_service.clone(), // This was the issue
    //     chat_override_service_for_test_9,
    //     user_persona_service_for_test_9, // Added user_persona_service
    //     hybrid_token_counter_for_test_9,
    //     encryption_service_for_test_9.clone(),
    //     lorebook_service_for_test_9
    // ));

    // Mock Qdrant to return a point with a field of the wrong type in metadata
    let query_text = "Query for wrong metadata type";
    let session_id = Uuid::new_v4();
    let limit = 3;
    let _mock_query_embedding = vec![0.9; 3072]; // Prefixed with _

    mock_qdrant_service_concrete.set_search_response(Ok(vec![
        create_mock_scored_point_simple(&MockScoredPointParams {
            id_uuid: Uuid::new_v4(),
            score: 0.75,
            session_id,
            message_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            speaker: "User".to_string(),
            timestamp: Utc::now(),
            text: "Final text".to_string(),
            source_type: "chat_message".to_string(),
        }),
        // This point will have a field of the wrong type (e.g., speaker as integer)
        {
            let mut point_with_wrong_type =
                create_mock_scored_point_simple(&MockScoredPointParams {
                    id_uuid: Uuid::new_v4(),
                    score: 0.75,
                    session_id,
                    message_id: Uuid::new_v4(),
                    user_id: Uuid::new_v4(),
                    speaker: "User".to_string(),
                    timestamp: Utc::now(),
                    text: "Text for wrong type".to_string(),
                    source_type: "chat_message".to_string(),
                });
            point_with_wrong_type
                .payload
                .insert("speaker".to_string(), Value::from(123i64)); // speaker is integer
            point_with_wrong_type
        },
    ]));

    let real_embeddings_service =
        EmbeddingPipelineService::new(ChunkConfig::from(test_app.config.as_ref()));
    let file_storage_service_9 = Arc::new(
        scribe_backend::services::file_storage_service::FileStorageService::new("./test_uploads")
            .expect("Failed to create test file storage service"),
    );
    // Use the app_state created within this test, not the one from the outer scope (app_state_arc)
    let services_for_metadata_test_4 = AppStateServices {
        ai_client: test_app
            .mock_ai_client
            .clone()
            .expect("Mock AI client should be present"),
        embedding_client: mock_embedding_client.clone(), // Use the mock_embedding_client from this test's scope
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: Arc::new(real_embeddings_service),
        chat_override_service: chat_override_service_for_test_9, // Use services created in this test
        user_persona_service: user_persona_service_for_test_9,
        token_counter: hybrid_token_counter_for_test_9,
        encryption_service: encryption_service_for_test_9.clone(),
        lorebook_service: lorebook_service_for_test_9,
        auth_backend: auth_backend_9,
        file_storage_service: file_storage_service_9,
        email_service: Arc::new(
            scribe_backend::services::email_service::LoggingEmailService::new(
                "http://localhost:3000".to_string(),
            ),
        ),
    };
    let app_state_for_metadata_test = Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services_for_metadata_test_4,
    ));

    let result = app_state_for_metadata_test
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state_for_metadata_test.clone(),
            Uuid::new_v4(),
            Some(session_id),
            None,
            None, // chronicle_id_for_search
            query_text,
            limit,
        )
        .await;

    // 3. Assertions
    // Expect Ok, but only one valid chunk should be returned.
    assert!(
        result.is_ok(),
        "retrieve_relevant_chunks should succeed even with metadata errors: {:?}",
        result.err()
    );
    let retrieved_chunks = result.unwrap();
    assert_eq!(
        retrieved_chunks.len(),
        1,
        "Expected 1 chunk, the one with invalid metadata should be skipped"
    );
    assert_eq!(retrieved_chunks[0].text, "Final text");
}

// TODO: Add tests for retrieve_relevant_chunks integration if needed,
// likely involving inserting known points and then querying them.

#[tokio::test]
// #[ignore] // Test requires external Qdrant service // Temporarily un-ignore
#[serial]
async fn test_rag_context_injection_with_qdrant() {
    // Setup: Initialize test environment with real Qdrant
    let test_app = test_helpers::spawn_app(false, false, true).await; // multi_thread = false, use_real_ai = false, use_real_qdrant = true
    log::info!(
        "Qdrant URL from test_app.config for RAG test: {}",
        test_app.config.qdrant_url.as_deref().unwrap_or("None")
    );

    // Check if QDRANT_URL is set in the loaded config
    if test_app.config.qdrant_url.is_none()
        || test_app
            .config
            .qdrant_url
            .as_deref()
            .unwrap_or("")
            .is_empty()
    {
        log::warn!("Skipping Qdrant integration test: QDRANT_URL not set in config for RAG test.");
        assert!(
            option_env!("CI").is_some(),
            "QDRANT_URL is not set in config for an un-ignored RAG integration test."
        );
        return;
    }

    // Create a real EmbeddingPipelineService
    let embeddings_service_instance = // Renamed to avoid conflict
        EmbeddingPipelineService::new(ChunkConfig::from(test_app.config.as_ref()));

    // Set up test data
    let user_id = Uuid::new_v4(); // Consistent user_id for all data
    let chat_session_id = Uuid::new_v4();
    let chat_message_id = Uuid::new_v4();
    let chat_message_content = "This is a test chat message about dragons for RAG.";

    let lorebook_id = Uuid::new_v4();
    let original_lore_entry_id = Uuid::new_v4();
    let lore_entry_content = "Lore about ancient dragons and their fiery breath.";
    let lore_entry_title = Some("Ancient Dragons".to_string());

    // Create a valid ChatMessage to process
    let chat_message = ChatMessage {
        id: chat_message_id,
        session_id: chat_session_id,
        message_type: MessageRole::User,
        content: chat_message_content.as_bytes().to_vec(),
        content_nonce: None,
        created_at: Utc::now(),
        user_id, // Use consistent user_id
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: "gemini-1.5-pro".to_string(),
    };

    // Configure mock embedding client for a sequence of calls
    let mock_embedding_client = test_app.mock_embedding_client.clone();
    let chat_chunk_embedding = vec![0.5; 768];
    let lore_chunk_embedding = vec![0.6; 768]; // Different embedding for lore
    let rag_query_embedding = vec![0.55; 768]; // Embedding for the RAG query

    mock_embedding_client.set_responses_sequence(vec![
        Ok(chat_chunk_embedding.clone()), // For chat message chunk
        Ok(lore_chunk_embedding.clone()), // For lorebook entry chunk
        Ok(rag_query_embedding.clone()),  // For the RAG query
    ]);

    // Create app state to pass to the service methods
    let encryption_service_for_test_10 = Arc::new(EncryptionService::new());
    let chat_override_service_for_test_10 = Arc::new(ChatOverrideService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_10.clone(),
    ));
    let tokenizer_service_for_test_10 = TokenizerService::new(
        "/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model",
    )
    .expect("Failed to create tokenizer for test");
    let hybrid_token_counter_for_test_10 = Arc::new(HybridTokenCounter::new_local_only(
        tokenizer_service_for_test_10,
    ));
    let user_persona_service_for_test_10 = Arc::new(UserPersonaService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_10.clone(),
    ));
    let lorebook_service_for_test_10 = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service_for_test_10.clone(),
        test_app.qdrant_service.clone(),
    ));
    let auth_backend_10 = Arc::new(scribe_backend::auth::user_store::Backend::new(
        test_app.db_pool.clone(),
    ));
    let file_storage_service_10 = Arc::new(
        scribe_backend::services::file_storage_service::FileStorageService::new("./test_uploads")
            .expect("Failed to create test file storage service"),
    );

    let services_for_rag = AppStateServices {
        ai_client: test_app.ai_client.clone(),
        embedding_client: test_app.mock_embedding_client.clone(),
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: Arc::new(embeddings_service_instance), // Use the renamed instance
        chat_override_service: chat_override_service_for_test_10,
        user_persona_service: user_persona_service_for_test_10,
        token_counter: hybrid_token_counter_for_test_10,
        encryption_service: encryption_service_for_test_10.clone(),
        lorebook_service: lorebook_service_for_test_10,
        auth_backend: auth_backend_10,
        file_storage_service: file_storage_service_10,
        email_service: Arc::new(
            scribe_backend::services::email_service::LoggingEmailService::new(
                "http://localhost:3000".to_string(),
            ),
        ),
    };
    let app_state_for_rag = Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services_for_rag,
    ));

    // Step 1a: Process and embed a chat message
    let process_chat_result = app_state_for_rag
        .embedding_pipeline_service
        .process_and_embed_message(
            app_state_for_rag.clone(),
            chat_message.clone(), // Clone chat_message
            None,
        )
        .await;
    assert!(
        process_chat_result.is_ok(),
        "Failed to process and embed chat message: {:?}",
        process_chat_result.err()
    );

    // Step 1b: Process and embed a lorebook entry
    let params = LorebookEntryParams {
        original_lorebook_entry_id: original_lore_entry_id,
        lorebook_id,
        user_id, // Use consistent user_id
        decrypted_content: lore_entry_content.to_string(),
        decrypted_title: lore_entry_title.clone(),
        decrypted_keywords: None, // No keywords for this test
        is_enabled: true,         // is_enabled
        is_constant: false,       // is_constant
    };

    let process_lore_result = app_state_for_rag
        .embedding_pipeline_service
        .process_and_embed_lorebook_entry(app_state_for_rag.clone(), params)
        .await;
    assert!(
        process_lore_result.is_ok(),
        "Failed to process and embed lorebook entry: {:?}",
        process_lore_result.err()
    );

    // Give Qdrant a moment to index the data
    tokio::time::sleep(Duration::from_millis(200)).await; // Increased delay slightly

    // Step 2: Retrieve relevant chunks using the service
    let query_text = "Tell me about dragons"; // Query designed to hit both
    let limit_per_source = 5;

    let retrieve_result = app_state_for_rag
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state_for_rag.clone(),
            user_id,                 // user_id
            Some(chat_session_id),   // session_id_for_chat_history
            Some(vec![lorebook_id]), // active_lorebook_ids_for_search
            None,                    // chronicle_id_for_search
            query_text,              // query_text
            limit_per_source,        // limit_per_source
        )
        .await;

    assert!(
        retrieve_result.is_ok(),
        "Failed to retrieve relevant chunks: {:?}",
        retrieve_result.err()
    );
    let retrieved_chunks = retrieve_result.unwrap();

    // Assert that we got chunks back (expecting 2: one chat, one lore)
    assert_eq!(
        retrieved_chunks.len(),
        2,
        "Expected 2 chunks to be retrieved (one chat, one lore)"
    );

    // Verify content and metadata of retrieved chunks
    // Note: Order depends on scores, which depend on mock embeddings.
    // For this test, assume chat_chunk_embedding and lore_chunk_embedding are distinct enough
    // from rag_query_embedding to be retrieved, and their relative order might vary.
    let mut found_chat_chunk = false;
    let mut found_lore_chunk = false;

    for chunk in retrieved_chunks {
        match chunk.metadata {
            RetrievedMetadata::Chat(meta) => {
                assert_eq!(
                    meta.session_id, chat_session_id,
                    "Chat metadata session_id mismatch"
                );
                assert_eq!(
                    meta.message_id, chat_message_id,
                    "Chat metadata message_id mismatch"
                );
                assert_eq!(meta.user_id, user_id, "Chat metadata user_id mismatch");
                assert_eq!(meta.speaker, "User", "Chat metadata speaker mismatch");
                assert_eq!(
                    meta.source_type, "chat_message",
                    "Chat metadata source_type mismatch"
                );
                assert!(
                    meta.text.contains("dragons for RAG"),
                    "Chat metadata text content mismatch"
                );
                found_chat_chunk = true;
            }
            RetrievedMetadata::Lorebook(meta) => {
                assert_eq!(
                    meta.lorebook_id, lorebook_id,
                    "Lorebook metadata lorebook_id mismatch"
                );
                assert_eq!(
                    meta.original_lorebook_entry_id, original_lore_entry_id,
                    "Lorebook metadata original_lorebook_entry_id mismatch"
                );
                assert_eq!(meta.user_id, user_id, "Lorebook metadata user_id mismatch");
                assert_eq!(
                    meta.entry_title, lore_entry_title,
                    "Lorebook metadata entry_title mismatch"
                );
                assert_eq!(
                    meta.source_type, "lorebook_entry",
                    "Lorebook metadata source_type mismatch"
                );
                assert!(
                    meta.chunk_text.contains("ancient dragons"),
                    "Lorebook metadata chunk_text content mismatch"
                );
                found_lore_chunk = true;
            }
            RetrievedMetadata::Chronicle(_) => {
                // Chronicle metadata is not expected in this test case
                panic!("Unexpected Chronicle metadata in embedding pipeline test");
            }
        }
    }

    assert!(found_chat_chunk, "Did not find the expected chat chunk");
    assert!(found_lore_chunk, "Did not find the expected lorebook chunk");

    // Verify that the mock embedding client was called three times
    let embed_calls = mock_embedding_client.get_calls();
    assert_eq!(
        embed_calls.len(),
        3,
        "Expected 3 calls to embedding client (chat chunk, lore chunk, RAG query)"
    );
    assert_eq!(
        embed_calls[0].0, chat_message_content,
        "First embed call should be chat content"
    );
    assert_eq!(
        embed_calls[1].0, lore_entry_content,
        "Second embed call should be lore content"
    );
    assert_eq!(
        embed_calls[2].0, query_text,
        "Third embed call should be RAG query"
    );
}

// --- New Tests for MockQdrantClientService Coverage ---

#[tokio::test]
async fn test_mock_qdrant_store_points_and_get_last() {
    let mock_qdrant = Arc::new(MockQdrantClientService::new());
    let qdrant_trait = mock_qdrant.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>;

    let point_id_uuid = Uuid::new_v4();
    let point_id = qdrant_client::qdrant::PointId {
        point_id_options: Some(qdrant_client::qdrant::point_id::PointIdOptions::Uuid(
            point_id_uuid.to_string(),
        )),
    };
    let vector_data: Vec<f32> = vec![0.1; 768]; // Example vector data

    let test_point = qdrant_client::qdrant::PointStruct {
        id: Some(point_id.clone()),
        // Use simpler vector initialization with .into()
        vectors: Some(vector_data.into()),
        payload: HashMap::default(),
    };
    let points_to_store = vec![test_point.clone()];

    // Call store_points
    let store_result = qdrant_trait.store_points(points_to_store.clone()).await;
    assert!(store_result.is_ok(), "store_points failed");

    // Verify call count and last points using the mock's getters
    assert_eq!(
        mock_qdrant.get_upsert_call_count(),
        1,
        "Upsert call count mismatch"
    );
    let last_points = mock_qdrant
        .get_last_upsert_points()
        .expect("No upsert points recorded");
    assert_eq!(last_points.len(), 1, "Expected 1 point to be recorded");
    // Basic check on the recorded point ID
    assert_eq!(
        last_points[0].id, test_point.id,
        "Recorded point ID mismatch"
    );
}

#[tokio::test]
async fn test_mock_qdrant_retrieve_points() {
    let mock_qdrant = Arc::new(MockQdrantClientService::new());
    let qdrant_trait = mock_qdrant.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>;

    // Set a response for retrieve_points (uses search_response internally in mock)
    let point_id = Uuid::new_v4();
    let mock_retrieved_point = create_mock_scored_point_simple(&MockScoredPointParams {
        // Use existing helper
        id_uuid: point_id,
        score: 0.9,
        session_id: Uuid::new_v4(),
        message_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        speaker: "TestSpeaker".to_string(),
        timestamp: chrono::Utc::now(),
        text: "Retrieved text".to_string(),
        source_type: "chat_message".to_string(),
    });
    mock_qdrant.set_search_response(Ok(vec![mock_retrieved_point.clone()]));

    // Call retrieve_points
    let filter = create_message_id_filter(Uuid::new_v4()); // Example filter
    let retrieve_result = qdrant_trait.retrieve_points(Some(filter), 5).await;

    assert!(retrieve_result.is_ok(), "retrieve_points failed");
    let retrieved_points = retrieve_result.unwrap();
    assert_eq!(retrieved_points.len(), 1, "Expected 1 point retrieved");
    assert_eq!(
        retrieved_points[0].id, mock_retrieved_point.id,
        "Retrieved point ID mismatch"
    );
    assert!(
        (retrieved_points[0].score - mock_retrieved_point.score).abs() < f32::EPSILON,
        "Retrieved point score mismatch: expected {}, got {}",
        mock_retrieved_point.score,
        retrieved_points[0].score
    );
}

#[tokio::test]
async fn test_mock_qdrant_delete_points() {
    let mock_qdrant = Arc::new(MockQdrantClientService::new());
    let qdrant_trait = mock_qdrant.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>;

    let point_id_to_delete = qdrant_client::qdrant::PointId {
        point_id_options: Some(qdrant_client::qdrant::point_id::PointIdOptions::Uuid(
            Uuid::new_v4().to_string(),
        )),
    };

    // Call delete_points
    let delete_result = qdrant_trait.delete_points(vec![point_id_to_delete]).await;

    // Assert it returns Ok (mock implementation is simple)
    assert!(delete_result.is_ok(), "delete_points failed");
    // We cannot easily verify internal state change for delete in the current mock
}

#[tokio::test]
async fn test_mock_qdrant_update_collection_settings() {
    let mock_qdrant = Arc::new(MockQdrantClientService::new());
    let qdrant_trait = mock_qdrant.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>;

    // Call update_collection_settings
    let update_result = qdrant_trait.update_collection_settings().await;

    // Assert it returns Ok (mock implementation is simple)
    assert!(update_result.is_ok(), "update_collection_settings failed");
    // We cannot easily verify internal state change for update_collection_settings in the current mock
}

// --- End MockQdrantClientService Coverage Tests ---

#[tokio::test]
#[serial]
async fn test_rag_chat_history_isolation_by_user_and_session() {
    // 1. Setup TestApp with real Qdrant
    let test_app = test_helpers::spawn_app(false, false, true).await;
    log::info!(
        "Qdrant URL from test_app.config for RAG isolation test: {}",
        test_app.config.qdrant_url.as_deref().unwrap_or("None")
    );

    if test_app.config.qdrant_url.is_none()
        || test_app
            .config
            .qdrant_url
            .as_deref()
            .unwrap_or("")
            .is_empty()
    {
        log::warn!(
            "Skipping Qdrant integration test: QDRANT_URL not set in config for RAG isolation test."
        );
        assert!(
            option_env!("CI").is_some(),
            "QDRANT_URL is not set in config for an un-ignored RAG isolation test."
        );
        return;
    }

    let embeddings_service_instance =
        EmbeddingPipelineService::new(ChunkConfig::from(test_app.config.as_ref()));

    let mock_embedding_client = test_app.mock_embedding_client.clone();

    // Create AppState
    let encryption_service = Arc::new(EncryptionService::new());
    let chat_override_service = Arc::new(ChatOverrideService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
    ));
    let tokenizer_service = TokenizerService::new(
        "/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model",
    )
    .expect("Failed to create tokenizer for test");
    let hybrid_token_counter = Arc::new(HybridTokenCounter::new_local_only(tokenizer_service));
    let user_persona_service = Arc::new(UserPersonaService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
    ));
    let lorebook_service = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
        test_app.qdrant_service.clone(),
    ));
    let auth_backend = Arc::new(scribe_backend::auth::user_store::Backend::new(
        test_app.db_pool.clone(),
    ));
    let file_storage_service = Arc::new(
        scribe_backend::services::file_storage_service::FileStorageService::new("./test_uploads")
            .expect("Failed to create test file storage service"),
    );

    let services_for_isolation_test = AppStateServices {
        ai_client: test_app.ai_client.clone(),
        embedding_client: mock_embedding_client.clone(),
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: Arc::new(embeddings_service_instance),
        chat_override_service,
        user_persona_service,
        token_counter: hybrid_token_counter,
        encryption_service: encryption_service.clone(),
        lorebook_service,
        auth_backend,
        file_storage_service,
        email_service: Arc::new(
            scribe_backend::services::email_service::LoggingEmailService::new(
                "http://localhost:3000".to_string(),
            ),
        ),
    };
    let app_state = Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services_for_isolation_test,
    ));

    // 2. Define User IDs and Session IDs
    let user_a_id = Uuid::new_v4();
    let user_b_id = Uuid::new_v4();

    let session_a1_id = Uuid::new_v4();
    let session_a2_id = Uuid::new_v4();
    let session_b1_id = Uuid::new_v4();

    // 3. Define Message Content and IDs
    let content_a1 = "User A Session 1 secret dragon plans";
    let message_a1_id = Uuid::new_v4();
    let chat_message_a1 = ChatMessage {
        id: message_a1_id,
        session_id: session_a1_id,
        message_type: MessageRole::User,
        content: content_a1.as_bytes().to_vec(),
        content_nonce: None,
        created_at: Utc::now(),
        user_id: user_a_id,
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: "gemini-1.5-pro".to_string(),
    };

    let content_a2 = "User A Session 2 confidential cat strategies";
    let message_a2_id = Uuid::new_v4();
    let chat_message_a2 = ChatMessage {
        id: message_a2_id,
        session_id: session_a2_id,
        message_type: MessageRole::User,
        content: content_a2.as_bytes().to_vec(),
        content_nonce: None,
        created_at: Utc::now(),
        user_id: user_a_id,
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: "gemini-1.5-pro".to_string(),
    };

    let content_b1 = "User B Session 1 private alien agenda";
    let message_b1_id = Uuid::new_v4();
    let chat_message_b1 = ChatMessage {
        id: message_b1_id,
        session_id: session_b1_id,
        message_type: MessageRole::User,
        content: content_b1.as_bytes().to_vec(),
        content_nonce: None,
        created_at: Utc::now(),
        user_id: user_b_id,
        prompt_tokens: None,
        completion_tokens: None,
        raw_prompt_ciphertext: None,
        raw_prompt_nonce: None,
        model_name: "gemini-1.5-pro".to_string(),
    };

    // 4. Configure Mock Embeddings (one for each message chunk, one for each query)
    let embedding_dim = 768;
    let embedding_a1 = vec![0.1; embedding_dim];
    let embedding_a2 = vec![0.2; embedding_dim];
    let embedding_b1 = vec![0.3; embedding_dim];
    let query_embedding_dragons = vec![0.11; embedding_dim]; // Similar to A1
    let query_embedding_cats = vec![0.22; embedding_dim]; // Similar to A2
    let query_embedding_aliens = vec![0.33; embedding_dim]; // Similar to B1

    mock_embedding_client.set_responses_sequence(vec![
        Ok(embedding_a1.clone()),            // For processing message_a1
        Ok(embedding_a2.clone()),            // For processing message_a2
        Ok(embedding_b1.clone()),            // For processing message_b1
        Ok(query_embedding_dragons.clone()), // For query "dragons" (User A, Session A1)
        Ok(query_embedding_cats.clone()),    // For query "cats" (User A, Session A2)
        Ok(query_embedding_aliens.clone()), // For query "aliens" (User A, Session B1) - should find nothing of B's
        Ok(query_embedding_aliens.clone()), // For query "aliens" (User B, Session B1)
        Ok(query_embedding_dragons.clone()), // For query "dragons" (User B, Session A1) - should find nothing of A's
    ]);

    // 5. Process and Embed Messages
    app_state
        .embedding_pipeline_service
        .process_and_embed_message(app_state.clone(), chat_message_a1.clone(), None)
        .await
        .unwrap();
    app_state
        .embedding_pipeline_service
        .process_and_embed_message(app_state.clone(), chat_message_a2.clone(), None)
        .await
        .unwrap();
    app_state
        .embedding_pipeline_service
        .process_and_embed_message(app_state.clone(), chat_message_b1.clone(), None)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await; // Allow indexing

    // 6. Perform RAG Queries and Assert
    let limit = 5;

    // Query 1: User A for Session A1 (expects content_a1)
    let query1_text = "dragon plans";
    let chunks1 = app_state
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state.clone(),
            user_a_id,
            Some(session_a1_id),
            None,
            None, // chronicle_id_for_search
            query1_text,
            limit,
        )
        .await
        .unwrap();
    assert_eq!(
        chunks1.len(),
        1,
        "Query 1: Expected 1 chunk for User A, Session A1"
    );
    if let RetrievedMetadata::Chat(meta) = &chunks1[0].metadata {
        assert_eq!(meta.user_id, user_a_id);
        assert_eq!(meta.session_id, session_a1_id);
        assert!(meta.text.contains("dragon plans"));
    } else {
        panic!("Query 1: Expected Chat metadata");
    }

    // Query 2: User A for Session A2 (expects content_a2)
    let query2_text = "cat strategies";
    let chunks2 = app_state
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state.clone(),
            user_a_id,
            Some(session_a2_id),
            None,
            None, // chronicle_id_for_search
            query2_text,
            limit,
        )
        .await
        .unwrap();
    assert_eq!(
        chunks2.len(),
        1,
        "Query 2: Expected 1 chunk for User A, Session A2"
    );
    if let RetrievedMetadata::Chat(meta) = &chunks2[0].metadata {
        assert_eq!(meta.user_id, user_a_id);
        assert_eq!(meta.session_id, session_a2_id);
        assert!(meta.text.contains("cat strategies"));
    } else {
        panic!("Query 2: Expected Chat metadata");
    }

    // Query 3: User A for Session B1 (expects no chunks from B1)
    let query3_text = "alien agenda";
    let chunks3 = app_state
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state.clone(),
            user_a_id,
            Some(session_b1_id),
            None,
            None, // chronicle_id_for_search
            query3_text,
            limit,
        )
        .await
        .unwrap();
    assert!(
        chunks3.is_empty(),
        "Query 3: Expected 0 chunks for User A querying User B's session"
    );

    // Query 4: User B for Session B1 (expects content_b1)
    let query4_text = "alien agenda";
    let chunks4 = app_state
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state.clone(),
            user_b_id,
            Some(session_b1_id),
            None,
            None, // chronicle_id_for_search
            query4_text,
            limit,
        )
        .await
        .unwrap();
    assert_eq!(
        chunks4.len(),
        1,
        "Query 4: Expected 1 chunk for User B, Session B1"
    );
    if let RetrievedMetadata::Chat(meta) = &chunks4[0].metadata {
        assert_eq!(meta.user_id, user_b_id);
        assert_eq!(meta.session_id, session_b1_id);
        assert!(meta.text.contains("alien agenda"));
    } else {
        panic!("Query 4: Expected Chat metadata");
    }

    // Query 5: User B for Session A1 (expects no chunks from A1)
    let query5_text = "dragon plans";
    let chunks5 = app_state
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state.clone(),
            user_b_id,
            Some(session_a1_id),
            None,
            None, // chronicle_id_for_search
            query5_text,
            limit,
        )
        .await
        .unwrap();
    assert!(
        chunks5.is_empty(),
        "Query 5: Expected 0 chunks for User B querying User A's session"
    );

    // Verify embedding calls
    let calls = mock_embedding_client.get_calls();
    assert_eq!(
        calls.len(),
        3 + 5,
        "Expected 3 message processing calls + 5 query calls to embedding client"
    ); // 3 messages processed, 5 queries made
    assert_eq!(calls[0].0, content_a1);
    assert_eq!(calls[1].0, content_a2);
    assert_eq!(calls[2].0, content_b1);
    assert_eq!(calls[3].0, query1_text);
    assert_eq!(calls[4].0, query2_text);
    assert_eq!(calls[5].0, query3_text);
    assert_eq!(calls[6].0, query4_text);
    assert_eq!(calls[7].0, query5_text);
}
#[tokio::test]
#[serial]
async fn test_rag_lorebook_isolation_by_user_and_id() {
    // 1. Setup TestApp with real Qdrant
    let test_app = test_helpers::spawn_app(false, false, true).await;
    log::info!(
        "Qdrant URL from test_app.config for RAG lorebook isolation test: {}",
        test_app.config.qdrant_url.as_deref().unwrap_or("None")
    );

    if test_app.config.qdrant_url.is_none()
        || test_app
            .config
            .qdrant_url
            .as_deref()
            .unwrap_or("")
            .is_empty()
    {
        log::warn!(
            "Skipping Qdrant integration test: QDRANT_URL not set in config for RAG lorebook isolation test."
        );
        assert!(
            option_env!("CI").is_some(),
            "QDRANT_URL is not set in config for an un-ignored RAG lorebook isolation test."
        );
        return;
    }

    let embeddings_service_instance =
        EmbeddingPipelineService::new(ChunkConfig::from(test_app.config.as_ref()));

    let mock_embedding_client = test_app.mock_embedding_client.clone();

    // Create AppState
    let encryption_service = Arc::new(EncryptionService::new());
    let chat_override_service = Arc::new(ChatOverrideService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
    ));
    let tokenizer_service = TokenizerService::new(
        "/home/socol/Workspace/sanguine-scribe/backend/resources/tokenizers/gemma.model",
    )
    .expect("Failed to create tokenizer for test");
    let hybrid_token_counter = Arc::new(HybridTokenCounter::new_local_only(tokenizer_service));
    let user_persona_service = Arc::new(UserPersonaService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
    ));
    let lorebook_service = Arc::new(LorebookService::new(
        test_app.db_pool.clone(),
        encryption_service.clone(),
        test_app.qdrant_service.clone(),
    ));
    let auth_backend = Arc::new(scribe_backend::auth::user_store::Backend::new(
        test_app.db_pool.clone(),
    ));
    let file_storage_service = Arc::new(
        scribe_backend::services::file_storage_service::FileStorageService::new("./test_uploads")
            .expect("Failed to create test file storage service"),
    );

    let services_for_lorebook_isolation_test = AppStateServices {
        ai_client: test_app.ai_client.clone(),
        embedding_client: mock_embedding_client.clone(),
        qdrant_service: test_app.qdrant_service.clone(),
        embedding_pipeline_service: Arc::new(embeddings_service_instance),
        chat_override_service,
        user_persona_service,
        token_counter: hybrid_token_counter,
        encryption_service: encryption_service.clone(),
        lorebook_service,
        auth_backend,
        file_storage_service,
        email_service: Arc::new(
            scribe_backend::services::email_service::LoggingEmailService::new(
                "http://localhost:3000".to_string(),
            ),
        ),
    };
    let app_state = Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        services_for_lorebook_isolation_test,
    ));

    // 2. Define User IDs and Lorebook IDs
    let user_c_id = Uuid::new_v4();
    let user_d_id = Uuid::new_v4();

    let lorebook_c1_id = Uuid::new_v4(); // User C's first lorebook
    let lorebook_c2_id = Uuid::new_v4(); // User C's second lorebook
    let lorebook_d1_id = Uuid::new_v4(); // User D's first lorebook

    // 3. Define Lorebook Entry Content and IDs
    let entry_c1_content = "User C Lorebook 1: Elves and their ancient magic.";
    let entry_c1_id = Uuid::new_v4();

    let entry_c2_content = "User C Lorebook 2: Dwarves and their mountain kingdoms.";
    let entry_c2_id = Uuid::new_v4();

    let entry_d1_content = "User D Lorebook 1: Orcs and their tribal customs.";
    let entry_d1_id = Uuid::new_v4();

    // 4. Configure Mock Embeddings
    let embedding_dim = 768;
    let embedding_c1 = vec![0.4; embedding_dim];
    let embedding_c2 = vec![0.5; embedding_dim];
    let embedding_d1 = vec![0.6; embedding_dim];
    let query_embedding_elves = vec![0.41; embedding_dim]; // Similar to C1
    let query_embedding_dwarves = vec![0.51; embedding_dim]; // Similar to C2
    let query_embedding_orcs = vec![0.61; embedding_dim]; // Similar to D1

    let query_embedding_elves_dwarves = vec![0.45; embedding_dim]; // Between C1 and C2

    mock_embedding_client.set_responses_sequence(vec![
        Ok(embedding_c1.clone()),                  // For processing entry_c1
        Ok(embedding_c2.clone()),                  // For processing entry_c2
        Ok(embedding_d1.clone()),                  // For processing entry_d1
        Ok(query_embedding_elves.clone()),         // Query "elves" (User C, Lorebook C1)
        Ok(query_embedding_dwarves.clone()),       // Query "dwarves" (User C, Lorebook C2)
        Ok(query_embedding_orcs.clone()), // Query "orcs" (User C, Lorebook D1) - should find nothing of D's
        Ok(query_embedding_orcs.clone()), // Query "orcs" (User D, Lorebook D1)
        Ok(query_embedding_elves.clone()), // Query "elves" (User D, Lorebook C1) - should find nothing of C's
        Ok(query_embedding_elves_dwarves.clone()), // For query6_text
    ]);

    // 5. Process and Embed Lorebook Entries
    let params_c1 = LorebookEntryParams {
        original_lorebook_entry_id: entry_c1_id,
        lorebook_id: lorebook_c1_id,
        user_id: user_c_id,
        decrypted_content: entry_c1_content.to_string(),
        decrypted_title: Some("Elves".to_string()),
        decrypted_keywords: None,
        is_enabled: true,
        is_constant: false,
    };

    app_state
        .embedding_pipeline_service
        .process_and_embed_lorebook_entry(app_state.clone(), params_c1)
        .await
        .unwrap();
    let params_c2 = LorebookEntryParams {
        original_lorebook_entry_id: entry_c2_id,
        lorebook_id: lorebook_c2_id,
        user_id: user_c_id,
        decrypted_content: entry_c2_content.to_string(),
        decrypted_title: Some("Dwarves".to_string()),
        decrypted_keywords: None,
        is_enabled: true,
        is_constant: false,
    };

    app_state
        .embedding_pipeline_service
        .process_and_embed_lorebook_entry(app_state.clone(), params_c2)
        .await
        .unwrap();
    let params_d1 = LorebookEntryParams {
        original_lorebook_entry_id: entry_d1_id,
        lorebook_id: lorebook_d1_id,
        user_id: user_d_id,
        decrypted_content: entry_d1_content.to_string(),
        decrypted_title: Some("Orcs".to_string()),
        decrypted_keywords: None,
        is_enabled: true,
        is_constant: false,
    };

    app_state
        .embedding_pipeline_service
        .process_and_embed_lorebook_entry(app_state.clone(), params_d1)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await; // Allow indexing

    // 6. Perform RAG Queries and Assert
    let limit = 5;

    // Query 1: User C for Lorebook C1 (expects entry_c1_content)
    let query1_text = "elves magic";
    let chunks1 = app_state
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state.clone(),
            user_c_id,
            None,
            Some(vec![lorebook_c1_id]),
            None, // chronicle_id_for_search
            query1_text,
            limit,
        )
        .await
        .unwrap();
    assert_eq!(
        chunks1.len(),
        1,
        "Query 1: Expected 1 chunk for User C, Lorebook C1"
    );
    if let RetrievedMetadata::Lorebook(meta) = &chunks1[0].metadata {
        assert_eq!(meta.user_id, user_c_id);
        assert_eq!(meta.lorebook_id, lorebook_c1_id);
        assert!(meta.chunk_text.contains("Elves"));
    } else {
        panic!("Query 1: Expected Lorebook metadata");
    }

    // Query 2: User C for Lorebook C2 (expects entry_c2_content)
    let query2_text = "dwarves kingdoms";
    let chunks2 = app_state
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state.clone(),
            user_c_id,
            None,
            Some(vec![lorebook_c2_id]),
            None, // chronicle_id_for_search
            query2_text,
            limit,
        )
        .await
        .unwrap();
    assert_eq!(
        chunks2.len(),
        1,
        "Query 2: Expected 1 chunk for User C, Lorebook C2"
    );
    if let RetrievedMetadata::Lorebook(meta) = &chunks2[0].metadata {
        assert_eq!(meta.user_id, user_c_id);
        assert_eq!(meta.lorebook_id, lorebook_c2_id);
        assert!(meta.chunk_text.contains("Dwarves"));
    } else {
        panic!("Query 2: Expected Lorebook metadata");
    }

    // Query 3: User C for Lorebook D1 (expects no chunks from D1)
    let query3_text = "orcs customs";
    let chunks3 = app_state
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state.clone(),
            user_c_id,
            None,
            Some(vec![lorebook_d1_id]),
            None, // chronicle_id_for_search
            query3_text,
            limit,
        )
        .await
        .unwrap();
    assert!(
        chunks3.is_empty(),
        "Query 3: Expected 0 chunks for User C querying User D's lorebook"
    );

    // Query 4: User D for Lorebook D1 (expects entry_d1_content)
    let query4_text = "orcs customs";
    let chunks4 = app_state
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state.clone(),
            user_d_id,
            None,
            Some(vec![lorebook_d1_id]),
            None, // chronicle_id_for_search
            query4_text,
            limit,
        )
        .await
        .unwrap();
    assert_eq!(
        chunks4.len(),
        1,
        "Query 4: Expected 1 chunk for User D, Lorebook D1"
    );
    if let RetrievedMetadata::Lorebook(meta) = &chunks4[0].metadata {
        assert_eq!(meta.user_id, user_d_id);
        assert_eq!(meta.lorebook_id, lorebook_d1_id);
        assert!(meta.chunk_text.contains("Orcs"));
    } else {
        panic!("Query 4: Expected Lorebook metadata");
    }

    // Query 5: User D for Lorebook C1 (expects no chunks from C1)
    let query5_text = "elves magic";
    let chunks5 = app_state
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state.clone(),
            user_d_id,
            None,
            Some(vec![lorebook_c1_id]),
            None, // chronicle_id_for_search
            query5_text,
            limit,
        )
        .await
        .unwrap();
    assert!(
        chunks5.is_empty(),
        "Query 5: Expected 0 chunks for User D querying User C's lorebook"
    );

    // Query 6: User C for both Lorebook C1 and C2 (expects both entries)
    let query6_text = "elves and dwarves"; // A query that should hit both C1 and C2
    // Need to adjust mock embeddings for this query to be more generic or ensure it hits both
    // For simplicity, we'll assume the existing query embeddings are sufficient if Qdrant search is broad enough
    // Or, we can add a new mock embedding for this specific query.
    // Let's assume the individual queries for "elves" and "dwarves" are sufficient to test this.
    // A more robust test would involve a query embedding that is somewhat similar to both C1 and C2.
    // For now, we will test by querying with both lorebook IDs active.
    let chunks6 = app_state
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state.clone(),
            user_c_id,
            None,
            Some(vec![lorebook_c1_id, lorebook_c2_id]),
            None,                    // chronicle_id_for_search
            query6_text,
            limit,
        )
        .await
        .unwrap();

    assert_eq!(
        chunks6.len(),
        2,
        "Query 6: Expected 2 chunks for User C, Lorebooks C1 & C2. Found {}, check mock embedding sequence.",
        chunks6.len()
    );
    let mut found_c1_in_q6 = false;
    let mut found_c2_in_q6 = false;
    for chunk in chunks6 {
        if let RetrievedMetadata::Lorebook(meta) = &chunk.metadata {
            if meta.lorebook_id == lorebook_c1_id && meta.chunk_text.contains("Elves") {
                found_c1_in_q6 = true;
            }
            if meta.lorebook_id == lorebook_c2_id && meta.chunk_text.contains("Dwarves") {
                found_c2_in_q6 = true;
            }
        }
    }
    assert!(
        found_c1_in_q6,
        "Query 6: Did not find entry from Lorebook C1"
    );
    assert!(
        found_c2_in_q6,
        "Query 6: Did not find entry from Lorebook C2"
    );

    // Verify embedding calls
    let calls = mock_embedding_client.get_calls();
    assert_eq!(
        calls.len(),
        3 + 5 + 1,
        "Expected 3 entry processing calls + 6 query calls (9 total) to embedding client"
    );
    assert_eq!(calls[0].0, entry_c1_content);
    assert_eq!(calls[1].0, entry_c2_content);
    assert_eq!(calls[2].0, entry_d1_content);
    assert_eq!(calls[3].0, query1_text);
    assert_eq!(calls[4].0, query2_text);
    assert_eq!(calls[5].0, query3_text); // User C, Lorebook D1
    assert_eq!(calls[6].0, query4_text); // User D, Lorebook D1
    assert_eq!(calls[7].0, query5_text); // User D, Lorebook C1
    assert_eq!(calls[8].0, query6_text); // User C, Lorebooks C1 & C2
}
