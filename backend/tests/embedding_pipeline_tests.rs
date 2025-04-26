use chrono::Utc;
use log;
use mockall::predicate::*;
use qdrant_client::qdrant::{PointId, RetrievedPoint, Value, point_id::PointIdOptions};
use scribe_backend::{
    AppState,
    models::chats::{ChatMessage, MessageRole},
    services::embedding_pipeline::{
        EmbeddingMetadata, EmbeddingPipelineService, process_and_embed_message,
        retrieve_relevant_chunks,
    },
    test_helpers::{MockAiClient, MockEmbeddingClient, MockQdrantClientService, config, db},
    vector_db::qdrant_client::{QdrantClientService, ScoredPoint, create_message_id_filter},
};
use serial_test::serial;
use std::convert::TryFrom; // Needed for EmbeddingMetadata::try_from
use std::{collections::HashMap, env, sync::Arc};
use uuid::Uuid; // For mock assertions

// Comment out the test requiring a Qdrant instance setup via testcontainers
#[tokio::test]
#[ignore = "Integration test requires Qdrant instance"]
async fn test_process_and_embed_message_integration() {
    // 1. Setup dependencies
    // Use helpers via their modules
    // let qdrant_port = docker::run_qdrant_container().await;
    // This line has a type error (expected u16, found Option)
    // let qdrant_client = qdrant::setup_qdrant(None).await;
    let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
    let mock_ai_client = Arc::new(MockAiClient::new());
    let pool = db::setup_test_database(None).await;
    let config = Arc::new(config::initialize_test_config(None));

    // Create Qdrant service instance directly for AppState
    let qdrant_service = Arc::new(
        QdrantClientService::new(config.clone())
            .await
            .expect("Failed to create QdrantClientService for test"),
    );

    // Instantiate the real EmbeddingPipelineService
    let embedding_pipeline_service = Arc::new(EmbeddingPipelineService);

    // Create AppState using the constructor
    let app_state = Arc::new(AppState::new(
        pool.clone(),
        config.clone(),
        mock_ai_client.clone(),
        mock_embedding_client.clone(),
        qdrant_service.clone(),
        embedding_pipeline_service.clone(),
    ));

    // 2. Prepare test data
    let test_message_id = Uuid::new_v4();
    let test_session_id = Uuid::new_v4();
    // let test_user_id = Uuid::new_v4(); // user_id field does not exist on ChatMessage
    let test_content = "This is a test message with multiple sentences. It should be chunked into pieces for storage.".to_string();
    let test_message = ChatMessage {
        id: test_message_id,
        session_id: test_session_id,
        // user_id: test_user_id, // REMOVED
        message_type: MessageRole::User,
        content: test_content.clone(),
        // tokens: None, // REMOVED
        // model_iden: None, // REMOVED
        // provider_model_iden: None, // REMOVED
        // finish_reason: None, // REMOVED
        created_at: Utc::now(),
        // updated_at: Utc::now(), // REMOVED
    };

    // Configure mock embedding client response
    let embedding_dimension = 3072; // Match Qdrant collection dimension
    let mock_embedding = vec![0.1; embedding_dimension];
    mock_embedding_client.set_response(Ok(mock_embedding.clone()));

    // 3. Call the function under test
    let result = process_and_embed_message(app_state.clone(), test_message.clone()).await;
    assert!(
        result.is_ok(),
        "process_and_embed_message failed: {:?}",
        result.err()
    );

    // 4. Verification: Check Qdrant for stored points
    tokio::time::sleep(std::time::Duration::from_millis(500)).await; // Allow indexing

    // Use the new retrieve_points method with the message_id filter
    let filter = create_message_id_filter(test_message_id);
    let retrieved_points: Vec<RetrievedPoint> = qdrant_service
        .retrieve_points(Some(filter), 10) // Limit retrieval to 10 points
        .await
        .expect("Failed to retrieve points from Qdrant");

    // --- Assertions ---

    assert!(
        !retrieved_points.is_empty(),
        "No points found in Qdrant for the message ID"
    );

    // Use the actual chunking function for reliable assertion
    let expected_chunks = scribe_backend::text_processing::chunking::chunk_text(&test_content)
        .expect("Failed to chunk test content for verification");
    let expected_num_chunks = expected_chunks.len();

    assert_eq!(
        retrieved_points.len(),
        expected_num_chunks,
        "Expected {} chunks based on chunking logic, but found {} points in Qdrant",
        expected_num_chunks,
        retrieved_points.len()
    );

    // Verify metadata and content of each point
    let mut found_chunk_texts: Vec<String> = Vec::new();
    for point in retrieved_points {
        let payload_map: HashMap<String, Value> = point.payload;
        let metadata = EmbeddingMetadata::try_from(payload_map)
            .expect("Failed to parse EmbeddingMetadata from Qdrant payload");

        assert_eq!(
            metadata.message_id, test_message_id,
            "Metadata message_id mismatch"
        );
        assert_eq!(
            metadata.session_id, test_session_id,
            "Metadata session_id mismatch"
        );
        assert_eq!(
            metadata.speaker,
            format!("{:?}", test_message.message_type),
            "Metadata speaker mismatch"
        );
        assert_eq!(
            metadata.timestamp, test_message.created_at,
            "Metadata timestamp mismatch"
        );

        assert!(
            expected_chunks
                .iter()
                .any(|chunk| chunk.content == metadata.text),
            "Stored text '{}' did not match any expected chunk",
            metadata.text
        );

        found_chunk_texts.push(metadata.text);
    }

    // Verify that all expected chunks were found
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

// --- Unit Tests for retrieve_relevant_chunks ---

// Helper to create a mock ScoredPoint
fn create_mock_scored_point(
    id_uuid: Uuid,
    score: f32,
    session_id: Uuid,
    message_id: Uuid,
    speaker: &str,
    timestamp: chrono::DateTime<Utc>,
    text: &str,
) -> ScoredPoint {
    let mut payload = HashMap::new();
    payload.insert(
        "session_id".to_string(),
        Value::from(session_id.to_string()),
    );
    payload.insert(
        "message_id".to_string(),
        Value::from(message_id.to_string()),
    );
    payload.insert("speaker".to_string(), Value::from(speaker.to_string()));
    payload.insert("timestamp".to_string(), Value::from(timestamp.to_rfc3339()));
    payload.insert("text".to_string(), Value::from(text.to_string()));

    ScoredPoint {
        id: Some(PointId {
            point_id_options: Some(PointIdOptions::Uuid(id_uuid.to_string())),
        }),
        version: 1,
        score,
        payload,
        vectors: None,
        shard_key: None,
        order_value: None,
    }
}

#[tokio::test]
async fn test_retrieve_relevant_chunks_success() {
    // 1. Setup Mocks
    let mock_embedding_client = MockEmbeddingClient::new();
    let mock_qdrant_service = MockQdrantClientService::new();

    let query_text = "What is the meaning of life?";
    let session_id = Uuid::new_v4();
    let limit = 3;
    let mock_query_embedding = vec![0.5; 3072]; // Example embedding

    // Configure mock embedding client response
    mock_embedding_client.set_response(Ok(mock_query_embedding.clone()));

    // Mock QdrantClientService behavior
    let point_id1 = Uuid::new_v4();
    let point_id2 = Uuid::new_v4();
    let mock_timestamp = Utc::now();
    let mock_scored_points = vec![
        create_mock_scored_point(
            point_id1,
            0.95,
            session_id,
            Uuid::new_v4(),
            "User",
            mock_timestamp,
            "Chunk 1 text",
        ),
        create_mock_scored_point(
            point_id2,
            0.88,
            session_id,
            Uuid::new_v4(),
            "Assistant",
            mock_timestamp,
            "Chunk 2 text",
        ),
    ];

    // Use set_search_response instead of expect_search_points
    mock_qdrant_service.set_search_response(Ok(mock_scored_points.clone()));

    // No need to convert to trait explicitly, MockQdrantClientService now implements QdrantClientServiceTrait
    let result = retrieve_relevant_chunks(
        Arc::new(mock_qdrant_service),
        Arc::new(mock_embedding_client),
        session_id,
        query_text, // No to_string() call
        limit,
    )
    .await;

    // 3. Assertions
    assert!(
        result.is_ok(),
        "retrieve_relevant_chunks failed: {:?}",
        result.err()
    );
    let retrieved_chunks = result.unwrap();

    assert_eq!(
        retrieved_chunks.len(),
        2,
        "Expected 2 chunks to be retrieved"
    );

    // Verify content of the first chunk
    assert_eq!(retrieved_chunks[0].score, 0.95);
    assert_eq!(retrieved_chunks[0].text, "Chunk 1 text");
    assert_eq!(retrieved_chunks[0].metadata.session_id, session_id);
    assert_eq!(retrieved_chunks[0].metadata.speaker, "User");
    assert_eq!(retrieved_chunks[0].metadata.text, "Chunk 1 text"); // Ensure metadata text matches chunk text

    // Verify content of the second chunk
    assert_eq!(retrieved_chunks[1].score, 0.88);
    assert_eq!(retrieved_chunks[1].text, "Chunk 2 text");
    assert_eq!(retrieved_chunks[1].metadata.session_id, session_id);
    assert_eq!(retrieved_chunks[1].metadata.speaker, "Assistant");
    assert_eq!(retrieved_chunks[1].metadata.text, "Chunk 2 text");
}

#[tokio::test]
async fn test_retrieve_relevant_chunks_no_results() {
    // 1. Setup Mocks
    let mock_embedding_client = MockEmbeddingClient::new();
    let mock_qdrant_service = MockQdrantClientService::new();

    let query_text = "A query that finds nothing";
    let session_id = Uuid::new_v4();
    let limit = 5;
    let mock_query_embedding = vec![0.1; 3072];

    // Configure mock embedding client response
    mock_embedding_client.set_response(Ok(mock_query_embedding.clone()));

    // Use set_search_response for the mock
    mock_qdrant_service.set_search_response(Ok(Vec::new()));

    // 2. Call the function - no need for trait type conversion
    let result = retrieve_relevant_chunks(
        Arc::new(mock_qdrant_service),
        Arc::new(mock_embedding_client),
        session_id,
        query_text, // No to_string() call
        limit,
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
    // 1. Setup Mocks
    let mock_embedding_client = MockEmbeddingClient::new();
    let mock_qdrant_service = MockQdrantClientService::new();

    let query_text = "Query leading to Qdrant error";
    let session_id = Uuid::new_v4();
    let limit = 2;
    let mock_query_embedding = vec![0.2; 3072];

    // Configure mock embedding client response
    mock_embedding_client.set_response(Ok(mock_query_embedding.clone()));

    // Use set_search_response for error
    mock_qdrant_service.set_search_response(Err(scribe_backend::errors::AppError::VectorDbError(
        "Simulated Qdrant search failure".to_string(),
    )));

    // 2. Call the function
    let result = retrieve_relevant_chunks(
        Arc::new(mock_qdrant_service),
        Arc::new(mock_embedding_client),
        session_id,
        query_text, // No to_string() call
        limit,
    )
    .await;

    // 3. Assertions
    assert!(
        result.is_err(),
        "Expected retrieve_relevant_chunks to return an error"
    );
    if let Err(e) = result {
        // Check if the error is the expected type (or wraps it)
        assert!(
            matches!(e, scribe_backend::errors::AppError::VectorDbError(_)),
            "Expected a VectorDbError"
        );
        assert!(e.to_string().contains("Simulated Qdrant search failure"));
    }
}

#[tokio::test]
async fn test_retrieve_relevant_chunks_embedding_error() {
    // 1. Setup Mocks
    let mock_embedding_client = MockEmbeddingClient::new();
    let mock_qdrant_service = MockQdrantClientService::new(); // No expectations needed here

    let query_text = "Query leading to embedding error";
    let session_id = Uuid::new_v4();
    let limit = 4;

    // Configure mock embedding client to return an error
    mock_embedding_client.set_response(Err(scribe_backend::errors::AppError::GeminiError(
        "Simulated embedding failure".to_string(),
    )));

    // 2. Call the function
    let result = retrieve_relevant_chunks(
        Arc::new(mock_qdrant_service),
        Arc::new(mock_embedding_client),
        session_id,
        query_text, // No to_string() call
        limit,
    )
    .await;

    // 3. Assertions
    assert!(
        result.is_err(),
        "Expected retrieve_relevant_chunks to return an error"
    );
    if let Err(e) = result {
        // Check if the error is the expected type (or wraps it)
        assert!(
            matches!(e, scribe_backend::errors::AppError::GeminiError(_)),
            "Expected a GeminiError"
        );
        assert!(e.to_string().contains("Simulated embedding failure"));
    }
}

// TODO: Add tests for retrieve_relevant_chunks integration if needed,
// likely involving inserting known points and then querying them.

#[tokio::test]
#[ignore] // Test requires external Qdrant service
#[serial]
async fn test_rag_context_injection_with_qdrant() {
    // Skip test if QDRANT_URL is not set (e.g., in CI without service)
    if env::var("QDRANT_URL").is_err() {
        log::warn!("Skipping Qdrant integration test: QDRANT_URL not set.");
        return;
    }
    // Remove call to non-existent/commented-out function
    // let qdrant_port = docker::run_qdrant_container().await;
    // Use QDRANT_URL directly from environment for the test
    let _qdrant_url = env::var("QDRANT_URL").expect("QDRANT_URL check failed after initial check");

    // Setup: Initialize tracing, config, DB, Qdrant client
}
