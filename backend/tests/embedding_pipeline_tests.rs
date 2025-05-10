use scribe_backend::services::embedding_pipeline::EmbeddingPipelineServiceTrait;
use chrono::Utc;
use log;
use mockall::predicate::*;
use mockall::Any; // Added for as_any()
use qdrant_client::qdrant::{PointId, RetrievedPoint, Value, point_id::PointIdOptions};
use scribe_backend::{
    models::chats::{ChatMessage, MessageRole},
    services::embedding_pipeline::{
        EmbeddingMetadata, EmbeddingPipelineService,
    },
    test_helpers::{MockAiClient, MockEmbeddingClient, MockQdrantClientService, self}, // Removed AppStateBuilder, config. Added self for spawn_app
    vector_db::qdrant_client::{QdrantClientService, ScoredPoint, create_message_id_filter, QdrantClientServiceTrait},
     text_processing::chunking::{ChunkConfig, ChunkingMetric}, // Added import
    llm::EmbeddingClient,
    state::AppState, // Added AppState
};
use serial_test::serial;
use std::convert::TryFrom; // Needed for EmbeddingMetadata::try_from
use std::{collections::HashMap, env, sync::Arc};
use uuid::Uuid; // For mock assertions

// Comment out the test requiring a Qdrant instance setup via testcontainers
#[tokio::test]
#[ignore = "Integration test requires Qdrant instance"]
async fn test_process_and_embed_message_integration() {
    // 1. Setup dependencies using spawn_app
    let test_app = test_helpers::spawn_app(false, false).await; // use_real_ai = false, use_real_qdrant = false

    // Get necessary components from test_app
    let mock_embedding_client = test_app.mock_embedding_client.clone();
    // The qdrant_service from test_app is already the correct trait object (mock or real)
    let qdrant_service_trait = test_app.qdrant_service.clone();
    let embedding_pipeline_service_trait = test_app.mock_embedding_pipeline_service.clone(); // This remains a mock for this service
    let app_state = Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        test_app.mock_ai_client.clone().expect("Mock AI client should be present"),
        test_app.mock_embedding_client.clone(),
        test_app.qdrant_service.clone(), // Use the qdrant_service from test_app
        test_app.mock_embedding_pipeline_service.clone(),
        // test_app.embedding_call_tracker.clone() // This is part of AppState internal construction now
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
        content: test_content.clone().into(), // Convert String to Vec<u8>
        content_nonce: None,
        // tokens: None, // REMOVED
        // model_iden: None, // REMOVED
        // provider_model_iden: None, // REMOVED
        // finish_reason: None, // REMOVED
        created_at: Utc::now(),
        // updated_at: Utc::now(), // REMOVED
        user_id: Uuid::new_v4(), // Add dummy user_id for test data
    };

    // Configure mock embedding client response
    let embedding_dimension = 3072; // Changed from 768 to match Qdrant collection dimension
    let mock_embedding = vec![0.1; embedding_dimension];
    mock_embedding_client.set_response(Ok(mock_embedding.clone()));

    // 3. Call the function under test
    let result = embedding_pipeline_service_trait.process_and_embed_message(
        app_state.clone(), // Pass AppState
        test_message.clone()
    ).await;
    assert!(
        result.is_ok(),
        "process_and_embed_message failed: {:?}",
        result.err()
    );

    // 4. Verification: Check Qdrant for stored points
    tokio::time::sleep(std::time::Duration::from_millis(500)).await; // Allow indexing

    // Use the new retrieve_points method with the message_id filter
    let filter = create_message_id_filter(test_message_id);
    let retrieved_points: Vec<RetrievedPoint> = qdrant_service_trait
        .retrieve_points(Some(filter), 10) // Limit retrieval to 10 points
        .await
        .expect("Failed to retrieve points from Qdrant");

    // --- Assertions ---

    assert!(
        !retrieved_points.is_empty(),
        "No points found in Qdrant for the message ID"
    );

    // Use the actual chunking function for reliable assertion
    // Get chunk config from the app_state's config
    let verification_chunk_config = ChunkConfig::from(test_app.config.as_ref());
    let expected_chunks = scribe_backend::text_processing::chunking::chunk_text(&test_content, &verification_chunk_config, None, 0)
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

#[tokio::test]
async fn test_process_and_embed_message_all_chunks_fail_embedding() {
    // 1. Setup dependencies using spawn_app
    let test_app = test_helpers::spawn_app(false, false).await; // use_real_ai = false, use_real_qdrant = false

    // Get mock clients from test_app
    let mock_embedding_client = test_app.mock_embedding_client.clone();
    let mock_qdrant_service_concrete = test_app.mock_qdrant_service.clone().expect("Mock Qdrant service should be present");


    // The EmbeddingPipelineService is now part of AppState provided by spawn_app
    let embedding_pipeline_service_trait = test_app.mock_embedding_pipeline_service.clone();
    let app_state = Arc::new(AppState::new(
        test_app.db_pool.clone(),
        test_app.config.clone(),
        test_app.mock_ai_client.clone().expect("Mock AI client should be present"),
        test_app.mock_embedding_client.clone(),
        test_app.qdrant_service.clone(), // Use the qdrant_service from test_app (which is the mock)
        test_app.mock_embedding_pipeline_service.clone(),
        // test_app.embedding_call_tracker.clone()
    ));


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
    };

    // Configure mock embedding client to always return an error
    let embedding_error = scribe_backend::errors::AppError::EmbeddingError("Simulated embedding failure".to_string());
    mock_embedding_client.set_response(Err(embedding_error));

    // Mock Qdrant upsert (it should NOT be called)
    mock_qdrant_service_concrete.set_upsert_response(Ok(()));
    // The test logic ensures upsert isn't called if embeddings fail.

    // 3. Call the function under test
    // Call the method on the service instance, passing the AppState
    let result = embedding_pipeline_service_trait.process_and_embed_message(
        app_state.clone(), // Pass AppState
        test_message.clone()
    ).await;

    // 4. Assertions
    assert!(
        result.is_ok(),
        "process_and_embed_message should return Ok even if all embeddings fail, but got: {:?}",
        result.err()
    );

    // Verify embedding client was called for each chunk
    // Use chunk config from test_app.config for verification
    let verification_chunk_config = ChunkConfig::from(test_app.config.as_ref());
    let expected_chunks = scribe_backend::text_processing::chunking::chunk_text(&test_content, &verification_chunk_config, None, 0)
        .expect("Failed to chunk test content for verification")
        .into_iter()
        .map(|c| (c.content, "RETRIEVAL_DOCUMENT".to_string())) // Match expected call format
        .collect::<Vec<_>>();

    let embed_calls = mock_embedding_client.get_calls();
    assert_eq!(embed_calls.len(), expected_chunks.len(), "Embedding client should be called for each chunk");

    // The expect_upsert_points().never() assertion handles checking that Qdrant wasn't called.
    // This implicitly covers line 225 where the log "No valid points generated for upserting" occurs.
    // Explicitly check call count
    assert_eq!(
        mock_qdrant_service_concrete.get_upsert_call_count(),
        0,
        "Qdrant upsert should not have been called"
    );
    // Verify the exact calls made to embedding client
    assert_eq!(embed_calls, expected_chunks, "Embedding client calls mismatch");
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

    // Set vectors to None for simplicity in mock helper
    // let vector_data: Vec<f32> = vec![0.1; 768]; 
    // let vectors_output = qdrant_client::qdrant::VectorsOutput { ... }; 

    ScoredPoint {
        id: Some(PointId {
            point_id_options: Some(PointIdOptions::Uuid(id_uuid.to_string())),
        }),
        version: 1,
        score,
        payload,
        // Set vectors to None
        vectors: None,
        shard_key: None,
        order_value: None,
    }
}

#[tokio::test]
async fn test_retrieve_relevant_chunks_success() {
    // Setup: Use spawn_app
    let test_app = test_helpers::spawn_app(false, false).await; // use_real_ai = false, use_real_qdrant = false
    let mock_embedding_client = test_app.mock_embedding_client.clone();
    
    let mock_qdrant_service = test_app.mock_qdrant_service.clone().expect("Mock Qdrant service should be present");


    // Configure mock embedding client response
    let embedding_dimension = 768;
    let mock_query_embedding = vec![0.5; embedding_dimension];
    mock_embedding_client.set_response(Ok(mock_query_embedding.clone()));

    let query = "What is the meaning of life?";
    let session_id = Uuid::new_v4();
    let limit = 3;

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

    mock_qdrant_service.set_search_response(Ok(mock_scored_points.clone()));

    // Instantiate the service under test
    // The EmbeddingPipelineService is now part of AppState provided by spawn_app,
    // so we use test_app.app_state.embedding_pipeline_service directly.
    // let test_chunk_config = ChunkConfig { metric: ChunkingMetric::Char, max_size: 500, overlap: 50 };
    // let embedding_pipeline_service = Arc::new(EmbeddingPipelineService::new(test_chunk_config));

    // Call the method using app_state from TestApp
    let result = test_app.mock_embedding_pipeline_service.retrieve_relevant_chunks(
        Arc::new(AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            test_app.mock_ai_client.clone().expect("Mock AI client should be present"),
            test_app.mock_embedding_client.clone(),
            test_app.qdrant_service.clone(), // Use the qdrant_service from test_app
            test_app.mock_embedding_pipeline_service.clone(),
            // test_app.embedding_call_tracker.clone()
        )),
        session_id,
        query,
        limit
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

    // Verify calls (accessing the original mock objects, not the Arcs)
    let embed_calls = mock_embedding_client.get_calls();
    assert_eq!(embed_calls.len(), 1, "Expected 1 call to embedding client");
    assert_eq!(embed_calls[0].0, query, "Embedding query mismatch");

    assert_eq!(mock_qdrant_service.get_search_call_count(), 1, "Expected 1 call to Qdrant search");
    let last_search_params = mock_qdrant_service.get_last_search_params().expect("No search params recorded");
    assert_eq!(last_search_params.0, mock_query_embedding, "Search vector mismatch");
    assert_eq!(last_search_params.1, limit as u64, "Search limit mismatch");
    // Check filter (should be Some and match session_id)
    let filter = last_search_params.2.expect("Search filter was None");
    // Simple check: filter string representation contains session_id
    assert!(format!("{:?}", filter).contains(&session_id.to_string()), "Filter does not contain session_id");
}

#[tokio::test]
async fn test_retrieve_relevant_chunks_no_results() {
    // 1. Setup: Use spawn_app
    let test_app = test_helpers::spawn_app(false, false).await; // use_real_ai = false, use_real_qdrant = false
    let mock_embedding_client = test_app.mock_embedding_client.clone();
    
    let mock_qdrant_service = test_app.mock_qdrant_service.clone().expect("Mock Qdrant service should be present");


    let query_text = "A query that finds nothing";
    let session_id = Uuid::new_v4();
    let limit = 5;
    let mock_query_embedding = vec![0.1; 3072];

    // Configure mock embedding client response
    mock_embedding_client.set_response(Ok(mock_query_embedding.clone()));

    // Use set_search_response for the mock
    mock_qdrant_service.set_search_response(Ok(Vec::new()));

    // The EmbeddingPipelineService is now part of AppState provided by spawn_app
    // let test_chunk_config = ChunkConfig { metric: ChunkingMetric::Char, max_size: 500, overlap: 50 };
    // let embedding_pipeline_service = Arc::new(EmbeddingPipelineService::new(test_chunk_config));

    // 2. Call the method using app_state from TestApp
    let result = test_app.mock_embedding_pipeline_service.retrieve_relevant_chunks(
        Arc::new(AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            test_app.mock_ai_client.clone().expect("Mock AI client should be present"),
            test_app.mock_embedding_client.clone(),
            test_app.qdrant_service.clone(), // Use the qdrant_service from test_app
            test_app.mock_embedding_pipeline_service.clone(),
            // test_app.embedding_call_tracker.clone()
        )),
        session_id,
        query_text,
        limit
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
    // 1. Setup: Use spawn_app
    let test_app = test_helpers::spawn_app(false, false).await; // use_real_ai = false, use_real_qdrant = false
    let mock_embedding_client = test_app.mock_embedding_client.clone();

    let mock_qdrant_service = test_app.mock_qdrant_service.clone().expect("Mock Qdrant service should be present");


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

    // The EmbeddingPipelineService is now part of AppState provided by spawn_app
    // let test_chunk_config = ChunkConfig { metric: ChunkingMetric::Char, max_size: 500, overlap: 50 };
    // let embedding_pipeline_service = Arc::new(EmbeddingPipelineService::new(test_chunk_config));

    // 2. Call the method using app_state from TestApp
    let result = test_app.mock_embedding_pipeline_service.retrieve_relevant_chunks(
        Arc::new(AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            test_app.mock_ai_client.clone().expect("Mock AI client should be present"),
            test_app.mock_embedding_client.clone(),
            test_app.qdrant_service.clone(), // Use the qdrant_service from test_app
            test_app.mock_embedding_pipeline_service.clone(),
            // test_app.embedding_call_tracker.clone()
        )),
        session_id,
        query_text,
        limit
    ).await;

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
async fn test_retrieve_relevant_chunks_metadata_invalid_uuid() {
    // 1. Setup: Use spawn_app
    let test_app = test_helpers::spawn_app(false, false).await; // use_real_ai = false, use_real_qdrant = false
    let mock_embedding_client = test_app.mock_embedding_client.clone();

    let mock_qdrant_service = test_app.mock_qdrant_service.clone().expect("Mock Qdrant service should be present");


    let query_text = "Query for invalid UUID metadata";
    let session_id = Uuid::new_v4();
    let limit = 3;
    let mock_query_embedding = vec![0.6; 3072];

    mock_embedding_client.set_response(Ok(mock_query_embedding.clone()));

    // Create a point with an invalid message_id UUID string
    let mut invalid_payload = create_mock_scored_point(
        Uuid::new_v4(), 0.9, session_id, Uuid::new_v4(), "User", Utc::now(), "Valid text",
    ).payload;
    invalid_payload.insert("message_id".to_string(), Value::from("not-a-real-uuid")); // Invalid UUID

    let mock_invalid_point = ScoredPoint {
        id: Some(PointId { point_id_options: Some(PointIdOptions::Uuid(Uuid::new_v4().to_string())) }),
        version: 1,
        score: 0.9,
        payload: invalid_payload,
        vectors: None, shard_key: None, order_value: None,
    };

    mock_qdrant_service.set_search_response(Ok(vec![mock_invalid_point]));

    // The EmbeddingPipelineService is now part of AppState provided by spawn_app
    // let test_chunk_config = ChunkConfig { metric: ChunkingMetric::Char, max_size: 500, overlap: 50 };
    // let embedding_pipeline_service = Arc::new(EmbeddingPipelineService::new(test_chunk_config));

    // 2. Call the method using app_state from TestApp
    let result = test_app.mock_embedding_pipeline_service.retrieve_relevant_chunks(
        Arc::new(AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            test_app.mock_ai_client.clone().expect("Mock AI client should be present"),
            test_app.mock_embedding_client.clone(),
            test_app.qdrant_service.clone(), // Use the qdrant_service from test_app
            test_app.mock_embedding_pipeline_service.clone(),
            // test_app.embedding_call_tracker.clone()
        )),
        session_id,
        query_text,
        limit
    ).await;

    // 3. Assertions
    assert!(result.is_ok(), "retrieve_relevant_chunks should succeed even with metadata errors: {:?}", result.err());
    let retrieved_chunks = result.unwrap();
    assert!(retrieved_chunks.is_empty(), "Expected no chunks due to metadata parsing error");
    // We expect an error log, but cannot assert on it directly here.
    // This covers lines like 50, 66.
}

#[tokio::test]
async fn test_retrieve_relevant_chunks_metadata_invalid_timestamp() {
    // 1. Setup: Use spawn_app
    let test_app = test_helpers::spawn_app(false, false).await; // use_real_ai = false, use_real_qdrant = false
    let mock_embedding_client = test_app.mock_embedding_client.clone();

    let mock_qdrant_service = test_app.mock_qdrant_service.clone().expect("Mock Qdrant service should be present");


    let query_text = "Query for invalid timestamp metadata";
    let session_id = Uuid::new_v4();
    let limit = 3;
    let mock_query_embedding = vec![0.7; 3072];

    mock_embedding_client.set_response(Ok(mock_query_embedding.clone()));

    // Create a point with an invalid timestamp string
    let mut invalid_payload = create_mock_scored_point(
        Uuid::new_v4(), 0.85, session_id, Uuid::new_v4(), "Assistant", Utc::now(), "More text",
    ).payload;
    invalid_payload.insert("timestamp".to_string(), Value::from("not-a-timestamp")); // Invalid timestamp

    let mock_invalid_point = ScoredPoint {
        id: Some(PointId { point_id_options: Some(PointIdOptions::Uuid(Uuid::new_v4().to_string())) }),
        version: 1,
        score: 0.85,
        payload: invalid_payload,
        vectors: None, shard_key: None, order_value: None,
    };

    mock_qdrant_service.set_search_response(Ok(vec![mock_invalid_point]));

    // The EmbeddingPipelineService is now part of AppState provided by spawn_app
    // let test_chunk_config = ChunkConfig { metric: ChunkingMetric::Char, max_size: 500, overlap: 50 };
    // let embedding_pipeline_service = Arc::new(EmbeddingPipelineService::new(test_chunk_config));

    // 2. Call the method using app_state from TestApp
    let result = test_app.mock_embedding_pipeline_service.retrieve_relevant_chunks(
        Arc::new(AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            test_app.mock_ai_client.clone().expect("Mock AI client should be present"),
            test_app.mock_embedding_client.clone(),
            test_app.qdrant_service.clone(), // Use the qdrant_service from test_app
            test_app.mock_embedding_pipeline_service.clone(),
            // test_app.embedding_call_tracker.clone()
        )),
        session_id,
        query_text,
        limit
    ).await;

    // 3. Assertions
    assert!(result.is_ok(), "retrieve_relevant_chunks should succeed even with metadata errors: {:?}", result.err());
    let retrieved_chunks = result.unwrap();
    assert!(retrieved_chunks.is_empty(), "Expected no chunks due to metadata parsing error");
    // Covers lines like 93-94.
}

#[tokio::test]
async fn test_retrieve_relevant_chunks_metadata_missing_field() {
    // 1. Setup: Use spawn_app
    let test_app = test_helpers::spawn_app(false, false).await; // use_real_ai = false, use_real_qdrant = false
    let mock_embedding_client = test_app.mock_embedding_client.clone();

    let mock_qdrant_service = test_app.mock_qdrant_service.clone().expect("Mock Qdrant service should be present");


    let query_text = "Query for missing metadata field";
    let session_id = Uuid::new_v4();
    let limit = 3;
    let mock_query_embedding = vec![0.8; 3072];

    mock_embedding_client.set_response(Ok(mock_query_embedding.clone()));

    // Create a point with a missing 'text' field
    let mut invalid_payload = create_mock_scored_point(
        Uuid::new_v4(), 0.8, session_id, Uuid::new_v4(), "User", Utc::now(), "Some text",
    ).payload;
    invalid_payload.remove("text"); // Remove required field

    let mock_invalid_point = ScoredPoint {
        id: Some(PointId { point_id_options: Some(PointIdOptions::Uuid(Uuid::new_v4().to_string())) }),
        version: 1,
        score: 0.8,
        payload: invalid_payload,
        vectors: None, shard_key: None, order_value: None,
    };

    mock_qdrant_service.set_search_response(Ok(vec![mock_invalid_point]));

    // The EmbeddingPipelineService is now part of AppState provided by spawn_app
    // let test_chunk_config = ChunkConfig { metric: ChunkingMetric::Char, max_size: 500, overlap: 50 };
    // let embedding_pipeline_service = Arc::new(EmbeddingPipelineService::new(test_chunk_config));

    // 2. Call the method using app_state from TestApp
    let result = test_app.mock_embedding_pipeline_service.retrieve_relevant_chunks(
        Arc::new(AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            test_app.mock_ai_client.clone().expect("Mock AI client should be present"),
            test_app.mock_embedding_client.clone(),
            test_app.qdrant_service.clone(), // Use the qdrant_service from test_app
            test_app.mock_embedding_pipeline_service.clone(),
            // test_app.embedding_call_tracker.clone()
        )),
        session_id,
        query_text,
        limit
    ).await;

    // 3. Assertions
    assert!(result.is_ok(), "retrieve_relevant_chunks should succeed even with metadata errors: {:?}", result.err());
    let retrieved_chunks = result.unwrap();
    assert!(retrieved_chunks.is_empty(), "Expected no chunks due to metadata parsing error");
    // Covers lines like 44-46, 60-62, 76-77, 87-89, 105-106 and the logging on 343, 346, 348-350.
}
#[tokio::test]
async fn test_retrieve_relevant_chunks_metadata_wrong_type() {
    // 1. Setup: Use spawn_app
    let test_app = test_helpers::spawn_app(false, false).await; // use_real_ai = false, use_real_qdrant = false
    let mock_embedding_client = test_app.mock_embedding_client.clone();

    let mock_qdrant_service = test_app.mock_qdrant_service.clone().expect("Mock Qdrant service should be present");


    let query_text = "Query for wrong metadata type";
    let session_id = Uuid::new_v4();
    let limit = 3;
    let mock_query_embedding = vec![0.9; 3072];

    mock_embedding_client.set_response(Ok(mock_query_embedding.clone()));

    // Create a point with 'speaker' as an integer instead of string
    let mut invalid_payload = create_mock_scored_point(
        Uuid::new_v4(), 0.75, session_id, Uuid::new_v4(), "User", Utc::now(), "Final text",
    ).payload;
    // Replace speaker string with an integer value
    invalid_payload.insert("speaker".to_string(), Value { kind: Some(qdrant_client::qdrant::value::Kind::IntegerValue(123)) });

    let mock_invalid_point = ScoredPoint {
        id: Some(PointId { point_id_options: Some(PointIdOptions::Uuid(Uuid::new_v4().to_string())) }),
        version: 1,
        score: 0.75,
        payload: invalid_payload,
        vectors: None, shard_key: None, order_value: None,
    };

    mock_qdrant_service.set_search_response(Ok(vec![mock_invalid_point]));

    // The EmbeddingPipelineService is now part of AppState provided by spawn_app
    // let test_chunk_config = ChunkConfig { metric: ChunkingMetric::Char, max_size: 500, overlap: 50 };
    // let embedding_pipeline_service = Arc::new(EmbeddingPipelineService::new(test_chunk_config));

    // 2. Call the method using app_state from TestApp
    let result = test_app.mock_embedding_pipeline_service.retrieve_relevant_chunks(
        Arc::new(AppState::new(
            test_app.db_pool.clone(),
            test_app.config.clone(),
            test_app.mock_ai_client.clone().expect("Mock AI client should be present"),
            test_app.mock_embedding_client.clone(),
            test_app.qdrant_service.clone(), // Use the qdrant_service from test_app
            test_app.mock_embedding_pipeline_service.clone(),
            // test_app.embedding_call_tracker.clone()
        )),
        session_id,
        query_text,
        limit
    ).await;

    // 3. Assertions
    assert!(result.is_ok(), "retrieve_relevant_chunks should succeed even with metadata errors: {:?}", result.err());
    let retrieved_chunks = result.unwrap();
    assert!(retrieved_chunks.is_empty(), "Expected no chunks due to metadata parsing error (wrong type)");
    // This covers the `_ => None` branches (lines 42, 58, 74, 85, 103) and the subsequent error logging.
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
    // Setup: Initialize tracing, config, DB, Qdrant client
    // Standardize setup using spawn_app
    let _test_app = test_helpers::spawn_app(false, true).await; // use_real_ai = false, use_real_qdrant = true
                                                         // Further setup specific to this test would go here,
                                                         // potentially using _test_app components.

    // Remove call to non-existent/commented-out function
    // let qdrant_port = docker::run_qdrant_container().await;
    // Use QDRANT_URL directly from environment for the test
    let _qdrant_url = env::var("QDRANT_URL").expect("QDRANT_URL check failed after initial check");

    // Setup: Initialize tracing, config, DB, Qdrant client
}

// --- New Tests for MockQdrantClientService Coverage ---

#[tokio::test]
async fn test_mock_qdrant_store_points_and_get_last() {
    let mock_qdrant = Arc::new(MockQdrantClientService::new());
    let qdrant_trait = mock_qdrant.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>;

    let point_id_uuid = Uuid::new_v4();
    let point_id = qdrant_client::qdrant::PointId {
        point_id_options: Some(qdrant_client::qdrant::point_id::PointIdOptions::Uuid(point_id_uuid.to_string())),
    };
    let vector_data: Vec<f32> = vec![0.1; 768]; // Example vector data

    let test_point = qdrant_client::qdrant::PointStruct {
        id: Some(point_id.clone()),
        // Use simpler vector initialization with .into()
        vectors: Some(vector_data.into()),
        payload: Default::default(),
    };
    let points_to_store = vec![test_point.clone()];

    // Call store_points
    let store_result = qdrant_trait.store_points(points_to_store.clone()).await;
    assert!(store_result.is_ok(), "store_points failed");

    // Verify call count and last points using the mock's getters
    assert_eq!(mock_qdrant.get_upsert_call_count(), 1, "Upsert call count mismatch");
    let last_points = mock_qdrant.get_last_upsert_points().expect("No upsert points recorded");
    assert_eq!(last_points.len(), 1, "Expected 1 point to be recorded");
    // Basic check on the recorded point ID
    assert_eq!(last_points[0].id, test_point.id, "Recorded point ID mismatch");
}

#[tokio::test]
async fn test_mock_qdrant_retrieve_points() {
    let mock_qdrant = Arc::new(MockQdrantClientService::new());
    let qdrant_trait = mock_qdrant.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>;

    // Set a response for retrieve_points (uses search_response internally in mock)
    let point_id = Uuid::new_v4();
    let mock_retrieved_point = create_mock_scored_point( // Use existing helper
        point_id,
        0.9,
        Uuid::new_v4(),
        Uuid::new_v4(),
        "TestSpeaker",
        chrono::Utc::now(),
        "Retrieved text",
    );
    mock_qdrant.set_search_response(Ok(vec![mock_retrieved_point.clone()]));

    // Call retrieve_points
    let filter = create_message_id_filter(Uuid::new_v4()); // Example filter
    let retrieve_result = qdrant_trait.retrieve_points(Some(filter), 5).await;

    assert!(retrieve_result.is_ok(), "retrieve_points failed");
    let retrieved_points = retrieve_result.unwrap();
    assert_eq!(retrieved_points.len(), 1, "Expected 1 point retrieved");
    assert_eq!(retrieved_points[0].id, mock_retrieved_point.id, "Retrieved point ID mismatch");
    assert_eq!(retrieved_points[0].score, mock_retrieved_point.score, "Retrieved point score mismatch");
}

#[tokio::test]
async fn test_mock_qdrant_delete_points() {
    let mock_qdrant = Arc::new(MockQdrantClientService::new());
    let qdrant_trait = mock_qdrant.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>;

    let point_id_to_delete = qdrant_client::qdrant::PointId {
        point_id_options: Some(qdrant_client::qdrant::point_id::PointIdOptions::Uuid(Uuid::new_v4().to_string())),
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

