use scribe_backend::{
    AppState,
    models::chats::{ChatMessage, MessageRole},
    services::embedding_pipeline::{process_and_embed_message, EmbeddingMetadata, EmbeddingPipelineService},
    test_helpers::{db, config, MockEmbeddingClient, MockAiClient},
    vector_db::{
        qdrant_client::{QdrantClientService, create_message_id_filter},
    },
};
use std::{collections::HashMap, sync::Arc, env};
use uuid::Uuid;
use chrono::Utc;
use qdrant_client::qdrant::{Value, RetrievedPoint};
use std::convert::TryFrom; // Needed for EmbeddingMetadata::try_from
use serial_test::serial; // For the #[serial] attribute on the last test
use log; // For the log::warn in the last test
// Use the crate name and new public modules to import test helpers


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
            .expect("Failed to create QdrantClientService for test")
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
    assert!(result.is_ok(), "process_and_embed_message failed: {:?}", result.err());

    // 4. Verification: Check Qdrant for stored points
    tokio::time::sleep(std::time::Duration::from_millis(500)).await; // Allow indexing

    // Use the new retrieve_points method with the message_id filter
    let filter = create_message_id_filter(test_message_id);
    let retrieved_points: Vec<RetrievedPoint> = qdrant_service
        .retrieve_points(Some(filter), 10) // Limit retrieval to 10 points
        .await
        .expect("Failed to retrieve points from Qdrant");

    // --- Assertions --- 

    assert!(!retrieved_points.is_empty(), "No points found in Qdrant for the message ID");

    // Use the actual chunking function for reliable assertion
    let expected_chunks = scribe_backend::text_processing::chunking::chunk_text(&test_content)
        .expect("Failed to chunk test content for verification");
    let expected_num_chunks = expected_chunks.len();

    assert_eq!(retrieved_points.len(), expected_num_chunks, 
               "Expected {} chunks based on chunking logic, but found {} points in Qdrant", 
               expected_num_chunks, retrieved_points.len());

    // Verify metadata and content of each point
    let mut found_chunk_texts: Vec<String> = Vec::new();
    for point in retrieved_points {
        let payload_map: HashMap<String, Value> = point.payload;
        let metadata = EmbeddingMetadata::try_from(payload_map)
            .expect("Failed to parse EmbeddingMetadata from Qdrant payload");

        assert_eq!(metadata.message_id, test_message_id, "Metadata message_id mismatch");
        assert_eq!(metadata.session_id, test_session_id, "Metadata session_id mismatch");
        assert_eq!(metadata.speaker, format!("{:?}", test_message.message_type), "Metadata speaker mismatch"); 
        assert_eq!(metadata.timestamp, test_message.created_at, "Metadata timestamp mismatch"); 
        
        assert!(expected_chunks.iter().any(|chunk| chunk.content == metadata.text),
                "Stored text '{}' did not match any expected chunk", metadata.text);
        
        found_chunk_texts.push(metadata.text);
    }

    // Verify that all expected chunks were found
    assert_eq!(found_chunk_texts.len(), expected_num_chunks, "Number of verified chunks doesn't match expected");
    for expected_chunk in expected_chunks {
        assert!(found_chunk_texts.contains(&expected_chunk.content), "Expected chunk missing: {}", expected_chunk.content);
    }

}


// TODO: Add tests for retrieve_relevant_chunks integration if needed,
// likely involving inserting known points and then querying them.


#[cfg(feature = "integration-tests")]
#[tokio::test]
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
    let qdrant_url = env::var("QDRANT_URL").expect("QDRANT_URL check failed after initial check");

    // Setup: Initialize tracing, config, DB, Qdrant client
}

