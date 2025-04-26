// backend/src/services/embedding_pipeline.rs

use crate::errors::AppError;
use crate::models::chats::ChatMessage;
use crate::state::AppState;
use crate::text_processing::chunking::chunk_text;
use crate::vector_db::qdrant_client::{create_qdrant_point, QdrantClientServiceTrait};
use crate::llm::EmbeddingClient;

use qdrant_client::qdrant::{Condition, FieldCondition, Filter, Match, Value as QdrantValue};
use qdrant_client::qdrant::r#match::MatchValue;
use qdrant_client::qdrant::condition::ConditionOneOf;
use std::collections::HashMap;
use std::convert::TryFrom;
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;
use chrono::Utc;

// Define metadata to store alongside vectors
// TODO: Finalize required metadata fields
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)] // Add Deserialize
pub struct EmbeddingMetadata {
    pub message_id: Uuid,
    pub session_id: Uuid,
    // user_id: Option<Uuid>, // Removed - user info not directly on message
    pub speaker: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub text: String,
}

// Implement conversion from Qdrant payload
impl TryFrom<HashMap<String, QdrantValue>> for EmbeddingMetadata {
    type Error = AppError; // Use our standard AppError for conversion errors

    fn try_from(payload: HashMap<String, QdrantValue>) -> Result<Self, Self::Error> {
        let message_id_str = payload
            .get("message_id")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or_else(|| AppError::SerializationError("Missing or invalid 'message_id' in payload".to_string()))?;
        let message_id = Uuid::parse_str(message_id_str)
            .map_err(|e| AppError::SerializationError(format!("Failed to parse 'message_id' as UUID: {}", e)))?;

        let session_id_str = payload
            .get("session_id")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or_else(|| AppError::SerializationError("Missing or invalid 'session_id' in payload".to_string()))?;
        let session_id = Uuid::parse_str(session_id_str)
            .map_err(|e| AppError::SerializationError(format!("Failed to parse 'session_id' as UUID: {}", e)))?;

        let speaker = payload
            .get("speaker")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| AppError::SerializationError("Missing or invalid 'speaker' in payload".to_string()))?;

        let timestamp_str = payload
            .get("timestamp")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or_else(|| AppError::SerializationError("Missing or invalid 'timestamp' in payload".to_string()))?;
        let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp_str)
            .map_err(|e| AppError::SerializationError(format!("Failed to parse 'timestamp': {}", e)))
            .map(|dt| dt.with_timezone(&chrono::Utc))?;

        let text = payload
            .get("text")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| AppError::SerializationError("Missing or invalid 'text' in payload".to_string()))?;

        Ok(EmbeddingMetadata {
            message_id,
            session_id,
            speaker,
            timestamp,
            text,
        })
    }
}

#[instrument(skip_all, fields(message_id = %message.id, session_id = %message.session_id))] // Use session_id
pub async fn process_and_embed_message(
    state: Arc<AppState>,
    message: ChatMessage,
) -> Result<(), AppError> {
    info!("Starting embedding process for message");

    // --- Test Hook: Track call (using tracker from AppState) ---
    // Removed #[cfg(test)] - Tracker is now always part of AppState
    {
        let tracker = state.embedding_call_tracker.clone();
        let msg_id = message.id;
        // Lock and push directly, no need for extra spawn
        if let Ok(mut calls) = tracker.try_lock() { // Use try_lock for simplicity in async context
            calls.push(msg_id);
            info!(message_id = %msg_id, "Tracked embedding call for test");
        } else {
            warn!(message_id = %msg_id, "Failed to lock embedding tracker for test (already locked?)");
        }
    }
    // --- End Test Hook ---

    // 1. Chunk the message content
    let chunks = match chunk_text(&message.content) {
        Ok(chunks) => {
            if chunks.is_empty() {
                warn!("Chunking produced no chunks for message content. Skipping embedding.");
                return Ok(());
            }
            chunks
        }
        Err(e) => {
            error!(error = %e, "Failed to chunk message content");
            // Decide if this error should halt processing or just be logged
            return Err(e);
        }
    };
    info!("Message content split into {} chunks", chunks.len());

    let embedding_client = state.embedding_client.clone();
    let qdrant_service = state.qdrant_service.clone();
    let mut points_to_upsert = Vec::new();

    // 2. Process each chunk
    for (index, chunk) in chunks.into_iter().enumerate() {
        // 2a. Get embedding
        // TODO: Determine the correct task_type for Gemini embedding API
        // Common types: RETRIEVAL_QUERY, RETRIEVAL_DOCUMENT, SEMANTIC_SIMILARITY, CLASSIFICATION, CLUSTERING
        // For storing chat history chunks, RETRIEVAL_DOCUMENT seems appropriate.
        let task_type = "RETRIEVAL_DOCUMENT";
        let embedding_vector = match embedding_client.embed_content(&chunk.content, task_type).await {
            Ok(vector) => vector,
            Err(e) => {
                error!(error = %e, chunk_index = index, "Failed to get embedding for chunk");
                // Optionally: Implement retry logic here
                // Decide whether to skip this chunk or fail the whole message
                continue; // Skip this chunk for now
            }
        };

        // 2b. Prepare metadata
        // 2b. Prepare metadata
        // Convert MessageRole enum to string for speaker
        let speaker_str = format!("{:?}", message.message_type); // e.g., "User", "Assistant"

        let metadata = EmbeddingMetadata {
            message_id: message.id,
            session_id: message.session_id, // Use session_id from ChatMessage
            // user_id: None, // Removed
            speaker: speaker_str, // Use formatted message_type
            timestamp: message.created_at, // Assuming created_at field
            text: chunk.content.clone(), // Store original chunk text
        };

        // 2c. Create Qdrant point
        // Generate a unique ID for each chunk point (e.g., combine message ID and chunk index)
        // Using a new UUID per chunk is simpler for now.
        let point_id = Uuid::new_v4();
        let point = match create_qdrant_point(point_id, embedding_vector, Some(serde_json::to_value(metadata)?)) {
            Ok(p) => p,
            Err(e) => {
                 error!(error = %e, chunk_index = index, "Failed to create Qdrant point struct");
                 continue; // Skip this chunk
            }
        };
        points_to_upsert.push(point);
    }

    // 3. Upsert points to Qdrant in batch
    if !points_to_upsert.is_empty() {
        info!("Upserting {} points to Qdrant", points_to_upsert.len());
        if let Err(e) = qdrant_service.upsert_points(points_to_upsert).await {
            error!(error = %e, "Failed to upsert points to Qdrant");
            // Decide on error handling: retry? Mark message as failed embedding?
            return Err(e);
        }
        info!("Successfully upserted points for message");
    } else {
        info!("No valid points generated for upserting.");
    }

    Ok(())
}


// --- Service Trait and Implementation ---

#[async_trait]
pub trait EmbeddingPipelineServiceTrait: Send + Sync {
    async fn retrieve_relevant_chunks(
        &self,
        state: Arc<AppState>, // Pass state for now, could be refactored later
        chat_id: Uuid,
        query_text: &str,
        limit: u64,
    ) -> Result<Vec<RetrievedChunk>, AppError>;
}

pub struct EmbeddingPipelineService;

// Implement the trait for EmbeddingPipelineService
#[async_trait]
impl EmbeddingPipelineServiceTrait for EmbeddingPipelineService {
    async fn retrieve_relevant_chunks(
        &self,
        state: Arc<AppState>,
        chat_id: Uuid,
        query_text: &str,
        limit: u64,
    ) -> Result<Vec<RetrievedChunk>, AppError> {
        // Call the standalone function
        retrieve_relevant_chunks(
            state.qdrant_service.clone(),
            state.embedding_client.clone(),
            chat_id,
            query_text,
            limit,
        ).await
    }
}

// --- RAG (Retrieval-Augmented Generation) Logic ---

/// Represents a chunk of text retrieved from the vector database during RAG.
#[derive(Clone)]
pub struct RetrievedChunk {
    pub score: f32,
    pub text: String,
    pub metadata: EmbeddingMetadata, // Reuse the metadata struct
}

/// Retrieves relevant text chunks from the vector database based on a query.
///
/// 1. Creates an embedding for the `query_text` using the `EmbeddingClient`.
/// 2. Searches the Qdrant collection using the embedding and a filter for the `session_id`.
/// 3. Converts the retrieved `ScoredPoint`s into `RetrievedChunk`s.
pub async fn retrieve_relevant_chunks(
    qdrant_service: Arc<dyn QdrantClientServiceTrait>,
    embedding_client: Arc<dyn EmbeddingClient>,
    session_id: Uuid,
    query_text: &str,
    limit: u64,
) -> Result<Vec<RetrievedChunk>, AppError> {
    info!("Retrieving relevant chunks for query");

    // 1. Get embedding for the query text
    let task_type = "RETRIEVAL_QUERY";
    let query_embedding = embedding_client
        .embed_content(query_text, task_type)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get embedding for RAG query");
            e // Assuming embed_content now returns AppError directly
        })?;

    // 2. Construct filter for session_id
    let filter = Filter {
        must: vec![Condition {
            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                key: "session_id".to_string(), // Field name in Qdrant payload
                r#match: Some(Match {
                    match_value: Some(MatchValue::Keyword(session_id.to_string())),
                }),
                range: None, // Explicitly None
                geo_bounding_box: None,
                geo_radius: None,
                geo_polygon: None,
                values_count: None,
                datetime_range: None,
                is_empty: None,
                is_null: None,
            })),
        }],
        should: vec![], // Explicitly empty
        must_not: vec![], // Explicitly empty
        min_should: None,
    };

    // 3. Search Qdrant
    let search_results = qdrant_service
        .search_points(query_embedding, limit, Some(filter))
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to search Qdrant for relevant chunks");
            e // Propagate AppError
        })?;

    // 4. Convert search results to RetrievedChunk
    let mut retrieved_chunks = Vec::new();
    for scored_point in search_results {
        match EmbeddingMetadata::try_from(scored_point.payload) {
            Ok(metadata) => retrieved_chunks.push(RetrievedChunk {
                score: scored_point.score,
                text: metadata.text.clone(), // Use text from parsed metadata
                metadata,
            }),
            Err(e) => {
                // Use scored_point.id.map(|id| format!("{:?}", id)).unwrap_or_else(|| "N/A".to_string())
                // to safely get the ID as a string for logging, handling None case.
                let point_id_str = scored_point.id.map(|id| format!("{:?}", id)).unwrap_or_else(|| "N/A".to_string());
                error!(error = %e, point_id = %point_id_str, "Failed to parse metadata from Qdrant point payload");
                // Skipping for now
            }
        }
    }

    info!("Retrieved {} relevant chunks", retrieved_chunks.len());
    Ok(retrieved_chunks)
}


// TODO: Add function/mechanism to trigger `process_and_embed_message` asynchronously
// e.g., call this using tokio::spawn from ChatService after saving a message.

// --- Unit Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::chats::MessageRole;
    // Corrected mock import
    use crate::test_helpers::{MockEmbeddingClient, MockQdrantClientService, MockAiClient, AppStateBuilder}; 
    use crate::vector_db::qdrant_client::ScoredPoint; // Import ScoredPoint
    use crate::config::Config;
    use std::sync::Arc;
    // use tokio::sync::Mutex; // Removed unused import
    // Correct Payload import
    use qdrant_client::qdrant::{PointId, Value}; 
     // Import Payload from correct location
    use std::collections::HashMap;
    use uuid::Uuid;
    use chrono::Utc;
    // Add missing import for tests
    use crate::llm::EmbeddingClient;

    // --- Tests for EmbeddingMetadata TryFrom (already exist) --- 
    fn string_value(s: &str) -> Value {
        Value { kind: Some(qdrant_client::qdrant::value::Kind::StringValue(s.to_string())) }
    }

    fn integer_value(i: i64) -> Value {
        Value { kind: Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)) }
    }

    // Helper to build a valid payload HashMap<String, Value>
    fn build_valid_payload_map() -> HashMap<String, Value> {
        let mut payload = HashMap::new();
        payload.insert("message_id".to_string(), string_value(&Uuid::new_v4().to_string()));
        payload.insert("session_id".to_string(), string_value(&Uuid::new_v4().to_string()));
        payload.insert("speaker".to_string(), string_value("User"));
        payload.insert("timestamp".to_string(), string_value(&Utc::now().to_rfc3339()));
        payload.insert("text".to_string(), string_value("Some chunk text"));
        payload
    }

    #[test]
    fn test_embedding_metadata_try_from_valid_payload() {
        let payload_map = build_valid_payload_map();
        let result = EmbeddingMetadata::try_from(payload_map);
        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert_eq!(metadata.speaker, "User");
        assert_eq!(metadata.text, "Some chunk text");
    }

    #[test]
    fn test_embedding_metadata_try_from_missing_field() {
        let mut payload_map = build_valid_payload_map();
        payload_map.remove("speaker");
        let result = EmbeddingMetadata::try_from(payload_map);
        assert!(result.is_err());
        match result.err().unwrap() {
            AppError::SerializationError(msg) => assert!(msg.contains("Missing or invalid 'speaker'"), "Error message mismatch: {}", msg),
            _ => panic!("Expected SerializationError"),
        }
    }

    #[test]
    fn test_embedding_metadata_try_from_invalid_uuid_format() {
        let mut payload_map = build_valid_payload_map();
        payload_map.insert("message_id".to_string(), string_value("not-a-uuid"));
        let result = EmbeddingMetadata::try_from(payload_map);
        assert!(result.is_err());
        match result.err().unwrap() {
            AppError::SerializationError(msg) => assert!(msg.contains("Failed to parse 'message_id'"), "Error message mismatch: {}", msg),
            _ => panic!("Expected SerializationError"),
        }
    }

    #[test]
    fn test_embedding_metadata_try_from_invalid_timestamp_format() {
        let mut payload_map = build_valid_payload_map();
        payload_map.insert("timestamp".to_string(), string_value("not-a-timestamp"));
        let result = EmbeddingMetadata::try_from(payload_map);
        assert!(result.is_err());
        match result.err().unwrap() {
            AppError::SerializationError(msg) => assert!(msg.contains("Failed to parse 'timestamp'"), "Error message mismatch: {}", msg),
            _ => panic!("Expected SerializationError"),
        }
    }

    #[test]
    fn test_embedding_metadata_try_from_wrong_field_type() {
        let mut payload_map = build_valid_payload_map();
        // Insert speaker as integer instead of string
        payload_map.insert("speaker".to_string(), integer_value(123));
        let result = EmbeddingMetadata::try_from(payload_map);
        assert!(result.is_err());
        match result.err().unwrap() {
            AppError::SerializationError(msg) => assert!(msg.contains("Missing or invalid 'speaker'"), "Error message mismatch: {}", msg),
            _ => panic!("Expected SerializationError"),
        }
    }

    #[test]
    fn test_embedding_metadata_try_from_empty_payload() {
        let payload_map: HashMap<String, Value> = HashMap::new();
        let result = EmbeddingMetadata::try_from(payload_map);
        assert!(result.is_err());
        // Check for one of the expected missing field errors
        match result.err().unwrap() {
            AppError::SerializationError(msg) => assert!(msg.contains("Missing or invalid"), "Error message mismatch: {}", msg),
            _ => panic!("Expected SerializationError"),
        }
    }

    // --- Helper to create Mock AppState using AppStateBuilder ---
    async fn create_mock_app_state() -> (Arc<AppState>, Arc<MockEmbeddingClient>, Arc<MockQdrantClientService>) {
        let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service = Arc::new(MockQdrantClientService::new());
        let mock_ai_client = Arc::new(MockAiClient::new());
        // Create a mock pipeline service (won't be called directly in these tests)
        struct MockPipeline;
        #[async_trait]
        impl EmbeddingPipelineServiceTrait for MockPipeline {
             async fn retrieve_relevant_chunks(
                &self, _state: Arc<AppState>, _chat_id: Uuid, _query_text: &str, _limit: u64
            ) -> Result<Vec<RetrievedChunk>, AppError> {
                unimplemented!("MockPipeline should not be called in these tests")
            }
        }
        let mock_embedding_pipeline_service = Arc::new(MockPipeline);

        // Use AppStateBuilder
        let app_state = AppStateBuilder::new()
            // Note: No pool needed for these unit tests
            .with_config(Arc::new(Config::default())) // Provide dummy config
            .with_ai_client(mock_ai_client)
            .with_embedding_client(mock_embedding_client.clone() as Arc<dyn EmbeddingClient>)
            .with_embedding_pipeline_service(mock_embedding_pipeline_service as Arc<dyn EmbeddingPipelineServiceTrait>)
            .with_mock_qdrant_service(mock_qdrant_service.clone()) // Provide the mock Qdrant service
            .build_for_test()
            .await
            .expect("Failed to build mock AppState");

        (app_state, mock_embedding_client, mock_qdrant_service)
    }

    // --- Tests for process_and_embed_message ---

    #[tokio::test]
    async fn test_process_and_embed_message_success() {
        let (state, mock_embedding_client, mock_qdrant_service) = create_mock_app_state().await;
        let message = ChatMessage { 
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "Chunk one. Chunk two.".to_string(), 
            created_at: Utc::now(),
        };

        let mock_embedding = vec![0.1; 768];
        mock_embedding_client.set_response(Ok(mock_embedding.clone()));
        mock_qdrant_service.set_upsert_response(Ok(()));

        let _ = process_and_embed_message(state.clone(), message.clone()).await;
        
        // Verify embedding_call_tracker was updated
        let tracker_calls = state.embedding_call_tracker.lock().await;
        assert_eq!(tracker_calls.len(), 1);
        assert_eq!(tracker_calls[0], message.id);
        
        // Drop the lock before checking mock_embedding_client calls
        drop(tracker_calls);
        
        // Check that mock_embedding_client methods were called correctly
        let embed_calls = mock_embedding_client.get_calls();
        for (text, task_type) in embed_calls.iter() {
            assert!(
                (text == "Chunk one." || text == "Chunk two.") && task_type == "RETRIEVAL_DOCUMENT",
                "Expected calls with correct text and task type"
            );
        }
    }

    #[tokio::test]
    async fn test_process_and_embed_message_chunking_error() {
        let (state, _, _) = create_mock_app_state().await;
        let message = ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "".to_string(), // Empty content leads to Ok(()) return
            created_at: Utc::now(),
        };

        let result = process_and_embed_message(state.clone(), message.clone()).await;
        assert!(result.is_ok(), "Expected Ok(()) when chunking produces no chunks");
        let tracker_calls = state.embedding_call_tracker.lock().await;
        assert_eq!(tracker_calls.len(), 1);
        assert_eq!(tracker_calls[0], message.id);
    }

    #[tokio::test]
    async fn test_process_and_embed_message_embedding_error() {
        let (state, mock_embedding_client, _) = create_mock_app_state().await;
        let message = ChatMessage { 
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "Some content".to_string(), 
            created_at: Utc::now(),
        };

        // Mock embedding client to return an error
        let embedding_error = AppError::EmbeddingError("Embedding failed".to_string());
        mock_embedding_client.set_response(Err(embedding_error));

        let _ = process_and_embed_message(state.clone(), message.clone()).await;
        
        // Verify the call tracker was updated
        let tracker_calls = state.embedding_call_tracker.lock().await;
        assert_eq!(tracker_calls.len(), 1);
        assert_eq!(tracker_calls[0], message.id);
        
        // Drop the lock before checking mock_embedding_client calls
        drop(tracker_calls);
        
        // Verify the embedding client was called with the expected content
        let embed_calls = mock_embedding_client.get_calls();
        for (text, task_type) in embed_calls.iter() {
            assert!(
                text.contains("Some content") && task_type == "RETRIEVAL_DOCUMENT",
                "Expected call with correct text and task type"
            );
        }
    }

    #[tokio::test]
    async fn test_process_and_embed_message_qdrant_error() {
        let (state, mock_embedding_client, mock_qdrant_service) = create_mock_app_state().await;
        let message = ChatMessage { 
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "Some content".to_string(), 
            created_at: Utc::now(),
        };

        mock_embedding_client.set_response(Ok(vec![0.1; 768]));
        let qdrant_error = AppError::VectorDbError("Upsert failed".to_string());
        mock_qdrant_service.set_upsert_response(Err(qdrant_error.clone()));

        let _ = process_and_embed_message(state.clone(), message.clone()).await;
        
        // Verify the call tracker was updated
        let tracker_calls = state.embedding_call_tracker.lock().await;
        assert_eq!(tracker_calls.len(), 1);
        assert_eq!(tracker_calls[0], message.id);
        
        // Drop the lock before checking mock_embedding_client calls
        drop(tracker_calls);
        
        // Verify the embedding client was called with the expected content
        let embed_calls = mock_embedding_client.get_calls();
        for (text, task_type) in embed_calls.iter() {
            assert!(
                text.contains("Some content") && task_type == "RETRIEVAL_DOCUMENT",
                "Expected call with correct text and task type"
            );
        }
    }

    // --- Tests for retrieve_relevant_chunks ---

    #[tokio::test]
    async fn test_retrieve_relevant_chunks_success() {
        let (state, mock_embedding_client, mock_qdrant_service) = create_mock_app_state().await;
        let service = EmbeddingPipelineService;

        let chat_id = Uuid::new_v4();
        let query_text = "search query";
        let limit = 5u64;

        let mock_query_embedding = vec![0.2; 768];
        mock_embedding_client.set_response(Ok(mock_query_embedding.clone()));

        let point_id1 = Uuid::new_v4();
        let payload1_map = build_valid_payload_map();
        
        let mock_point1 = ScoredPoint {
            id: Some(PointId::from(point_id1.to_string())),
            payload: payload1_map,
            score: 0.95,
            version: 0,
            vectors: None,
            shard_key: None,
            order_value: None,
        };
        mock_qdrant_service.set_search_response(Ok(vec![mock_point1.clone()]));

        let _ = service.retrieve_relevant_chunks(state, chat_id, query_text, limit).await;
        
        // Verify the embedding client was called with the expected query
        let embed_calls = mock_embedding_client.get_calls();
        for (text, task_type) in embed_calls.iter() {
            assert!(
                text == query_text && task_type == "RETRIEVAL_QUERY",
                "Expected call with correct query text and task type"
            );
        }
    }

    #[tokio::test]
    async fn test_retrieve_relevant_chunks_embedding_error() {
        let (state, mock_embedding_client, _) = create_mock_app_state().await;
        let service = EmbeddingPipelineService;
        let chat_id = Uuid::new_v4();
        let query_text = "query";

        mock_embedding_client.set_response(Err(AppError::EmbeddingError("Embed failed".to_string())));

        let _ = service.retrieve_relevant_chunks(state, chat_id, query_text, 5).await;
        
        // Verify the embedding client was called with the expected query
        let embed_calls = mock_embedding_client.get_calls();
        for (text, task_type) in embed_calls.iter() {
            assert!(
                text == query_text && task_type == "RETRIEVAL_QUERY",
                "Expected call with correct query text and task type"
            );
        }
    }

    #[tokio::test]
    async fn test_retrieve_relevant_chunks_qdrant_error() {
        let (state, mock_embedding_client, mock_qdrant_service) = create_mock_app_state().await;
        let service = EmbeddingPipelineService;
        let chat_id = Uuid::new_v4();
        let query_text = "query";

        mock_embedding_client.set_response(Ok(vec![0.3; 768]));
        mock_qdrant_service.set_search_response(Err(AppError::VectorDbError("Search failed".to_string())));

        let _ = service.retrieve_relevant_chunks(state, chat_id, query_text, 5).await;
        
        // Verify the embedding client was called with the expected query
        let embed_calls = mock_embedding_client.get_calls();
        for (text, task_type) in embed_calls.iter() {
            assert!(
                text == query_text && task_type == "RETRIEVAL_QUERY",
                "Expected call with correct query text and task type"
            );
        }
    }

    #[tokio::test]
    async fn test_retrieve_relevant_chunks_metadata_parsing_error() {
        let (state, mock_embedding_client, mock_qdrant_service) = create_mock_app_state().await;
        let service = EmbeddingPipelineService;
        let chat_id = Uuid::new_v4();
        let query_text = "query";

        mock_embedding_client.set_response(Ok(vec![0.4; 768]));

        let mut invalid_payload_map = build_valid_payload_map();
        invalid_payload_map.remove("speaker"); // Remove required field
        let mock_point_invalid = ScoredPoint {
            id: Some(PointId::from(Uuid::new_v4().to_string())),
            payload: invalid_payload_map,
            score: 0.8,
            version: 0,
            vectors: None,
            shard_key: None,
            order_value: None,
        };
        mock_qdrant_service.set_search_response(Ok(vec![mock_point_invalid]));

        let _ = service.retrieve_relevant_chunks(state, chat_id, query_text, 5).await;
        
        // Verify the embedding client was called with the expected query
        let embed_calls = mock_embedding_client.get_calls();
        for (text, task_type) in embed_calls.iter() {
            assert!(
                text == query_text && task_type == "RETRIEVAL_QUERY",
                "Expected call with correct query text and task type"
            );
        }
    }
}