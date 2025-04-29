// backend/src/services/embedding_pipeline.rs

use crate::errors::AppError;
use crate::llm::EmbeddingClient;
use crate::models::chats::ChatMessage;
use crate::state::AppState;
use crate::text_processing::chunking::chunk_text;
use crate::vector_db::qdrant_client::{QdrantClientServiceTrait, create_qdrant_point};

use async_trait::async_trait;
use qdrant_client::qdrant::condition::ConditionOneOf;
use qdrant_client::qdrant::r#match::MatchValue;
use qdrant_client::qdrant::{Condition, FieldCondition, Filter, Match, Value as QdrantValue};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::Arc;
use tracing::{error, info, instrument, warn};
use uuid::Uuid;

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
            .ok_or_else(|| {
                AppError::SerializationError(
                    "Missing or invalid 'message_id' in payload".to_string(),
                )
            })?;
        let message_id = Uuid::parse_str(message_id_str).map_err(|e| {
            AppError::SerializationError(format!("Failed to parse 'message_id' as UUID: {}", e))
        })?;

        let session_id_str = payload
            .get("session_id")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or_else(|| {
                AppError::SerializationError(
                    "Missing or invalid 'session_id' in payload".to_string(),
                )
            })?;
        let session_id = Uuid::parse_str(session_id_str).map_err(|e| {
            AppError::SerializationError(format!("Failed to parse 'session_id' as UUID: {}", e))
        })?;

        let speaker = payload
            .get("speaker")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                AppError::SerializationError("Missing or invalid 'speaker' in payload".to_string())
            })?;

        let timestamp_str = payload
            .get("timestamp")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or_else(|| {
                AppError::SerializationError(
                    "Missing or invalid 'timestamp' in payload".to_string(),
                )
            })?;
        let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp_str)
            .map_err(|e| {
                AppError::SerializationError(format!("Failed to parse 'timestamp': {}", e))
            })
            .map(|dt| dt.with_timezone(&chrono::Utc))?;

        let text = payload
            .get("text")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                AppError::SerializationError("Missing or invalid 'text' in payload".to_string())
            })?;

        Ok(EmbeddingMetadata {
            message_id,
            session_id,
            speaker,
            timestamp,
            text,
        })
    }
}

#[instrument(skip_all, fields(message_id = %message.id, session_id = %message.session_id))]
pub async fn process_and_embed_message(
    embedding_client: Arc<dyn EmbeddingClient + Send + Sync>,
    qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync>,
    message: ChatMessage,
) -> Result<(), AppError> {
    info!("Starting embedding process for message");

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
            return Err(e);
        }
    };
    info!("Message content split into {} chunks", chunks.len());

    let mut points_to_upsert = Vec::new();

    // 2. Process each chunk
    for (index, chunk) in chunks.into_iter().enumerate() {
        // 2a. Get embedding
        // TODO: Determine the correct task_type for Gemini embedding API
        // Common types: RETRIEVAL_QUERY, RETRIEVAL_DOCUMENT, SEMANTIC_SIMILARITY, CLASSIFICATION, CLUSTERING
        // For storing chat history chunks, RETRIEVAL_DOCUMENT seems appropriate.
        let task_type = "RETRIEVAL_DOCUMENT";
        let embedding_vector = match embedding_client
            .embed_content(&chunk.content, task_type)
            .await
        {
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
            speaker: speaker_str,          // Use formatted message_type
            timestamp: message.created_at, // Assuming created_at field
            text: chunk.content.clone(),   // Store original chunk text
        };

        // 2c. Create Qdrant point
        // Generate a unique ID for each chunk point (e.g., combine message ID and chunk index)
        // Using a new UUID per chunk is simpler for now.
        let point_id = Uuid::new_v4();
        let point = match create_qdrant_point(
            point_id,
            embedding_vector,
            Some(serde_json::to_value(metadata)?),
        ) {
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
        if let Err(e) = qdrant_service.store_points(points_to_upsert).await {
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
        )
        .await
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
        should: vec![],   // Explicitly empty
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
                let point_id_str = scored_point
                    .id
                    .map(|id| format!("{:?}", id))
                    .unwrap_or_else(|| "N/A".to_string());
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
    // Removed unused import: use crate::config::Config;
    use crate::test_helpers::{
        MockEmbeddingClient, MockQdrantClientService, // Removed unused: AppStateBuilder, MockAiClient
    };
    use crate::vector_db::qdrant_client::ScoredPoint; // Import ScoredPoint
    use std::sync::Arc;
    // use tokio::sync::Mutex; // Removed unused import
    // Correct Payload import
    use qdrant_client::qdrant::Value; // Removed unused: PointId
    // Import Payload from correct location
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;
    // Add missing import for tests
    use crate::llm::EmbeddingClient;

    // --- Tests for EmbeddingMetadata TryFrom (already exist) ---
    fn string_value(s: &str) -> Value {
        Value {
            kind: Some(qdrant_client::qdrant::value::Kind::StringValue(
                s.to_string(),
            )),
        }
    }

    fn integer_value(i: i64) -> Value {
        Value {
            kind: Some(qdrant_client::qdrant::value::Kind::IntegerValue(i)),
        }
    }

    // Helper to build a valid payload HashMap<String, Value>
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
        payload.insert("speaker".to_string(), string_value("User"));
        payload.insert(
            "timestamp".to_string(),
            string_value(&Utc::now().to_rfc3339()),
        );
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
            AppError::SerializationError(msg) => assert!(
                msg.contains("Missing or invalid 'speaker'"),
                "Error message mismatch: {}",
                msg
            ),
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
            AppError::SerializationError(msg) => assert!(
                msg.contains("Failed to parse 'message_id'"),
                "Error message mismatch: {}",
                msg
            ),
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
            AppError::SerializationError(msg) => assert!(
                msg.contains("Failed to parse 'timestamp'"),
                "Error message mismatch: {}",
                msg
            ),
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
            AppError::SerializationError(msg) => assert!(
                msg.contains("Missing or invalid 'speaker'"),
                "Error message mismatch: {}",
                msg
            ),
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
            AppError::SerializationError(msg) => assert!(
                msg.contains("Missing or invalid"),
                "Error message mismatch: {}",
                msg
            ),
            _ => panic!("Expected SerializationError"),
        }
    }

    // --- Tests for process_and_embed_message ---

    #[tokio::test]
    async fn test_process_and_embed_message_success() {
        // Create mocks directly
        let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service = Arc::new(MockQdrantClientService::new());

        let message = ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "Chunk one. Chunk two.".to_string(),
            created_at: Utc::now(),
            user_id: Uuid::new_v4(), // Add dummy user_id for test data
        };

        let mock_embedding = vec![0.1; 768]; // Use appropriate dimension
        mock_embedding_client.set_response(Ok(mock_embedding.clone()));
        mock_qdrant_service.set_upsert_response(Ok(()));

        // Call the function directly with mocks
        let result = process_and_embed_message(
            mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
            mock_qdrant_service.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>,
            message.clone(),
        )
        .await;

        assert!(result.is_ok(), "process_and_embed_message failed: {:?}", result.err());

        // Check that mock_embedding_client methods were called correctly
        let embed_calls = mock_embedding_client.get_calls();
        // Correct assertion: The input is treated as one short paragraph -> one chunk
        assert_eq!(embed_calls.len(), 1, "Expected 1 embedding call for the single chunk");
        // Check the content of the single call
        if embed_calls.len() == 1 {
            assert_eq!(embed_calls[0].0, message.content);
            assert_eq!(embed_calls[0].1, "RETRIEVAL_DOCUMENT");
        }

        // Check Qdrant mock was called (with one point)
        assert_eq!(mock_qdrant_service.get_upsert_call_count(), 1, "Expected 1 upsert call");
        // Further assertions on points passed to upsert could be added
        if let Some(points) = mock_qdrant_service.get_last_upsert_points() {
            assert_eq!(points.len(), 1, "Expected 1 point to be upserted");
        }
    }

    #[tokio::test]
    async fn test_process_and_embed_message_chunking_error() {
        // Create mocks directly
        let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service = Arc::new(MockQdrantClientService::new());

        let message = ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "".to_string(), // Empty content leads to Ok(()) return
            created_at: Utc::now(),
            user_id: Uuid::new_v4(), // Add dummy user_id for test data
        };

        // No need to set mock responses as they shouldn't be called

        let result = process_and_embed_message(
            mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
            mock_qdrant_service.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>,
            message.clone(),
        )
        .await;
        assert!(
            result.is_ok(),
            "Expected Ok(()) when chunking produces no chunks"
        );

        // Verify mocks were NOT called
        assert_eq!(mock_embedding_client.get_calls().len(), 0, "Embedding should not be called");
        assert_eq!(mock_qdrant_service.get_upsert_call_count(), 0, "Upsert should not be called");
    }

    #[tokio::test]
    async fn test_process_and_embed_message_embedding_error() {
        // Create mocks directly
        let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service = Arc::new(MockQdrantClientService::new());

        let message = ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "Some content".to_string(),
            created_at: Utc::now(),
            user_id: Uuid::new_v4(), // Add dummy user_id for test data
        };

        // Mock embedding client to return an error
        let embedding_error = AppError::EmbeddingError("Embedding failed".to_string());
        mock_embedding_client.set_response(Err(embedding_error));
        // Mock Qdrant upsert (should not be called)
        mock_qdrant_service.set_upsert_response(Ok(()));

        // Call function directly
        let result = process_and_embed_message(
            mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
            mock_qdrant_service.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>,
            message.clone(),
        )
        .await;

        // Should return Ok even if embedding fails internally
        assert!(result.is_ok(), "Expected Ok(()) even on embedding error, but got: {:?}", result.err());

        // Verify the embedding client was called
        let embed_calls = mock_embedding_client.get_calls();
        assert_eq!(embed_calls.len(), 1, "Expected 1 embedding call");
        assert_eq!(embed_calls[0].0, "Some content");

        // Verify Qdrant was NOT called
        assert_eq!(mock_qdrant_service.get_upsert_call_count(), 0, "Upsert should not be called");
    }

    #[tokio::test]
    async fn test_process_and_embed_message_qdrant_error() {
        // Create mocks directly
        let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service = Arc::new(MockQdrantClientService::new());

        let message = ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "Some content".to_string(),
            created_at: Utc::now(),
            user_id: Uuid::new_v4(), // Add dummy user_id for test data
        };

        // Mock embedding success
        mock_embedding_client.set_response(Ok(vec![0.1; 768]));
        // Mock Qdrant upsert to return an error
        let qdrant_error = AppError::VectorDbError("Upsert failed".to_string());
        mock_qdrant_service.set_upsert_response(Err(qdrant_error.clone()));

        // Call function directly
        let result = process_and_embed_message(
            mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
            mock_qdrant_service.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>,
            message.clone(),
        )
        .await;

        // Expect the Qdrant error to be returned
        assert!(result.is_err(), "Expected an error due to Qdrant failure");
        match result.err().unwrap() {
            AppError::VectorDbError(msg) => assert!(msg.contains("Upsert failed")),
            _ => panic!("Expected VectorDbError"),
        }

        // Verify the embedding client was called
        let embed_calls = mock_embedding_client.get_calls();
        assert_eq!(embed_calls.len(), 1);
        assert_eq!(embed_calls[0].0, "Some content");

        // Verify Qdrant upsert was called
        assert_eq!(mock_qdrant_service.get_upsert_call_count(), 1);
    }

    // --- Tests for retrieve_relevant_chunks ---

    // Helper to create a mock ScoredPoint (assuming it exists or is added)
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
            id: Some(qdrant_client::qdrant::PointId { // Add PointId struct path
                point_id_options: Some(qdrant_client::qdrant::point_id::PointIdOptions::Uuid(id_uuid.to_string())), // Add PointIdOptions path
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
        // Create mocks directly
        let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service = Arc::new(MockQdrantClientService::new());

        let query_text = "What is the meaning of life?";
        let session_id = Uuid::new_v4();
        let limit = 3;
        let mock_query_embedding = vec![0.5; 768]; // Use appropriate dimension

        mock_embedding_client.set_response(Ok(mock_query_embedding.clone()));

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

        // Call the function directly
        let result = retrieve_relevant_chunks(
            mock_qdrant_service.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>,
            mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
            session_id,
            query_text,
            limit,
        )
        .await;

        assert!(result.is_ok(), "retrieve_relevant_chunks failed: {:?}", result.err());
        let retrieved_chunks = result.unwrap();
        assert_eq!(retrieved_chunks.len(), 2);
        assert_eq!(retrieved_chunks[0].text, "Chunk 1 text");
        assert_eq!(retrieved_chunks[1].text, "Chunk 2 text");
        assert_eq!(mock_embedding_client.get_calls().len(), 1, "Expected 1 embedding call");
        assert_eq!(mock_qdrant_service.get_search_call_count(), 1, "Expected 1 search call");
    }

    #[tokio::test]
    async fn test_retrieve_relevant_chunks_embedding_error() {
        // Create mocks directly
        let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service = Arc::new(MockQdrantClientService::new());

        let query_text = "Query causing embedding error";
        let session_id = Uuid::new_v4();
        let limit = 5;

        let embedding_error = AppError::EmbeddingError("Embedding lookup failed".to_string());
        mock_embedding_client.set_response(Err(embedding_error.clone()));

        // Qdrant mock shouldn't be called
        mock_qdrant_service.set_search_response(Ok(vec![]));

        // Call the function directly
        let result = retrieve_relevant_chunks(
            mock_qdrant_service.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>,
            mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
            session_id,
            query_text,
            limit,
        )
        .await;

        assert!(result.is_err(), "Expected error due to embedding failure");
        match result.err().unwrap() {
            AppError::EmbeddingError(msg) => assert!(msg.contains("Embedding lookup failed")),
            _ => panic!("Expected EmbeddingError"),
        }

        assert_eq!(mock_embedding_client.get_calls().len(), 1);
        assert_eq!(mock_qdrant_service.get_search_call_count(), 0, "Search should not be called");
    }

    #[tokio::test]
    async fn test_retrieve_relevant_chunks_qdrant_error() {
        // Create mocks directly
        let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service = Arc::new(MockQdrantClientService::new());

        let query_text = "Query causing Qdrant error";
        let session_id = Uuid::new_v4();
        let limit = 2;
        let mock_query_embedding = vec![0.2; 768];

        mock_embedding_client.set_response(Ok(mock_query_embedding.clone()));
        let qdrant_error = AppError::VectorDbError("Qdrant search failed".to_string());
        mock_qdrant_service.set_search_response(Err(qdrant_error.clone()));

        // Call the function directly
        let result = retrieve_relevant_chunks(
            mock_qdrant_service.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>,
            mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
            session_id,
            query_text,
            limit,
        )
        .await;

        assert!(result.is_err(), "Expected error due to Qdrant failure");
        match result.err().unwrap() {
            AppError::VectorDbError(msg) => assert!(msg.contains("Qdrant search failed")),
            _ => panic!("Expected VectorDbError"),
        }

        assert_eq!(mock_embedding_client.get_calls().len(), 1);
        assert_eq!(mock_qdrant_service.get_search_call_count(), 1);
    }

    #[tokio::test]
    async fn test_retrieve_relevant_chunks_metadata_parsing_error() {
        // Create mocks directly
        let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service = Arc::new(MockQdrantClientService::new());

        let query_text = "Query for bad metadata";
        let session_id = Uuid::new_v4();
        let limit = 3;
        let mock_query_embedding = vec![0.9; 768];

        mock_embedding_client.set_response(Ok(mock_query_embedding.clone()));

        // Create a point with invalid payload (e.g., missing field)
        let mut invalid_payload = create_mock_scored_point(
            Uuid::new_v4(), 0.9, session_id, Uuid::new_v4(), "User", Utc::now(), "Valid text",
        ).payload;
        invalid_payload.remove("timestamp"); // Remove required field

        let mock_invalid_point = ScoredPoint {
            id: Some(qdrant_client::qdrant::PointId { point_id_options: Some(qdrant_client::qdrant::point_id::PointIdOptions::Uuid(Uuid::new_v4().to_string())) }),
            version: 1,
            score: 0.9,
            payload: invalid_payload,
            vectors: None, shard_key: None, order_value: None,
        };
        mock_qdrant_service.set_search_response(Ok(vec![mock_invalid_point]));

        // Call the function directly
        let result = retrieve_relevant_chunks(
            mock_qdrant_service.clone() as Arc<dyn QdrantClientServiceTrait + Send + Sync>,
            mock_embedding_client.clone() as Arc<dyn EmbeddingClient + Send + Sync>,
            session_id,
            query_text,
            limit,
        )
        .await;

        // Expect Ok, but empty chunks because the point was skipped due to parsing error
        assert!(result.is_ok(), "Expected Ok even with metadata errors: {:?}", result.err());
        let retrieved_chunks = result.unwrap();
        assert!(retrieved_chunks.is_empty(), "Expected no chunks due to metadata parsing error");

        assert_eq!(mock_embedding_client.get_calls().len(), 1);
        assert_eq!(mock_qdrant_service.get_search_call_count(), 1);
        // Check logs for error message (cannot assert directly here)
    }
}
