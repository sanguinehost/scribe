// backend/src/services/embedding_pipeline.rs

use crate::errors::AppError;
use crate::llm::EmbeddingClient;
use crate::models::chats::ChatMessage;
use crate::state::AppState;
use crate::text_processing::chunking::{chunk_text, ChunkConfig}; // Import ChunkConfig and ChunkingMetric
use crate::vector_db::qdrant_client::{create_qdrant_point, QdrantClientServiceTrait};

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

// This function is now moved into the EmbeddingPipelineService impl below


// --- Service Trait and Implementation ---

#[async_trait]
pub trait EmbeddingPipelineServiceTrait: Send + Sync {
    /// Processes a single chat message: chunks, embeds, and stores it.
    async fn process_and_embed_message(
        &self,
        state: Arc<AppState>, // Pass state for access to clients
        message: ChatMessage,
    ) -> Result<(), AppError>;

    /// Retrieves relevant chunks based on a query.
    async fn retrieve_relevant_chunks(
        &self,
        state: Arc<AppState>, // Pass state for now, could be refactored later
        chat_id: Uuid,
        query_text: &str,
        limit: u64,
    ) -> Result<Vec<RetrievedChunk>, AppError>;
}

pub struct EmbeddingPipelineService {
    chunk_config: ChunkConfig, // Store chunking configuration
}

impl EmbeddingPipelineService {
    /// Creates a new EmbeddingPipelineService.
    pub fn new(chunk_config: ChunkConfig) -> Self {
        Self { chunk_config }
    }
}

// Implement the trait for EmbeddingPipelineService
#[async_trait]
impl EmbeddingPipelineServiceTrait for EmbeddingPipelineService {
    #[instrument(skip_all, fields(message_id = %message.id, session_id = %message.session_id))]
    async fn process_and_embed_message(
        &self,
        state: Arc<AppState>, // Get clients from state
        message: ChatMessage,
    ) -> Result<(), AppError> {
        info!("Starting embedding process for message");
        let embedding_client = state.embedding_client.clone();
        let qdrant_service = state.qdrant_service.clone();

        // 1. Chunk the message content using the stored config
        // Determine source_id for the chunk_text function (using message id)
        let source_id = Some(message.id.to_string());
        // Initial offset is 0 as we process one message at a time here
        let initial_offset = 0;

        let chunks = match chunk_text(
            &message.content,
            &self.chunk_config, // Use stored config
            source_id,
            initial_offset,
        ) {
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
            let task_type = "RETRIEVAL_DOCUMENT";
            let embedding_vector = match embedding_client
                .embed_content(&chunk.content, task_type)
                .await
            {
                Ok(vector) => vector,
                Err(e) => {
                    error!(error = %e, chunk_index = index, "Failed to get embedding for chunk");
                    continue; // Skip this chunk for now
                }
            };

            // 2b. Prepare metadata
            let speaker_str = format!("{:?}", message.message_type);
            let metadata = EmbeddingMetadata {
                message_id: message.id,
                session_id: message.session_id,
                speaker: speaker_str,
                timestamp: message.created_at,
                text: chunk.content.clone(), // Store original chunk text from the TextChunk struct
            };

            // 2c. Create Qdrant point
            let point_id = Uuid::new_v4(); // Unique ID per chunk point
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
                return Err(e);
            }
            info!("Successfully upserted points for message");
        } else {
            info!("No valid points generated for upserting.");
        }

        Ok(())
    }

    // retrieve_relevant_chunks implementation remains the same
    async fn retrieve_relevant_chunks(
        &self,
        state: Arc<AppState>,
        chat_id: Uuid, // Renamed from session_id for clarity
        query_text: &str,
        limit: u64,
    ) -> Result<Vec<RetrievedChunk>, AppError> {
        // Call the standalone function (or move its logic here too if preferred)
        retrieve_relevant_chunks_standalone( // Renamed standalone function
            state.qdrant_service.clone(),
            state.embedding_client.clone(),
            chat_id, // Pass chat_id
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

/// Standalone function for retrieving relevant text chunks.
/// Kept separate for potential reuse or testing isolation.
#[instrument(skip_all, fields(session_id = %session_id, query_len = query_text.len(), limit))]
async fn retrieve_relevant_chunks_standalone( // Renamed
    qdrant_service: Arc<dyn QdrantClientServiceTrait>,
    embedding_client: Arc<dyn EmbeddingClient>,
    session_id: Uuid, // Keep session_id name here as it's used for filtering
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
            e
        })?;

    // 2. Construct filter for session_id
    let filter = Filter {
        must: vec![Condition {
            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                key: "session_id".to_string(),
                r#match: Some(Match {
                    match_value: Some(MatchValue::Keyword(session_id.to_string())),
                }),
                range: None,
                geo_bounding_box: None,
                geo_radius: None,
                geo_polygon: None,
                values_count: None,
                datetime_range: None,
                is_empty: None,
                is_null: None,
            })),
        }],
        should: vec![],
        must_not: vec![],
        min_should: None,
    };

    // 3. Search Qdrant
    let search_results = qdrant_service
        .search_points(query_embedding, limit, Some(filter))
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to search Qdrant for relevant chunks");
            e
        })?;

    // 4. Convert search results to RetrievedChunk
    let mut retrieved_chunks = Vec::new();
    for scored_point in search_results {
        match EmbeddingMetadata::try_from(scored_point.payload) {
            Ok(metadata) => retrieved_chunks.push(RetrievedChunk {
                score: scored_point.score,
                text: metadata.text.clone(),
                metadata,
            }),
            Err(e) => {
                let point_id_str = scored_point
                    .id
                    .map(|id| format!("{:?}", id))
                    .unwrap_or_else(|| "N/A".to_string());
                error!(error = %e, point_id = %point_id_str, "Failed to parse metadata from Qdrant point payload");
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
    use crate::test_helpers::{
        MockEmbeddingClient, MockQdrantClientService,
    };
    use crate::vector_db::qdrant_client::ScoredPoint;
    use std::sync::Arc;
    use qdrant_client::qdrant::Value;
    use chrono::Utc;
    use std::collections::HashMap;
    use uuid::Uuid;
    use crate::llm::EmbeddingClient;
    use crate::text_processing::chunking::{ChunkConfig, ChunkingMetric}; // Import test deps

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

    // --- Tests for process_and_embed_message (now a method) ---

    // Helper to create a default AppState for tests
    fn create_test_app_state(
        embedding_client: Arc<dyn EmbeddingClient + Send + Sync>,
        qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync>,
    ) -> Arc<AppState> {
        // Create minimal config for AppState
        let config = Arc::new(crate::config::Config {
            database_url: None,
            gemini_api_key: None,
            port: 8080,
            cookie_signing_key: Some("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_string()), // Example key
            session_cookie_secure: false,
            qdrant_url: Some("http://localhost:6333".to_string()),
            qdrant_collection_name: "test_collection".to_string(),
            embedding_dimension: 768,
            chunking_metric: "char".to_string(), // Default for test state
            chunking_max_size: 500,
            chunking_overlap: 50,
            qdrant_distance_metric: "Cosine".to_string(), // Added default for test
            qdrant_on_disk: None,                       // Added default for test
        });
        // Create dummy pool and AI client (not used directly by process_and_embed_message)
        let pool = crate::test_helpers::create_test_pool();
        let ai_client = Arc::new(crate::test_helpers::MockAiClient::new());
        // Create dummy embedding pipeline service (not used directly by process_and_embed_message)
        let dummy_chunk_config = ChunkConfig {
             metric: ChunkingMetric::Char,
             max_size: 100,
             overlap: 10,
        };
        let embedding_pipeline_service = Arc::new(EmbeddingPipelineService::new(dummy_chunk_config));


        Arc::new(AppState::new(
            pool,
            config,
            ai_client,
            embedding_client,
            qdrant_service,
            embedding_pipeline_service, // Pass the dummy service
        ))
    }

     // Helper to create a default ChunkConfig for tests
     fn default_test_chunk_config() -> ChunkConfig {
         ChunkConfig {
             metric: ChunkingMetric::Char, // Default to char for simplicity in some tests
             max_size: 500,
             overlap: 50,
         }
     }


    #[tokio::test]
    async fn test_process_and_embed_message_method_success() {
        let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service = Arc::new(MockQdrantClientService::new());
        let test_state = create_test_app_state(mock_embedding_client.clone(), mock_qdrant_service.clone());

        // Create the service instance with test config
        let service = EmbeddingPipelineService::new(default_test_chunk_config());

        let message = ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "Chunk one. Chunk two.".to_string(), // Will be one chunk with default config
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
        };

        let mock_embedding = vec![0.1; 768];
        mock_embedding_client.set_response(Ok(mock_embedding.clone()));
        mock_qdrant_service.set_upsert_response(Ok(()));

        // Call the method on the service instance
        let result = service.process_and_embed_message(test_state, message.clone()).await;

        assert!(result.is_ok(), "process_and_embed_message failed: {:?}", result.err());

        let embed_calls = mock_embedding_client.get_calls();
        assert_eq!(embed_calls.len(), 1, "Expected 1 embedding call");
        if !embed_calls.is_empty() {
            assert_eq!(embed_calls[0].0, message.content); // Content matches
            assert_eq!(embed_calls[0].1, "RETRIEVAL_DOCUMENT");
        }

        assert_eq!(mock_qdrant_service.get_upsert_call_count(), 1, "Expected 1 upsert call");
        if let Some(points) = mock_qdrant_service.get_last_upsert_points() {
            assert_eq!(points.len(), 1, "Expected 1 point to be upserted");
            // Check metadata in the point
            if let Some(point) = points.first() {
                let metadata = EmbeddingMetadata::try_from(point.payload.clone()).expect("Payload should be valid metadata");
                assert_eq!(metadata.message_id, message.id);
                assert_eq!(metadata.session_id, message.session_id);
                assert_eq!(metadata.speaker, "User"); // Check speaker format
                assert_eq!(metadata.text, message.content); // Check stored text
            } else {
                panic!("Upserted point has no payload");
            }
        }
    }

     #[tokio::test]
     async fn test_process_and_embed_message_method_uses_service_config() {
         let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
         let mock_qdrant_service = Arc::new(MockQdrantClientService::new());
         let test_state = create_test_app_state(mock_embedding_client.clone(), mock_qdrant_service.clone());

         // Create a config that WILL cause splitting
         let specific_chunk_config = ChunkConfig {
             metric: ChunkingMetric::Char,
             max_size: 10, // Force split
             overlap: 2,
         };
         let service = EmbeddingPipelineService::new(specific_chunk_config);

         let message = ChatMessage {
             id: Uuid::new_v4(),
             session_id: Uuid::new_v4(),
             message_type: MessageRole::User,
             content: "This message is definitely longer than ten characters.".to_string(),
             created_at: Utc::now(),
             user_id: Uuid::new_v4(),
         };

         let mock_embedding = vec![0.2; 768];
         mock_embedding_client.set_response(Ok(mock_embedding.clone())); // Need multiple responses if called multiple times
         mock_qdrant_service.set_upsert_response(Ok(()));

         let result = service.process_and_embed_message(test_state, message.clone()).await;
         assert!(result.is_ok());

         // Assert that chunking happened (more than 1 embedding call)
         let embed_calls = mock_embedding_client.get_calls();
         assert!(embed_calls.len() > 1, "Expected more than 1 embedding call due to chunking");

         // Assert that upsert was called (likely still 1 batch call)
         assert_eq!(mock_qdrant_service.get_upsert_call_count(), 1);
         if let Some(points) = mock_qdrant_service.get_last_upsert_points() {
             assert!(points.len() > 1, "Expected more than 1 point to be upserted");
             // Check first chunk text (approximate)
             if let Some(first_point) = points.first() {
                 let text = first_point.payload["text"].as_str().map_or("", |s| s);
                 assert!(text.starts_with("This messa"));
             }
         }
     }


    #[tokio::test]
    async fn test_process_and_embed_message_method_empty_content() {
        let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service = Arc::new(MockQdrantClientService::new());
        let test_state = create_test_app_state(mock_embedding_client.clone(), mock_qdrant_service.clone());
        let service = EmbeddingPipelineService::new(default_test_chunk_config());

        let message = ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "   ".to_string(), // Empty after trim
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
        };

        let result = service.process_and_embed_message(test_state, message.clone()).await;
        assert!(result.is_ok(), "Expected Ok(()) for empty content");

        assert_eq!(mock_embedding_client.get_calls().len(), 0);
        assert_eq!(mock_qdrant_service.get_upsert_call_count(), 0);
    }

    #[tokio::test]
    async fn test_process_and_embed_message_method_embedding_error() {
        let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service = Arc::new(MockQdrantClientService::new());
        let test_state = create_test_app_state(mock_embedding_client.clone(), mock_qdrant_service.clone());
        let service = EmbeddingPipelineService::new(default_test_chunk_config());

        let message = ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "Some content".to_string(),
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
        };

        let embedding_error = AppError::EmbeddingError("Embedding failed".to_string());
        mock_embedding_client.set_response(Err(embedding_error));
        mock_qdrant_service.set_upsert_response(Ok(()));

        let result = service.process_and_embed_message(test_state, message.clone()).await;
        assert!(result.is_ok(), "Expected Ok(()) even on embedding error"); // Internal error is logged, doesn't fail the op

        assert_eq!(mock_embedding_client.get_calls().len(), 1);
        assert_eq!(mock_qdrant_service.get_upsert_call_count(), 0); // Upsert skipped
    }

    #[tokio::test]
    async fn test_process_and_embed_message_method_qdrant_error() {
        let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service = Arc::new(MockQdrantClientService::new());
        let test_state = create_test_app_state(mock_embedding_client.clone(), mock_qdrant_service.clone());
        let service = EmbeddingPipelineService::new(default_test_chunk_config());

        let message = ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "Some content".to_string(),
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
        };

        mock_embedding_client.set_response(Ok(vec![0.1; 768]));
        let qdrant_error = AppError::VectorDbError("Upsert failed".to_string());
        mock_qdrant_service.set_upsert_response(Err(qdrant_error.clone()));

        let result = service.process_and_embed_message(test_state, message.clone()).await;
        assert!(result.is_err(), "Expected an error due to Qdrant failure");
        match result.err().unwrap() {
            AppError::VectorDbError(msg) => assert!(msg.contains("Upsert failed")),
            _ => panic!("Expected VectorDbError"),
        }

        assert_eq!(mock_embedding_client.get_calls().len(), 1);
        assert_eq!(mock_qdrant_service.get_upsert_call_count(), 1);
    }


    // --- Tests for retrieve_relevant_chunks (now uses standalone) ---

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
         payload.insert("session_id".to_string(), Value::from(session_id.to_string()));
         payload.insert("message_id".to_string(), Value::from(message_id.to_string()));
         payload.insert("speaker".to_string(), Value::from(speaker.to_string()));
         payload.insert("timestamp".to_string(), Value::from(timestamp.to_rfc3339()));
         payload.insert("text".to_string(), Value::from(text.to_string()));

         ScoredPoint {
             id: Some(qdrant_client::qdrant::PointId {
                 point_id_options: Some(qdrant_client::qdrant::point_id::PointIdOptions::Uuid(id_uuid.to_string())),
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
    async fn test_retrieve_relevant_chunks_method_success() {
        let mock_embedding_client = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service = Arc::new(MockQdrantClientService::new());
        let test_state = create_test_app_state(mock_embedding_client.clone(), mock_qdrant_service.clone());
        let service = EmbeddingPipelineService::new(default_test_chunk_config()); // Config not used by retrieve

        let query_text = "What is the meaning of life?";
        let chat_id = Uuid::new_v4();
        let limit = 3;
        let mock_query_embedding = vec![0.5; 768];

        mock_embedding_client.set_response(Ok(mock_query_embedding.clone()));

        let point_id1 = Uuid::new_v4();
        let point_id2 = Uuid::new_v4();
        let mock_timestamp = Utc::now();
        let mock_scored_points = vec![
            create_mock_scored_point(point_id1, 0.95, chat_id, Uuid::new_v4(), "User", mock_timestamp, "Chunk 1 text"),
            create_mock_scored_point(point_id2, 0.88, chat_id, Uuid::new_v4(), "Assistant", mock_timestamp, "Chunk 2 text"),
        ];
        mock_qdrant_service.set_search_response(Ok(mock_scored_points.clone()));

        // Call the method on the service instance
        let result = service.retrieve_relevant_chunks(test_state, chat_id, query_text, limit).await;

        assert!(result.is_ok(), "retrieve_relevant_chunks failed: {:?}", result.err());
        let retrieved_chunks = result.unwrap();
        assert_eq!(retrieved_chunks.len(), 2);
        assert_eq!(retrieved_chunks[0].text, "Chunk 1 text");
        assert_eq!(retrieved_chunks[1].text, "Chunk 2 text");
        assert_eq!(mock_embedding_client.get_calls().len(), 1);
        assert_eq!(mock_qdrant_service.get_search_call_count(), 1);
        // Check filter used in search
        if let Some((_, _, filter)) = mock_qdrant_service.get_last_search_params() {
            if let Some(filter) = filter {
                assert_eq!(filter.must.len(), 1);
                if let Some(qdrant_client::qdrant::condition::ConditionOneOf::Field(field_cond)) = &filter.must[0].condition_one_of {
                    assert_eq!(field_cond.key, "session_id");
                    assert_eq!(
                        field_cond.r#match.as_ref().unwrap().match_value,
                        Some(MatchValue::Keyword(chat_id.to_string()))
                    );
                } else {
                    panic!("Filter condition was not a FieldCondition");
                }
            } else {
                panic!("No filter was captured by the mock");
            }
        } else {
            panic!("No search parameters were captured by the mock");
        }
    }

    // Other retrieve tests (embedding error, qdrant error, metadata error)
    // would be similar, calling the service method but testing the underlying
    // standalone function's error handling via the mocks. No need to repeat them all here
    // unless the service method added significantly different logic.
}
