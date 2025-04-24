// backend/src/services/embedding_pipeline.rs

use crate::errors::AppError;
// use crate::config::Config; // Removed unused import
// Removed unused: EmbeddingClient, QdrantClientService, PointsSelectorOneOf, SelectorOptions, WithPayloadSelector
use crate::models::chats::ChatMessage; // Assuming ChatMessage model exists
use crate::state::AppState; // To access clients
use crate::text_processing::chunking::chunk_text;
use crate::vector_db::qdrant_client::create_qdrant_point; // Keep create_qdrant_point
use qdrant_client::qdrant::{Filter, Condition, Value}; // Keep Filter, Condition; Add Value; Remove ScoredPoint
use std::collections::HashMap;
use std::convert::TryFrom;
// Removed FieldCondition, Match, MatchValue as filter construction changed
use async_trait::async_trait; // Add async_trait
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
impl TryFrom<HashMap<String, Value>> for EmbeddingMetadata {
    type Error = AppError; // Use our standard AppError for conversion errors

    fn try_from(payload: HashMap<String, Value>) -> Result<Self, Self::Error> {
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

// --- RAG Retrieval Logic ---

// Represents a retrieved chunk with its score and metadata
#[derive(Debug, Clone, serde::Deserialize)] // Deserialize needed if parsing payload
pub struct RetrievedChunk {
    pub score: f32,
    pub text: String,
    pub metadata: EmbeddingMetadata, // Reuse the metadata struct
}

#[async_trait]
impl EmbeddingPipelineServiceTrait for EmbeddingPipelineService {
    #[instrument(skip(self, state, query_text), fields(chat_id = %chat_id, limit), err)]
    async fn retrieve_relevant_chunks(
        &self,
        state: Arc<AppState>,
    chat_id: Uuid,
    query_text: &str,
    limit: u64,
) -> Result<Vec<RetrievedChunk>, AppError> {
    info!("Retrieving relevant chunks for query");

    // 1. Get embedding for the query text
    // Use RETRIEVAL_QUERY task type for similarity search queries
    let task_type = "RETRIEVAL_QUERY";
    let query_embedding = state
        .embedding_client
        .embed_content(query_text, task_type)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to get embedding for RAG query");
            e // Propagate the error
        })?;

    // 2. Create a filter to scope search to the specific chat_id
    // 2. Create a filter to scope search to the specific session_id using the new API
    let filter = Filter::must([
        // Use Condition::matches for keyword matching
        Condition::matches("session_id", chat_id.to_string()),
    ]);

    // 3. Search Qdrant
    let search_results = state
        .qdrant_service
        .search_points(query_embedding, limit, Some(filter))
        .await?;

    // 4. Process results: Extract text and metadata from payload
    let mut retrieved_chunks = Vec::new();
    for scored_point in search_results {
        // Payload is now directly HashMap<String, Value>, not Option<HashMap<...>>
        // Check if payload is empty before attempting conversion
        if !scored_point.payload.is_empty() {
            // Attempt conversion directly from the HashMap payload
            // Use explicit TryInto trait form as suggested by compiler E0107
            match std::convert::TryInto::<EmbeddingMetadata>::try_into(scored_point.payload) {
                Ok(metadata) => {
                     retrieved_chunks.push(RetrievedChunk {
                        score: scored_point.score,
                        text: metadata.text.clone(), // Text is stored in metadata
                        metadata,
                    });
                }
                Err(e) => {
                    error!(error = %e, point_id = ?scored_point.id, "Failed to deserialize payload from Qdrant search result");
                    // Skip this point if payload is invalid
                    continue;
                }
            }
        } else {
             warn!(point_id = ?scored_point.id, "Qdrant search result has empty payload");
        }
    }

    info!("Retrieved {} relevant chunks", retrieved_chunks.len());
    Ok(retrieved_chunks)
}
}


// TODO: Add function/mechanism to trigger `process_and_embed_message` asynchronously
// e.g., call this using tokio::spawn from ChatService after saving a message.

// --- Unit Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use qdrant_client::qdrant::{Value, value::Kind};
    use std::collections::HashMap;
    use uuid::Uuid;
    use chrono::Utc; // Keep Utc

    // Helper to create a Value::StringValue
    fn string_value(s: &str) -> Value {
        Value { kind: Some(Kind::StringValue(s.to_string())) }
    }

     // Helper to create a Value::IntegerValue
    fn integer_value(i: i64) -> Value {
         Value { kind: Some(Kind::IntegerValue(i)) }
    }

    // Helper to build a valid payload HashMap for testing
    fn build_valid_payload() -> HashMap<String, Value> {
        let message_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let timestamp = Utc::now().to_rfc3339();

        HashMap::from([
            ("message_id".to_string(), string_value(&message_id.to_string())),
            ("session_id".to_string(), string_value(&session_id.to_string())),
            ("speaker".to_string(), string_value("User")),
            ("timestamp".to_string(), string_value(&timestamp)),
            ("text".to_string(), string_value("Sample chunk text")),
        ])
    }

    #[test]
    fn test_embedding_metadata_try_from_valid_payload() {
        let payload = build_valid_payload();
        let result = EmbeddingMetadata::try_from(payload.clone()); // Clone for assertion checks
        assert!(result.is_ok());
        let metadata = result.unwrap();

        // Basic checks
        assert_eq!(metadata.speaker, "User");
        assert_eq!(metadata.text, "Sample chunk text");

        // Extract string values correctly using pattern matching
        let message_id_str = match payload["message_id"].kind.as_ref().unwrap() {
            Kind::StringValue(s) => s.as_str(),
            _ => panic!("Expected StringValue for message_id"),
        };
        let session_id_str = match payload["session_id"].kind.as_ref().unwrap() {
            Kind::StringValue(s) => s.as_str(),
            _ => panic!("Expected StringValue for session_id"),
        };
        let timestamp_str = match payload["timestamp"].kind.as_ref().unwrap() {
            Kind::StringValue(s) => s.as_str(),
            _ => panic!("Expected StringValue for timestamp"),
        };

        // Compare UUIDs and timestamps by parsing back from the extracted strings
        assert_eq!(metadata.message_id, Uuid::parse_str(message_id_str).unwrap());
        assert_eq!(metadata.session_id, Uuid::parse_str(session_id_str).unwrap());
        let expected_ts = chrono::DateTime::parse_from_rfc3339(timestamp_str).unwrap().with_timezone(&Utc);
        assert_eq!(metadata.timestamp, expected_ts);
    }

    #[test]
    fn test_embedding_metadata_try_from_missing_field() {
        let mut payload = build_valid_payload();
        payload.remove("session_id"); // Remove a required field

        let result = EmbeddingMetadata::try_from(payload);
        assert!(result.is_err());
        match result.err().unwrap() {
            AppError::SerializationError(msg) => {
                assert!(msg.contains("Missing or invalid 'session_id'"));
            }
            _ => panic!("Expected SerializationError due to missing field"),
        }
    }

    #[test]
    fn test_embedding_metadata_try_from_invalid_uuid_format() {
        let mut payload = build_valid_payload();
        payload.insert("message_id".to_string(), string_value("not-a-valid-uuid")); // Invalid format

        let result = EmbeddingMetadata::try_from(payload);
        assert!(result.is_err());
         match result.err().unwrap() {
            AppError::SerializationError(msg) => {
                assert!(msg.contains("Failed to parse 'message_id' as UUID"));
            }
            _ => panic!("Expected SerializationError due to invalid UUID format"),
        }
    }

     #[test]
    fn test_embedding_metadata_try_from_invalid_timestamp_format() {
        let mut payload = build_valid_payload();
         payload.insert("timestamp".to_string(), string_value("invalid-date-format")); // Invalid format

        let result = EmbeddingMetadata::try_from(payload);
        assert!(result.is_err());
         match result.err().unwrap() {
            AppError::SerializationError(msg) => {
                assert!(msg.contains("Failed to parse 'timestamp'"));
            }
            _ => panic!("Expected SerializationError due to invalid timestamp format"),
        }
    }

     #[test]
    fn test_embedding_metadata_try_from_wrong_field_type() {
        let mut payload = build_valid_payload();
        // Insert 'speaker' as an integer instead of a string
         payload.insert("speaker".to_string(), integer_value(123));

        let result = EmbeddingMetadata::try_from(payload);
        assert!(result.is_err());
         match result.err().unwrap() {
            AppError::SerializationError(msg) => {
                 // The error message might vary slightly depending on how Option::and_then unwraps
                assert!(msg.contains("'speaker'"));
                // We expect it to fail because we expect a StringValue but get an Integer value
            }
            _ => panic!("Expected SerializationError due to wrong field type"),
        }
    }

     #[test]
    fn test_embedding_metadata_try_from_empty_payload() {
        let payload: HashMap<String, Value> = HashMap::new();
        let result = EmbeddingMetadata::try_from(payload);
        assert!(result.is_err());
        // Expect error because required fields are missing
         match result.err().unwrap() {
            AppError::SerializationError(msg) => {
                assert!(msg.contains("Missing or invalid")); // Should complain about the first field it checks
            }
            _ => panic!("Expected SerializationError due to empty payload"),
        }
    }

    // TODO: Add Integration tests later for:
    // - process_and_embed_message (requires mocks or live services)
    // - retrieve_relevant_chunks (requires mocks or live services)
}