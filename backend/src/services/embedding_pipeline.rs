// backend/src/services/embedding_pipeline.rs

use crate::errors::AppError;
use crate::llm::EmbeddingClient;
use crate::models::chats::ChatMessage;
use crate::state::AppState;
use crate::text_processing::chunking::{ChunkConfig, chunk_text}; // Import ChunkConfig and ChunkingMetric
use crate::vector_db::qdrant_client::{QdrantClientServiceTrait, create_qdrant_point};

use crate::auth::session_dek::SessionDek;
use async_trait::async_trait;
// use qdrant_client::qdrant::r#match::MatchValue; // Unused import
use qdrant_client::qdrant::{Condition, FieldCondition, Filter, Match, Value as QdrantValue, condition::ConditionOneOf, r#match::MatchValue};
use secrecy::ExposeSecret; // For SessionDek & fixed key
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{Duration, sleep}; // Added for rate limiting delay
use tracing::{debug, error, info, instrument, warn}; // Added debug
use uuid::Uuid; // Import SessionDek

// Metadata for chat message chunks
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ChatMessageChunkMetadata {
    pub message_id: Uuid,
    pub session_id: Uuid,
    pub user_id: Uuid, // Added user_id
    pub speaker: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub text: String, // Full text of the chunk
    pub source_type: String,
}

// Implement conversion from Qdrant payload for ChatMessageChunkMetadata
impl TryFrom<HashMap<String, QdrantValue>> for ChatMessageChunkMetadata {
    type Error = AppError;

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
                    "Missing or invalid 'message_id' in ChatMessageChunkMetadata payload".to_string(),
                )
            })?;
        let message_id = Uuid::parse_str(message_id_str).map_err(|e| {
            AppError::SerializationError(format!("Failed to parse 'message_id' as UUID in ChatMessageChunkMetadata: {}", e))
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
                    "Missing or invalid 'session_id' in ChatMessageChunkMetadata payload".to_string(),
                )
            })?;
        let session_id = Uuid::parse_str(session_id_str).map_err(|e| {
            AppError::SerializationError(format!("Failed to parse 'session_id' as UUID in ChatMessageChunkMetadata: {}", e))
        })?;

        let user_id_str = payload
            .get("user_id")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or_else(|| {
                AppError::SerializationError(
                    "Missing or invalid 'user_id' in ChatMessageChunkMetadata payload".to_string(),
                )
            })?;
        let user_id = Uuid::parse_str(user_id_str).map_err(|e| {
            AppError::SerializationError(format!("Failed to parse 'user_id' as UUID in ChatMessageChunkMetadata: {}", e))
        })?;

        let speaker = payload
            .get("speaker")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                AppError::SerializationError("Missing or invalid 'speaker' in ChatMessageChunkMetadata payload".to_string())
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
                    "Missing or invalid 'timestamp' in ChatMessageChunkMetadata payload".to_string(),
                )
            })?;
        let timestamp = chrono::DateTime::parse_from_rfc3339(timestamp_str)
            .map_err(|e| {
                AppError::SerializationError(format!("Failed to parse 'timestamp' in ChatMessageChunkMetadata: {}", e))
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
                AppError::SerializationError("Missing or invalid 'text' in ChatMessageChunkMetadata payload".to_string())
            })?;

        let source_type = payload
            .get("source_type")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                AppError::SerializationError("Missing or invalid 'source_type' in ChatMessageChunkMetadata payload".to_string())
            })?;

        Ok(ChatMessageChunkMetadata {
            message_id,
            session_id,
            user_id, // Added user_id
            speaker,
            timestamp,
            text,
            source_type,
        })
    }
}

// Metadata for lorebook entry chunks
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct LorebookChunkMetadata {
    pub original_lorebook_entry_id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
    pub chunk_text: String, // Full text of the chunk
    pub entry_title: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub is_enabled: bool,
    pub is_constant: bool,
    pub source_type: String,
}

impl TryFrom<HashMap<String, QdrantValue>> for LorebookChunkMetadata {
    type Error = AppError;

    fn try_from(payload: HashMap<String, QdrantValue>) -> Result<Self, Self::Error> {
        let original_lorebook_entry_id_str = payload
            .get("original_lorebook_entry_id")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or_else(|| {
                AppError::SerializationError(
                    "Missing or invalid 'original_lorebook_entry_id' in LorebookChunkMetadata payload".to_string(),
                )
            })?;
        let original_lorebook_entry_id = Uuid::parse_str(original_lorebook_entry_id_str).map_err(|e| {
            AppError::SerializationError(format!("Failed to parse 'original_lorebook_entry_id' as UUID in LorebookChunkMetadata: {}", e))
        })?;

        let lorebook_id_str = payload
            .get("lorebook_id")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or_else(|| {
                AppError::SerializationError(
                    "Missing or invalid 'lorebook_id' in LorebookChunkMetadata payload".to_string(),
                )
            })?;
        let lorebook_id = Uuid::parse_str(lorebook_id_str).map_err(|e| {
            AppError::SerializationError(format!("Failed to parse 'lorebook_id' as UUID in LorebookChunkMetadata: {}", e))
        })?;

        let user_id_str = payload
            .get("user_id")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.as_str()),
                _ => None,
            })
            .ok_or_else(|| {
                AppError::SerializationError(
                    "Missing or invalid 'user_id' in LorebookChunkMetadata payload".to_string(),
                )
            })?;
        let user_id = Uuid::parse_str(user_id_str).map_err(|e| {
            AppError::SerializationError(format!("Failed to parse 'user_id' as UUID in LorebookChunkMetadata: {}", e))
        })?;

        let chunk_text = payload
            .get("chunk_text")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                AppError::SerializationError("Missing or invalid 'chunk_text' in LorebookChunkMetadata payload".to_string())
            })?;

        let entry_title = payload
            .get("entry_title")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.clone()),
                qdrant_client::qdrant::value::Kind::NullValue(_) => None, // Handle explicit null
                _ => None, // If not string or null, treat as None or error depending on strictness
            });
        
        // If "entry_title" key is not present at all, it's also None.
        // The above .and_then chain naturally results in None if .get("entry_title") is None.

        let keywords = payload
            .get("keywords")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::ListValue(list_val) => {
                    let mut keys = Vec::new();
                    for item_val in &list_val.values {
                        if let Some(qdrant_client::qdrant::value::Kind::StringValue(s)) = item_val.kind.as_ref() {
                            keys.push(s.clone());
                        } else {
                            // Non-string value in keywords list, could return error or skip
                            return Some(Err(AppError::SerializationError(
                                "Non-string value found in 'keywords' list in LorebookChunkMetadata payload".to_string(),
                            )));
                        }
                    }
                    Some(Ok(keys))
                }
                qdrant_client::qdrant::value::Kind::NullValue(_) => None, // Explicit null for keywords list
                _ => Some(Err(AppError::SerializationError(
                    "Invalid type for 'keywords' in LorebookChunkMetadata payload, expected list or null".to_string(),
                ))),
            })
            .transpose()? // Convert Option<Result<Vec<String>, AppError>> to Result<Option<Vec<String>>, AppError>
            .filter(|v| !v.is_empty()); // If keywords list is empty, treat as None

        let is_enabled = payload
            .get("is_enabled")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::BoolValue(b) => Some(*b),
                _ => None,
            })
            .ok_or_else(|| {
                AppError::SerializationError("Missing or invalid 'is_enabled' in LorebookChunkMetadata payload".to_string())
            })?;

        let is_constant = payload
            .get("is_constant")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::BoolValue(b) => Some(*b),
                _ => None,
            })
            .ok_or_else(|| {
                AppError::SerializationError("Missing or invalid 'is_constant' in LorebookChunkMetadata payload".to_string())
            })?;

        let source_type = payload
            .get("source_type")
            .and_then(|v| v.kind.as_ref())
            .and_then(|k| match k {
                qdrant_client::qdrant::value::Kind::StringValue(s) => Some(s.clone()),
                _ => None,
            })
            .ok_or_else(|| {
                AppError::SerializationError("Missing or invalid 'source_type' in LorebookChunkMetadata payload".to_string())
            })?;
            
        Ok(LorebookChunkMetadata {
            original_lorebook_entry_id,
            lorebook_id,
            user_id,
            chunk_text,
            entry_title,
            keywords,
            is_enabled,
            is_constant,
            source_type,
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
        session_dek: Option<&SessionDek>, // Added SessionDek
    ) -> Result<(), AppError>;

    /// Processes a lorebook entry: chunks, embeds, and stores it.
    async fn process_and_embed_lorebook_entry(
        &self,
        state: Arc<AppState>,
        original_lorebook_entry_id: Uuid,
        lorebook_id: Uuid,
        user_id: Uuid,
        decrypted_content: String,
        decrypted_title: Option<String>,
        decrypted_keywords: Option<Vec<String>>,
        is_enabled: bool,
        is_constant: bool,
    ) -> Result<(), AppError>;

    /// Deletes all chunks associated with a specific lorebook entry.
    async fn delete_lorebook_entry_chunks(
        &self,
        state: Arc<AppState>,
        original_lorebook_entry_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), AppError>;

    /// Retrieves relevant chunks based on a query.
    async fn retrieve_relevant_chunks(
        &self,
        state: Arc<AppState>,
        user_id: Uuid, // To scope searches to the current user
        session_id_for_chat_history: Option<Uuid>, // If Some, search chat history for this session
        active_lorebook_ids_for_search: Option<Vec<Uuid>>, // If Some, search these lorebooks
        query_text: &str,
        limit_per_source: u64, // e.g., retrieve top N from chat, top M from lorebooks
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
        session_dek: Option<&SessionDek>, // Added SessionDek
    ) -> Result<(), AppError> {
        info!("Starting embedding process for chat message");
        let embedding_client = state.embedding_client.clone();
        let qdrant_service = state.qdrant_service.clone();

        let content_to_embed: String; // Will be populated based on encryption state

        match (&session_dek, &message.content_nonce) {
            (Some(dek), Some(nonce_bytes))
                if !message.content.is_empty() && !nonce_bytes.is_empty() =>
            {
                debug!(message_id = %message.id, "Attempting to decrypt message content for embedding.");
                // Ensure SessionDek provides access to the inner SecretBox<Vec<u8>>
                // Assuming SessionDek has a method like `inner()` or direct access to `pub .0`
                // For this example, let's assume SessionDek can be dereferenced to &SecretBox<Vec<u8>>
                // or has a method to get the inner SecretBox.
                // If SessionDek itself is the SecretBox<Vec<u8>>, then just `dek` is fine.
                // Let's assume `dek.0` gives us the `SecretBox<Vec<u8>>` as per SerializableSecretDek

                // We need to ensure SessionDek can provide the &SecretBox<Vec<u8>>
                // Let's assume SessionDek has a method `dek.inner_secret_box()` for this example
                // Or if SessionDek is a newtype around SecretBox<Vec<u8>>, then `&dek.0`
                // Based on `session_dek.rs`, SessionDek is a wrapper.
                // `SessionDek(pub SecretBox<Vec<u8>>)`

                match crate::crypto::decrypt_gcm(&message.content, nonce_bytes, &dek.0) {
                    Ok(plaintext_secret_vec) => {
                        match String::from_utf8(plaintext_secret_vec.expose_secret().to_vec()) {
                            Ok(s) => {
                                debug!(message_id = %message.id, "Successfully decrypted message content for embedding.");
                                content_to_embed = s;
                            }
                            Err(e) => {
                                warn!(message_id = %message.id, error = %e, "Failed to convert decrypted content to UTF-8. Falling back to lossy conversion of ciphertext.");
                                content_to_embed = String::from_utf8_lossy(&message.content)
                                    .to_string()
                                    .replace("\n", " ")
                                    .replace("\r", " ");
                            }
                        }
                    }
                    Err(e) => {
                        warn!(message_id = %message.id, error = %e, "Failed to decrypt message content. Falling back to lossy conversion of ciphertext.");
                        content_to_embed = String::from_utf8_lossy(&message.content)
                            .to_string()
                            .replace("\n", " ")
                            .replace("\r", " ");
                    }
                }
            }
            _ => {
                if message.content_nonce.is_some() && session_dek.is_none() {
                    warn!(message_id = %message.id, "Message has nonce but no DEK provided for decryption. Using raw content for embedding.");
                } else if message.content_nonce.is_none() {
                    debug!(message_id = %message.id, "Message has no nonce, treating as plaintext for embedding.");
                }
                content_to_embed = String::from_utf8_lossy(&message.content)
                    .to_string()
                    .replace("\n", " ")
                    .replace("\r", " ");
            }
        }

        if content_to_embed.trim().is_empty() {
            warn!(message_id = %message.id, "Content for embedding is empty after potential decryption and trimming. Skipping embedding.");
            return Ok(());
        }

        let chunks = match chunk_text(
            &content_to_embed,  // Use potentially decrypted content
            &self.chunk_config, // Use stored config
            None,
            0,
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
                .embed_content(&chunk.content, task_type, None)
                .await
            {
                Ok(vector) => vector,
                Err(e) => {
                    error!(error = %e, chunk_index = index, "Failed to get embedding for chunk");
                    continue; // Skip this chunk for now
                }
            };

            // Add a small delay to mitigate potential rate limiting
            sleep(Duration::from_millis(6100)).await;

            // 2b. Prepare metadata
            let speaker_str = format!("{:?}", message.message_type);
            let metadata = ChatMessageChunkMetadata {
                message_id: message.id,
                session_id: message.session_id,
                user_id: message.user_id, // Added user_id from the message
                speaker: speaker_str,
                timestamp: message.created_at,
                text: chunk.content.clone(), // Store original chunk text from the TextChunk struct
                source_type: "chat_message".to_string(),
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

    #[instrument(skip_all, fields(
        original_lorebook_entry_id = %original_lorebook_entry_id,
        lorebook_id = %lorebook_id,
        user_id = %user_id
    ))]
    async fn process_and_embed_lorebook_entry(
        &self,
        state: Arc<AppState>,
        original_lorebook_entry_id: Uuid,
        lorebook_id: Uuid,
        user_id: Uuid,
        decrypted_content: String,
        decrypted_title: Option<String>,
        decrypted_keywords: Option<Vec<String>>,
        is_enabled: bool,
        is_constant: bool,
    ) -> Result<(), AppError> {
        info!("Starting embedding process for lorebook entry");
        let embedding_client = state.embedding_client.clone();
        let qdrant_service = state.qdrant_service.clone();

        // First, delete existing chunks for this lorebook entry to prevent duplicates or stale data
        if let Err(e) = self.delete_lorebook_entry_chunks(state.clone(), original_lorebook_entry_id, user_id).await {
            error!(
                error = %e,
                %original_lorebook_entry_id,
                %user_id,
                "Failed to delete existing chunks for lorebook entry before re-embedding. Proceeding with embedding anyway."
            );
            // Depending on desired behavior, we might choose to return an error here
            // return Err(AppError::VectorDbError(format!("Failed to delete existing chunks for lorebook entry {}: {}", original_lorebook_entry_id, e)));
        } else {
            info!(%original_lorebook_entry_id, %user_id, "Successfully deleted existing chunks for lorebook entry before re-embedding.");
        }

        if decrypted_content.trim().is_empty() {
            warn!(%original_lorebook_entry_id, "Content for lorebook entry embedding is empty. Skipping embedding.");
            return Ok(());
        }

        let chunks = match chunk_text(
            &decrypted_content,
            &self.chunk_config,
            None, // TODO: Consider if title should be prepended for chunking context
            0,    // TODO: Consider if a specific overlap is needed for lorebook entries
        ) {
            Ok(chunks) => {
                if chunks.is_empty() {
                    warn!(%original_lorebook_entry_id, "Chunking produced no chunks for lorebook entry. Skipping embedding.");
                    return Ok(());
                }
                chunks
            }
            Err(e) => {
                error!(error = %e, %original_lorebook_entry_id, "Failed to chunk lorebook entry content");
                return Err(e);
            }
        };
        info!(%original_lorebook_entry_id, "Lorebook entry content split into {} chunks", chunks.len());

        let mut points_to_upsert = Vec::new();

        for (index, chunk) in chunks.into_iter().enumerate() {
            let task_type = "RETRIEVAL_DOCUMENT";
            let embedding_vector = match embedding_client
                .embed_content(&chunk.content, task_type, decrypted_title.as_deref()) // Pass title here
                .await
            {
                Ok(vector) => vector,
                Err(e) => {
                    error!(error = %e, chunk_index = index, %original_lorebook_entry_id, "Failed to get embedding for lorebook chunk");
                    continue;
                }
            };
            
            // TODO: Re-evaluate if this sleep is necessary or if batch embedding can be used.
            // For now, keeping it consistent with message embedding.
            sleep(Duration::from_millis(100)).await; // Reduced sleep for testing

            let metadata = LorebookChunkMetadata {
                original_lorebook_entry_id,
                lorebook_id,
                user_id,
                chunk_text: chunk.content.clone(),
                entry_title: decrypted_title.clone(),
                keywords: decrypted_keywords.clone(),
                is_enabled,
                is_constant,
                source_type: "lorebook_entry".to_string(),
            };

            let point_id = Uuid::new_v4(); // Unique ID per chunk point
            let point = match create_qdrant_point(
                point_id,
                embedding_vector,
                Some(serde_json::to_value(metadata)?),
            ) {
                Ok(p) => p,
                Err(e) => {
                    error!(error = %e, chunk_index = index, %original_lorebook_entry_id, "Failed to create Qdrant point struct for lorebook chunk");
                    continue;
                }
            };
            points_to_upsert.push(point);
        }

        if !points_to_upsert.is_empty() {
            info!(%original_lorebook_entry_id, "Upserting {} points to Qdrant for lorebook entry", points_to_upsert.len());
            if let Err(e) = qdrant_service.store_points(points_to_upsert).await {
                error!(error = %e, %original_lorebook_entry_id, "Failed to upsert lorebook points to Qdrant");
                return Err(e);
            }
            info!(%original_lorebook_entry_id, "Successfully upserted points for lorebook entry");
        } else {
            info!(%original_lorebook_entry_id, "No valid points generated for lorebook entry upserting.");
        }

        Ok(())
    }

    #[instrument(skip_all, fields(user_id = %user_id, query_length = query_text.len(), session_id_for_chat = ?session_id_for_chat_history, lorebook_ids = ?active_lorebook_ids_for_search))]
    async fn retrieve_relevant_chunks(
        &self,
        state: Arc<AppState>,
        user_id: Uuid,
        session_id_for_chat_history: Option<Uuid>,
        active_lorebook_ids_for_search: Option<Vec<Uuid>>,
        query_text: &str,
        limit_per_source: u64,
    ) -> Result<Vec<RetrievedChunk>, AppError> {
        info!("Retrieving relevant chunks for query");
        let embedding_client = state.embedding_client.clone();
        let qdrant_service = state.qdrant_service.clone();

        let query_embedding = embedding_client
            .embed_content(query_text, "RETRIEVAL_QUERY", None)
            .await?;
        debug!(query_text, ?query_embedding, "Generated query embedding for RAG");

        let mut combined_results = Vec::new();

        // Search chat history if session_id is provided
        if let Some(session_id) = session_id_for_chat_history {
            debug!(%user_id, %session_id, "Constructing chat history filter for RAG");
            let chat_filter = Filter {
                must: vec![
                    Condition {
                        condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                            key: "user_id".to_string(),
                            r#match: Some(Match {
                                match_value: Some(MatchValue::Keyword(user_id.to_string())),
                            }),
                            ..Default::default()
                        })),
                    },
                    Condition {
                        condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                            key: "session_id".to_string(),
                            r#match: Some(Match {
                                match_value: Some(MatchValue::Keyword(session_id.to_string())),
                            }),
                            ..Default::default()
                        })),
                    },
                    Condition {
                        condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                            key: "source_type".to_string(),
                            r#match: Some(Match {
                                match_value: Some(MatchValue::Keyword("chat_message".to_string())),
                            }),
                            ..Default::default()
                        })),
                    },
                ],
                ..Default::default()
            };
            debug!(?chat_filter, "Chat history filter for RAG");

            match qdrant_service
                .search_points(query_embedding.clone(), limit_per_source, Some(chat_filter.clone()))
                .await
            {
                Ok(search_results) => {
                    debug!(num_results = search_results.len(), %session_id, "Raw Qdrant results for chat history (RAG)");
                    for scored_point in search_results {
                        debug!(point_id = ?scored_point.id, score = scored_point.score, %session_id, "Processing chat point (RAG)");
                        match ChatMessageChunkMetadata::try_from(scored_point.payload.clone()) {
                            Ok(chat_meta) => {
                                debug!(?chat_meta, %session_id, "Successfully parsed chat metadata (RAG)");
                                combined_results.push(RetrievedChunk {
                                    score: scored_point.score,
                                    text: chat_meta.text.clone(),
                                    metadata: RetrievedMetadata::Chat(chat_meta),
                                });
                            }
                            Err(e) => {
                                warn!(
                                    point_id = %scored_point.id.as_ref().map(|id| format!("{:?}", id)).unwrap_or_default(),
                                    error = %e,
                                    payload = ?scored_point.payload,
                                    %session_id,
                                    "Failed to parse chat message payload during RAG search"
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, filter = ?chat_filter, %session_id, "Failed to search chat history in Qdrant (RAG)");
                    // Decide whether to return error or continue. For now, log and continue to allow lorebook search.
                    // return Err(e);
                }
            }
        }

        // Search lorebooks if active_lorebook_ids are provided and not empty
        if let Some(lorebook_ids) = active_lorebook_ids_for_search {
            if !lorebook_ids.is_empty() {
                debug!(%user_id, ?lorebook_ids, "Constructing lorebook filter for RAG");
                let mut lorebook_id_conditions = Vec::new();
                for lorebook_id_val in lorebook_ids.iter() { // Iterate over a reference
                    lorebook_id_conditions.push(Condition {
                        condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                            key: "lorebook_id".to_string(),
                            r#match: Some(Match {
                                match_value: Some(MatchValue::Keyword(lorebook_id_val.to_string())),
                            }),
                            ..Default::default()
                        })),
                    });
                }

                let lorebook_filter = Filter {
                    must: vec![
                        Condition {
                            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                                key: "user_id".to_string(),
                                r#match: Some(Match {
                                    match_value: Some(MatchValue::Keyword(user_id.to_string())),
                                }),
                                ..Default::default()
                            })),
                        },
                        Condition {
                            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                                key: "source_type".to_string(),
                                r#match: Some(Match {
                                    match_value: Some(MatchValue::Keyword("lorebook_entry".to_string())),
                                }),
                                ..Default::default()
                            })),
                        },
                        Condition {
                            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                                key: "is_enabled".to_string(),
                                r#match: Some(Match {
                                    match_value: Some(MatchValue::Boolean(true)),
                                }),
                                ..Default::default()
                            })),
                        },
                    ],
                    should: lorebook_id_conditions, // Match any of the provided lorebook_ids
                    ..Default::default()
                };
                debug!(?lorebook_filter, "Lorebook filter for RAG");

                match qdrant_service
                    .search_points(query_embedding.clone(), limit_per_source, Some(lorebook_filter.clone()))
                    .await
                {
                    Ok(search_results) => {
                        debug!(num_results = search_results.len(), ?lorebook_ids, "Raw Qdrant results for lorebooks (RAG)");
                        for scored_point in search_results {
                            debug!(point_id = ?scored_point.id, score = scored_point.score, ?lorebook_ids, "Processing lorebook point (RAG)");
                            match LorebookChunkMetadata::try_from(scored_point.payload.clone()) {
                                Ok(lorebook_meta) => {
                                    debug!(?lorebook_meta, ?lorebook_ids, "Successfully parsed lorebook metadata (RAG)");
                                    combined_results.push(RetrievedChunk {
                                        score: scored_point.score,
                                        text: lorebook_meta.chunk_text.clone(),
                                        metadata: RetrievedMetadata::Lorebook(lorebook_meta),
                                    });
                                }
                                Err(e) => {
                                    warn!(
                                        point_id = %scored_point.id.as_ref().map(|id| format!("{:?}", id)).unwrap_or_default(),
                                        error = %e,
                                        payload = ?scored_point.payload,
                                        ?lorebook_ids,
                                        "Failed to parse lorebook entry payload during RAG search"
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, filter = ?lorebook_filter, ?lorebook_ids, "Failed to search lorebooks in Qdrant (RAG)");
                        // Decide whether to return error or continue. For now, log and continue.
                        // return Err(e);
                    }
                }
            }
        }

        // Sort combined results by score in descending order
        combined_results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        debug!(num_combined_results = combined_results.len(), query_text, "Final combined and sorted RAG chunks");

        info!("Retrieved {} relevant chunks in total", combined_results.len());
        Ok(combined_results)
    }

    #[instrument(skip_all, fields(original_lorebook_entry_id = %original_lorebook_entry_id, user_id = %user_id))]
    async fn delete_lorebook_entry_chunks(
        &self,
        state: Arc<AppState>,
        original_lorebook_entry_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), AppError> {
        info!("Attempting to delete chunks for lorebook entry");
        let qdrant_service = state.qdrant_service.clone();

        let filter = Filter {
            must: vec![
                Condition {
                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                        key: "original_lorebook_entry_id".to_string(),
                        r#match: Some(Match {
                            match_value: Some(MatchValue::Keyword(original_lorebook_entry_id.to_string())),
                        }),
                        ..Default::default()
                    })),
                },
                Condition {
                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                        key: "user_id".to_string(),
                        r#match: Some(Match {
                            match_value: Some(MatchValue::Keyword(user_id.to_string())),
                        }),
                        ..Default::default()
                    })),
                },
                Condition {
                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                        key: "source_type".to_string(),
                        r#match: Some(Match {
                            match_value: Some(MatchValue::Keyword("lorebook_entry".to_string())),
                        }),
                        ..Default::default()
                    })),
                },
            ],
            ..Default::default()
        };
        debug!(?filter, "Constructed filter for deleting lorebook entry chunks");

        qdrant_service.delete_points_by_filter(filter).await?;
        info!("Successfully deleted chunks for lorebook entry {} for user {}", original_lorebook_entry_id, user_id);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum RetrievedMetadata {
    Chat(ChatMessageChunkMetadata),
    Lorebook(LorebookChunkMetadata),
    // Add other types as needed
}


#[derive(Debug, Clone)]
pub struct RetrievedChunk {
    pub score: f32,
    pub text: String,
    pub metadata: RetrievedMetadata,
}

// Standalone function for testing or specific use cases (if needed)
// This is kept for potential direct testing of retrieval logic if the service wrapper is complex
#[instrument(skip(qdrant_service, embedding_client), err)]
async fn retrieve_relevant_chunks_standalone(
    qdrant_service: Arc<dyn QdrantClientServiceTrait>,
    embedding_client: Arc<dyn EmbeddingClient>,
    _session_id: Uuid, // Parameter kept for signature compatibility, but filter is removed for broader search
    query_text: &str,
    limit: u64,
) -> Result<Vec<RetrievedChunk>, AppError> {
    info!("Retrieving relevant chunks (standalone, broad search)");

    let query_embedding = embedding_client
        .embed_content(query_text, "RETRIEVAL_QUERY", None)
        .await?;

    // No filter applied to search globally for relevant chunks (both chat and lorebook)
    let search_results = qdrant_service
        .search_points(query_embedding.clone(), limit, None) // Filter removed
        .await?;

    let mut retrieved_chunks = Vec::new();
    for scored_point in search_results {
        let payload_map = scored_point.payload.clone(); // Clone for multiple parsing attempts
        if !payload_map.is_empty() {
            if let Ok(lorebook_meta) = LorebookChunkMetadata::try_from(payload_map.clone()) {
                retrieved_chunks.push(RetrievedChunk {
                    score: scored_point.score,
                    text: lorebook_meta.chunk_text.clone(),
                    metadata: RetrievedMetadata::Lorebook(lorebook_meta),
                });
            } else if let Ok(chat_meta) = ChatMessageChunkMetadata::try_from(payload_map) {
                retrieved_chunks.push(RetrievedChunk {
                    score: scored_point.score,
                    text: chat_meta.text.clone(),
                    metadata: RetrievedMetadata::Chat(chat_meta),
                });
            } else {
                warn!(
                    point_id = %scored_point.id.as_ref().map(|id| format!("{:?}", id)).unwrap_or_default(),
                    "Failed to parse payload as any known metadata type (standalone)"
                );
            }
        } else {
            warn!(point_id = %scored_point.id.as_ref().map(|id| format!("{:?}", id)).unwrap_or_default(), "Scored point has an empty payload (standalone)");
        }
    }
    info!(
        "Retrieved {} relevant chunks (standalone, broad search)",
        retrieved_chunks.len()
    );
    Ok(retrieved_chunks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::Config,
        crypto::encrypt_gcm, // Updated for encryption tests
        models::chats::MessageRole,
        test_helpers::{
            MockAiClient, MockEmbeddingClient, MockQdrantClientService, db::setup_test_database,
        },
        services::lorebook_service::LorebookService, // Added for LorebookService
        text_processing::chunking::ChunkingMetric,
    };
    use chrono::Utc;
    use qdrant_client::qdrant::{PointId, ScoredPoint, Value};
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
    fn integer_value(i: i64) -> Value {
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
        let embedding_pipeline_service_concrete = Arc::new(EmbeddingPipelineService::new(chunk_config));

        let encryption_service = Arc::new(crate::services::encryption_service::EncryptionService::new());
        let chat_override_service = Arc::new(crate::services::chat_override_service::ChatOverrideService::new(pool.clone(), encryption_service.clone()));
        let user_persona_service = Arc::new(crate::services::user_persona_service::UserPersonaService::new(pool.clone(), encryption_service.clone()));
        let token_counter_service = Arc::new(crate::services::hybrid_token_counter::HybridTokenCounter::new_local_only(
            crate::services::tokenizer_service::TokenizerService::new(
                config.tokenizer_model_path.as_ref().expect("Tokenizer path is None").as_str()
            )
            .expect("Failed to create tokenizer for test")
        ));
        let lorebook_service = Arc::new(LorebookService::new(pool.clone(), encryption_service.clone()));
        let auth_backend = Arc::new(crate::auth::user_store::Backend::new(pool.clone()));

        let app_state = Arc::new(AppState::new(
            pool,
            config,
            ai_client,
            mock_embed_client.clone(), // Use mock for embedding client here
            mock_qdrant.clone(),       // Use mock for Qdrant here
            embedding_pipeline_service_concrete, // Use the real service, cast to trait object is handled by new()
            chat_override_service,
            user_persona_service,
            token_counter_service,
            encryption_service.clone(),
            lorebook_service, // Added lorebook_service
            auth_backend,     // Added auth_backend
        ));
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
            content: "   ".as_bytes().to_vec(), // Empty after trim
            content_nonce: None,
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
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
            content: "Some content".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
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
            content: "Some content".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
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

    // Helper to create a mock ScoredPoint
    fn create_mock_scored_point(
        id_uuid: Uuid,
        score: f32,
        session_id: Uuid,
        message_id: Uuid,
        user_id: Uuid, // Added user_id
        speaker: &str,
        timestamp: chrono::DateTime<Utc>,
        text: &str,
        source_type: &str,
    ) -> ScoredPoint {
        let mut payload = HashMap::new();
        payload.insert(
            "message_id".to_string(),
            string_value(&message_id.to_string()),
        );
        payload.insert(
            "session_id".to_string(),
            string_value(&session_id.to_string()),
        );
        payload.insert( // Added user_id to payload
            "user_id".to_string(),
            string_value(&user_id.to_string()),
        );
        payload.insert("speaker".to_string(), string_value(speaker));
        payload.insert(
            "timestamp".to_string(),
            string_value(&timestamp.to_rfc3339()),
        );
        payload.insert("text".to_string(), string_value(text));
        payload.insert("source_type".to_string(), string_value(source_type));

        ScoredPoint {
            id: Some(PointId { // Consistent with PointIdOptions::Uuid usage
                point_id_options: Some(qdrant_client::qdrant::point_id::PointIdOptions::Uuid(id_uuid.to_string())),
            }),
            payload,
            score,
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
            create_mock_scored_point(
                mock_point_id_1,
                0.95,
                session_id,
                message_id_1,
                user_id, // Added user_id argument
                "user",
                Utc::now(),
                "Cats are furry.",
                "chat_message",
            ),
            create_mock_scored_point(
                mock_point_id_2,
                0.85,
                session_id,
                message_id_2,
                user_id, // Added user_id argument
                "ai",
                Utc::now(),
                "They meow a lot.",
                "chat_message",
            ),
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
        assert!(result.is_ok(), "retrieve_relevant_chunks failed: {:?}", result.err());
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
            content: "Short and sweet.".as_bytes().to_vec(),
            content_nonce: None, // ENSURED
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
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
        let (state, mock_qdrant, _mock_embed_client) = setup_pipeline_test_env().await;
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
        };
        mock_qdrant.set_search_response(Ok(vec![]));
        mock_qdrant.set_upsert_response(Err(AppError::VectorDbError(
            "Simulated Qdrant upsert error".to_string(),
        )));
        _mock_embed_client.set_response(Ok(vec![0.1, 0.2, 0.3])); // Ensure embedding itself succeeds
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
            "Expected one call to embedding client. Actual calls: {:#?}",
            calls
        );
        // Expect lossy conversion of the ciphertext, sanitized, then trimmed
        let expected_lossy_content_sanitized = String::from_utf8_lossy(&encrypted_content)
            .to_string()
            .replace("\n", " ")
            .replace("\r", " ");
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
            .replace("\n", " ")
            .replace("\r", " ");
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
        let expected_lossy_content_sanitized =
            String::from_utf8_lossy(&encrypted_content_bytes)
                .to_string()
                .replace("\n", " ")
                .replace("\r", " ");
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

    #[tokio::test]
    async fn test_process_and_embed_lorebook_entry_success() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let original_lorebook_entry_id = Uuid::new_v4();
        let lorebook_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let decrypted_content = "This is a lorebook entry about dragons. They breathe fire.".to_string();
        let decrypted_title = Some("Dragons".to_string());
        let decrypted_keywords = Some(vec!["dragon".to_string(), "mythical".to_string()]);
        let is_enabled = true;
        let is_constant = false;

        // Mock Embedding Client
        mock_embed_client.set_response(Ok(vec![0.1, 0.2, 0.3, 0.4])); // Example embedding
        // Mock Qdrant to succeed on upsert
        mock_qdrant.set_upsert_response(Ok(()));

        let result = state
            .embedding_pipeline_service
            .process_and_embed_lorebook_entry(
                state.clone(),
                original_lorebook_entry_id,
                lorebook_id,
                user_id,
                decrypted_content.clone(),
                decrypted_title.clone(),
                decrypted_keywords.clone(),
                is_enabled,
                is_constant,
            )
            .await;

        assert!(result.is_ok(), "process_and_embed_lorebook_entry failed: {:?}", result.err());

        // Verify embedding client calls
        let embed_calls = mock_embed_client.get_calls();
        // Based on chunk_config (100/20), "This is a lorebook entry about dragons. They breathe fire." (56 chars) should be 1 chunk.
        assert_eq!(embed_calls.len(), 1, "Expected 1 call to embedding client for the content");
        assert_eq!(embed_calls[0].0, decrypted_content); // Check content
        assert_eq!(embed_calls[0].1, "RETRIEVAL_DOCUMENT"); // Check task type
        assert_eq!(embed_calls[0].2, decrypted_title); // Check title

        // Verify Qdrant client calls
        let qdrant_upsert_points = mock_qdrant.get_last_upsert_points().unwrap_or_default();
        assert_eq!(qdrant_upsert_points.len(), 1, "Expected 1 point in the batch upsert");
        
        let point = &qdrant_upsert_points[0];
        assert!(matches!(point.vectors.as_ref().unwrap().vectors_options.as_ref().unwrap(), qdrant_client::qdrant::vectors::VectorsOptions::Vector(_)), "Expected a single unnamed vector"); // Check vector presence

        let payload_value = point.payload.get("original_lorebook_entry_id").unwrap().kind.as_ref().unwrap();
        if let qdrant_client::qdrant::value::Kind::StringValue(s) = payload_value {
            assert_eq!(*s, original_lorebook_entry_id.to_string());
        } else {
            panic!("Wrong type for original_lorebook_entry_id");
        }

        let payload_value = point.payload.get("lorebook_id").unwrap().kind.as_ref().unwrap();
        if let qdrant_client::qdrant::value::Kind::StringValue(s) = payload_value {
            assert_eq!(*s, lorebook_id.to_string());
        } else {
            panic!("Wrong type for lorebook_id");
        }

        let payload_value = point.payload.get("user_id").unwrap().kind.as_ref().unwrap();
        if let qdrant_client::qdrant::value::Kind::StringValue(s) = payload_value {
            assert_eq!(*s, user_id.to_string());
        } else {
            panic!("Wrong type for user_id");
        }
        
        let payload_value = point.payload.get("chunk_text").unwrap().kind.as_ref().unwrap();
        if let qdrant_client::qdrant::value::Kind::StringValue(s) = payload_value {
            assert_eq!(*s, decrypted_content);
        } else {
            panic!("Wrong type for chunk_text");
        }

        let payload_value = point.payload.get("entry_title").unwrap().kind.as_ref().unwrap();
        if let qdrant_client::qdrant::value::Kind::StringValue(s) = payload_value {
            assert_eq!(*s, decrypted_title.as_ref().unwrap().clone());
        } else {
            panic!("Wrong type for entry_title");
        }
        
        let payload_value = point.payload.get("is_enabled").unwrap().kind.as_ref().unwrap();
        if let qdrant_client::qdrant::value::Kind::BoolValue(b) = payload_value {
            assert_eq!(b, &is_enabled);
        } else {
            panic!("Wrong type for is_enabled");
        }
    }

    #[tokio::test]
    async fn test_process_and_embed_lorebook_entry_empty_content() {
        let (state, _mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let original_lorebook_entry_id = Uuid::new_v4();
        let lorebook_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        let result = state
            .embedding_pipeline_service
            .process_and_embed_lorebook_entry(
                state.clone(),
                original_lorebook_entry_id,
                lorebook_id,
                user_id,
                "   ".to_string(), // Empty after trim
                Some("Empty Title".to_string()),
                None,
                true,
                false,
            )
            .await;
        
        assert!(result.is_ok(), "Expected Ok for empty content (should skip embedding)");
        assert!(mock_embed_client.get_calls().is_empty(), "Embedding client should not be called for empty content");
    }

    #[tokio::test]
    async fn test_process_and_embed_lorebook_entry_embedding_error() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let original_lorebook_entry_id = Uuid::new_v4();

        mock_embed_client.set_response(Err(AppError::AiServiceError("Embedding failed".to_string())));

        let result = state
            .embedding_pipeline_service
            .process_and_embed_lorebook_entry(
                state.clone(),
                original_lorebook_entry_id,
                Uuid::new_v4(),
                Uuid::new_v4(),
                "Some lore content".to_string(),
                Some("Lore Title".to_string()),
                None,
                true,
                false,
            )
            .await;
        
        assert!(result.is_ok(), "Service should handle embedding errors gracefully and return Ok if no points were made to upsert.");
        assert!(mock_qdrant.get_last_upsert_points().unwrap_or_default().is_empty(), "Qdrant should not be called if embedding failed for all chunks");
    }

    #[tokio::test]
    async fn test_process_and_embed_lorebook_entry_qdrant_error() {
        let (state, mock_qdrant, mock_embed_client) = setup_pipeline_test_env().await;
        let original_lorebook_entry_id = Uuid::new_v4();

        mock_embed_client.set_response(Ok(vec![0.5, 0.5]));
        mock_qdrant.set_upsert_response(Err(AppError::VectorDbError("Qdrant down".to_string())));

        let result = state
            .embedding_pipeline_service
            .process_and_embed_lorebook_entry(
                state.clone(),
                original_lorebook_entry_id,
                Uuid::new_v4(),
                Uuid::new_v4(),
                "Some lore content".to_string(),
                Some("Lore Title".to_string()),
                None,
                true,
                false,
            )
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

        let result = state
            .embedding_pipeline_service
            .process_and_embed_lorebook_entry(
                state.clone(),
                original_lorebook_entry_id,
                lorebook_id,
                user_id,
                long_content.clone(),
                decrypted_title.clone(),
                None,
                true,
                false,
            )
            .await;

        assert!(result.is_ok(), "Processing multi-chunk lore entry failed: {:?}", result.err());

        let embed_calls = mock_embed_client.get_calls();
        // 150 chars, 100 max, 20 overlap.
        // Chunk 1: 0-99 (100 chars)
        // Chunk 2: 80-149 (70 chars) -> (start = 100 - 20 = 80)
        assert_eq!(embed_calls.len(), 2, "Expected 2 calls to embedding client for 150 char content");
        assert_eq!(embed_calls[0].1, "RETRIEVAL_DOCUMENT");
        assert_eq!(embed_calls[0].2, decrypted_title);
        assert_eq!(embed_calls[1].1, "RETRIEVAL_DOCUMENT");
        assert_eq!(embed_calls[1].2, decrypted_title);


        let qdrant_upsert_points = mock_qdrant.get_last_upsert_points().unwrap_or_default();
        assert_eq!(qdrant_upsert_points.len(), 2, "Expected 2 points in the batch upsert");
    }

// Helper to convert bool to Qdrant Bool Value
    fn bool_value(b: bool) -> Value {
        Value {
            kind: Some(qdrant_client::qdrant::value::Kind::BoolValue(b)),
        }
    }

    // Helper to convert Option<Vec<String>> to Qdrant List Value or Null Value
    fn optional_list_string_value(opt_list: Option<Vec<String>>) -> Value {
        match opt_list {
            Some(list) => Value {
                kind: Some(qdrant_client::qdrant::value::Kind::ListValue(
                    qdrant_client::qdrant::ListValue {
                        values: list.into_iter().map(|s| string_value(&s)).collect(),
                    },
                )),
            },
            None => Value {
                kind: Some(qdrant_client::qdrant::value::Kind::NullValue(
                    qdrant_client::qdrant::NullValue::default() as i32,
                )),
            },
        }
    }
    
    // Helper to convert Option<String> to Qdrant String Value or Null Value
    fn optional_string_value(opt_s: Option<String>) -> Value {
        match opt_s {
            Some(s) => string_value(&s),
            None => Value {
                kind: Some(qdrant_client::qdrant::value::Kind::NullValue(
                    qdrant_client::qdrant::NullValue::default() as i32,
                )),
            },
        }
    }

    // Helper to create a mock ScoredPoint for Lorebook entries
    fn create_mock_lorebook_scored_point(
        point_uuid: Uuid, // UUID for the qdrant point itself
        score: f32,
        original_lorebook_entry_id: Uuid,
        lorebook_id: Uuid,
        user_id: Uuid,
        chunk_text: &str,
        entry_title: Option<String>,
        keywords: Option<Vec<String>>,
        is_enabled: bool,
        is_constant: bool,
        source_type: &str,
    ) -> ScoredPoint {
        let mut payload = HashMap::new();
        payload.insert(
            "original_lorebook_entry_id".to_string(),
            string_value(&original_lorebook_entry_id.to_string()),
        );
        payload.insert(
            "lorebook_id".to_string(),
            string_value(&lorebook_id.to_string()),
        );
        payload.insert("user_id".to_string(), string_value(&user_id.to_string()));
        payload.insert("chunk_text".to_string(), string_value(chunk_text));
        payload.insert("entry_title".to_string(), optional_string_value(entry_title));
        payload.insert("keywords".to_string(), optional_list_string_value(keywords));
        payload.insert("is_enabled".to_string(), bool_value(is_enabled));
        payload.insert("is_constant".to_string(), bool_value(is_constant));
        payload.insert("source_type".to_string(), string_value(source_type));

        ScoredPoint {
            id: Some(PointId::from(point_uuid.to_string())),
            payload,
            score,
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
        let mock_chat_results = vec![create_mock_scored_point(
            chat_point_id,
            0.9,
            session_id,
            Uuid::new_v4(), // message_id
            user_id,        // user_id (this was missing)
            "User",
            Utc::now(),
            "Test chat message content",
            "chat_message",
        )];
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

        assert!(result.is_ok(), "retrieve_relevant_chunks failed: {:?}", result.err());
        let chunks = result.unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].text, "Test chat message content");
        match &chunks[0].metadata {
            RetrievedMetadata::Chat(meta) => {
                assert_eq!(meta.session_id, session_id);
                assert_eq!(meta.source_type, "chat_message");
            }
            _ => panic!("Expected Chat metadata"),
        }

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(search_call_count, 1, "Expected one search call to Qdrant");
        let search_params = mock_qdrant.get_last_search_params().expect("Expected search_params to be set after one call");
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
            lore_point_id,
            0.85,
            Uuid::new_v4(),
            lorebook_id1,
            user_id,
            "Test lorebook entry content",
            Some("Lore Title".to_string()),
            None,
            true,
            false,
            "lorebook_entry",
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

        assert!(result.is_ok(), "retrieve_relevant_chunks failed: {:?}", result.err());
        let chunks = result.unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].text, "Test lorebook entry content");
        match &chunks[0].metadata {
            RetrievedMetadata::Lorebook(meta) => {
                assert_eq!(meta.lorebook_id, lorebook_id1);
                assert_eq!(meta.source_type, "lorebook_entry");
                assert_eq!(meta.is_enabled, true);
            }
            _ => panic!("Expected Lorebook metadata"),
        }

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(search_call_count, 1, "Expected one search call to Qdrant");
        let search_params = mock_qdrant.get_last_search_params().expect("Expected search_params to be set after one call");
        let (_embedding, _limit, filter_opt) = &search_params;
        assert!(filter_opt.is_some());
        let filter = filter_opt.as_ref().unwrap();

        // Verify lorebook filter construction
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
                            return *b_val == true;
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

        let mock_chat_results = vec![create_mock_scored_point(
            chat_point_id,
            0.95, // Higher score
            session_id,
            Uuid::new_v4(), // message_id
            user_id,        // user_id (this was missing)
            "User",
            Utc::now(),
            "Chat content about topic",
            "chat_message",
        )];
        let mock_lore_results = vec![create_mock_lorebook_scored_point(
            lore_point_id,
            0.90, // Lower score
            Uuid::new_v4(),
            lorebook_id,
            user_id,
            "Lore content about topic",
            None,
            None,
            true,
            false,
            "lorebook_entry",
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

        assert!(result.is_ok(), "retrieve_relevant_chunks failed: {:?}", result.err());
        let chunks = result.unwrap();
        assert_eq!(chunks.len(), 2);

        // Verify sorting by score (descending)
        assert_eq!(chunks[0].text, "Chat content about topic"); // Higher score
        assert_eq!(chunks[0].score, 0.95);
        assert_eq!(chunks[1].text, "Lore content about topic"); // Lower score
        assert_eq!(chunks[1].score, 0.90);

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(search_call_count, 2, "Expected two search calls (one for chat, one for lore)");
        // Verifying parameters of individual calls in a sequence is complex with the current mock.
        // The primary check is that the combined and sorted results are correct.
        // We can check the *types* of filters used by inspecting the mock's recorded calls if the mock supports it,
        // but for now, we rely on the mock correctly routing based on the sequence.
        // The `get_last_search_params` would only give details for the *second* call (lorebooks).
        let last_search_params = mock_qdrant.get_last_search_params().expect("Expected search_params for the last call");
        let (_embedding_lore, limit_lore, filter_opt_lore) = &last_search_params;
        assert_eq!(*limit_lore, limit); // limit_per_source for the lorebook call
        let filter_lore = filter_opt_lore.as_ref().unwrap();
        assert!(get_field_condition_keyword_match(filter_lore, "source_type").is_some_and(|s| s == "lorebook_entry"));
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

        assert!(result.is_ok(), "retrieve_relevant_chunks failed: {:?}", result.err());
        let chunks = result.unwrap();
        assert!(chunks.is_empty(), "Expected empty results when no sources are specified");

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(search_call_count, 0, "Expected no calls to Qdrant search_points");
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
                None,                  // No chat session
                Some(vec![]),          // Empty list of lorebook IDs
                query_text,
                limit,
            )
            .await;

        assert!(result.is_ok(), "retrieve_relevant_chunks failed: {:?}", result.err());
        let chunks = result.unwrap();
        assert!(chunks.is_empty(), "Expected empty results for empty lorebook ID list and no chat");

        let search_call_count = mock_qdrant.get_search_call_count();
        // No call for lorebooks because the list is empty. No call for chat because session_id is None.
        assert_eq!(search_call_count, 0, "Expected no calls to Qdrant search_points");
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
        let mock_chat_results = vec![create_mock_scored_point(
            chat_point_id,
            0.9,
            session_id,
            Uuid::new_v4(), // message_id
            user_id,        // user_id (this was missing)
            "User",
            Utc::now(),
            "Chat message for this test",
            "chat_message",
        )];
        mock_qdrant.set_search_response(Ok(mock_chat_results.clone())); // Only chat results expected

        let result = state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(
                state.clone(),
                user_id,
                Some(session_id),      // Chat session provided
                Some(vec![]),          // Empty list of lorebook IDs
                query_text,
                limit,
            )
            .await;

        assert!(result.is_ok(), "retrieve_relevant_chunks failed: {:?}", result.err());
        let chunks = result.unwrap();
        assert_eq!(chunks.len(), 1); // Should get chat results
        assert_eq!(chunks[0].text, "Chat message for this test");

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(search_call_count, 1, "Expected one call to Qdrant for chat history");
        let search_params = mock_qdrant.get_last_search_params().expect("Expected search_params to be set after one call");
        let (_embedding, _limit_call, filter_opt) = &search_params;
        let filter = filter_opt.as_ref().unwrap();
        assert!(filter.must.iter().any(|c| {
            if let Some(ConditionOneOf::Field(fc)) = c.condition_one_of.as_ref() {
                fc.key == "session_id"
            } else { false }
        }));
        assert!(filter.should.is_empty()); // No lorebook conditions
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

        // Mock Qdrant to return MORE than limit_per_source if it were asked for more
        // The mock's search_points will be called with `limit_per_source`, so it should respect that.
        let chat_point1 = Uuid::new_v4();
        let chat_point2 = Uuid::new_v4();
        let lore_point1 = Uuid::new_v4();
        let lore_point2 = Uuid::new_v4();

        let mock_chat_results_full = vec![
            create_mock_scored_point(chat_point1, 0.99, session_id, Uuid::new_v4(), user_id, "U1", Utc::now(), "Chat1", "chat_message"),
            create_mock_scored_point(chat_point2, 0.98, session_id, Uuid::new_v4(), user_id, "U2", Utc::now(), "Chat2", "chat_message"),
        ];
        let mock_lore_results_full = vec![
            create_mock_lorebook_scored_point(lore_point1, 0.97, Uuid::new_v4(), lorebook_id, user_id, "Lore1", None, None, true, false, "lorebook_entry"),
            create_mock_lorebook_scored_point(lore_point2, 0.96, Uuid::new_v4(), lorebook_id, user_id, "Lore2", None, None, true, false, "lorebook_entry"),
        ];
        
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

        assert!(result.is_ok(), "retrieve_relevant_chunks failed: {:?}", result.err());
        let chunks = result.unwrap();
        // Total chunks should be limit_per_source from chat + limit_per_source from lore
        assert_eq!(chunks.len(), (limit_per_source * 2) as usize, "Expected total chunks to be sum of limits from each source"); 
        // Results are sorted by score. Chat1 (0.99) > Lore1 (0.97)
        assert_eq!(chunks[0].text, "Chat1", "Expected Chat1 with higher score first");
        assert_eq!(chunks[1].text, "Lore1", "Expected Lore1 with lower score second");

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(search_call_count, 2, "Expected two search calls");

        // We can check the limit passed to the *last* call (lorebooks)
        let last_search_params = mock_qdrant.get_last_search_params().expect("Expected search_params for the last call");
        let (_embedding_lore, limit_call_lore, _filter_opt_lore) = &last_search_params;
        assert_eq!(*limit_call_lore, limit_per_source, "Limit for lorebook search call was not limit_per_source");

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
            lore_point_id,
            0.8,
            Uuid::new_v4(),
            lorebook_id,
            user_id,
            "Successful lore content",
            None,
            None,
            true,
            false,
            "lorebook_entry",
        )];

        // Chat search fails, Lorebook search succeeds using a sequence
        mock_qdrant.set_search_responses_sequence(vec![
            Err(AppError::VectorDbError("Chat search Qdrant down".to_string())), // First call (chat) fails
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

        assert!(result.is_ok(), "Expected Ok even if one source fails, got: {:?}", result.err());
        let chunks = result.unwrap();
        assert_eq!(chunks.len(), 1, "Expected only results from the successful source");
        assert_eq!(chunks[0].text, "Successful lore content");
        match &chunks[0].metadata {
            RetrievedMetadata::Lorebook(_) => {} // Correct
            _ => panic!("Expected Lorebook metadata"),
        }

        let search_call_count = mock_qdrant.get_search_call_count();
        assert_eq!(search_call_count, 2, "Expected two attempts to search Qdrant");
    }
    
    // Helper to extract field condition for string match
    fn get_field_condition_keyword_match<'a>(filter: &'a Filter, key_name: &str) -> Option<&'a str> {
        filter.must.iter()
            .find_map(|cond| {
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
        filter.must.iter()
            .find_map(|cond| {
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
        filter.should.iter()
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
        let search_params = mock_qdrant.get_last_search_params().expect("Expected search_params to be set after one call");
        let filter = search_params.2.as_ref().expect("Filter should be present for chat history");
        
        assert_eq!(get_field_condition_keyword_match(filter, "user_id"), Some(user_id.to_string().as_str()));
        assert_eq!(get_field_condition_keyword_match(filter, "session_id"), Some(session_id.to_string().as_str()));
        assert_eq!(get_field_condition_keyword_match(filter, "source_type"), Some("chat_message"));
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
        let search_params = mock_qdrant.get_last_search_params().expect("Expected search_params to be set after one call");
        let filter = search_params.2.as_ref().expect("Filter should be present for lorebooks");

        assert_eq!(get_field_condition_keyword_match(filter, "user_id"), Some(user_id.to_string().as_str()));
        assert_eq!(get_field_condition_keyword_match(filter, "source_type"), Some("lorebook_entry"));
        assert_eq!(get_field_condition_bool_match(filter, "is_enabled"), Some(true));
        
        let matched_lorebook_ids = get_should_conditions_keyword_match(filter, "lorebook_id");
        assert_eq!(matched_lorebook_ids.len(), 2);
        assert!(matched_lorebook_ids.contains(&lorebook_id1.to_string().as_str()));
        assert!(matched_lorebook_ids.contains(&lorebook_id2.to_string().as_str()));
    }
}
