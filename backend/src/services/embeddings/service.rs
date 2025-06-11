use crate::errors::AppError;
use crate::models::chats::ChatMessage;
use crate::state::AppState;
use crate::text_processing::chunking::{ChunkConfig, chunk_text};
use crate::vector_db::qdrant_client::create_qdrant_point;
use crate::auth::session_dek::SessionDek;
use super::trait_def::EmbeddingPipelineServiceTrait;
use super::metadata::{ChatMessageChunkMetadata, LorebookChunkMetadata, LorebookEntryParams};
use super::retrieval::{RetrievedChunk, RetrievedMetadata};
use async_trait::async_trait;
use qdrant_client::qdrant::{
    Condition, FieldCondition, Filter, Match, condition::ConditionOneOf,
    r#match::MatchValue,
};
use secrecy::ExposeSecret;
use std::sync::Arc;
use tokio::time::{Duration, sleep};
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

pub struct EmbeddingPipelineService {
    chunk_config: ChunkConfig, // Store chunking configuration
}

impl EmbeddingPipelineService {
    /// Creates a new `EmbeddingPipelineService`.
    #[must_use]
    pub const fn new(chunk_config: ChunkConfig) -> Self {
        Self { chunk_config }
    }
}

// Implement the trait for EmbeddingPipelineService
#[async_trait]
impl EmbeddingPipelineServiceTrait for EmbeddingPipelineService {
    /// Processes a chat message by chunking its content and storing embeddings in the vector database.
    ///
    /// # Errors
    ///
    /// Returns `AppError::DecryptionError` if message decryption fails,
    /// chunking errors if content chunking fails,
    /// embedding client errors if content embedding fails,
    /// `AppError::SerializationError` if metadata serialization fails,
    /// Qdrant service errors if vector storage operations fail.
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

        let content_to_embed = match (&session_dek, &message.content_nonce) {
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

                crate::crypto::decrypt_gcm(&message.content, nonce_bytes, &dek.0)
                    .map_or_else(
                        |e| {
                            warn!(message_id = %message.id, error = %e, "Failed to decrypt message content. Falling back to lossy conversion of ciphertext.");
                            String::from_utf8_lossy(&message.content)
                                .to_string()
                                .replace(['\n', '\r'], " ")
                        },
                        |plaintext_secret_vec| {
                            String::from_utf8(plaintext_secret_vec.expose_secret().clone())
                                .map_or_else(
                                    |e| {
                                        warn!(message_id = %message.id, error = %e, "Failed to convert decrypted content to UTF-8. Falling back to lossy conversion of ciphertext.");
                                        String::from_utf8_lossy(&message.content)
                                            .to_string()
                                            .replace(['\n', '\r'], " ")
                                    },
                                    |s| {
                                        debug!(message_id = %message.id, "Successfully decrypted message content for embedding.");
                                        s
                                    }
                                )
                        }
                    )
            }
            _ => {
                if message.content_nonce.is_some() && session_dek.is_none() {
                    warn!(message_id = %message.id, "Message has nonce but no DEK provided for decryption. Using raw content for embedding.");
                } else if message.content_nonce.is_none() {
                    debug!(message_id = %message.id, "Message has no nonce, treating as plaintext for embedding.");
                }
                String::from_utf8_lossy(&message.content)
                    .to_string()
                    .replace(['\n', '\r'], " ")
            }
        };

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
        if points_to_upsert.is_empty() {
            info!("No valid points generated for upserting.");
        } else {
            info!("Upserting {} points to Qdrant", points_to_upsert.len());
            if let Err(e) = qdrant_service.store_points(points_to_upsert).await {
                error!(error = %e, "Failed to upsert points to Qdrant");
                return Err(e);
            }
            info!("Successfully upserted points for message");
        }

        Ok(())
    }

    #[instrument(skip_all, fields(
        original_lorebook_entry_id = %params.original_lorebook_entry_id,
        lorebook_id = %params.lorebook_id,
        user_id = %params.user_id
    ))]
    async fn process_and_embed_lorebook_entry(
        &self,
        state: Arc<AppState>,
        params: LorebookEntryParams,
    ) -> Result<(), AppError> {
        let LorebookEntryParams {
            original_lorebook_entry_id,
            lorebook_id,
            user_id,
            decrypted_content,
            decrypted_title,
            decrypted_keywords,
            is_enabled,
            is_constant,
        } = params;
        info!("Starting embedding process for lorebook entry");
        let embedding_client = state.embedding_client.clone();
        let qdrant_service = state.qdrant_service.clone();

        // First, delete existing chunks for this lorebook entry to prevent duplicates or stale data
        if let Err(e) = self
            .delete_lorebook_entry_chunks(state.clone(), original_lorebook_entry_id, user_id)
            .await
        {
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

        if points_to_upsert.is_empty() {
            info!(%original_lorebook_entry_id, "No valid points generated for lorebook entry upserting.");
        } else {
            info!(%original_lorebook_entry_id, "Upserting {} points to Qdrant for lorebook entry", points_to_upsert.len());
            if let Err(e) = qdrant_service.store_points(points_to_upsert).await {
                error!(error = %e, %original_lorebook_entry_id, "Failed to upsert lorebook points to Qdrant");
                return Err(e);
            }
            info!(%original_lorebook_entry_id, "Successfully upserted points for lorebook entry");
        }

        Ok(())
    }

    /// Retrieves relevant chunks from chat history and/or lorebooks based on semantic similarity.
    ///
    /// # Errors
    ///
    /// Returns embedding client errors if query embedding fails,
    /// `AppError::SerializationError` if metadata deserialization fails,
    /// Qdrant service errors if vector search operations fail.
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
        debug!(
            query_text,
            ?query_embedding,
            "Generated query embedding for RAG"
        );

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
                .search_points(
                    query_embedding.clone(),
                    limit_per_source,
                    Some(chat_filter.clone()),
                )
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
                                    point_id = %scored_point.id.as_ref().map(|id| format!("{id:?}")).unwrap_or_default(),
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
        if let Some(ref lorebook_ids) = active_lorebook_ids_for_search {
            if !lorebook_ids.is_empty() {
                debug!(%user_id, ?lorebook_ids, "Constructing lorebook filter for RAG");
                let mut lorebook_id_conditions = Vec::new();
                for lorebook_id_val in lorebook_ids {
                    // Iterate over a reference
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
                                    match_value: Some(MatchValue::Keyword(
                                        "lorebook_entry".to_string(),
                                    )),
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
                    .search_points(
                        query_embedding.clone(),
                        limit_per_source,
                        Some(lorebook_filter.clone()),
                    )
                    .await
                {
                    Ok(search_results) => {
                        debug!(
                            num_results = search_results.len(),
                            ?lorebook_ids,
                            "Raw Qdrant results for lorebooks (RAG)"
                        );
                        for scored_point in search_results {
                            debug!(point_id = ?scored_point.id, score = scored_point.score, ?lorebook_ids, "Processing lorebook point (RAG)");
                            match LorebookChunkMetadata::try_from(scored_point.payload.clone()) {
                                Ok(lorebook_meta) => {
                                    debug!(
                                        ?lorebook_meta,
                                        ?lorebook_ids,
                                        "Successfully parsed lorebook metadata (RAG)"
                                    );
                                    combined_results.push(RetrievedChunk {
                                        score: scored_point.score,
                                        text: lorebook_meta.chunk_text.clone(),
                                        metadata: RetrievedMetadata::Lorebook(lorebook_meta),
                                    });
                                }
                                Err(e) => {
                                    warn!(
                                        point_id = %scored_point.id.as_ref().map(|id| format!("{id:?}")).unwrap_or_default(),
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

        // Retrieve constant lorebook entries if lorebook_ids are provided
        // These should always be included regardless of semantic similarity
        if let Some(lorebook_ids) = &active_lorebook_ids_for_search {
            if !lorebook_ids.is_empty() {
                debug!(%user_id, ?lorebook_ids, "Retrieving constant lorebook entries for RAG");
                let mut constant_lorebook_id_conditions = Vec::new();
                for lorebook_id_val in lorebook_ids {
                    constant_lorebook_id_conditions.push(Condition {
                        condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                            key: "lorebook_id".to_string(),
                            r#match: Some(Match {
                                match_value: Some(MatchValue::Keyword(lorebook_id_val.to_string())),
                            }),
                            ..Default::default()
                        })),
                    });
                }

                let constant_filter = Filter {
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
                                    match_value: Some(MatchValue::Keyword(
                                        "lorebook_entry".to_string(),
                                    )),
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
                        Condition {
                            condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                                key: "is_constant".to_string(),
                                r#match: Some(Match {
                                    match_value: Some(MatchValue::Boolean(true)),
                                }),
                                ..Default::default()
                            })),
                        },
                    ],
                    should: constant_lorebook_id_conditions,
                    ..Default::default()
                };
                debug!(?constant_filter, "Constant lorebook filter for RAG");

                // For constant entries, we use retrieve_points to get ALL matches
                // rather than just the top-k by similarity
                match qdrant_service
                    .retrieve_points(Some(constant_filter.clone()), 1000)
                    .await
                {
                    Ok(retrieve_results) => {
                        debug!(
                            num_constant_results = retrieve_results.len(),
                            ?lorebook_ids,
                            "Raw Qdrant retrieve results for constant lorebook entries (RAG)"
                        );
                        for point in retrieve_results {
                            debug!(point_id = ?point.id, ?lorebook_ids, "Processing constant lorebook point (RAG)");
                            match LorebookChunkMetadata::try_from(point.payload.clone()) {
                                Ok(lorebook_meta) => {
                                    debug!(
                                        ?lorebook_meta,
                                        ?lorebook_ids,
                                        "Successfully parsed constant lorebook metadata (RAG)"
                                    );
                                    // Give constant entries a high score to ensure they appear at the top
                                    combined_results.push(RetrievedChunk {
                                        score: 1.0, // Maximum score for constant entries
                                        text: lorebook_meta.chunk_text.clone(),
                                        metadata: RetrievedMetadata::Lorebook(lorebook_meta),
                                    });
                                }
                                Err(e) => {
                                    warn!(
                                        point_id = %point.id.as_ref().map(|id| format!("{id:?}")).unwrap_or_default(),
                                        error = %e,
                                        payload = ?point.payload,
                                        ?lorebook_ids,
                                        "Failed to parse constant lorebook entry payload during RAG search"
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, filter = ?constant_filter, ?lorebook_ids, "Failed to retrieve constant lorebooks in Qdrant (RAG)");
                        // Continue with other results even if constant entry retrieval fails
                    }
                }
            }
        }

        // Sort combined results by score in descending order
        combined_results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        debug!(
            num_combined_results = combined_results.len(),
            query_text, "Final combined and sorted RAG chunks"
        );

        info!(
            "Retrieved {} relevant chunks in total",
            combined_results.len()
        );
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
                            match_value: Some(MatchValue::Keyword(
                                original_lorebook_entry_id.to_string(),
                            )),
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
        debug!(
            ?filter,
            "Constructed filter for deleting lorebook entry chunks"
        );

        qdrant_service.delete_points_by_filter(filter).await?;
        info!(
            "Successfully deleted chunks for lorebook entry {} for user {}",
            original_lorebook_entry_id, user_id
        );
        Ok(())
    }
}

