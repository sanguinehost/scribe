use super::metadata::{ChatMessageChunkMetadata, LorebookChunkMetadata};
use super::utils::{extract_string_from_payload, extract_uuid_from_payload};
use crate::auth::SessionDek;
use crate::errors::AppError;
use crate::llm::EmbeddingClient;
use crate::vector_db::qdrant_client::QdrantClientServiceTrait;
use qdrant_client::qdrant::Value as QdrantValue;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, instrument, warn};

/// Helper function to decrypt lorebook content (encryption required)
#[allow(deprecated)]
pub fn decrypt_lorebook_content(
    metadata: &LorebookChunkMetadata,
    session_dek: Option<&SessionDek>,
) -> String {
    // Try to decrypt if we have encrypted content
    if let (Some(ref encrypted_chunk), Some(ref nonce)) = (
        metadata.encrypted_chunk_text.as_ref(),
        metadata.chunk_text_nonce.as_ref(),
    ) {
        // We have encrypted content
        if let Some(dek) = session_dek {
            match crate::crypto::decrypt_gcm(encrypted_chunk, nonce, &dek.0) {
                Ok(decrypted_secret) => {
                    let decrypted_bytes = secrecy::ExposeSecret::expose_secret(&decrypted_secret);
                    return String::from_utf8_lossy(decrypted_bytes).to_string();
                }
                Err(e) => {
                    warn!("Failed to decrypt lorebook content: {}", e);
                    return "[decryption failed]".to_string();
                }
            }
        } else {
            // No DEK available
            return "[encrypted - no DEK available]".to_string();
        }
    }

    // SECURITY: Missing encryption is a critical error - all data must be encrypted at rest
    warn!(
        "SECURITY VIOLATION: Lorebook content missing encryption (entry_id: {:?})",
        metadata.original_lorebook_entry_id
    );
    "[MISSING ENCRYPTION - SECURITY VIOLATION]".to_string()
}

/// Helper function to decrypt lorebook title (encryption required)
#[allow(deprecated)]
pub fn decrypt_lorebook_title(
    metadata: &LorebookChunkMetadata,
    session_dek: Option<&SessionDek>,
) -> String {
    // Try to decrypt if we have encrypted title
    if let (Some(ref encrypted_title), Some(ref nonce)) = (
        metadata.encrypted_title.as_ref(),
        metadata.title_nonce.as_ref(),
    ) {
        // We have encrypted title
        if let Some(dek) = session_dek {
            match crate::crypto::decrypt_gcm(encrypted_title, nonce, &dek.0) {
                Ok(decrypted_secret) => {
                    let decrypted_bytes = secrecy::ExposeSecret::expose_secret(&decrypted_secret);
                    let title = String::from_utf8_lossy(decrypted_bytes).to_string();
                    if title.trim().is_empty() {
                        return metadata
                            .entry_title
                            .clone()
                            .unwrap_or_else(|| "Untitled".to_string());
                    }
                    return title;
                }
                Err(e) => {
                    warn!("Failed to decrypt lorebook title: {}", e);
                    return metadata
                        .entry_title
                        .clone()
                        .unwrap_or_else(|| "[decryption failed]".to_string());
                }
            }
        } else {
            // No DEK available
            return metadata
                .entry_title
                .clone()
                .unwrap_or_else(|| "[encrypted - no DEK]".to_string());
        }
    }

    // Fallback to unencrypted title if present
    metadata
        .entry_title
        .clone()
        .unwrap_or_else(|| "Untitled".to_string())
}

/// Helper function to decrypt chat message content (encryption required)
#[allow(deprecated)]
pub fn decrypt_chat_content(
    metadata: &ChatMessageChunkMetadata,
    session_dek: Option<&SessionDek>,
) -> String {
    // Try to decrypt if we have encrypted content
    if let (Some(ref encrypted_text), Some(ref nonce)) = (
        metadata.encrypted_text.as_ref(),
        metadata.text_nonce.as_ref(),
    ) {
        // We have encrypted content
        if let Some(dek) = session_dek {
            match crate::crypto::decrypt_gcm(encrypted_text, nonce, &dek.0) {
                Ok(decrypted_secret) => {
                    let decrypted_bytes = secrecy::ExposeSecret::expose_secret(&decrypted_secret);
                    return String::from_utf8_lossy(decrypted_bytes).to_string();
                }
                Err(e) => {
                    warn!("Failed to decrypt chat message: {}", e);
                    return "[decryption failed]".to_string();
                }
            }
        } else {
            // No DEK available
            return "[encrypted - no DEK available]".to_string();
        }
    }

    // SECURITY: Missing encryption is a critical error - all data must be encrypted at rest
    warn!(
        "SECURITY VIOLATION: Chat message missing encryption (message_id: {:?})",
        metadata.message_id
    );
    "[MISSING ENCRYPTION - SECURITY VIOLATION]".to_string()
}

// ChronicleEventMetadata moved to metadata.rs
use super::metadata::ChronicleEventMetadata;

#[derive(Debug, Clone)]
pub enum RetrievedMetadata {
    Chat(ChatMessageChunkMetadata),
    Lorebook(LorebookChunkMetadata),
    Chronicle(ChronicleEventMetadata),
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
#[allow(dead_code)]
#[instrument(skip(qdrant_service, embedding_client), err)]
#[allow(deprecated)]
async fn retrieve_relevant_chunks_standalone(
    qdrant_service: Arc<dyn QdrantClientServiceTrait>,
    embedding_client: Arc<dyn EmbeddingClient>,
    session_id: crate::db::DbId,
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
        if payload_map.is_empty() {
            warn!(point_id = %scored_point.id.as_ref().map(|id| format!("{id:?}")).unwrap_or_default(), "Scored point has an empty payload (standalone)");
        } else if let Ok(lorebook_meta) = LorebookChunkMetadata::try_from(payload_map.clone()) {
            let text = decrypt_lorebook_content(&lorebook_meta, None); // No DEK in standalone search
            retrieved_chunks.push(RetrievedChunk {
                score: scored_point.score,
                text,
                metadata: RetrievedMetadata::Lorebook(lorebook_meta),
            });
        } else if let Ok(chat_meta) = ChatMessageChunkMetadata::try_from(payload_map) {
            let text = decrypt_chat_content(&chat_meta, None); // No DEK in standalone search
            retrieved_chunks.push(RetrievedChunk {
                score: scored_point.score,
                text,
                metadata: RetrievedMetadata::Chat(chat_meta),
            });
        } else {
            warn!(
                point_id = %scored_point.id.as_ref().map(|id| format!("{id:?}")).unwrap_or_default(),
                "Failed to parse payload as any known metadata type (standalone)"
            );
        }
    }
    info!(
        "Retrieved {} relevant chunks (standalone, broad search)",
        retrieved_chunks.len()
    );
    Ok(retrieved_chunks)
}
