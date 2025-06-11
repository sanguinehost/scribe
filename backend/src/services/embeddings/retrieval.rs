use crate::errors::AppError;
use crate::llm::EmbeddingClient;
use crate::vector_db::qdrant_client::QdrantClientServiceTrait;
use super::metadata::{ChatMessageChunkMetadata, LorebookChunkMetadata};
use std::sync::Arc;
use tracing::{info, instrument, warn};
use uuid::Uuid;

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
#[allow(dead_code)]
#[instrument(skip(qdrant_service, embedding_client), err)]
async fn retrieve_relevant_chunks_standalone(
    qdrant_service: Arc<dyn QdrantClientServiceTrait>,
    embedding_client: Arc<dyn EmbeddingClient>,
    session_id: Uuid,
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
