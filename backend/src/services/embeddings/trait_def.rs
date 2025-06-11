use crate::errors::AppError;
use crate::auth::session_dek::SessionDek;
use crate::models::chats::ChatMessage;
use crate::state::AppState;
use super::metadata::LorebookEntryParams;
use super::retrieval::RetrievedChunk;
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

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
        params: LorebookEntryParams,
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
