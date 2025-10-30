use super::metadata::LorebookEntryParams;
use super::retrieval::RetrievedChunk;
use crate::auth::session_dek::SessionDek;
use crate::errors::AppError;
use crate::models::chats::ChatMessage;
use crate::models::chronicle_event::ChronicleEvent;
use crate::state::AppState;
use async_trait::async_trait;
use std::sync::Arc;

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

    /// Processes a chronicle event: chunks, embeds, and stores it.
    async fn process_and_embed_chronicle_event(
        &self,
        state: Arc<AppState>,
        event: ChronicleEvent,
        session_dek: Option<&crate::auth::session_dek::SessionDek>,
    ) -> Result<(), AppError>;

    /// Deletes all chunks associated with specific message IDs.
    async fn delete_message_chunks(
        &self,
        state: Arc<AppState>,
        message_ids: Vec<crate::db::DbId>,
        user_id: crate::db::DbId,
    ) -> Result<(), AppError>;

    /// Deletes all chunks associated with a specific lorebook entry.
    async fn delete_lorebook_entry_chunks(
        &self,
        state: Arc<AppState>,
        original_lorebook_entry_id: crate::db::DbId,
        user_id: crate::db::DbId,
    ) -> Result<(), AppError>;

    /// Deletes all chunks associated with a specific chronicle event.
    async fn delete_chronicle_event_chunks(
        &self,
        state: Arc<AppState>,
        event_id: crate::db::DbId,
        user_id: crate::db::DbId,
    ) -> Result<(), AppError>;

    /// Deletes all chronicle event chunks associated with a specific chronicle.
    async fn delete_chronicle_events_by_chronicle_id(
        &self,
        state: Arc<AppState>,
        chronicle_id: crate::db::DbId,
        user_id: crate::db::DbId,
    ) -> Result<(), AppError>;

    /// Retrieves relevant chunks based on a query.
    async fn retrieve_relevant_chunks(
        &self,
        state: Arc<AppState>,
        user_id: crate::db::DbId, // To scope searches to the current user
        session_id_for_chat_history: Option<crate::db::DbId>, // If Some, search chat history for this session
        active_lorebook_ids_for_search: Option<Vec<crate::db::DbId>>, // If Some, search these lorebooks
        chronicle_id_for_search: Option<crate::db::DbId>, // If Some, search chronicle events for this chronicle
        query_text: &str,
        limit_per_source: u64, // e.g., retrieve top N from chat, top M from lorebooks, top K from chronicles
        session_dek: Option<&crate::auth::SessionDek>, // DEK for decrypting retrieved content
    ) -> Result<Vec<RetrievedChunk>, AppError>;
}
