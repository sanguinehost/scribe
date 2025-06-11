use crate::PgPool;
use crate::{
    AppState,
    auth::user_store::Backend as AuthBackend,
    errors::AppError,
    models::{
        Chat, // Changed from chats::ChatSession
        Lorebook,
        LorebookEntry,
        NewChatSessionLorebook, // Import directly
        NewLorebookEntry,
        lorebook_dtos::{
            AssociateLorebookToChatPayload, ChatSessionBasicInfo,
            ChatSessionLorebookAssociationResponse, CreateLorebookEntryPayload,
            CreateLorebookPayload, LorebookEntryResponse, LorebookEntrySummaryResponse,
            LorebookResponse, UpdateLorebookEntryPayload, UpdateLorebookPayload,
        },
    },
    schema::{lorebook_entries, lorebooks},
    services::{EncryptionService, embeddings::LorebookEntryParams},
    vector_db::qdrant_client::{
        Condition, ConditionOneOf, FieldCondition, Filter, Match, MatchValue,
        QdrantClientServiceTrait,
    },
};
use axum_login::AuthSession;
use chrono::Utc;
use diesel::result::{DatabaseErrorKind, Error as DieselError}; // Added for specific error handling
use diesel::{RunQueryDsl, SelectableHelper, prelude::*};
use secrecy::{ExposeSecret, SecretBox};
use std::sync::Arc;
use tracing::{debug, error, info, instrument};
use uuid::Uuid;
impl From<crate::models::lorebook_dtos::ScribeMinimalLorebook> for CreateLorebookPayload {
    fn from(val: crate::models::lorebook_dtos::ScribeMinimalLorebook) -> Self {
        Self {
            name: val.name,
            description: val.description,
        }
    }
}

#[derive(Clone)]
pub struct LorebookService {
    pool: PgPool,
    // TODO: Remove once encryption is implemented for lorebooks
    encryption_service: Arc<EncryptionService>, // Store as Arc
    qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync>, // Added for vector cleanup
}

// Module declarations
mod lorebook_crud;
mod entry_crud;
mod chat_associations;
mod character_associations;
mod export_import;
mod helpers;

// Re-export important items
pub use helpers::get_user_from_session;

impl LorebookService {
    #[must_use]
    pub fn new(
        pool: PgPool,
        encryption_service: Arc<EncryptionService>,
        qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync>,
    ) -> Self {
        // Accept Arc
        Self {
            pool,
            encryption_service,
            qdrant_service,
        }
    }
}
