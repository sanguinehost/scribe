use crate::db::DbPool;
use crate::{
    auth::user_store::Backend as AuthBackend,
    errors::AppError,
    models::{
        lorebook_dtos::{
            AssociateLorebookToChatPayload, ChatSessionBasicInfo,
            ChatSessionLorebookAssociationResponse, CreateLorebookEntryPayload,
            CreateLorebookPayload, LorebookEntryResponse, LorebookEntrySummaryResponse,
            LorebookResponse, UpdateLorebookEntryPayload, UpdateLorebookPayload,
        },
        Chat, // Changed from chats::ChatSession
        Lorebook,
        LorebookEntry,
        NewChatSessionLorebook, // Import directly
        NewLorebookEntry,
    },
    schema::{lorebook_entries, lorebooks},
    services::{embeddings::LorebookEntryParams, EncryptionService},
    vector_db::qdrant_client::{
        Condition, ConditionOneOf, FieldCondition, Filter, Match, MatchValue,
        QdrantClientServiceTrait,
    },
    AppState,
};
use axum_login::AuthSession;
use chrono::Utc;
use diesel::result::{DatabaseErrorKind, Error as DieselError}; // Added for specific error handling
use diesel::{prelude::*, RunQueryDsl, SelectableHelper};
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
    pool: DbPool,
    // TODO: Remove once encryption is implemented for lorebooks
    encryption_service: Arc<EncryptionService>, // Store as Arc
    qdrant_service: Arc<dyn QdrantClientServiceTrait + Send + Sync>, // Added for vector cleanup
}

// Module declarations
mod character_associations;
mod chat_associations;
mod chat_extraction;
mod entry_crud;
mod export_import;
mod helpers;
mod lorebook_crud;

// Re-export important items
pub use helpers::get_user_from_session;

impl LorebookService {
    #[must_use]
    pub fn new(
        pool: DbPool,
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

    /// Test-only method to list lorebook entries without authentication
    /// This bypasses the normal AuthSession requirement for testing purposes
    pub async fn list_lorebook_entries_for_test(
        &self,
        user_id: crate::DbUuid,
        lorebook_id: crate::DbUuid,
    ) -> Result<Vec<LorebookEntrySummaryResponse>, AppError> {
        debug!(
            "Attempting to list lorebook entries for test (user: {}, lorebook: {})",
            user_id, lorebook_id
        );

        let conn = crate::db::get_conn(&self.pool).await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        // 1. Verify lorebook ownership (same as normal method)
        let lorebook_id_clone = lorebook_id;
        let user_id_clone = user_id;
        let _lorebook = conn
            .interact(move |conn_sync| {
                lorebooks::table
                    .filter(lorebooks::id.eq(lorebook_id_clone))
                    .filter(lorebooks::user_id.eq(user_id_clone)) // Ensure ownership
                    .select(Lorebook::as_select())
                    .first::<Lorebook>(conn_sync)
                    .optional()
            })
            .await
            .map_err(|e| {
                error!(
                    "Interaction error while fetching lorebook for test: {:?}",
                    e
                );
                AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while fetching lorebook: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to query lorebook for test: {:?}", e);
                AppError::DatabaseQueryError(format!("Failed to query lorebook: {e}"))
            })?
            .ok_or_else(|| {
                error!(
                    "Lorebook with ID {} not found or user {} does not have access.",
                    lorebook_id, user_id
                );
                AppError::NotFound(format!(
                    "Lorebook with ID {lorebook_id} not found or access denied."
                ))
            })?;

        // 2. Fetch all entries for the lorebook (simplified version without decryption)
        let lorebook_id_clone = lorebook_id;
        let entries = conn
            .interact(move |conn_sync| {
                lorebook_entries::table
                    .filter(lorebook_entries::lorebook_id.eq(lorebook_id_clone))
                    .order(lorebook_entries::created_at.asc())
                    .select(LorebookEntry::as_select())
                    .load::<LorebookEntry>(conn_sync)
            })
            .await
            .map_err(|e| {
                error!(
                    "Interaction error while fetching lorebook entries for test: {:?}",
                    e
                );
                AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while fetching lorebook entries: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to query lorebook entries for test: {:?}", e);
                AppError::DatabaseQueryError(format!("Failed to query lorebook entries: {e}"))
            })?;

        // 3. Return summary responses (without decryption for simplicity in tests)
        let entry_responses: Vec<LorebookEntrySummaryResponse> = entries
            .into_iter()
            .map(|entry| LorebookEntrySummaryResponse {
                id: entry.id,
                lorebook_id: entry.lorebook_id,
                entry_title: format!("Test-{}", entry.id), // Simplified for testing
                is_enabled: true,                          // Default for tests
                is_constant: false,                        // Default for tests
                insertion_order: 1,                        // Default for tests
                updated_at: entry.updated_at,
            })
            .collect();

        Ok(entry_responses)
    }

    /// Test-only method to create lorebook without authentication
    /// This bypasses the normal AuthSession requirement for testing purposes
    pub async fn create_lorebook_for_test(
        &self,
        user_id: crate::DbUuid,
        payload: CreateLorebookPayload,
    ) -> Result<LorebookResponse, AppError> {
        debug!("Attempting to create lorebook for test (user: {})", user_id);

        let new_lorebook_id = Uuid::new_v4();
        let current_time = Utc::now();

        let new_lorebook_db = crate::models::NewLorebook {
            id: new_lorebook_id,
            user_id,
            name: payload.name.clone(),
            description: payload.description.clone(),
            source_format: "scribe_v1".to_string(),
            is_public: false, // Default for tests
            created_at: Some(current_time),
            updated_at: Some(current_time),
        };

        let conn = crate::db::get_conn(&self.pool).await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        let lorebook = conn
            .interact(move |conn_sync| {
                use diesel::RunQueryDsl;
                diesel::insert_into(lorebooks::table)
                    .values(&new_lorebook_db)
                    .returning(Lorebook::as_returning())
                    .get_result(conn_sync)
            })
            .await
            .map_err(|e| {
                error!(
                    "Interaction error while creating lorebook for test: {:?}",
                    e
                );
                AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while creating lorebook: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to create lorebook for test: {:?}", e);
                AppError::DatabaseQueryError(format!("Failed to create lorebook: {e}"))
            })?;

        Ok(LorebookResponse {
            id: lorebook.id,
            user_id: lorebook.user_id,
            name: lorebook.name,
            description: lorebook.description,
            source_format: lorebook.source_format,
            is_public: lorebook.is_public,
            created_at: lorebook.created_at,
            updated_at: lorebook.updated_at,
        })
    }

    /// Test-only method to create lorebook entry without authentication
    /// This bypasses the normal AuthSession requirement for testing purposes
    pub async fn create_lorebook_entry_for_test(
        &self,
        user_id: crate::DbUuid,
        lorebook_id: crate::DbUuid,
        payload: CreateLorebookEntryPayload,
        user_dek: &SecretBox<Vec<u8>>,
    ) -> Result<LorebookEntryResponse, AppError> {
        debug!(
            "Attempting to create lorebook entry for test (user: {}, lorebook: {})",
            user_id, lorebook_id
        );

        let conn = crate::db::get_conn(&self.pool).await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        // 1. Verify lorebook ownership (same as normal method)
        let lorebook_id_clone = lorebook_id;
        let user_id_clone = user_id;
        let _lorebook = conn
            .interact(move |conn_sync| {
                use crate::schema::lorebooks;
                use diesel::{QueryDsl, RunQueryDsl, SelectableHelper};
                lorebooks::table
                    .filter(lorebooks::id.eq(lorebook_id_clone))
                    .filter(lorebooks::user_id.eq(user_id_clone)) // Ensure ownership
                    .select(Lorebook::as_select())
                    .first::<Lorebook>(conn_sync)
                    .optional()
            })
            .await
            .map_err(|e| {
                error!(
                    "Interaction error while fetching lorebook for test: {:?}",
                    e
                );
                AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while fetching lorebook: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to query lorebook for test: {:?}", e);
                AppError::DatabaseQueryError(format!("Failed to query lorebook: {e}"))
            })?
            .ok_or_else(|| {
                error!(
                    "Lorebook with ID {} not found or user {} does not have access.",
                    lorebook_id, user_id
                );
                AppError::NotFound(format!(
                    "Lorebook with ID {lorebook_id} not found or access denied."
                ))
            })?;

        // 2. Encrypt sensitive fields
        let user_dek_bytes = user_dek.expose_secret();

        let (entry_title_ciphertext, entry_title_nonce) = self
            .encryption_service
            .encrypt(&payload.entry_title, user_dek_bytes)?;

        let text_to_encrypt_for_keys = payload.keys_text.as_deref().unwrap_or("");
        let (keys_text_ciphertext, keys_text_nonce) = self
            .encryption_service
            .encrypt(text_to_encrypt_for_keys, user_dek_bytes)?;

        let (content_ciphertext, content_nonce) = self
            .encryption_service
            .encrypt(&payload.content, user_dek_bytes)?;

        let (comment_ciphertext, comment_nonce) = match &payload.comment {
            Some(text) if !text.is_empty() => {
                let (cipher, nonce) = self.encryption_service.encrypt(text, user_dek_bytes)?;
                (Some(cipher), Some(nonce))
            }
            Some(_) => {
                // Handles Some("")
                let (cipher, nonce) = self.encryption_service.encrypt("", user_dek_bytes)?;
                (Some(cipher), Some(nonce))
            }
            None => (None, None), // For None comment, store None for ciphertext and nonce
        };

        let current_time = Utc::now();
        let new_entry_id = Uuid::new_v4();

        let new_entry_db = crate::models::NewLorebookEntry {
            id: new_entry_id,
            lorebook_id,
            user_id,
            original_sillytavern_uid: None,
            entry_title_ciphertext,
            entry_title_nonce,
            keys_text_ciphertext,
            keys_text_nonce,
            content_ciphertext,
            content_nonce,
            comment_ciphertext,
            comment_nonce,
            is_enabled: payload.is_enabled.unwrap_or(true),
            is_constant: payload.is_constant.unwrap_or(false),
            insertion_order: payload.insertion_order.unwrap_or(100),
            placement_hint: payload.placement_hint.clone(),
            sillytavern_metadata_ciphertext: None,
            sillytavern_metadata_nonce: None,
            name: Some(payload.entry_title.clone()),
            created_at: Some(current_time),
            updated_at: Some(current_time),
        };

        // 3. Insert into database
        #[cfg(feature = "postgres-backend")]
        let lorebook_entry = {
            conn
                .interact(move |conn_sync| {
                    use crate::schema::lorebook_entries;
                    use diesel::RunQueryDsl;
                    diesel::insert_into(lorebook_entries::table)
                        .values(&new_entry_db)
                        .returning(LorebookEntry::as_returning())
                        .get_result(conn_sync)
                })
                .await
                .map_err(|e| {
                    error!(
                        "Interaction error while creating lorebook entry for test: {:?}",
                        e
                    );
                    AppError::InternalServerErrorGeneric(format!(
                        "Database interaction failed while creating lorebook entry: {e}"
                    ))
                })?
                .map_err(|e| {
                    error!("Failed to create lorebook entry for test: {:?}", e);
                    AppError::DatabaseQueryError(format!("Failed to create lorebook entry: {e}"))
                })?
        };

        #[cfg(feature = "sqlite-backend")]
        let lorebook_entry = {
            use diesel::prelude::*;
            use crate::schema::lorebook_entries;

            // SQLite doesn't support RETURNING, so we insert and query back by ID
            let entry_id_clone = new_entry_db.id;

            crate::db::with_conn(&self.db_pool, move |conn_sync| {
                diesel::insert_into(lorebook_entries::table)
                    .values(&new_entry_db)
                    .execute(conn_sync)
                    .map_err(|e| AppError::DatabaseQueryError(format!("Failed to create lorebook entry: {e}")))?;

                lorebook_entries::table
                    .find(entry_id_clone)
                    .select(LorebookEntry::as_select())
                    .first::<LorebookEntry>(conn_sync)
                    .map_err(|e| AppError::DatabaseQueryError(format!("Failed to query lorebook entry after insert: {e}")))
            })
            .await?
        };

        // 4. Return response (simplified for test - we'll just return basic info)
        Ok(LorebookEntryResponse {
            id: lorebook_entry.id,
            lorebook_id: lorebook_entry.lorebook_id,
            user_id: lorebook_entry.user_id,
            entry_title: payload.entry_title,
            keys_text: payload.keys_text,
            content: payload.content,
            comment: payload.comment,
            is_enabled: lorebook_entry.is_enabled,
            is_constant: lorebook_entry.is_constant,
            insertion_order: lorebook_entry.insertion_order,
            placement_hint: lorebook_entry
                .placement_hint
                .unwrap_or_else(|| "after_prompt".to_string()),
            created_at: lorebook_entry.created_at,
            updated_at: lorebook_entry.updated_at,
        })
    }
}
