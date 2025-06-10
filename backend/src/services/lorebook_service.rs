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
        users::User,
    },
    schema::{lorebook_entries, lorebooks},
    services::{EncryptionService, embedding_pipeline::LorebookEntryParams},
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

    // --- Lorebook Methods ---

    /// Creates a new lorebook for the authenticated user.
    ///
    /// # Errors
    ///
    /// Returns `AppError::Unauthorized` if the user is not authenticated,
    /// `AppError::InternalServerErrorGeneric` if database connection fails or database interaction errors occur,
    /// database-related errors if the lorebook insertion fails.
    #[instrument(skip(self, auth_session, payload), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)))]
    pub async fn create_lorebook(
        &self,
        auth_session: &AuthSession<AuthBackend>, // Changed to AuthBackend
        payload: CreateLorebookPayload,
    ) -> Result<LorebookResponse, AppError> {
        debug!(?payload, "Attempting to create lorebook");
        let user = Self::get_user_from_session(auth_session)?;

        let new_lorebook_id = Uuid::new_v4();
        let current_time = Utc::now();

        let new_lorebook_db = crate::models::NewLorebook {
            id: new_lorebook_id,
            user_id: user.id,
            name: payload.name,
            description: payload.description,
            source_format: "scribe_v1".to_string(), // Default for API created
            is_public: false,                       // Default to private
            created_at: Some(current_time),
            updated_at: Some(current_time),
        };

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        let inserted_lorebook = conn
            .interact(move |conn_sync| {
                diesel::insert_into(lorebooks::table)
                    .values(&new_lorebook_db)
                    .returning(Lorebook::as_returning()) // Specify returning columns
                    .get_result::<Lorebook>(conn_sync)
            })
            .await
            .map_err(|e| {
                error!("Interaction error while inserting lorebook: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while creating lorebook: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to insert lorebook into DB: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Failed to create lorebook in DB: {e}"
                ))
            })?;

        info!("Successfully created lorebook [REDACTED_UUID] for user [REDACTED_UUID]");

        Ok(LorebookResponse {
            id: inserted_lorebook.id,
            user_id: inserted_lorebook.user_id,
            name: inserted_lorebook.name,
            description: inserted_lorebook.description,
            source_format: inserted_lorebook.source_format,
            is_public: inserted_lorebook.is_public,
            created_at: inserted_lorebook.created_at,
            updated_at: inserted_lorebook.updated_at,
        })
    }

    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)))]
    pub async fn list_lorebooks(
        &self,
        auth_session: &AuthSession<AuthBackend>,
    ) -> Result<Vec<LorebookResponse>, AppError> {
        debug!("Attempting to list lorebooks");
        let user = Self::get_user_from_session(auth_session)?;

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        let lorebooks_db = conn
            .interact(move |conn_sync| {
                lorebooks::table
                    .filter(lorebooks::user_id.eq(user.id))
                    .order(lorebooks::updated_at.desc()) // Or by name, or created_at
                    .select(Lorebook::as_select()) // Ensure selected columns match the struct
                    .load::<Lorebook>(conn_sync)
            })
            .await
            .map_err(|e| {
                error!("Interaction error while listing lorebooks: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while listing lorebooks: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to list lorebooks from DB: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Failed to list lorebooks from DB: {e}"
                ))
            })?;

        let lorebook_responses = lorebooks_db
            .into_iter()
            .map(|lb| LorebookResponse {
                id: lb.id,
                user_id: lb.user_id,
                name: lb.name,               // No decryption needed for Lorebook name
                description: lb.description, // No decryption needed for Lorebook description
                source_format: lb.source_format,
                is_public: lb.is_public,
                created_at: lb.created_at,
                updated_at: lb.updated_at,
            })
            .collect();

        Ok(lorebook_responses)
    }

    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id))]
    pub async fn get_lorebook(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        lorebook_id: Uuid,
    ) -> Result<LorebookResponse, AppError> {
        debug!(%lorebook_id, "Attempting to get lorebook");
        let user = Self::get_user_from_session(auth_session)?;

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        let lorebook_db = conn
            .interact(move |conn_sync| {
                lorebooks::table
                    .filter(lorebooks::id.eq(lorebook_id))
                    .select(Lorebook::as_select())
                    .first::<Lorebook>(conn_sync)
                    .optional() // Makes it return Result<Option<Lorebook>, _>
            })
            .await
            .map_err(|e| {
                error!("Interaction error while getting lorebook: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while getting lorebook: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to get lorebook from DB: {:?}", e);
                // This specific error might indicate a problem beyond just "not found"
                // but for now, we'll let the None case handle typical not found.
                AppError::DatabaseQueryError(e.to_string())
            })?;

        match lorebook_db {
            Some(lb) => {
                if lb.user_id != user.id {
                    // If the lorebook exists but belongs to another user, treat as Not Found
                    // to avoid leaking information about resource existence.
                    // Alternatively, could return AppError::Forbidden.
                    error!(
                        "User [REDACTED_UUID] attempted to access lorebook [REDACTED_UUID] owned by user [REDACTED_UUID]"
                    );
                    return Err(AppError::NotFound(format!(
                        "Lorebook with ID {lorebook_id} not found."
                    )));
                }
                Ok(LorebookResponse {
                    id: lb.id,
                    user_id: lb.user_id,
                    name: lb.name,
                    description: lb.description,
                    source_format: lb.source_format,
                    is_public: lb.is_public,
                    created_at: lb.created_at,
                    updated_at: lb.updated_at,
                })
            }
            None => Err(AppError::NotFound(format!(
                "Lorebook with ID {lorebook_id} not found."
            ))),
        }
    }

    #[instrument(skip(self, auth_session, payload), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id))]
    pub async fn update_lorebook(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        lorebook_id: Uuid,
        payload: UpdateLorebookPayload,
    ) -> Result<LorebookResponse, AppError> {
        debug!(?payload, "Attempting to update lorebook");

        // 1. Get current user
        let user = Self::get_user_from_session(auth_session)?;

        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        // 2. Fetch lorebook by id and check ownership
        let updated_lorebook = conn
            .interact(move |conn| {
                use crate::schema::lorebooks::dsl::{
                    description, id, lorebooks, name, updated_at, user_id,
                };

                // First verify the lorebook exists and belongs to the user
                let existing_lorebook = lorebooks
                    .filter(id.eq(lorebook_id))
                    .filter(user_id.eq(user.id))
                    .select(Lorebook::as_select())
                    .first::<Lorebook>(conn)
                    .optional()
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                if let Some(existing) = existing_lorebook {
                    // User owns this lorebook, proceed with update
                    // Build the update dynamically based on what fields are provided
                    let update_query = diesel::update(lorebooks.filter(id.eq(lorebook_id)));

                    // Only update fields that are provided (Some)
                    let new_name = payload.name.unwrap_or(existing.name);
                    let new_description = payload.description.or(existing.description);

                    let _rows_updated = update_query
                        .set((
                            name.eq(new_name),
                            description.eq(new_description),
                            updated_at.eq(Utc::now()),
                        ))
                        .execute(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    // Fetch the updated lorebook with proper column ordering
                    let updated = lorebooks
                        .filter(id.eq(lorebook_id))
                        .select(Lorebook::as_select())
                        .first::<Lorebook>(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    tracing::info!(
                        "Successfully updated lorebook [REDACTED_UUID] for user [REDACTED_UUID]"
                    );
                    Ok(updated)
                } else {
                    // Check if lorebook exists but belongs to another user
                    let exists = lorebooks
                        .filter(id.eq(lorebook_id))
                        .select(id)
                        .first::<Uuid>(conn)
                        .optional()
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                    if exists.is_some() {
                        Err(AppError::Forbidden("Access denied to lorebook".to_string()))
                    } else {
                        Err(AppError::NotFound("Lorebook not found".to_string()))
                    }
                }
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("Database interaction error: {e}")))??;

        // 6. Map to LorebookResponse
        Ok(LorebookResponse {
            id: updated_lorebook.id,
            user_id: updated_lorebook.user_id,
            name: updated_lorebook.name,
            description: updated_lorebook.description,
            source_format: updated_lorebook.source_format,
            is_public: updated_lorebook.is_public,
            created_at: updated_lorebook.created_at,
            updated_at: updated_lorebook.updated_at,
        })
    }

    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id))]
    pub async fn delete_lorebook(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        lorebook_id: Uuid,
    ) -> Result<(), AppError> {
        debug!("Attempting to delete lorebook");

        // 1. Get current user
        let user = Self::get_user_from_session(auth_session)?;

        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        // 2. Delete lorebook and verify ownership in a single transaction

        // Perform database deletion first
        conn
            .interact(move |conn| {
                use crate::schema::lorebooks::dsl::{id, lorebooks, user_id};

                // First verify the lorebook exists and belongs to the user
                let lorebook_owner = lorebooks
                    .filter(id.eq(lorebook_id))
                    .select(user_id)
                    .first::<Uuid>(conn)
                    .optional()
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                match lorebook_owner {
                    Some(owner_id) if owner_id == user.id => {
                        // User owns this lorebook
                        // Due to foreign key constraints with CASCADE DELETE,
                        // deleting the lorebook will automatically delete:
                        // - All lorebook_entries
                        // - All chat_session_lorebooks associations

                        diesel::delete(
                            lorebooks
                                .filter(id.eq(lorebook_id))
                                .filter(user_id.eq(user.id)),
                        )
                        .execute(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                        tracing::info!(
                            "Successfully deleted lorebook [REDACTED_UUID] from database for user [REDACTED_UUID]"
                        );
                        Ok(())
                    }
                    Some(_) => {
                        // Lorebook exists but belongs to another user
                        Err(AppError::Forbidden("Access denied to lorebook".to_string()))
                    }
                    None => {
                        // Lorebook doesn't exist
                        Err(AppError::NotFound("Lorebook not found".to_string()))
                    }
                }
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("Database interaction error: {e}")))??; // Propagate the error

        // After successful database deletion, clean up vector embeddings
        tracing::info!(
            "Cleaning up vector embeddings for lorebook [REDACTED_UUID] for user [REDACTED_UUID]"
        );

        let vector_filter = Filter {
            must: vec![
                Condition {
                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                        key: "lorebook_id".to_string(),
                        r#match: Some(Match {
                            match_value: Some(MatchValue::Keyword(lorebook_id.to_string())),
                        }),
                        ..Default::default()
                    })),
                },
                Condition {
                    condition_one_of: Some(ConditionOneOf::Field(FieldCondition {
                        key: "user_id".to_string(),
                        r#match: Some(Match {
                            match_value: Some(MatchValue::Keyword(user.id.to_string())),
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

        // Delete vector embeddings
        if let Err(e) = self
            .qdrant_service
            .delete_points_by_filter(vector_filter)
            .await
        {
            // Log the error but don't fail the entire operation since DB deletion succeeded
            error!(
                error = %e,
                lorebook_id = "[REDACTED_UUID]",
                user_id = "[REDACTED_UUID]",
                "Failed to delete vector embeddings for lorebook, but database deletion succeeded"
            );
        } else {
            tracing::info!(
                "Successfully deleted vector embeddings for lorebook [REDACTED_UUID] for user [REDACTED_UUID]"
            );
        }

        tracing::info!(
            "Successfully completed full deletion (database + vectors) for lorebook [REDACTED_UUID] for user [REDACTED_UUID]"
        );

        Ok(())
    }

    // --- Lorebook Entry Methods ---

    #[instrument(skip(self, auth_session, payload, user_dek, state), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id))]
    pub async fn create_lorebook_entry(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        lorebook_id: Uuid,
        payload: CreateLorebookEntryPayload,
        user_dek: Option<&SecretBox<Vec<u8>>>,
        state: Arc<AppState>, // Added AppState
    ) -> Result<LorebookEntryResponse, AppError> {
        debug!(?payload, "Attempting to create lorebook entry");
        let user = Self::get_user_from_session(auth_session)?;
        let user_id_for_embedding = user.id; // Clone for embedding task

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        // 1. Fetch lorebook by id, check ownership
        let lorebook_id_clone = lorebook_id; // Clone for use in interact closure
        let user_id_clone = user.id; // Clone for use in interact closure
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
                error!("Interaction error while fetching lorebook: {:?}", e);
AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while fetching lorebook: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to query lorebook: {:?}", e);
                AppError::DatabaseQueryError(format!("Failed to query lorebook: {e}"))
            })?
            .ok_or_else(|| {
                error!(
                    "Lorebook with ID [REDACTED_UUID] not found or user [REDACTED_UUID] does not have access."
                );
                AppError::NotFound(format!(
                    "Lorebook with ID {lorebook_id} not found or access denied."
                ))
            })?;

        // 2. Encrypt sensitive fields
        let user_dek_secret_box = user_dek.ok_or_else(|| {
            error!("User DEK not available for lorebook entry creation for user [REDACTED_UUID]");
            AppError::EncryptionError(
                "User DEK not available for lorebook entry creation. User might not be fully logged in or DEK was not set.".to_string(),
            )
        })?;
        let user_dek_bytes = user_dek_secret_box.expose_secret();

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

        let (comment_ciphertext, comment_nonce) = match payload.comment {
            Some(text) if !text.is_empty() => {
                let (cipher, nonce) = self.encryption_service.encrypt(&text, user_dek_bytes)?;
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

        let new_entry_db = NewLorebookEntry {
            id: new_entry_id,
            lorebook_id,
            user_id: user.id,
            original_sillytavern_uid: None,
            entry_title_ciphertext,
            entry_title_nonce,
            keys_text_ciphertext: keys_text_ciphertext.clone(), // Clone here for potential use in response
            keys_text_nonce: keys_text_nonce.clone(),           // Clone here
            content_ciphertext,
            content_nonce,
            comment_ciphertext: comment_ciphertext.clone(), // Clone here
            comment_nonce: comment_nonce.clone(),           // Clone here
            is_enabled: payload.is_enabled.unwrap_or(true),
            is_constant: payload.is_constant.unwrap_or(false),
            insertion_order: payload.insertion_order.unwrap_or(100),
            placement_hint: payload.placement_hint, // Stored as Option<String>
            sillytavern_metadata_ciphertext: None,
            sillytavern_metadata_nonce: None,
            name: None, // Deprecated in favor of encrypted title
            created_at: Some(current_time),
            updated_at: Some(current_time),
        };

        // 3. Save to DB
        let inserted_entry_db = new_entry_db.clone(); // Clone before moving into interact
        let inserted_entry = conn
            .interact(move |conn_sync| {
                diesel::insert_into(lorebook_entries::table)
                    .values(&inserted_entry_db) // Use the cloned value
                    .returning(LorebookEntry::as_returning())
                    .get_result::<LorebookEntry>(conn_sync)
            })
            .await
            .map_err(|e| {
                error!("Interaction error while inserting lorebook entry: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while creating lorebook entry: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to insert lorebook entry into DB: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Failed to create lorebook entry in DB: {e}"
                ))
            })?;

        // 4. Return decrypted LorebookEntryResponse
        // Use the same DEK that was passed as parameter
        let user_dek_bytes_for_decrypt = user_dek_bytes;

        let decrypted_entry_title_bytes = self
            .encryption_service
            .decrypt(
                &inserted_entry.entry_title_ciphertext,
                &inserted_entry.entry_title_nonce,
                user_dek_bytes_for_decrypt,
            )
            .map_err(|e| {
                error!(
                    "Failed to decrypt entry_title for new entry [REDACTED_UUID]: {:?}",
                    e
                );
                AppError::DecryptionError("Failed to decrypt entry title".to_string())
            })?;
        let decrypted_entry_title =
            String::from_utf8_lossy(&decrypted_entry_title_bytes).into_owned();

        // Decrypt keys_text:
        // If keys_text_ciphertext is not empty, decrypt it.
        // If it's empty but nonce is present, it was an empty string.
        // If both are empty (or nonce indicates it was None, if we had such a scheme), then it's None.
        // Given current encryption of "" for None or Some(""), this logic needs refinement
        // if we need to distinguish None from Some("").
        // For now, if ciphertext is present (even if it's just an AEAD tag for an empty string), decrypt.
        let decrypted_keys_text = {
            // If keys_text_ciphertext is empty, it means it was stored as such (e.g. for None or empty string)
            // However, encryption of "" produces a non-empty ciphertext (the tag).
            // So, if keys_text_ciphertext is truly empty, it means it was explicitly set to empty Vec
            // *before* encryption, which shouldn't happen with the current encrypt logic for "" or None.
            // The only case for empty ciphertext with the current logic is if it was never set (e.g. DB default)
            // or explicitly set to empty Vec (which is not what encrypt("") does).
            // Let's assume if nonce is present, there's something to decrypt or it was an encrypted empty string.
            if inserted_entry.keys_text_nonce.is_empty() {
                // This case (empty nonce) should not happen if encryption always occurs
                // and returns a valid nonce. If it does, it indicates an issue.
                error!(
                    "Empty nonce found for keys_text for entry [REDACTED_UUID], ciphertext_len: {}",
                    inserted_entry.keys_text_ciphertext.len()
                );
                None // Or handle as an error
            } else {
                // Nonce is always generated by encrypt
                let bytes = self
                    .encryption_service
                    .decrypt(
                        &inserted_entry.keys_text_ciphertext,
                        &inserted_entry.keys_text_nonce,
                        user_dek_bytes_for_decrypt,
                    )
                    .map_err(|e| {
                        error!(
                            "Failed to decrypt keys_text for new entry [REDACTED_UUID]: {:?}",
                            e
                        );
                        AppError::DecryptionError("Failed to decrypt keys text".to_string())
                    })?;
                // If decrypted bytes are empty, it was an encrypted empty string.
                // If original payload.keys_text was None, we encrypted "".
                // If original payload.keys_text was Some(""), we encrypted "".
                // So, in both these cases, decrypted bytes will be empty.
                // The DTO expects Option<String>. How to differentiate?
                // Current logic: if payload.keys_text is None, we encrypt "".
                // If payload.keys_text is Some(""), we encrypt "".
                // So, we can't distinguish. We should return Some("") if bytes are empty.
                // If the original payload.keys_text was None or Some(""), we encrypted "".
                // Upon decryption, this will result in an empty string.
                // The LorebookEntryResponse.keys_text is Option<String>.
                // We will return Some("") for a decrypted empty string.
                // If we needed to distinguish a true None, the storage or DTO would need adjustment.
                Some(String::from_utf8_lossy(&bytes).into_owned())
            }
        };

        let decrypted_content_bytes = self
            .encryption_service
            .decrypt(
                &inserted_entry.content_ciphertext,
                &inserted_entry.content_nonce,
                user_dek_bytes_for_decrypt,
            )
            .map_err(|e| {
                error!(
                    "Failed to decrypt content for new entry [REDACTED_UUID]: {:?}",
                    e
                );
                AppError::DecryptionError("Failed to decrypt content".to_string())
            })?;
        let decrypted_content = String::from_utf8_lossy(&decrypted_content_bytes).into_owned();

        let decrypted_comment = match (
            &inserted_entry.comment_ciphertext,
            &inserted_entry.comment_nonce,
        ) {
            (Some(cipher), Some(nonce)) => {
                let bytes = self
                    .encryption_service
                    .decrypt(cipher, nonce, user_dek_bytes_for_decrypt)
                    .map_err(|e| {
                        error!(
                            "Failed to decrypt comment for new entry [REDACTED_UUID]: {:?}",
                            e
                        );
                        AppError::DecryptionError("Failed to decrypt comment".to_string())
                    })?;
                Some(String::from_utf8_lossy(&bytes).into_owned())
            }
            _ => None,
        };

        // After successful DB insertion and decryption for response, trigger async vectorization
        let state_clone = state.clone();
        let embedding_pipeline_service = state_clone.embedding_pipeline_service.clone();

        let original_lorebook_entry_id_for_embedding = inserted_entry.id;
        let lorebook_id_for_embedding = lorebook_id;
        // user_id_for_embedding is already defined above
        let decrypted_content_for_embedding = decrypted_content.clone();
        let decrypted_title_for_embedding = Some(decrypted_entry_title.clone()); // Title is not optional for embedding if available

        let decrypted_keywords_for_embedding = decrypted_keys_text.as_ref().and_then(|keys_str| {
            if keys_str.trim().is_empty() {
                None
            } else {
                let keywords: Vec<String> = keys_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if keywords.is_empty() {
                    None
                } else {
                    Some(keywords)
                }
            }
        });

        let is_enabled_for_embedding = new_entry_db.is_enabled; // Use value from payload/defaults
        let is_constant_for_embedding = new_entry_db.is_constant; // Use value from payload/defaults

        tokio::spawn(async move {
            debug!("Spawning task to process and embed lorebook entry: [REDACTED_UUID]");

            let params = LorebookEntryParams {
                original_lorebook_entry_id: original_lorebook_entry_id_for_embedding,
                lorebook_id: lorebook_id_for_embedding,
                user_id: user_id_for_embedding,
                decrypted_content: decrypted_content_for_embedding,
                decrypted_title: decrypted_title_for_embedding,
                decrypted_keywords: decrypted_keywords_for_embedding,
                is_enabled: is_enabled_for_embedding,
                is_constant: is_constant_for_embedding,
            };

            if let Err(e) = embedding_pipeline_service
                .process_and_embed_lorebook_entry(state_clone, params)
                .await
            {
                error!(
                    "Failed to process and embed lorebook entry [REDACTED_UUID] in background: {:?}",
                    e
                );
            } else {
                debug!("Successfully queued lorebook entry [REDACTED_UUID] for embedding.");
            }
        });

        Ok(LorebookEntryResponse {
            id: inserted_entry.id,
            lorebook_id: inserted_entry.lorebook_id,
            user_id: inserted_entry.user_id,
            entry_title: decrypted_entry_title, // Already cloned for embedding if needed
            keys_text: decrypted_keys_text,     // Already cloned for embedding if needed
            content: decrypted_content,         // Already cloned for embedding
            comment: decrypted_comment,
            is_enabled: inserted_entry.is_enabled,
            is_constant: inserted_entry.is_constant,
            insertion_order: inserted_entry.insertion_order,
            placement_hint: inserted_entry
                .placement_hint
                .unwrap_or_else(|| "system_default".to_string()),
            created_at: inserted_entry.created_at,
            updated_at: inserted_entry.updated_at,
        })
    }

    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id))]
    pub async fn list_lorebook_entries(
        &self,
        auth_session: &AuthSession<AuthBackend>, // Changed to AuthBackend
        lorebook_id: Uuid,
        user_dek: Option<&SecretBox<Vec<u8>>>, // Add DEK parameter
    ) -> Result<Vec<LorebookEntrySummaryResponse>, AppError> {
        debug!("Attempting to list lorebook entries");
        let user = Self::get_user_from_session(auth_session)?;

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        // 1. Verify lorebook ownership
        let lorebook_id_clone = lorebook_id;
        let user_id_clone = user.id;
        let _lorebook = conn
            .interact(move |conn_sync| {
                lorebooks::table
                    .filter(lorebooks::id.eq(lorebook_id_clone))
                    .filter(lorebooks::user_id.eq(user_id_clone))
                    .select(Lorebook::as_select())
                    .first::<Lorebook>(conn_sync)
                    .optional()
            })
            .await
            .map_err(|e| {
                error!("Interaction error while fetching lorebook: {:?}", e);
AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while fetching lorebook: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to query lorebook: {:?}", e);
                AppError::DatabaseQueryError(format!("Failed to query lorebook: {e}"))
            })?
            .ok_or_else(|| {
                error!(
                    "Lorebook with ID [REDACTED_UUID] not found or user [REDACTED_UUID] does not have access."
                );
                AppError::NotFound(format!(
                    "Lorebook with ID {lorebook_id} not found or access denied."
                ))
            })?;

        // 2. Fetch all entries for the lorebook
        let lorebook_id_for_entries = lorebook_id;
        let entries = conn
            .interact(move |conn_sync| {
                lorebook_entries::table
                    .filter(lorebook_entries::lorebook_id.eq(lorebook_id_for_entries))
                    .order((
                        lorebook_entries::insertion_order.asc(),
                        lorebook_entries::created_at.asc(),
                    ))
                    .select(LorebookEntry::as_select())
                    .load::<LorebookEntry>(conn_sync)
            })
            .await
            .map_err(|e| {
                error!("Interaction error while fetching lorebook entries: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while fetching entries: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to query lorebook entries: {:?}", e);
                AppError::DatabaseQueryError(format!("Failed to query lorebook entries: {e}"))
            })?;

        // 3. Decrypt entry titles and map to response
        let user_dek_secret_box = user_dek.ok_or_else(|| {
            error!(
                "User DEK not available for lorebook entry list decryption for user [REDACTED_UUID]"
            );
            AppError::EncryptionError(
                "User DEK not available for lorebook entry decryption.".to_string(),
            )
        })?;
        let user_dek_bytes = user_dek_secret_box.expose_secret();

        let mut entry_responses = Vec::new();
        for entry in entries {
            // Decrypt entry title
            let decrypted_title_bytes = self
                .encryption_service
                .decrypt(
                    &entry.entry_title_ciphertext,
                    &entry.entry_title_nonce,
                    user_dek_bytes,
                )
                .map_err(|e| {
                    error!(
                        "Failed to decrypt entry title for entry [REDACTED_UUID]: {:?}",
                        e
                    );
                    AppError::DecryptionError(
                        "Failed to decrypt entry title for entry [REDACTED_UUID]".to_string(),
                    )
                })?;
            let decrypted_title = String::from_utf8_lossy(&decrypted_title_bytes).into_owned();

            entry_responses.push(LorebookEntrySummaryResponse {
                id: entry.id,
                lorebook_id: entry.lorebook_id,
                entry_title: decrypted_title,
                is_enabled: entry.is_enabled,
                is_constant: entry.is_constant,
                insertion_order: entry.insertion_order,
                updated_at: entry.updated_at,
            });
        }

        Ok(entry_responses)
    }

    /// Lists all lorebook entries with full content (decrypted) for the given lorebook.
    /// This is the method that should be used by the frontend to get complete entry data.
    #[instrument(skip(self, auth_session, user_dek), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id))]
    pub async fn list_lorebook_entries_with_content(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        lorebook_id: Uuid,
        user_dek: Option<&SecretBox<Vec<u8>>>,
    ) -> Result<Vec<LorebookEntryResponse>, AppError> {
        debug!("Attempting to list lorebook entries with content");
        let user = Self::get_user_from_session(auth_session)?;

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        // 1. Verify lorebook ownership
        let lorebook_id_clone = lorebook_id;
        let user_id_clone = user.id;
        let _lorebook = conn
            .interact(move |conn_sync| {
                lorebooks::table
                    .filter(lorebooks::id.eq(lorebook_id_clone))
                    .filter(lorebooks::user_id.eq(user_id_clone))
                    .select(Lorebook::as_select())
                    .first::<Lorebook>(conn_sync)
                    .optional()
            })
            .await
            .map_err(|e| {
                error!("Interaction error while fetching lorebook: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while fetching lorebook: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to query lorebook: {:?}", e);
                AppError::DatabaseQueryError(format!("Failed to query lorebook: {e}"))
            })?
            .ok_or_else(|| {
                error!(
                    "Lorebook with ID {} not found or user {} does not have access.",
                    lorebook_id, user.id
                );
                AppError::NotFound(format!(
                    "Lorebook with ID {lorebook_id} not found or access denied."
                ))
            })?;

        // 2. Fetch all entries for the lorebook
        let lorebook_id_for_entries = lorebook_id;
        let entries = conn
            .interact(move |conn_sync| {
                lorebook_entries::table
                    .filter(lorebook_entries::lorebook_id.eq(lorebook_id_for_entries))
                    .order((
                        lorebook_entries::insertion_order.asc(),
                        lorebook_entries::created_at.asc(),
                    ))
                    .select(LorebookEntry::as_select())
                    .load::<LorebookEntry>(conn_sync)
            })
            .await
            .map_err(|e| {
                error!("Interaction error while fetching lorebook entries: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while fetching entries: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to query lorebook entries: {:?}", e);
                AppError::DatabaseQueryError(format!("Failed to query lorebook entries: {e}"))
            })?;

        // 3. Decrypt all fields for each entry
        let user_dek_secret_box = user_dek.ok_or_else(|| {
            error!(
                "User DEK not available for lorebook entry list decryption for user [REDACTED_UUID]"
            );
            AppError::EncryptionError(
                "User DEK not available for lorebook entry decryption.".to_string(),
            )
        })?;
        let user_dek_bytes = user_dek_secret_box.expose_secret();

        let mut entry_responses = Vec::new();
        for entry in entries {
            // Decrypt entry title
            let decrypted_title_bytes = self
                .encryption_service
                .decrypt(
                    &entry.entry_title_ciphertext,
                    &entry.entry_title_nonce,
                    user_dek_bytes,
                )
                .map_err(|e| {
                    error!(
                        "Failed to decrypt entry title for entry [REDACTED_UUID]: {:?}",
                        e
                    );
                    AppError::DecryptionError(
                        "Failed to decrypt entry title for entry [REDACTED_UUID]".to_string(),
                    )
                })?;
            let decrypted_title = String::from_utf8_lossy(&decrypted_title_bytes).into_owned();

            // Decrypt keys_text
            let keys_text = if entry.keys_text_ciphertext.is_empty() {
                None
            } else {
                let decrypted_keys_bytes = self
                    .encryption_service
                    .decrypt(
                        &entry.keys_text_ciphertext,
                        &entry.keys_text_nonce,
                        user_dek_bytes,
                    )
                    .map_err(|e| {
                        error!(
                            "Failed to decrypt keys_text for entry [REDACTED_UUID]: {:?}",
                            e
                        );
                        AppError::DecryptionError(
                            "Failed to decrypt keys text for entry [REDACTED_UUID]".to_string(),
                        )
                    })?;
                let decrypted_keys = String::from_utf8_lossy(&decrypted_keys_bytes).into_owned();
                if decrypted_keys.is_empty() {
                    None
                } else {
                    Some(decrypted_keys)
                }
            };

            // Decrypt content
            let decrypted_content_bytes = self
                .encryption_service
                .decrypt(
                    &entry.content_ciphertext,
                    &entry.content_nonce,
                    user_dek_bytes,
                )
                .map_err(|e| {
                    error!(
                        "Failed to decrypt content for entry [REDACTED_UUID]: {:?}",
                        e
                    );
                    AppError::DecryptionError(
                        "Failed to decrypt content for entry [REDACTED_UUID]".to_string(),
                    )
                })?;
            let decrypted_content = String::from_utf8_lossy(&decrypted_content_bytes).into_owned();

            // Decrypt comment if present
            let comment = match (&entry.comment_ciphertext, &entry.comment_nonce) {
                (Some(cipher), Some(nonce)) => {
                    let decrypted_comment_bytes = self
                        .encryption_service
                        .decrypt(cipher, nonce, user_dek_bytes)
                        .map_err(|e| {
                            error!(
                                "Failed to decrypt comment for entry [REDACTED_UUID]: {:?}",
                                e
                            );
                            AppError::DecryptionError(
                                "Failed to decrypt comment for entry [REDACTED_UUID]".to_string(),
                            )
                        })?;
                    let decrypted_comment =
                        String::from_utf8_lossy(&decrypted_comment_bytes).into_owned();
                    if decrypted_comment.is_empty() {
                        None
                    } else {
                        Some(decrypted_comment)
                    }
                }
                _ => None,
            };

            entry_responses.push(LorebookEntryResponse {
                id: entry.id,
                lorebook_id: entry.lorebook_id,
                user_id: entry.user_id,
                entry_title: decrypted_title,
                keys_text,
                content: decrypted_content,
                comment,
                is_enabled: entry.is_enabled,
                is_constant: entry.is_constant,
                insertion_order: entry.insertion_order,
                placement_hint: entry
                    .placement_hint
                    .unwrap_or_else(|| "after_prompt".to_string()),
                created_at: entry.created_at,
                updated_at: entry.updated_at,
            });
        }

        Ok(entry_responses)
    }

    #[instrument(skip(self, auth_session, user_dek), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id, entry_id = %entry_id))]
    pub async fn get_lorebook_entry(
        &self,
        auth_session: &AuthSession<AuthBackend>, // Changed to AuthBackend
        lorebook_id: Uuid,
        entry_id: Uuid,
        user_dek: Option<&SecretBox<Vec<u8>>>, // Add DEK parameter
    ) -> Result<LorebookEntryResponse, AppError> {
        debug!("Attempting to get lorebook entry");
        let user = Self::get_user_from_session(auth_session)?;

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        // 1. Fetch the entry and verify ownership
        let entry_id_clone = entry_id;
        let user_id_clone = user.id;
        let lorebook_id_clone = lorebook_id;
        let entry = conn
            .interact(move |conn_sync| {
                lorebook_entries::table
                    .filter(lorebook_entries::id.eq(entry_id_clone))
                    .filter(lorebook_entries::user_id.eq(user_id_clone))
                    .filter(lorebook_entries::lorebook_id.eq(lorebook_id_clone))
                    .select(LorebookEntry::as_select())
                    .first::<LorebookEntry>(conn_sync)
                    .optional()
            })
            .await
            .map_err(|e| {
                error!("Interaction error while fetching lorebook entry: {:?}", e);
AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while fetching entry: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to query lorebook entry: {:?}", e);
                AppError::DatabaseQueryError(format!("Failed to query lorebook entry: {e}"))
            })?
            .ok_or_else(|| {
                error!(
                    "Lorebook entry with ID [REDACTED_UUID] not found or user [REDACTED_UUID] does not have access."
                );
                AppError::NotFound(format!(
                    "Lorebook entry with ID {entry_id} not found or access denied."
                ))
            })?;

        // 2. Decrypt all fields
        let user_dek_secret_box = user_dek.ok_or_else(|| {
            error!("User DEK not available for lorebook entry decryption for user [REDACTED_UUID]");
            AppError::EncryptionError(
                "User DEK not available for lorebook entry decryption.".to_string(),
            )
        })?;
        let user_dek_bytes = user_dek_secret_box.expose_secret();

        // Decrypt entry title
        let decrypted_title_bytes = self
            .encryption_service
            .decrypt(
                &entry.entry_title_ciphertext,
                &entry.entry_title_nonce,
                user_dek_bytes,
            )
            .map_err(|_e| {
                error!("Failed to decrypt entry title: [REDACTED_ERROR]");
                AppError::DecryptionError("Failed to decrypt entry title".to_string())
            })?;
        let decrypted_title = String::from_utf8_lossy(&decrypted_title_bytes).into_owned();

        // Decrypt keys_text
        let keys_text = if entry.keys_text_ciphertext.is_empty() {
            None
        } else {
            let decrypted_keys_bytes = self
                .encryption_service
                .decrypt(
                    &entry.keys_text_ciphertext,
                    &entry.keys_text_nonce,
                    user_dek_bytes,
                )
                .map_err(|_e| {
                    error!("Failed to decrypt keys_text: [REDACTED_ERROR]");
                    AppError::DecryptionError("Failed to decrypt keys text".to_string())
                })?;
            let decrypted_keys = String::from_utf8_lossy(&decrypted_keys_bytes).into_owned();
            if decrypted_keys.is_empty() {
                None
            } else {
                Some(decrypted_keys)
            }
        };

        // Decrypt content
        let decrypted_content_bytes = self
            .encryption_service
            .decrypt(
                &entry.content_ciphertext,
                &entry.content_nonce,
                user_dek_bytes,
            )
            .map_err(|_e| {
                error!("Failed to decrypt content: [REDACTED_ERROR]");
                AppError::DecryptionError("Failed to decrypt content".to_string())
            })?;
        let decrypted_content = String::from_utf8_lossy(&decrypted_content_bytes).into_owned();

        // Decrypt comment if present
        let comment = match (&entry.comment_ciphertext, &entry.comment_nonce) {
            (Some(cipher), Some(nonce)) => {
                let decrypted_comment_bytes = self
                    .encryption_service
                    .decrypt(cipher, nonce, user_dek_bytes)
                    .map_err(|_e| {
                        error!("Failed to decrypt comment: [REDACTED_ERROR]");
                        AppError::DecryptionError("Failed to decrypt comment".to_string())
                    })?;
                let decrypted_comment =
                    String::from_utf8_lossy(&decrypted_comment_bytes).into_owned();
                if decrypted_comment.is_empty() {
                    None
                } else {
                    Some(decrypted_comment)
                }
            }
            _ => None,
        };

        Ok(LorebookEntryResponse {
            id: entry.id,
            lorebook_id: entry.lorebook_id,
            user_id: entry.user_id,
            entry_title: decrypted_title,
            keys_text,
            content: decrypted_content,
            comment,
            is_enabled: entry.is_enabled,
            is_constant: entry.is_constant,
            insertion_order: entry.insertion_order,
            placement_hint: entry.placement_hint.clone().unwrap_or_default(),
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        })
    }

    #[instrument(skip(self, auth_session, payload, user_dek, state), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id_param, entry_id = %entry_id))]
    pub async fn update_lorebook_entry(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        lorebook_id_param: Uuid,
        entry_id: Uuid,
        payload: UpdateLorebookEntryPayload,
        user_dek: Option<&SecretBox<Vec<u8>>>,
        state: Arc<AppState>,
    ) -> Result<LorebookEntryResponse, AppError> {
        debug!(?payload, "Attempting to update lorebook entry");
        let user = Self::get_user_from_session(auth_session)?;
        let user_id_for_embedding = user.id; // Clone for embedding task

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        // 1. Fetch the existing entry to verify ownership and get current values
        let entry_id_clone = entry_id; // Clone for interact closure
        let lorebook_id_param_clone = lorebook_id_param; // Clone for interact closure
        let user_id_clone = user.id; // Clone for interact closure

        let mut entry_to_update = conn
            .interact(move |conn_sync| {
                lorebook_entries::table
                    .filter(lorebook_entries::id.eq(entry_id_clone))
                    .filter(lorebook_entries::lorebook_id.eq(lorebook_id_param_clone))
                    .filter(lorebook_entries::user_id.eq(user_id_clone))
                    .select(LorebookEntry::as_select())
                    .first::<LorebookEntry>(conn_sync)
                    .optional()
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "DB interaction failed while fetching entry: {e}"
                ))
            })?
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to query entry: {e}")))?
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "Lorebook entry with ID {entry_id} not found or access denied."
                ))
            })?;

        // 2. Get DEK for encryption
        let user_dek_secret_box = user_dek.ok_or_else(|| {
            error!("User DEK not available for lorebook entry update for user [REDACTED_UUID]");
            AppError::EncryptionError(
                "User DEK not available for lorebook entry update.".to_string(),
            )
        })?;
        let user_dek_bytes = user_dek_secret_box.expose_secret();

        // 3. Apply updates from payload, encrypting if necessary
        if let Some(title_str) = payload.entry_title {
            let (cipher, nonce) = self
                .encryption_service
                .encrypt(&title_str, user_dek_bytes)?;
            entry_to_update.entry_title_ciphertext = cipher;
            entry_to_update.entry_title_nonce = nonce;
        }

        if payload.keys_text.is_some() {
            let keys_to_encrypt = payload.keys_text.as_deref().unwrap_or("");
            let (cipher, nonce) = self
                .encryption_service
                .encrypt(keys_to_encrypt, user_dek_bytes)?;
            entry_to_update.keys_text_ciphertext = cipher;
            entry_to_update.keys_text_nonce = nonce;
        }

        if let Some(content_str) = payload.content {
            let (cipher, nonce) = self
                .encryption_service
                .encrypt(&content_str, user_dek_bytes)?;
            entry_to_update.content_ciphertext = cipher;
            entry_to_update.content_nonce = nonce;
        }

        if payload.comment.is_some() {
            // Handles Some(String) and Some("")
            let comment_to_encrypt = payload.comment.as_deref().unwrap_or("");
            let (cipher, nonce) = self
                .encryption_service
                .encrypt(comment_to_encrypt, user_dek_bytes)?;
            entry_to_update.comment_ciphertext = Some(cipher);
            entry_to_update.comment_nonce = Some(nonce);
        }
        // Note: If payload.comment is None, we don't touch the existing comment fields.
        // If the intention is to clear a comment, the payload should send Some("").

        if let Some(is_enabled) = payload.is_enabled {
            if entry_to_update.is_enabled != is_enabled {
                entry_to_update.is_enabled = is_enabled;
            }
        }
        if let Some(is_constant) = payload.is_constant {
            if entry_to_update.is_constant != is_constant {
                entry_to_update.is_constant = is_constant;
            }
        }
        if let Some(insertion_order) = payload.insertion_order {
            if entry_to_update.insertion_order != insertion_order {
                entry_to_update.insertion_order = insertion_order;
            }
        }
        if payload.placement_hint.is_some() {
            // Handles Some(String) and Some("")
            let hint_str = payload.placement_hint.unwrap(); // Safe due to is_some()
            if entry_to_update.placement_hint.as_deref() != Some(&hint_str) {
                entry_to_update.placement_hint = Some(hint_str);
            }
        }

        // Always update timestamp on PUT to ensure `updated_at` is current
        entry_to_update.updated_at = Utc::now();

        // 4. Save to DB
        let updated_db_entry_struct = entry_to_update.clone(); // Clone for interact closure
        let updated_db_entry = conn
            .interact(move |conn_sync| {
                diesel::update(lorebook_entries::table.find(entry_id))
                    .set(&updated_db_entry_struct)
                    .returning(LorebookEntry::as_returning())
                    .get_result::<LorebookEntry>(conn_sync)
            })
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "DB interaction failed while updating entry: {e}"
                ))
            })?
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to update entry: {e}")))?;

        // 5. Decrypt fields from the updated_db_entry for embedding and response
        let decrypted_title_for_response_and_embed =
            String::from_utf8_lossy(&self.encryption_service.decrypt(
                &updated_db_entry.entry_title_ciphertext,
                &updated_db_entry.entry_title_nonce,
                user_dek_bytes,
            )?)
            .into_owned();

        let decrypted_keys_text_for_response_and_embed = {
            if updated_db_entry.keys_text_nonce.is_empty() {
                None
            } else {
                Some(
                    String::from_utf8_lossy(&self.encryption_service.decrypt(
                        &updated_db_entry.keys_text_ciphertext,
                        &updated_db_entry.keys_text_nonce,
                        user_dek_bytes,
                    )?)
                    .into_owned(),
                )
            }
        };

        let decrypted_content_for_response_and_embed =
            String::from_utf8_lossy(&self.encryption_service.decrypt(
                &updated_db_entry.content_ciphertext,
                &updated_db_entry.content_nonce,
                user_dek_bytes,
            )?)
            .into_owned();

        let decrypted_comment_for_response = match (
            &updated_db_entry.comment_ciphertext,
            &updated_db_entry.comment_nonce,
        ) {
            (Some(cipher), Some(nonce)) => Some(
                String::from_utf8_lossy(&self.encryption_service.decrypt(
                    cipher,
                    nonce,
                    user_dek_bytes,
                )?)
                .into_owned(),
            ),
            _ => None,
        };

        // 6. Trigger re-embedding
        let state_clone = state.clone();
        let embedding_pipeline_service = state_clone.embedding_pipeline_service.clone();
        let original_lorebook_entry_id_for_embedding = updated_db_entry.id;
        let lorebook_id_for_embedding = updated_db_entry.lorebook_id;
        // user_id_for_embedding is already defined
        let content_for_embedding = decrypted_content_for_response_and_embed.clone();
        let title_for_embedding = Some(decrypted_title_for_response_and_embed.clone());
        let keywords_for_embedding = decrypted_keys_text_for_response_and_embed
            .as_ref()
            .and_then(|keys_str| {
                if keys_str.trim().is_empty() {
                    None
                } else {
                    let keywords: Vec<String> = keys_str
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if keywords.is_empty() {
                        None
                    } else {
                        Some(keywords)
                    }
                }
            });
        let is_enabled_for_embedding = updated_db_entry.is_enabled;
        let is_constant_for_embedding = updated_db_entry.is_constant;

        tokio::spawn(async move {
            debug!("Spawning task to re-process and embed updated lorebook entry: [REDACTED_UUID]");

            let params = LorebookEntryParams {
                original_lorebook_entry_id: original_lorebook_entry_id_for_embedding,
                lorebook_id: lorebook_id_for_embedding,
                user_id: user_id_for_embedding,
                decrypted_content: content_for_embedding,
                decrypted_title: title_for_embedding,
                decrypted_keywords: keywords_for_embedding,
                is_enabled: is_enabled_for_embedding,
                is_constant: is_constant_for_embedding,
            };

            if let Err(_e) = embedding_pipeline_service
                .process_and_embed_lorebook_entry(state_clone, params)
                .await
            {
                error!(
                    "Failed to re-process and embed updated lorebook entry [REDACTED_UUID] in background: [REDACTED_ERROR]"
                );
            } else {
                debug!(
                    "Successfully queued updated lorebook entry [REDACTED_UUID] for re-embedding."
                );
            }
        });

        // 7. Construct and return response
        Ok(LorebookEntryResponse {
            id: updated_db_entry.id,
            lorebook_id: updated_db_entry.lorebook_id,
            user_id: updated_db_entry.user_id,
            entry_title: decrypted_title_for_response_and_embed,
            keys_text: decrypted_keys_text_for_response_and_embed,
            content: decrypted_content_for_response_and_embed,
            comment: decrypted_comment_for_response,
            is_enabled: updated_db_entry.is_enabled,
            is_constant: updated_db_entry.is_constant,
            insertion_order: updated_db_entry.insertion_order,
            placement_hint: updated_db_entry
                .placement_hint
                .unwrap_or_else(|| "system_default".to_string()),
            created_at: updated_db_entry.created_at,
            updated_at: updated_db_entry.updated_at,
        })
    }

    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id, entry_id = %entry_id))]
    pub async fn delete_lorebook_entry(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        lorebook_id: Uuid,
        entry_id: Uuid,
    ) -> Result<(), AppError> {
        debug!("Attempting to delete lorebook entry");

        // 1. Get current user
        let user = Self::get_user_from_session(auth_session)?;

        let conn = self
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;

        // 2. Fetch lorebook entry and verify ownership in a single query

        conn
            .interact(move |conn| {
                use crate::schema::lorebook_entries::dsl::{id, lorebook_entries, lorebook_id, user_id};

                // First, verify the entry exists and belongs to the user
                let entry_owner = lorebook_entries
                    .filter(id.eq(entry_id))
                    .filter(lorebook_id.eq(lorebook_id))
                    .select(user_id)
                    .first::<Uuid>(conn)
                    .optional()
                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                match entry_owner {
                    Some(owner_id) if owner_id == user.id => {
                        // User owns this entry, proceed with deletion
                        diesel::delete(
                            lorebook_entries
                                .filter(id.eq(entry_id))
                                .filter(user_id.eq(user.id)),
                        )
                        .execute(conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

                        tracing::info!(
                            "Successfully deleted lorebook entry [REDACTED_UUID] for user [REDACTED_UUID]"
                        );
                        Ok(())
                    }
                    Some(_) => {
                        // Entry exists but belongs to another user
                        Err(AppError::Forbidden("Access denied to lorebook entry".to_string()))
                    }
                    None => {
                        // Entry doesn't exist
                        Err(AppError::NotFound("Lorebook entry not found".to_string()))
                    }
                }
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("Database interaction error: {e}")))?
    }

    // --- Chat Session Lorebook Association Methods ---

    #[instrument(skip(self, auth_session, payload), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), chat_session_id = %chat_session_id))]
    pub async fn associate_lorebook_to_chat(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        chat_session_id: Uuid,
        payload: AssociateLorebookToChatPayload,
        user_dek: Option<&SecretBox<Vec<u8>>>, // Added for entry decryption
        state: Arc<AppState>,                  // Added for embedding pipeline
    ) -> Result<ChatSessionLorebookAssociationResponse, AppError> {
        debug!(
            ?payload,
            lorebook_id = "[REDACTED_UUID]",
            "Attempting to associate lorebook to chat session [REDACTED_UUID]"
        );
        let user = Self::get_user_from_session(auth_session)?;
        let lorebook_id_to_associate = payload.lorebook_id;

        let conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get DB connection: {}", e);
            AppError::DbPoolError(e.to_string())
        })?;

        // 1. Verify chat session ownership and get character ID
        let current_user_id = user.id; // Clone user_id for use in closures
        let chat_session = conn.interact(move |conn_sync| {
            use crate::schema::chat_sessions::dsl as cs_dsl;
            cs_dsl::chat_sessions
                .filter(cs_dsl::id.eq(chat_session_id))
                .filter(cs_dsl::user_id.eq(current_user_id))
                .select(Chat::as_select()) // Changed ChatSession to Chat
                .first::<Chat>(conn_sync) // Changed ChatSession to Chat
                .optional()
        })
        .await
        .map_err(|e| {
            error!(
                "DB interaction failed while verifying chat session ownership for session [REDACTED_UUID]: {}",
                e
            );
            AppError::DbInteractError(format!("DB interaction failed: {e}"))
        })?
        .map_err(|db_err| {
            error!(
                "Failed to query chat session [REDACTED_UUID]: {}",
                db_err
            );
            AppError::DatabaseQueryError(db_err.to_string())
        })?
        .ok_or_else(|| {
            error!(
                "Chat session [REDACTED_UUID] not found or user [REDACTED_UUID] does not have access."
            );
            AppError::NotFound(format!(
                "Chat session with ID {chat_session_id} not found or access denied."
            ))
        })?;

        // 2. Verify lorebook ownership and get its name
        let lorebook_name = conn
            .interact(move |conn_sync| {
                use crate::schema::lorebooks::dsl as lb_dsl;
                lb_dsl::lorebooks
                    .filter(lb_dsl::id.eq(lorebook_id_to_associate))
                    .filter(lb_dsl::user_id.eq(current_user_id))
                    .select(lb_dsl::name)
                    .first::<String>(conn_sync)
                    .optional()
            })
            .await
            .map_err(|e| {
                error!(
                    "DB interaction failed while verifying lorebook ownership for lorebook [REDACTED_UUID]: {}",
                    e
                );
                AppError::DbInteractError(format!("DB interaction failed: {e}"))
            })?
            .map_err(|db_err| {
                error!(
                    "Failed to query lorebook [REDACTED_UUID]: {}",
                    db_err
                );
                AppError::DatabaseQueryError(db_err.to_string())
            })?
            .ok_or_else(|| {
                error!(
                    "Lorebook [REDACTED_UUID] not found or user [REDACTED_UUID] does not have access."
                );
                AppError::NotFound(format!(
                    "Lorebook with ID {lorebook_id_to_associate} not found or access denied."
                ))
            })?;

        // 3. Check if lorebook is already linked via character
        let character_id = chat_session.character_id;
        let is_character_linked = conn
            .interact(move |conn_sync| {
                use crate::schema::character_lorebooks::dsl as cl_dsl;
                cl_dsl::character_lorebooks
                    .filter(cl_dsl::character_id.eq(character_id))
                    .filter(cl_dsl::lorebook_id.eq(lorebook_id_to_associate))
                    .filter(cl_dsl::user_id.eq(current_user_id))
                    .count()
                    .get_result::<i64>(conn_sync)
                    .map(|count| count > 0)
            })
            .await
            .map_err(|e| {
                error!(
                    "DB interaction failed while checking character lorebook association: {}",
                    e
                );
                AppError::DbInteractError(format!("DB interaction failed: {e}"))
            })?
            .map_err(|db_err| {
                error!("Failed to query character lorebook association: {}", db_err);
                AppError::DatabaseQueryError(db_err.to_string())
            })?;

        // If the lorebook is linked via character and has a 'disable' override,
        // remove the override because the user is explicitly adding it to the chat.
        if is_character_linked {
            info!(
                "Lorebook [REDACTED_UUID] is being explicitly associated with chat [REDACTED_UUID]. It's also a character lorebook. Removing any 'disable' override."
            );

            let lorebook_id_clone_for_override = lorebook_id_to_associate;
            let chat_session_id_clone_for_override = chat_session_id;
            let user_id_clone_for_override = current_user_id;

            let override_removed_result = conn
                .interact(move |conn_sync| {
                    use crate::schema::chat_character_lorebook_overrides::dsl as cclo_dsl;
                    let target = cclo_dsl::chat_character_lorebook_overrides
                        .filter(cclo_dsl::chat_session_id.eq(chat_session_id_clone_for_override))
                        .filter(cclo_dsl::lorebook_id.eq(lorebook_id_clone_for_override))
                        .filter(cclo_dsl::user_id.eq(user_id_clone_for_override))
                        .filter(cclo_dsl::action.eq("disable"));

                    diesel::delete(target).execute(conn_sync)
                })
                .await;

            match override_removed_result {
                Ok(Ok(rows_deleted)) if rows_deleted > 0 => {
                    info!(
                        "Removed 'disable' override for character-linked lorebook [REDACTED_UUID] in chat [REDACTED_UUID] as it's being explicitly added."
                    );
                }
                Ok(Ok(_)) => { /* No override was present or deleted, which is fine */ }
                Ok(Err(db_err)) => {
                    error!("Failed to delete lorebook override: {}", db_err);
                    // Decide if this should be a hard error or just a warning.
                    // For now, let's make it a hard error to ensure data consistency.
                    return Err(AppError::DatabaseQueryError(db_err.to_string()));
                }
                Err(e) => {
                    error!(
                        "DB interaction failed while checking/removing lorebook override: {}",
                        e
                    );
                    return Err(AppError::DbInteractError(format!(
                        "DB interaction failed: {e}"
                    )));
                }
            }
        }

        // 4. Create or update the direct chat-level association.
        // This ensures its `source` will be 'Chat'.
        let association_creation_time = Utc::now();
        let current_user_id_clone_for_insert = current_user_id; // Clone for interact closure
        let lorebook_id_to_associate_clone_for_insert = lorebook_id_to_associate; // Clone for interact closure

        let new_record_for_insert = NewChatSessionLorebook {
            // Renamed to avoid conflict if new_record was used above
            chat_session_id,
            lorebook_id: lorebook_id_to_associate_clone_for_insert,
            user_id: current_user_id_clone_for_insert,
            created_at: Some(association_creation_time),
            updated_at: Some(association_creation_time),
        };

        conn.interact(move |conn_sync| {
                use crate::schema::chat_session_lorebooks::dsl as csl_dsl;
                diesel::insert_into(csl_dsl::chat_session_lorebooks)
                    .values(&new_record_for_insert) // Use the renamed variable
                    .on_conflict((csl_dsl::chat_session_id, csl_dsl::lorebook_id))
                    .do_update()
                    // Set updated_at to ensure the trigger fires, or if no trigger, it's explicitly updated.
                    // If your DB trigger handles updated_at on its own, you might not need to set it here.
                    // However, explicitly setting it ensures the value is current if the trigger isn't comprehensive.
                    .set(csl_dsl::updated_at.eq(diesel::dsl::now))
                    .execute(conn_sync)
            })
            .await
            .map_err(|e| {
            error!("DB interaction failed while creating association between chat [REDACTED_UUID] and lorebook [REDACTED_UUID]: {}", e);
            AppError::DbInteractError(format!("DB interaction failed: {e}"))
        })?
        .map_err(|db_err: DieselError| { // Explicitly type db_err
            error!("Failed to insert chat session lorebook association: {}", db_err); // No UUIDs here
            match db_err {
                DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {
                    AppError::Conflict("This lorebook is already associated with the chat session.".to_string())
                }
                _ => AppError::DatabaseQueryError(db_err.to_string()),
            }
        })?;

        info!(
            "Successfully associated lorebook [REDACTED_UUID] with chat session [REDACTED_UUID] for user [REDACTED_UUID]"
        );

        // After successful association, attempt to embed all enabled entries from the lorebook.
        // This is a best-effort operation; failures here should not fail the association.
        let user_dek_bytes_for_embedding = if let Some(dek) = user_dek {
            dek.expose_secret().clone()
        } else {
            error!(
                "User DEK not available for embedding entries during lorebook [REDACTED_UUID] association to chat [REDACTED_UUID] for user [REDACTED_UUID]. Skipping embedding."
            );
            // Return success for association, as embedding is secondary.
            return Ok(ChatSessionLorebookAssociationResponse {
                chat_session_id,
                lorebook_id: lorebook_id_to_associate,
                user_id: current_user_id,
                lorebook_name,
                created_at: association_creation_time,
            });
        };

        let entries_to_embed_result = conn
            .interact({
                let lorebook_id_for_fetch = lorebook_id_to_associate;
                let user_id_for_fetch = current_user_id;
                move |conn_sync| {
                    lorebook_entries::table
                        .filter(lorebook_entries::lorebook_id.eq(lorebook_id_for_fetch))
                        .filter(lorebook_entries::user_id.eq(user_id_for_fetch))
                        .select(LorebookEntry::as_select())
                        .load::<LorebookEntry>(conn_sync)
                }
            })
            .await;

        match entries_to_embed_result {
            Ok(Ok(entries)) => {
                if entries.is_empty() {
                    info!(
                        "No entries found in lorebook [REDACTED_UUID] to embed during association with chat [REDACTED_UUID]."
                    );
                } else {
                    info!(
                        "Found {} entries in lorebook [REDACTED_UUID] to potentially embed during association with chat [REDACTED_UUID].",
                        entries.len()
                    );
                }
                for entry in entries {
                    if entry.is_enabled {
                        debug!("Processing entry [REDACTED_UUID] for embedding.",);
                        let encryption_service = self.encryption_service.clone();
                        let user_dek_bytes_entry_clone = user_dek_bytes_for_embedding.clone(); // Clone for this entry's decryption

                        let decrypted_title_result = encryption_service.decrypt(
                            &entry.entry_title_ciphertext,
                            &entry.entry_title_nonce,
                            &user_dek_bytes_entry_clone,
                        );
                        let decrypted_content_result = encryption_service.decrypt(
                            &entry.content_ciphertext,
                            &entry.content_nonce,
                            &user_dek_bytes_entry_clone,
                        );
                        let decrypted_keys_text_result = if entry.keys_text_nonce.is_empty() {
                            Ok(None) // No keys text to decrypt
                        } else {
                            encryption_service
                                .decrypt(
                                    &entry.keys_text_ciphertext,
                                    &entry.keys_text_nonce,
                                    &user_dek_bytes_entry_clone,
                                )
                                .map(Some) // Wrap in Some if decryption is successful
                        };

                        match (
                            decrypted_title_result,
                            decrypted_content_result,
                            decrypted_keys_text_result,
                        ) {
                            (Ok(title_bytes), Ok(content_bytes), Ok(keys_bytes_opt)) => {
                                let decrypted_title_for_embedding =
                                    String::from_utf8_lossy(&title_bytes).into_owned();
                                let decrypted_content_for_embedding =
                                    String::from_utf8_lossy(&content_bytes).into_owned();

                                let decrypted_keys_text_str_opt = keys_bytes_opt
                                    .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());

                                let decrypted_keywords_for_embedding =
                                    decrypted_keys_text_str_opt.as_ref().and_then(|keys_str| {
                                        if keys_str.trim().is_empty() {
                                            None
                                        } else {
                                            let keywords: Vec<String> = keys_str
                                                .split(',')
                                                .map(|s| s.trim().to_string())
                                                .filter(|s| !s.is_empty())
                                                .collect();
                                            if keywords.is_empty() {
                                                None
                                            } else {
                                                Some(keywords)
                                            }
                                        }
                                    });

                                let state_clone_for_task = state.clone();
                                let embedding_pipeline_service_clone =
                                    state_clone_for_task.embedding_pipeline_service.clone();
                                let entry_id_for_embedding = entry.id;
                                let lorebook_id_for_embedding_task = lorebook_id_to_associate;
                                let user_id_for_embedding_task = current_user_id;
                                let is_enabled_for_embedding_task = entry.is_enabled; // Should be true here
                                let is_constant_for_embedding_task = entry.is_constant;

                                tokio::spawn(async move {
                                    debug!(
                                        "Spawning task to process and embed lorebook entry [REDACTED_UUID] from lorebook [REDACTED_UUID] during chat association."
                                    );

                                    let params = LorebookEntryParams {
                                        original_lorebook_entry_id: entry_id_for_embedding,
                                        lorebook_id: lorebook_id_for_embedding_task,
                                        user_id: user_id_for_embedding_task,
                                        decrypted_content: decrypted_content_for_embedding,
                                        decrypted_title: Some(decrypted_title_for_embedding),
                                        decrypted_keywords: decrypted_keywords_for_embedding,
                                        is_enabled: is_enabled_for_embedding_task,
                                        is_constant: is_constant_for_embedding_task,
                                    };

                                    if let Err(e) = embedding_pipeline_service_clone
                                        .process_and_embed_lorebook_entry(
                                            state_clone_for_task,
                                            params,
                                        )
                                        .await
                                    {
                                        error!(
                                            "Failed to process and embed lorebook entry [REDACTED_UUID] in background during association: {:?}",
                                            e
                                        );
                                    } else {
                                        debug!(
                                            "Successfully queued lorebook entry [REDACTED_UUID] for embedding during association."
                                        );
                                    }
                                });
                            }
                            (Err(e), _, _) => error!(
                                "Failed to decrypt title for entry [REDACTED_UUID]: {:?}. Skipping embedding.",
                                e
                            ),
                            (_, Err(e), _) => error!(
                                "Failed to decrypt content for entry [REDACTED_UUID]: {:?}. Skipping embedding.",
                                e
                            ),
                            (_, _, Err(e)) => error!(
                                "Failed to decrypt keys_text for entry [REDACTED_UUID]: {:?}. Skipping embedding.",
                                e
                            ),
                        }
                    } else {
                        debug!(
                            "Skipping disabled entry [REDACTED_UUID] during bulk embedding for lorebook [REDACTED_UUID]."
                        );
                    }
                }
            }
            Ok(Err(db_err)) => {
                error!(
                    "Failed to query entries for lorebook [REDACTED_UUID] during association with chat [REDACTED_UUID]: {}. Skipping embedding of entries.",
                    db_err
                );
            }
            Err(interact_err) => {
                error!(
                    "DB interaction failed while fetching entries for lorebook [REDACTED_UUID] during association with chat [REDACTED_UUID]: {}. Skipping embedding of entries.",
                    interact_err
                );
            }
        }

        Ok(ChatSessionLorebookAssociationResponse {
            chat_session_id,
            lorebook_id: lorebook_id_to_associate,
            user_id: current_user_id,
            lorebook_name,
            created_at: association_creation_time, // Use the time captured before DB interaction
        })
    }

    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), chat_session_id = %chat_session_id_param))]
    pub async fn list_chat_lorebook_associations(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        chat_session_id_param: Uuid,
    ) -> Result<Vec<ChatSessionLorebookAssociationResponse>, AppError> {
        debug!(
            chat_session_id = "[REDACTED_UUID]",
            "Attempting to list chat lorebook associations"
        );
        let user = Self::get_user_from_session(auth_session)?;
        let current_user_id = user.id;

        let conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get DB connection: {}", e);
            AppError::DbPoolError(e.to_string())
        })?;

        // 1. Verify chat session ownership
        conn.interact(move |conn_sync| {
            use crate::schema::chat_sessions::dsl as cs_dsl;
            cs_dsl::chat_sessions
                .filter(cs_dsl::id.eq(chat_session_id_param))
                .filter(cs_dsl::user_id.eq(current_user_id))
                .select(cs_dsl::id)
                .first::<Uuid>(conn_sync)
                .optional()
        })
        .await
        .map_err(|e| {
            error!(
                "DB interaction failed while verifying chat session ownership for session [REDACTED_UUID]: {}",
                e
            );
            AppError::DbInteractError(format!("DB interaction failed: {e}"))
        })?
        .map_err(|db_err| {
            error!(
                "Failed to query chat session [REDACTED_UUID]: {}",
                db_err
            );
            AppError::DatabaseQueryError(db_err.to_string())
        })?
        .ok_or_else(|| {
            error!(
                "Chat session [REDACTED_UUID] not found or user [REDACTED_UUID] does not have access."
            );
            AppError::NotFound(format!(
                "Chat session with ID {chat_session_id_param} not found or access denied."
            ))
        })?;

        // 2. Fetch associations and join with lorebooks table for names
        let associations_with_names = conn
            .interact(move |conn_sync| {
                use crate::schema::chat_session_lorebooks::dsl as csl_dsl;
                use crate::schema::lorebooks::dsl as l_dsl;

                csl_dsl::chat_session_lorebooks
                    .inner_join(l_dsl::lorebooks.on(csl_dsl::lorebook_id.eq(l_dsl::id)))
                    .filter(csl_dsl::chat_session_id.eq(chat_session_id_param))
                    .filter(csl_dsl::user_id.eq(current_user_id)) // Ensure association belongs to the user
                    .select((
                        csl_dsl::chat_session_id,
                        csl_dsl::lorebook_id,
                        csl_dsl::user_id,
                        l_dsl::name,         // lorebook name
                        csl_dsl::created_at, // association creation time
                    ))
                    .load::<(Uuid, Uuid, Uuid, String, chrono::DateTime<Utc>)>(conn_sync)
            })
            .await
            .map_err(|e| {
                error!(
                    "DB interaction failed while listing associations for chat [REDACTED_UUID]: {}",
                    e
                );
                AppError::DbInteractError(format!("DB interaction failed: {e}"))
            })?
            .map_err(|db_err| {
                error!(
                    "Failed to query chat session lorebook associations for chat [REDACTED_UUID]: {}",
                    db_err
                );
                AppError::DatabaseQueryError(db_err.to_string())
            })?;

        let response_data = associations_with_names
            .into_iter()
            .map(|(cs_id, lb_id, u_id, lb_name, assoc_created_at)| {
                ChatSessionLorebookAssociationResponse {
                    chat_session_id: cs_id,
                    lorebook_id: lb_id,
                    user_id: u_id,
                    lorebook_name: lb_name,
                    created_at: assoc_created_at,
                }
            })
            .collect();

        Ok(response_data)
    }

    /// Enhanced version that includes source information and override status
    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), chat_session_id = %chat_session_id_param))]
    pub async fn list_enhanced_chat_lorebook_associations(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        chat_session_id_param: Uuid,
    ) -> Result<
        Vec<crate::models::lorebook_dtos::EnhancedChatSessionLorebookAssociationResponse>,
        AppError,
    > {
        debug!(
            chat_session_id = "[REDACTED_UUID]",
            "Attempting to list enhanced chat lorebook associations"
        );
        let user = Self::get_user_from_session(auth_session)?;
        let current_user_id = user.id;

        let conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get DB connection: {}", e);
            AppError::DbPoolError(e.to_string())
        })?;

        // 1. Get chat session and character ID
        let (_session_found, character_id) = conn
            .interact(move |conn_sync| {
                use crate::schema::chat_sessions::dsl as cs_dsl;
                cs_dsl::chat_sessions
                    .filter(cs_dsl::id.eq(chat_session_id_param))
                    .filter(cs_dsl::user_id.eq(current_user_id))
                    .select((cs_dsl::id, cs_dsl::character_id))
                    .first::<(Uuid, Uuid)>(conn_sync)
                    .optional()
            })
            .await
            .map_err(|e| {
                error!(
                    "DB interaction failed while verifying chat session: {}",
                    e
                );
                AppError::DbInteractError(format!("DB interaction failed: {e}"))
            })?
            .map_err(|db_err| {
                error!(
                    "Failed to query chat session [REDACTED_UUID]: {}",
                    db_err
                );
                AppError::DatabaseQueryError(db_err.to_string())
            })?
            .ok_or_else(|| {
                error!(
                    "Chat session [REDACTED_UUID] not found or user [REDACTED_UUID] does not have access."
                );
                AppError::NotFound(format!(
                    "Chat session with ID {chat_session_id_param} not found or access denied."
                ))
            })?;

        // 2. Get all lorebook associations with source information
        let associations_data = conn
            .interact(move |conn_sync| {
                use crate::schema::{
                    character_lorebooks::dsl as cl_dsl,
                    chat_character_lorebook_overrides::dsl as cclo_dsl,
                    chat_session_lorebooks::dsl as csl_dsl, lorebooks::dsl as l_dsl,
                };

                // Get chat-linked associations
                let chat_associations = csl_dsl::chat_session_lorebooks
                    .inner_join(l_dsl::lorebooks.on(csl_dsl::lorebook_id.eq(l_dsl::id)))
                    .filter(csl_dsl::chat_session_id.eq(chat_session_id_param))
                    .filter(csl_dsl::user_id.eq(current_user_id))
                    .select((csl_dsl::lorebook_id, l_dsl::name, csl_dsl::created_at))
                    .load::<(Uuid, String, chrono::DateTime<Utc>)>(conn_sync)?;

                // Get character-linked associations
                let character_associations = cl_dsl::character_lorebooks
                    .inner_join(l_dsl::lorebooks.on(cl_dsl::lorebook_id.eq(l_dsl::id)))
                    .filter(cl_dsl::character_id.eq(character_id))
                    .filter(cl_dsl::user_id.eq(current_user_id))
                    .select((cl_dsl::lorebook_id, l_dsl::name, cl_dsl::created_at))
                    .load::<(Uuid, String, chrono::DateTime<Utc>)>(conn_sync)?;

                // Get all overrides for this chat session
                let overrides = cclo_dsl::chat_character_lorebook_overrides
                    .filter(cclo_dsl::chat_session_id.eq(chat_session_id_param))
                    .filter(cclo_dsl::user_id.eq(current_user_id))
                    .select((cclo_dsl::lorebook_id, cclo_dsl::action))
                    .load::<(Uuid, String)>(conn_sync)?;

                Ok::<_, diesel::result::Error>((
                    chat_associations,
                    character_associations,
                    overrides,
                ))
            })
            .await
            .map_err(|e| {
                error!(
                    "DB interaction failed while listing enhanced associations: {}",
                    e
                );
                AppError::DbInteractError(format!("DB interaction failed: {e}"))
            })?
            .map_err(|db_err| {
                error!("Failed to query enhanced associations: {}", db_err);
                AppError::DatabaseQueryError(db_err.to_string())
            })?;

        let (chat_associations, character_associations, overrides) = associations_data;

        debug!(
            chat_session_id = %chat_session_id_param,
            chat_associations_count = chat_associations.len(),
            character_associations_count = character_associations.len(),
            overrides_count = overrides.len(),
            "Fetched raw lorebook association data."
        );

        for (id, name, _) in &chat_associations {
            debug!(
                chat_session_id = %chat_session_id_param,
                lorebook_id = %id,
                lorebook_name = %name,
                source = "Chat",
                "Raw chat association."
            );
        }

        for (id, name, _) in &character_associations {
            debug!(
                chat_session_id = %chat_session_id_param,
                lorebook_id = %id,
                lorebook_name = %name,
                source = "Character",
                "Raw character association."
            );
            // Also log if this character association has an override
            if let Some(action) = overrides
                .iter()
                .find(|(ov_id, _)| ov_id == id)
                .map(|(_, act)| act)
            {
                debug!(
                    chat_session_id = %chat_session_id_param,
                    lorebook_id = %id,
                    lorebook_name = %name,
                    override_action = %action,
                    "Character association has override."
                );
            }
        }

        for (id, action) in &overrides {
            debug!(
                chat_session_id = %chat_session_id_param,
                lorebook_id = %id,
                override_action = %action,
                "Raw override."
            );
        }

        // 3. Build override map
        let override_map: std::collections::HashMap<Uuid, String> = overrides.into_iter().collect();

        // 4. Build a map to store unique lorebook associations, prioritizing chat-level
        let mut unique_associations: std::collections::HashMap<
            Uuid,
            crate::models::lorebook_dtos::EnhancedChatSessionLorebookAssociationResponse,
        > = std::collections::HashMap::new();

        // First, add chat-linked associations (these take precedence)
        for (lorebook_id, lorebook_name, created_at) in chat_associations {
            unique_associations.insert(
                lorebook_id,
                crate::models::lorebook_dtos::EnhancedChatSessionLorebookAssociationResponse {
                    chat_session_id: chat_session_id_param,
                    lorebook_id,
                    user_id: current_user_id,
                    lorebook_name,
                    source: crate::models::lorebook_dtos::LorebookAssociationSource::Chat,
                    is_overridden: false, // Chat associations cannot be overridden by character overrides
                    override_action: None,
                    created_at,
                },
            );
        }

        // Then, add character-linked associations, but only if not already present (i.e., not overridden by a chat association)
        for (lorebook_id, lorebook_name, created_at) in character_associations {
            if !unique_associations.contains_key(&lorebook_id) {
                let override_action = override_map.get(&lorebook_id);
                let is_overridden = override_action.is_some();

                unique_associations.insert(
                    lorebook_id,
                    crate::models::lorebook_dtos::EnhancedChatSessionLorebookAssociationResponse {
                        chat_session_id: chat_session_id_param,
                        lorebook_id,
                        user_id: current_user_id,
                        lorebook_name,
                        source: crate::models::lorebook_dtos::LorebookAssociationSource::Character,
                        is_overridden,
                        override_action: override_action.cloned(),
                        created_at,
                    },
                );
            }
        }

        // Convert the map values to a vector
        Ok(unique_associations.into_values().collect())
    }

    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), chat_session_id = %chat_session_id_param, lorebook_id = %lorebook_id_param))]
    pub async fn disassociate_lorebook_from_chat(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        chat_session_id_param: Uuid,
        lorebook_id_param: Uuid,
    ) -> Result<(), AppError> {
        debug!("Attempting to disassociate lorebook [REDACTED_UUID] from chat [REDACTED_UUID]");
        let user = Self::get_user_from_session(auth_session)?;
        let current_user_id = user.id;

        let conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get DB connection: {}", e);
            AppError::DbPoolError(e.to_string())
        })?;

        // 1. Get chat session and character ID for validation and character lorebook check
        let (_chat_session_id, character_id) = conn
            .interact(move |conn_sync| {
                use crate::schema::chat_sessions::dsl as cs_dsl;
                cs_dsl::chat_sessions
                    .filter(cs_dsl::id.eq(chat_session_id_param))
                    .filter(cs_dsl::user_id.eq(current_user_id))
                    .select((cs_dsl::id, cs_dsl::character_id))
                    .first::<(Uuid, Uuid)>(conn_sync)
                    .optional()
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
            .map_err(|db_err| AppError::DatabaseQueryError(db_err.to_string()))?
            .ok_or_else(|| {
                AppError::NotFound(format!(
                    "Chat session with ID {chat_session_id_param} not found or access denied."
                ))
            })?;

        // 2. Check what type of association this is and handle appropriately
        let association_info = conn
            .interact(move |conn_sync| {
                use crate::schema::{
                    character_lorebooks::dsl as cl_dsl, chat_session_lorebooks::dsl as csl_dsl,
                };

                // Check if it's a chat-level association
                let chat_association_exists = csl_dsl::chat_session_lorebooks
                    .filter(csl_dsl::chat_session_id.eq(chat_session_id_param))
                    .filter(csl_dsl::lorebook_id.eq(lorebook_id_param))
                    .filter(csl_dsl::user_id.eq(current_user_id))
                    .count()
                    .get_result::<i64>(conn_sync)?
                    > 0;

                // Check if it's a character-level association
                let character_association_exists = cl_dsl::character_lorebooks
                    .filter(cl_dsl::character_id.eq(character_id))
                    .filter(cl_dsl::lorebook_id.eq(lorebook_id_param))
                    .filter(cl_dsl::user_id.eq(current_user_id))
                    .count()
                    .get_result::<i64>(conn_sync)?
                    > 0;

                Ok::<_, diesel::result::Error>((
                    chat_association_exists,
                    character_association_exists,
                ))
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
            .map_err(|db_err| AppError::DatabaseQueryError(db_err.to_string()))?;

        let (is_chat_association, is_character_association) = association_info;

        if is_chat_association && is_character_association {
            // REDUNDANT ASSOCIATION CASE - both chat and character level exist
            // Remove the chat association and create a disable override for the character one
            info!(
                "Redundant associations detected for lorebook [REDACTED_UUID] in chat [REDACTED_UUID]. Removing chat association and disabling character association."
            );

            let rows_deleted = conn
                .interact(move |conn_sync| {
                    use crate::schema::chat_session_lorebooks::dsl as csl_dsl;
                    diesel::delete(
                        csl_dsl::chat_session_lorebooks
                            .filter(csl_dsl::chat_session_id.eq(chat_session_id_param))
                            .filter(csl_dsl::lorebook_id.eq(lorebook_id_param))
                            .filter(csl_dsl::user_id.eq(current_user_id)),
                    )
                    .execute(conn_sync)
                })
                .await
                .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
                .map_err(|db_err| AppError::DatabaseQueryError(db_err.to_string()))?;

            if rows_deleted > 0 {
                // Also create a disable override for the character association
                self.set_character_lorebook_override(
                    auth_session,
                    chat_session_id_param,
                    lorebook_id_param,
                    "disable".to_string(),
                )
                .await?;

                info!(
                    "Successfully cleaned up redundant associations for lorebook [REDACTED_UUID] in chat [REDACTED_UUID]"
                );
                Ok(())
            } else {
                Err(AppError::NotFound(
                    "Chat lorebook association not found for this chat session and user."
                        .to_string(),
                ))
            }
        } else if is_chat_association {
            // Handle chat-level association only - delete it
            let rows_deleted = conn
                .interact(move |conn_sync| {
                    use crate::schema::chat_session_lorebooks::dsl as csl_dsl;
                    diesel::delete(
                        csl_dsl::chat_session_lorebooks
                            .filter(csl_dsl::chat_session_id.eq(chat_session_id_param))
                            .filter(csl_dsl::lorebook_id.eq(lorebook_id_param))
                            .filter(csl_dsl::user_id.eq(current_user_id)),
                    )
                    .execute(conn_sync)
                })
                .await
                .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
                .map_err(|db_err| AppError::DatabaseQueryError(db_err.to_string()))?;

            if rows_deleted > 0 {
                info!(
                    "Successfully removed chat-level lorebook association [REDACTED_UUID] from chat [REDACTED_UUID]"
                );
                Ok(())
            } else {
                Err(AppError::NotFound(
                    "Chat lorebook association not found for this chat session and user."
                        .to_string(),
                ))
            }
        } else if is_character_association {
            // Handle character-level association - create a disable override
            info!(
                "Creating disable override for character lorebook [REDACTED_UUID] in chat [REDACTED_UUID]"
            );
            self.set_character_lorebook_override(
                auth_session,
                chat_session_id_param,
                lorebook_id_param,
                "disable".to_string(),
            )
            .await?;

            info!(
                "Successfully disabled character lorebook [REDACTED_UUID] for chat [REDACTED_UUID]"
            );
            Ok(())
        } else {
            // No association found
            Err(AppError::NotFound(
                "No lorebook association found for this chat session and user. The lorebook may not be associated with this chat or character.".to_string(),
            ))
        }
    }

    #[instrument(skip(self, auth_session, user_dek), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id_param))]
    pub async fn list_associated_chat_sessions_for_lorebook(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        lorebook_id_param: Uuid,
        user_dek: Option<&SecretBox<Vec<u8>>>,
    ) -> Result<Vec<ChatSessionBasicInfo>, AppError> {
        debug!(
            lorebook_id = "[REDACTED_UUID]",
            "Attempting to list chat sessions associated with lorebook"
        );
        let user = Self::get_user_from_session(auth_session)?;
        let current_user_id = user.id;

        let conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get DB connection: {}", e);
            AppError::DbPoolError(e.to_string())
        })?;

        // 1. Verify lorebook ownership
        conn.interact(move |conn_sync| {
            use crate::schema::lorebooks::dsl as l_dsl;
            l_dsl::lorebooks
                .filter(l_dsl::id.eq(lorebook_id_param))
                .filter(l_dsl::user_id.eq(current_user_id))
                .select(l_dsl::id)
                .first::<Uuid>(conn_sync)
                .optional()
        })
        .await
        .map_err(|e| {
            error!(
                "DB interaction failed while verifying lorebook ownership for lorebook [REDACTED_UUID]: {}",
                e
            );
            AppError::DbInteractError(format!("DB interaction failed: {e}"))
        })?
        .map_err(|db_err| {
            error!("Failed to query lorebook [REDACTED_UUID]: {}", db_err);
            AppError::DatabaseQueryError(db_err.to_string())
        })?
        .ok_or_else(|| {
            error!(
                "Lorebook [REDACTED_UUID] not found or user [REDACTED_UUID] does not have access."
            );
            AppError::NotFound(format!(
                "Lorebook with ID {lorebook_id_param} not found or access denied."
            ))
        })?;

        // 2. Fetch associated chat sessions
        let associated_chats = conn
            .interact(move |conn_sync| {
                use crate::schema::chat_session_lorebooks::dsl as csl_dsl;
                use crate::schema::chat_sessions::dsl as cs_dsl;

                csl_dsl::chat_session_lorebooks
                    .inner_join(cs_dsl::chat_sessions.on(csl_dsl::chat_session_id.eq(cs_dsl::id)))
                    .filter(csl_dsl::lorebook_id.eq(lorebook_id_param))
                    .filter(csl_dsl::user_id.eq(current_user_id)) // Ensure association belongs to the user
                    .select((
                        cs_dsl::id,               // chat_session_id
                        cs_dsl::title_ciphertext, // chat_session title (encrypted)
                        cs_dsl::title_nonce,      // chat_session title nonce
                    ))
                    .load::<(Uuid, Option<Vec<u8>>, Option<Vec<u8>>)>(conn_sync)
            })
            .await
            .map_err(|e| {
                error!(
                    "DB interaction failed while listing associated chats for lorebook [REDACTED_UUID]: {}",
                    e
                );
                AppError::DbInteractError(format!("DB interaction failed: {e}"))
            })?
            .map_err(|db_err| {
                error!(
                    "Failed to query associated chat sessions for lorebook [REDACTED_UUID]: {}",
                    db_err
                );
                AppError::DatabaseQueryError(db_err.to_string())
            })?;

        let dek_bytes = user_dek
            .ok_or_else(|| {
                error!("User DEK not provided for decrypting chat session titles.");
                AppError::EncryptionError(
                    "User DEK not available for title decryption.".to_string(),
                )
            })?
            .expose_secret();

        let mut response_data = Vec::new();
        for (chat_id, encrypted_title_opt, nonce_opt) in associated_chats {
            let title = match (encrypted_title_opt, nonce_opt) {
                (Some(ciphertext), Some(nonce)) => {
                    if ciphertext.is_empty() && nonce.is_empty() {
                        // Convention for NULL in DB post-encryption
                        None
                    } else {
                        match self
                            .encryption_service
                            .decrypt(&ciphertext, &nonce, dek_bytes)
                        {
                            Ok(decrypted_bytes) => String::from_utf8(decrypted_bytes).ok(),
                            Err(e) => {
                                error!(
                                    "Failed to decrypt title for chat session [REDACTED_UUID]: {:?}",
                                    e
                                );
                                Some("[Decryption Error]".to_string())
                            }
                        }
                    }
                }
                _ => None, // If either ciphertext or nonce is missing
            };
            response_data.push(ChatSessionBasicInfo {
                chat_session_id: chat_id,
                title,
            });
        }

        Ok(response_data)
    }

    /// Exports a lorebook in SillyTavern format
    ///
    /// # Errors
    ///
    /// Returns `AppError::Unauthorized` if the user is not authenticated,
    /// `AppError::NotFound` if the lorebook doesn't exist or user doesn't have access,
    /// `AppError::InternalServerErrorGeneric` if database connection fails or database interaction errors occur.
    #[instrument(skip(self, auth_session, user_dek), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id))]
    pub async fn export_lorebook(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        user_dek: Option<&SecretBox<Vec<u8>>>,
        lorebook_id: Uuid,
    ) -> Result<crate::models::lorebook_dtos::ExportedLorebook, AppError> {
        let _user = Self::get_user_from_session(auth_session)?;

        // First get the lorebook metadata
        let lorebook = self.get_lorebook(auth_session, lorebook_id).await?;

        // Fetch all entry summaries for this lorebook
        let entry_summaries = self
            .list_lorebook_entries(auth_session, lorebook_id, user_dek)
            .await?;

        // Convert to SillyTavern format
        use std::collections::HashMap;
        let mut exported_entries = HashMap::new();

        // Fetch full details for each entry
        for (index, summary) in entry_summaries.into_iter().enumerate() {
            // Get full entry details
            match self
                .get_lorebook_entry(auth_session, lorebook_id, summary.id, user_dek)
                .await
            {
                Ok(full_entry) => {
                    let keywords: Vec<String> = full_entry
                        .keys_text
                        .unwrap_or_default()
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();

                    let exported_entry = crate::models::lorebook_dtos::ExportedLorebookEntry {
                        uid: index as i32,
                        key: keywords,
                        keysecondary: Vec::new(), // Not used by Scribe
                        comment: full_entry.comment.unwrap_or_default(),
                        content: full_entry.content,
                        disable: !full_entry.is_enabled, // Invert the logic
                        constant: full_entry.is_constant,
                        order: full_entry.insertion_order,
                        position: if full_entry.placement_hint == "before_prompt" {
                            0
                        } else {
                            1
                        },
                        selective: true, // Default value for SillyTavern compatibility
                        display_index: index as i32,
                        add_memo: true, // Default value for SillyTavern compatibility
                        group: String::new(),
                        group_override: false,
                        group_weight: 100,
                        sticky: 0,
                        cooldown: 0,
                        delay: 0,
                        probability: 100,
                        depth: 4,
                        use_probability: true,
                        role: None,
                        vectorized: false,
                        exclude_recursion: false,
                        prevent_recursion: false,
                        delay_until_recursion: false,
                        scan_depth: None,
                        case_sensitive: None,
                        match_whole_words: None,
                        use_group_scoring: None,
                        automation_id: String::new(),
                        match_persona_description: false,
                        match_character_description: false,
                        match_character_personality: false,
                        match_character_depth_prompt: false,
                        match_scenario: false,
                        match_creator_notes: false,
                    };

                    exported_entries.insert(index.to_string(), exported_entry);
                }
                Err(e) => {
                    error!("Failed to fetch entry details for [REDACTED_UUID]: {:?}", e);
                }
            }
        }

        Ok(crate::models::lorebook_dtos::ExportedLorebook {
            entries: exported_entries,
            name: Some(lorebook.name),
            description: lorebook.description,
        })
    }

    /// Exports a lorebook in minimal Scribe format for RAG-based systems
    ///
    /// # Errors
    ///
    /// Returns `AppError::Unauthorized` if the user is not authenticated,
    /// Returns `AppError::NotFound` if the lorebook doesn't exist or user doesn't have access,
    /// Returns `AppError::InternalServerErrorGeneric` if database connection fails or database interaction errors occur.
    #[instrument(skip(self, auth_session, user_dek), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id))]
    pub async fn export_lorebook_minimal(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        user_dek: Option<&SecretBox<Vec<u8>>>,
        lorebook_id: Uuid,
    ) -> Result<crate::models::lorebook_dtos::ScribeMinimalLorebook, AppError> {
        let _user = Self::get_user_from_session(auth_session)?;

        // First get the lorebook metadata
        let lorebook = self.get_lorebook(auth_session, lorebook_id).await?;

        // Fetch all entries with full content
        let entries = self
            .list_lorebook_entries_with_content(auth_session, lorebook_id, user_dek)
            .await?;

        // Convert to minimal format
        let minimal_entries: Vec<crate::models::lorebook_dtos::ScribeMinimalLorebookEntry> =
            entries
                .into_iter()
                .map(|entry| {
                    let keywords: Vec<String> = entry
                        .keys_text
                        .unwrap_or_default()
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();

                    crate::models::lorebook_dtos::ScribeMinimalLorebookEntry {
                        title: entry.entry_title,
                        keywords,
                        content: entry.content,
                    }
                })
                .collect();

        Ok(crate::models::lorebook_dtos::ScribeMinimalLorebook {
            name: lorebook.name,
            description: lorebook.description,
            entries: minimal_entries,
        })
    }

    /// Imports a lorebook from SillyTavern format
    ///
    /// # Errors
    ///
    /// Returns `AppError::Unauthorized` if the user is not authenticated,
    /// `AppError::ValidationError` if the payload is invalid,
    /// `AppError::InternalServerErrorGeneric` if database connection fails or database interaction errors occur.
    #[instrument(skip(self, auth_session, user_dek, payload), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)))]
    pub async fn import_lorebook(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        user_dek: Option<&SecretBox<Vec<u8>>>,
        payload: crate::models::lorebook_dtos::LorebookUploadPayload,
        state: Arc<AppState>,
    ) -> Result<LorebookResponse, AppError> {
        let user = Self::get_user_from_session(auth_session)?;

        let new_lorebook_id = Uuid::new_v4();
        let current_time = Utc::now();

        let new_lorebook_db = crate::models::NewLorebook {
            id: new_lorebook_id,
            user_id: user.id,
            name: payload.name,
            description: payload.description,
            source_format: "silly_tavern_full_v1".to_string(), // Set correct format
            is_public: payload.is_public,                      // Use payload's is_public
            created_at: Some(current_time),
            updated_at: Some(current_time),
        };

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        let lorebook = conn
            .interact(move |conn_sync| {
                diesel::insert_into(lorebooks::table)
                    .values(&new_lorebook_db)
                    .returning(Lorebook::as_returning())
                    .get_result::<Lorebook>(conn_sync)
            })
            .await
            .map_err(|e| {
                error!("Interaction error while inserting lorebook: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Database interaction failed while creating lorebook: {e}"
                ))
            })?
            .map_err(|e| {
                error!("Failed to insert lorebook into DB: {:?}", e);
                AppError::InternalServerErrorGeneric(format!(
                    "Failed to create lorebook in DB: {e}"
                ))
            })?;

        info!(
            "Successfully created lorebook [REDACTED_UUID] with format 'silly_tavern_full_v1' for user [REDACTED_UUID]"
        );

        // Import all entries
        for (uid, entry) in payload.entries {
            let keys_text = if entry.key.as_ref().map_or(true, |k| k.is_empty()) {
                None
            } else {
                Some(entry.key.as_ref().unwrap().join(", "))
            };

            let placement_hint = match entry.position {
                Some(0) => "before_prompt".to_string(),
                Some(1) => "after_prompt".to_string(),
                _ => "after_prompt".to_string(),
            };

            let entry_payload = CreateLorebookEntryPayload {
                entry_title: entry
                    .display_name
                    .clone()
                    .or_else(|| entry.comment.clone())
                    .unwrap_or_else(|| format!("Entry {}", uid)),
                keys_text,
                content: entry.content.clone(),
                comment: entry.comment.clone(),
                is_enabled: entry
                    .enabled
                    .or_else(|| entry.disable.map(|d| !d))
                    .or(Some(true)), // Use enabled if present, otherwise invert disable, default to true
                is_constant: entry.constant,
                insertion_order: entry.order,
                placement_hint: Some(placement_hint),
            };

            tracing::debug!(
                "Creating lorebook entry [REDACTED_UUID]: title='[REDACTED]', content_len=[REDACTED], keys=[REDACTED]"
            );
            // Create the entry directly without embedding generation
            let new_entry_id = Uuid::new_v4();

            // Encrypt the fields if DEK is provided
            let (entry_title_ciphertext, entry_title_nonce) = if let Some(dek) = user_dek {
                match self
                    .encryption_service
                    .encrypt(&entry_payload.entry_title, dek.expose_secret())
                {
                    Ok((ciphertext, nonce)) => (ciphertext, nonce),
                    Err(e) => {
                        error!("Failed to encrypt entry title: {}", e);
                        continue;
                    }
                }
            } else {
                return Err(AppError::EncryptionError(
                    "User DEK not provided".to_string(),
                ));
            };

            let (keys_text_ciphertext, keys_text_nonce) =
                if let Some(keys) = &entry_payload.keys_text {
                    match self
                        .encryption_service
                        .encrypt(keys, user_dek.unwrap().expose_secret())
                    {
                        Ok((ciphertext, nonce)) => (ciphertext, nonce),
                        Err(e) => {
                            error!("Failed to encrypt keys text: {}", e);
                            continue;
                        }
                    }
                } else {
                    (vec![], vec![])
                };

            let (content_ciphertext, content_nonce) = match self
                .encryption_service
                .encrypt(&entry_payload.content, user_dek.unwrap().expose_secret())
            {
                Ok((ciphertext, nonce)) => (ciphertext, nonce),
                Err(e) => {
                    error!("Failed to encrypt content: {}", e);
                    continue;
                }
            };

            let (comment_ciphertext, comment_nonce) = if let Some(comment) = &entry_payload.comment
            {
                match self
                    .encryption_service
                    .encrypt(comment, user_dek.unwrap().expose_secret())
                {
                    Ok((ciphertext, nonce)) => (Some(ciphertext), Some(nonce)),
                    Err(e) => {
                        error!("Failed to encrypt comment: {}", e);
                        continue;
                    }
                }
            } else {
                (None, None)
            };

            let new_entry_db = NewLorebookEntry {
                id: new_entry_id,
                lorebook_id: lorebook.id,
                user_id: user.id,
                entry_title_ciphertext,
                entry_title_nonce,
                keys_text_ciphertext,
                keys_text_nonce,
                content_ciphertext,
                content_nonce,
                comment_ciphertext,
                comment_nonce,
                is_enabled: entry_payload.is_enabled.unwrap_or(true),
                is_constant: entry_payload.is_constant.unwrap_or(false),
                insertion_order: entry_payload.insertion_order.unwrap_or(100),
                name: None,
                placement_hint: entry_payload.placement_hint,
                original_sillytavern_uid: entry.uid,
                sillytavern_metadata_ciphertext: None,
                sillytavern_metadata_nonce: None,
                created_at: Some(current_time),
                updated_at: Some(current_time),
            };

            let conn = self.pool.get().await.map_err(|e| {
                AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
            })?;

            match conn
                .interact(move |conn_sync| {
                    diesel::insert_into(lorebook_entries::table)
                        .values(&new_entry_db)
                        .returning(LorebookEntry::as_returning())
                        .get_result::<LorebookEntry>(conn_sync)
                })
                .await
            {
                Ok(Ok(inserted_entry)) => {
                    // Generate embeddings for the newly created entry
                    info!("Generating embeddings for imported lorebook entry [REDACTED_UUID]");

                    let user_dek_bytes = user_dek.unwrap().expose_secret();

                    // Decrypt the content for embedding
                    let decrypted_title_result = self.encryption_service.decrypt(
                        &inserted_entry.entry_title_ciphertext,
                        &inserted_entry.entry_title_nonce,
                        user_dek_bytes,
                    );
                    let decrypted_content_result = self.encryption_service.decrypt(
                        &inserted_entry.content_ciphertext,
                        &inserted_entry.content_nonce,
                        user_dek_bytes,
                    );
                    let decrypted_keys_text_result = if inserted_entry.keys_text_nonce.is_empty() {
                        Ok(None)
                    } else {
                        self.encryption_service
                            .decrypt(
                                &inserted_entry.keys_text_ciphertext,
                                &inserted_entry.keys_text_nonce,
                                user_dek_bytes,
                            )
                            .map(Some)
                    };

                    match (
                        decrypted_title_result,
                        decrypted_content_result,
                        decrypted_keys_text_result,
                    ) {
                        (Ok(title_bytes), Ok(content_bytes), Ok(keys_bytes_opt)) => {
                            let decrypted_title =
                                String::from_utf8_lossy(&title_bytes).into_owned();
                            let decrypted_content =
                                String::from_utf8_lossy(&content_bytes).into_owned();
                            let decrypted_keywords = keys_bytes_opt
                                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                                .and_then(|keys_str| {
                                    if keys_str.trim().is_empty() {
                                        None
                                    } else {
                                        let keywords: Vec<String> = keys_str
                                            .split(',')
                                            .map(|s| s.trim().to_string())
                                            .filter(|s| !s.is_empty())
                                            .collect();
                                        if keywords.is_empty() {
                                            None
                                        } else {
                                            Some(keywords)
                                        }
                                    }
                                });

                            let params = crate::services::embedding_pipeline::LorebookEntryParams {
                                original_lorebook_entry_id: inserted_entry.id,
                                lorebook_id: inserted_entry.lorebook_id,
                                user_id: inserted_entry.user_id,
                                decrypted_content,
                                decrypted_title: Some(decrypted_title),
                                decrypted_keywords,
                                is_enabled: inserted_entry.is_enabled,
                                is_constant: inserted_entry.is_constant,
                            };

                            // Spawn embedding generation in background to avoid blocking import
                            let state_clone = state.clone();
                            tokio::spawn(async move {
                                if let Err(e) = state_clone
                                    .embedding_pipeline_service
                                    .process_and_embed_lorebook_entry(state_clone.clone(), params)
                                    .await
                                {
                                    error!(
                                        "Failed to generate embeddings for imported lorebook entry: {:?}",
                                        e
                                    );
                                }
                            });
                        }
                        _ => {
                            error!(
                                "Failed to decrypt lorebook entry fields for embedding generation. Skipping embeddings for this entry."
                            );
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!("Failed to import entry [REDACTED_UUID]: {:?}", e);
                    // Continue importing other entries
                }
                Err(e) => {
                    error!("Failed to import entry [REDACTED_UUID]: {:?}", e);
                    // Continue importing other entries
                }
            }
        }

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

    /// Imports a lorebook from Scribe Minimal format
    ///
    /// # Errors
    ///
    /// Returns `AppError::Unauthorized` if the user is not authenticated,
    /// `AppError::ValidationError` if the payload is invalid,
    /// `AppError::InternalServerErrorGeneric` if database connection fails or database interaction errors occur.
    #[instrument(skip(self, auth_session, user_dek, payload), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)))]
    pub async fn import_lorebook_from_scribe_minimal(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        user_dek: Option<&SecretBox<Vec<u8>>>,
        payload: crate::models::lorebook_dtos::ScribeMinimalLorebook,
        state: Arc<AppState>,
    ) -> Result<LorebookResponse, AppError> {
        let _user = Self::get_user_from_session(auth_session)?;

        // Create the lorebook
        let create_payload: CreateLorebookPayload = payload.clone().into(); // Use the From impl
        let lorebook = self.create_lorebook(auth_session, create_payload).await?;

        // Import all entries
        for entry in payload.entries {
            let keys_text = if entry.keywords.is_empty() {
                None
            } else {
                Some(entry.keywords.join(", "))
            };

            let entry_payload = CreateLorebookEntryPayload {
                entry_title: entry.title,
                keys_text,
                content: entry.content,
                comment: None,            // Scribe minimal format doesn't have comments
                is_enabled: Some(true),   // Default to enabled
                is_constant: Some(false), // Default to not constant
                insertion_order: Some(100), // Default order
                placement_hint: Some("after_prompt".to_string()), // Default placement
            };

            tracing::debug!(
                "Creating lorebook entry: title='{}', content_len={}, keys={:?}",
                entry_payload.entry_title,
                entry_payload.content.len(),
                entry_payload.keys_text
            );

            // Create the entry using the existing create_lorebook_entry method
            // This will handle encryption and embedding
            if let Err(e) = self
                .create_lorebook_entry(
                    auth_session,
                    lorebook.id,
                    entry_payload,
                    user_dek,
                    state.clone(),
                )
                .await
            {
                error!(
                    "Failed to import scribe minimal entry for lorebook [REDACTED_UUID]: {:?}",
                    e
                );
                // Continue importing other entries, don't fail the whole import
            }
        }

        Ok(lorebook)
    }

    /// Associates a lorebook with a character
    ///
    /// # Errors
    ///
    /// Returns `AppError::Unauthorized` if the user is not authenticated,
    /// `AppError::NotFound` if the character or lorebook doesn't exist,
    /// `AppError::InternalServerErrorGeneric` if database connection fails or database interaction errors occur.
    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)))]
    pub async fn associate_lorebook_to_character(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        character_id: Uuid,
        lorebook_id: Uuid,
    ) -> Result<(), AppError> {
        let user = Self::get_user_from_session(auth_session)?;

        // Verify both character and lorebook belong to the user
        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        // Check character ownership
        use crate::schema::characters;
        let character_exists = conn
            .interact(move |conn_sync| {
                characters::table
                    .filter(characters::id.eq(character_id))
                    .filter(characters::user_id.eq(user.id))
                    .count()
                    .get_result::<i64>(conn_sync)
                    .map(|count| count > 0)
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        if !character_exists {
            return Err(AppError::NotFound(
                "Character not found or access denied".to_string(),
            ));
        }

        // Check lorebook ownership
        let lorebook_exists = conn
            .interact({
                let user_id = user.id;
                move |conn_sync| {
                    lorebooks::table
                        .filter(lorebooks::id.eq(lorebook_id))
                        .filter(lorebooks::user_id.eq(user_id))
                        .count()
                        .get_result::<i64>(conn_sync)
                        .map(|count| count > 0)
                }
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        if !lorebook_exists {
            return Err(AppError::NotFound(
                "Lorebook not found or access denied".to_string(),
            ));
        }

        // Create association
        use crate::models::NewCharacterLorebook;
        use crate::schema::character_lorebooks;

        let new_association = NewCharacterLorebook {
            character_id,
            lorebook_id,
            user_id: user.id,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
        };

        conn.interact(move |conn_sync| {
            diesel::insert_into(character_lorebooks::table)
                .values(&new_association)
                .execute(conn_sync)
        })
        .await
        .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(())
    }

    /// Lists all lorebooks associated with a character
    ///
    /// # Errors
    ///
    /// Returns `AppError::Unauthorized` if the user is not authenticated,
    /// `AppError::NotFound` if the character doesn't exist,
    /// `AppError::InternalServerErrorGeneric` if database connection fails or database interaction errors occur.
    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)))]
    pub async fn list_character_lorebooks(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        character_id: Uuid,
    ) -> Result<Vec<LorebookResponse>, AppError> {
        let user = Self::get_user_from_session(auth_session)?;

        let conn = self.pool.get().await.map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Failed to get DB connection: {e}"))
        })?;

        let lorebooks = conn
            .interact(move |conn_sync| {
                use crate::schema::character_lorebooks;

                character_lorebooks::table
                    .inner_join(
                        lorebooks::table.on(lorebooks::id.eq(character_lorebooks::lorebook_id)),
                    )
                    .filter(character_lorebooks::character_id.eq(character_id))
                    .filter(character_lorebooks::user_id.eq(user.id))
                    .select(Lorebook::as_select())
                    .load::<Lorebook>(conn_sync)
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

        Ok(lorebooks
            .into_iter()
            .map(|lb| LorebookResponse {
                id: lb.id,
                user_id: lb.user_id,
                name: lb.name,
                description: lb.description,
                source_format: lb.source_format,
                is_public: lb.is_public,
                created_at: lb.created_at,
                updated_at: lb.updated_at,
            })
            .collect())
    }

    /// Creates or updates a character lorebook override for a specific chat session
    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)))]
    pub async fn set_character_lorebook_override(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        chat_session_id: Uuid,
        lorebook_id: Uuid,
        action: String, // "disable" or "enable"
    ) -> Result<(), AppError> {
        let user = Self::get_user_from_session(auth_session)?;
        let user_id = user.id;

        // Validate action
        if !matches!(action.as_str(), "disable" | "enable") {
            return Err(AppError::BadRequest(
                "Action must be 'disable' or 'enable'".to_string(),
            ));
        }

        let conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get DB connection: {}", e);
            AppError::DbPoolError(e.to_string())
        })?;

        let action_clone = action.clone();
        conn.interact(move |conn_sync| {
            use crate::schema::chat_character_lorebook_overrides::dsl;
            use diesel::upsert::excluded;

            // Use upsert to insert or update the override
            diesel::insert_into(dsl::chat_character_lorebook_overrides)
                .values(
                    &crate::models::lorebooks::NewChatCharacterLorebookOverride {
                        chat_session_id,
                        lorebook_id,
                        user_id,
                        action: action_clone,
                        created_at: None, // Use DB default
                        updated_at: None, // Use DB default
                    },
                )
                .on_conflict((dsl::chat_session_id, dsl::lorebook_id))
                .do_update()
                .set((
                    dsl::action.eq(excluded(dsl::action)),
                    dsl::updated_at.eq(excluded(dsl::updated_at)),
                ))
                .execute(conn_sync)
        })
        .await
        .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
        .map_err(|db_err| AppError::DatabaseQueryError(db_err.to_string()))?;

        info!(
            "Successfully set character lorebook override for chat [REDACTED_UUID], lorebook [REDACTED_UUID], action: {}",
            action
        );
        Ok(())
    }

    /// Removes a character lorebook override for a specific chat session
    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)))]
    pub async fn remove_character_lorebook_override(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        chat_session_id: Uuid,
        lorebook_id: Uuid,
    ) -> Result<(), AppError> {
        let user = Self::get_user_from_session(auth_session)?;
        let user_id = user.id;

        let conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get DB connection: {}", e);
            AppError::DbPoolError(e.to_string())
        })?;

        let rows_deleted = conn
            .interact(move |conn_sync| {
                use crate::schema::chat_character_lorebook_overrides::dsl;
                diesel::delete(
                    dsl::chat_character_lorebook_overrides
                        .filter(dsl::chat_session_id.eq(chat_session_id))
                        .filter(dsl::lorebook_id.eq(lorebook_id))
                        .filter(dsl::user_id.eq(user_id)),
                )
                .execute(conn_sync)
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
            .map_err(|db_err| AppError::DatabaseQueryError(db_err.to_string()))?;

        if rows_deleted == 0 {
            return Err(AppError::NotFound(
                "Character lorebook override not found".to_string(),
            ));
        }

        info!(
            "Successfully removed character lorebook override for chat [REDACTED_UUID], lorebook [REDACTED_UUID]"
        );
        Ok(())
    }

    /// Gets all character lorebook overrides for a specific chat session
    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)))]
    pub async fn get_character_lorebook_overrides(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        chat_session_id: Uuid,
    ) -> Result<Vec<crate::models::lorebooks::ChatCharacterLorebookOverride>, AppError> {
        let user = Self::get_user_from_session(auth_session)?;
        let user_id = user.id;

        let conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get DB connection: {}", e);
            AppError::DbPoolError(e.to_string())
        })?;

        let overrides = conn
            .interact(move |conn_sync| {
                use crate::schema::chat_character_lorebook_overrides::dsl;
                dsl::chat_character_lorebook_overrides
                    .filter(dsl::chat_session_id.eq(chat_session_id))
                    .filter(dsl::user_id.eq(user_id))
                    .select(crate::models::lorebooks::ChatCharacterLorebookOverride::as_select())
                    .load::<crate::models::lorebooks::ChatCharacterLorebookOverride>(conn_sync)
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
            .map_err(|db_err| AppError::DatabaseQueryError(db_err.to_string()))?;

        Ok(overrides)
    }

    // Helper to get user or return error
    //  // Will be used once methods are implemented
    fn get_user_from_session(auth_session: &AuthSession<AuthBackend>) -> Result<User, AppError> {
        // Changed to AuthBackend
        auth_session.user.clone().ok_or_else(|| {
            error!("User not authenticated for lorebook operation.");
            AppError::Unauthorized("User not authenticated".to_string())
        })
    }
}
