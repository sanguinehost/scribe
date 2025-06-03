use crate::PgPool;
use crate::{
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
    state::AppState,
};
use axum_login::AuthSession;
use chrono::Utc;
use diesel::result::{DatabaseErrorKind, Error as DieselError}; // Added for specific error handling
use diesel::{RunQueryDsl, SelectableHelper, prelude::*};
use secrecy::{ExposeSecret, SecretBox};
use std::sync::Arc;
use tracing::{debug, error, info, instrument};
use uuid::Uuid;

#[derive(Clone)]
pub struct LorebookService {
    pool: PgPool,
     // TODO: Remove once encryption is implemented for lorebooks
    encryption_service: Arc<EncryptionService>, // Store as Arc
}

impl LorebookService {
    #[must_use]
    pub const fn new(pool: PgPool, encryption_service: Arc<EncryptionService>) -> Self {
        // Accept Arc
        Self {
            pool,
            encryption_service,
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
                        "User {} attempted to access lorebook {} owned by user {}",
                        user.id, lb.id, lb.user_id
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
                use crate::schema::lorebooks::dsl::{description, id, lorebooks, name, updated_at, user_id};

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
                            "Successfully updated lorebook {} for user {}",
                            lorebook_id,
                            user.id
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
                            Err(AppError::Forbidden)
                        } else {
                            Err(AppError::NotFound("Lorebook not found".to_string()))
                        }
                }
            })
            .await
            .map_err(|e| {
                AppError::DbInteractError(format!("Database interaction error: {e}"))
            })??;

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
                            "Successfully deleted lorebook {} for user {}",
                            lorebook_id,
                            user.id
                        );
                        Ok(())
                    }
                    Some(_) => {
                        // Lorebook exists but belongs to another user
                        Err(AppError::Forbidden)
                    }
                    None => {
                        // Lorebook doesn't exist
                        Err(AppError::NotFound("Lorebook not found".to_string()))
                    }
                }
            })
            .await
            .map_err(|e| AppError::DbInteractError(format!("Database interaction error: {e}")))?
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
                    "Lorebook with ID {} not found or user {} does not have access.",
                    lorebook_id, user.id
                );
                AppError::NotFound(format!(
                    "Lorebook with ID {lorebook_id} not found or access denied."
                ))
            })?;

        // 2. Encrypt sensitive fields
        let user_dek_secret_box = user_dek.ok_or_else(|| {
            error!("User DEK not available for lorebook entry creation for user {}", user.id);
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
                let (cipher, nonce) = self
                    .encryption_service
                    .encrypt(&text, user_dek_bytes)?;
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
                    "Failed to decrypt entry_title for new entry {}: {:?}",
                    inserted_entry.id, e
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
                    "Empty nonce found for keys_text for entry {}, ciphertext_len: {}",
                    inserted_entry.id,
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
                            "Failed to decrypt keys_text for new entry {}: {:?}",
                            inserted_entry.id, e
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
                    "Failed to decrypt content for new entry {}: {:?}",
                    inserted_entry.id, e
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
                            "Failed to decrypt comment for new entry {}: {:?}",
                            inserted_entry.id, e
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
            info!(
                "Spawning task to process and embed lorebook entry: {}",
                original_lorebook_entry_id_for_embedding
            );

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
                    "Failed to process and embed lorebook entry {} in background: {:?}",
                    original_lorebook_entry_id_for_embedding, e
                );
            } else {
                info!(
                    "Successfully queued lorebook entry {} for embedding.",
                    original_lorebook_entry_id_for_embedding
                );
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

        // 3. Decrypt entry titles and map to response
        let user_dek_secret_box = user_dek.ok_or_else(|| {
            error!(
                "User DEK not available for lorebook entry list decryption for user {}",
                user.id
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
                        "Failed to decrypt entry title for entry {}: {:?}",
                        entry.id, e
                    );
                    AppError::DecryptionError(format!(
                        "Failed to decrypt entry title for entry {}",
                        entry.id
                    ))
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
                    "Lorebook entry with ID {} not found or user {} does not have access.",
                    entry_id, user.id
                );
                AppError::NotFound(format!(
                    "Lorebook entry with ID {entry_id} not found or access denied."
                ))
            })?;

        // 2. Decrypt all fields
        let user_dek_secret_box = user_dek.ok_or_else(|| {
            error!(
                "User DEK not available for lorebook entry decryption for user {}",
                user.id
            );
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
            .map_err(|e| {
                error!("Failed to decrypt entry title: {:?}", e);
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
                .map_err(|e| {
                    error!("Failed to decrypt keys_text: {:?}", e);
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
            .map_err(|e| {
                error!("Failed to decrypt content: {:?}", e);
                AppError::DecryptionError("Failed to decrypt content".to_string())
            })?;
        let decrypted_content = String::from_utf8_lossy(&decrypted_content_bytes).into_owned();

        // Decrypt comment if present
        let comment = match (&entry.comment_ciphertext, &entry.comment_nonce) {
            (Some(cipher), Some(nonce)) => {
                let decrypted_comment_bytes = self
                    .encryption_service
                    .decrypt(cipher, nonce, user_dek_bytes)
                    .map_err(|e| {
                        error!("Failed to decrypt comment: {:?}", e);
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
            error!(
                "User DEK not available for lorebook entry update for user {}",
                user.id
            );
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
        let decrypted_title_for_response_and_embed = String::from_utf8_lossy(
            &self
                .encryption_service
                .decrypt(
                    &updated_db_entry.entry_title_ciphertext,
                    &updated_db_entry.entry_title_nonce,
                    user_dek_bytes,
                )?,
        )
        .into_owned();

        let decrypted_keys_text_for_response_and_embed = {
            if updated_db_entry.keys_text_nonce.is_empty() {
                None
            } else {
                Some(
                    String::from_utf8_lossy(
                        &self
                            .encryption_service
                            .decrypt(
                                &updated_db_entry.keys_text_ciphertext,
                                &updated_db_entry.keys_text_nonce,
                                user_dek_bytes,
                            )?,
                    )
                    .into_owned(),
                )
            }
        };

        let decrypted_content_for_response_and_embed = String::from_utf8_lossy(
            &self
                .encryption_service
                .decrypt(
                    &updated_db_entry.content_ciphertext,
                    &updated_db_entry.content_nonce,
                    user_dek_bytes,
                )?,
        )
        .into_owned();

        let decrypted_comment_for_response = match (
            &updated_db_entry.comment_ciphertext,
            &updated_db_entry.comment_nonce,
        ) {
            (Some(cipher), Some(nonce)) => Some(
                String::from_utf8_lossy(
                    &self
                        .encryption_service
                        .decrypt(cipher, nonce, user_dek_bytes)?,
                )
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
            info!(
                "Spawning task to re-process and embed updated lorebook entry: {}",
                original_lorebook_entry_id_for_embedding
            );

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

            if let Err(e) = embedding_pipeline_service
                .process_and_embed_lorebook_entry(state_clone, params)
                .await
            {
                error!(
                    "Failed to re-process and embed updated lorebook entry {} in background: {:?}",
                    original_lorebook_entry_id_for_embedding, e
                );
            } else {
                info!(
                    "Successfully queued updated lorebook entry {} for re-embedding.",
                    original_lorebook_entry_id_for_embedding
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
                            "Successfully deleted lorebook entry {} for user {}",
                            entry_id,
                            user.id
                        );
                        Ok(())
                    }
                    Some(_) => {
                        // Entry exists but belongs to another user
                        Err(AppError::Forbidden)
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
        debug!(?payload, lorebook_id = %payload.lorebook_id, "Attempting to associate lorebook to chat session {}", chat_session_id);
        let user = Self::get_user_from_session(auth_session)?;
        let lorebook_id_to_associate = payload.lorebook_id;

        let conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get DB connection: {}", e);
            AppError::DbPoolError(e.to_string())
        })?;

        // 1. Verify chat session ownership
        let current_user_id = user.id; // Clone user_id for use in closures
        conn.interact(move |conn_sync| {
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
                "DB interaction failed while verifying chat session ownership for session {}: {}",
                chat_session_id, e
            );
            AppError::DbInteractError(format!("DB interaction failed: {e}"))
        })?
        .map_err(|db_err| {
            error!(
                "Failed to query chat session {}: {}",
                chat_session_id, db_err
            );
            AppError::DatabaseQueryError(db_err.to_string())
        })?
        .ok_or_else(|| {
            error!(
                "Chat session {} not found or user {} does not have access.",
                chat_session_id, current_user_id
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
                    "DB interaction failed while verifying lorebook ownership for lorebook {}: {}",
                    lorebook_id_to_associate, e
                );
                AppError::DbInteractError(format!("DB interaction failed: {e}"))
            })?
            .map_err(|db_err| {
                error!(
                    "Failed to query lorebook {}: {}",
                    lorebook_id_to_associate, db_err
                );
                AppError::DatabaseQueryError(db_err.to_string())
            })?
            .ok_or_else(|| {
                error!(
                    "Lorebook {} not found or user {} does not have access.",
                    lorebook_id_to_associate, current_user_id
                );
                AppError::NotFound(format!(
                    "Lorebook with ID {lorebook_id_to_associate} not found or access denied."
                ))
            })?;

        // 3. Create association
        // let new_association_id = Uuid::new_v4(); // Not needed for NewChatSessionLorebook
        let association_creation_time = Utc::now(); // For the response

        let new_record = NewChatSessionLorebook {
            chat_session_id,
            lorebook_id: lorebook_id_to_associate,
            user_id: current_user_id,
            created_at: Some(Utc::now()), // Or None if DB default is preferred
            updated_at: Some(Utc::now()), // Or None if DB default is preferred
        };

        conn.interact(move |conn_sync| {
            use crate::schema::chat_session_lorebooks::dsl as csl_dsl;
            diesel::insert_into(csl_dsl::chat_session_lorebooks)
                .values(&new_record)
                .execute(conn_sync) // .execute() is fine as we have all info for the response
        })
        .await
        .map_err(|e| {
            error!("DB interaction failed while creating association between chat {} and lorebook {}: {}", chat_session_id, lorebook_id_to_associate, e);
            AppError::DbInteractError(format!("DB interaction failed: {e}"))
        })?
        .map_err(|db_err: DieselError| { // Explicitly type db_err
            error!("Failed to insert chat session lorebook association: {}", db_err);
            match db_err {
                DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _) => {
                    AppError::Conflict("This lorebook is already associated with the chat session.".to_string())
                }
                _ => AppError::DatabaseQueryError(db_err.to_string()),
            }
        })?;

        info!(
            "Successfully associated lorebook {} with chat session {} for user {}",
            lorebook_id_to_associate, chat_session_id, current_user_id
        );

        // After successful association, attempt to embed all enabled entries from the lorebook.
        // This is a best-effort operation; failures here should not fail the association.
        let user_dek_bytes_for_embedding = if let Some(dek) = user_dek {
            dek.expose_secret().clone()
        } else {
            error!(
                "User DEK not available for embedding entries during lorebook {} association to chat {} for user {}. Skipping embedding.",
                lorebook_id_to_associate, chat_session_id, current_user_id
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
                        "No entries found in lorebook {} to embed during association with chat {}.",
                        lorebook_id_to_associate, chat_session_id
                    );
                } else {
                    info!(
                        "Found {} entries in lorebook {} to potentially embed during association with chat {}.",
                        entries.len(),
                        lorebook_id_to_associate,
                        chat_session_id
                    );
                }
                for entry in entries {
                    if entry.is_enabled {
                        debug!("Processing entry {} for embedding.", entry.id);
                        let encryption_service = self.encryption_service.clone();
                        let user_dek_bytes_entry_clone = user_dek_bytes_for_embedding.clone(); // Clone for this entry's decryption

                        let decrypted_title_result = encryption_service
                            .decrypt(
                                &entry.entry_title_ciphertext,
                                &entry.entry_title_nonce,
                                &user_dek_bytes_entry_clone,
                            );
                        let decrypted_content_result = encryption_service
                            .decrypt(
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
                                    info!(
                                        "Spawning task to process and embed lorebook entry {} from lorebook {} during chat association.",
                                        entry_id_for_embedding, lorebook_id_for_embedding_task
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
                                            "Failed to process and embed lorebook entry {} in background during association: {:?}",
                                            entry_id_for_embedding, e
                                        );
                                    } else {
                                        info!(
                                            "Successfully queued lorebook entry {} for embedding during association.",
                                            entry_id_for_embedding
                                        );
                                    }
                                });
                            }
                            (Err(e), _, _) => error!(
                                "Failed to decrypt title for entry {}: {:?}. Skipping embedding.",
                                entry.id, e
                            ),
                            (_, Err(e), _) => error!(
                                "Failed to decrypt content for entry {}: {:?}. Skipping embedding.",
                                entry.id, e
                            ),
                            (_, _, Err(e)) => error!(
                                "Failed to decrypt keys_text for entry {}: {:?}. Skipping embedding.",
                                entry.id, e
                            ),
                        }
                    } else {
                        debug!(
                            "Skipping disabled entry {} during bulk embedding for lorebook {}.",
                            entry.id, lorebook_id_to_associate
                        );
                    }
                }
            }
            Ok(Err(db_err)) => {
                error!(
                    "Failed to query entries for lorebook {} during association with chat {}: {}. Skipping embedding of entries.",
                    lorebook_id_to_associate, chat_session_id, db_err
                );
            }
            Err(interact_err) => {
                error!(
                    "DB interaction failed while fetching entries for lorebook {} during association with chat {}: {}. Skipping embedding of entries.",
                    lorebook_id_to_associate, chat_session_id, interact_err
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
        debug!(chat_session_id = %chat_session_id_param, "Attempting to list chat lorebook associations");
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
                "DB interaction failed while verifying chat session ownership for session {}: {}",
                chat_session_id_param, e
            );
            AppError::DbInteractError(format!("DB interaction failed: {e}"))
        })?
        .map_err(|db_err| {
            error!(
                "Failed to query chat session {}: {}",
                chat_session_id_param, db_err
            );
            AppError::DatabaseQueryError(db_err.to_string())
        })?
        .ok_or_else(|| {
            error!(
                "Chat session {} not found or user {} does not have access.",
                chat_session_id_param, current_user_id
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
                    "DB interaction failed while listing associations for chat {}: {}",
                    chat_session_id_param, e
                );
                AppError::DbInteractError(format!("DB interaction failed: {e}"))
            })?
            .map_err(|db_err| {
                error!(
                    "Failed to query chat session lorebook associations for chat {}: {}",
                    chat_session_id_param, db_err
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

    #[instrument(skip(self, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), chat_session_id = %chat_session_id_param, lorebook_id = %lorebook_id_param))]
    pub async fn disassociate_lorebook_from_chat(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        chat_session_id_param: Uuid,
        lorebook_id_param: Uuid,
    ) -> Result<(), AppError> {
        debug!(
            "Attempting to disassociate lorebook {} from chat {}",
            lorebook_id_param, chat_session_id_param
        );
        let user = Self::get_user_from_session(auth_session)?;
        let current_user_id = user.id;

        let conn = self.pool.get().await.map_err(|e| {
            error!("Failed to get DB connection: {}", e);
            AppError::DbPoolError(e.to_string())
        })?;

        // 1. Verify chat session ownership (optional here if we trust user_id on association, but good for safety)
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
        .map_err(|e| AppError::DbInteractError(format!("DB interaction failed: {e}")))?
        .map_err(|db_err| AppError::DatabaseQueryError(db_err.to_string()))?
        .ok_or_else(|| {
            AppError::NotFound(format!(
                "Chat session with ID {chat_session_id_param} not found or access denied."
            ))
        })?;

        // 2. Delete the association, ensuring it belongs to the user
        let rows_deleted = conn
            .interact(move |conn_sync| {
                use crate::schema::chat_session_lorebooks::dsl as csl_dsl;
                diesel::delete(
                    csl_dsl::chat_session_lorebooks
                        .filter(csl_dsl::chat_session_id.eq(chat_session_id_param))
                        .filter(csl_dsl::lorebook_id.eq(lorebook_id_param))
                        .filter(csl_dsl::user_id.eq(current_user_id)), // Crucial for security
                )
                .execute(conn_sync)
            })
            .await
            .map_err(|e| {
                error!(
                    "DB interaction failed while disassociating lorebook {} from chat {}: {}",
                    lorebook_id_param, chat_session_id_param, e
                );
                AppError::DbInteractError(format!("DB interaction failed: {e}"))
            })?
            .map_err(|db_err| {
                error!(
                    "Failed to delete chat session lorebook association: {}",
                    db_err
                );
                AppError::DatabaseQueryError(db_err.to_string())
            })?;

        if rows_deleted == 0 {
            info!(
                "No association found to delete for lorebook {} and chat session {} for user {}",
                lorebook_id_param, chat_session_id_param, current_user_id
            );
            // This could mean the association didn't exist, or didn't belong to this user for this session.
            // Returning NotFound is appropriate as the specific resource (association) to delete was not found under these conditions.
            return Err(AppError::NotFound(
                "Lorebook association not found for this chat session and user.".to_string(),
            ));
        }

        info!(
            "Successfully disassociated lorebook {} from chat session {} for user {}",
            lorebook_id_param, chat_session_id_param, current_user_id
        );
        Ok(())
    }

    #[instrument(skip(self, auth_session, user_dek), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), lorebook_id = %lorebook_id_param))]
    pub async fn list_associated_chat_sessions_for_lorebook(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        lorebook_id_param: Uuid,
        user_dek: Option<&SecretBox<Vec<u8>>>,
    ) -> Result<Vec<ChatSessionBasicInfo>, AppError> {
        debug!(lorebook_id = %lorebook_id_param, "Attempting to list chat sessions associated with lorebook");
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
                "DB interaction failed while verifying lorebook ownership for lorebook {}: {}",
                lorebook_id_param, e
            );
            AppError::DbInteractError(format!("DB interaction failed: {e}"))
        })?
        .map_err(|db_err| {
            error!("Failed to query lorebook {}: {}", lorebook_id_param, db_err);
            AppError::DatabaseQueryError(db_err.to_string())
        })?
        .ok_or_else(|| {
            error!(
                "Lorebook {} not found or user {} does not have access.",
                lorebook_id_param, current_user_id
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
                    "DB interaction failed while listing associated chats for lorebook {}: {}",
                    lorebook_id_param, e
                );
                AppError::DbInteractError(format!("DB interaction failed: {e}"))
            })?
            .map_err(|db_err| {
                error!(
                    "Failed to query associated chat sessions for lorebook {}: {}",
                    lorebook_id_param, db_err
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
                                    "Failed to decrypt title for chat session {}: {:?}",
                                    chat_id, e
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

    // Helper to get user or return error
    //  // Will be used once methods are implemented
    fn get_user_from_session(
        auth_session: &AuthSession<AuthBackend>,
    ) -> Result<User, AppError> {
        // Changed to AuthBackend
        auth_session.user.clone().ok_or_else(|| {
            error!("User not authenticated for lorebook operation.");
            AppError::Unauthorized("User not authenticated".to_string())
        })
    }

}
