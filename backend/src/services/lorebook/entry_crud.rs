use super::get_user_from_session;
use super::*;

impl LorebookService {
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
        let user = get_user_from_session(auth_session)?;
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
        let user = get_user_from_session(auth_session)?;

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
        let user = get_user_from_session(auth_session)?;

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
        let user = get_user_from_session(auth_session)?;

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
        let user = get_user_from_session(auth_session)?;
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
        let user = get_user_from_session(auth_session)?;

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
}
