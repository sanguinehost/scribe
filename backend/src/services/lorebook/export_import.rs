use super::*;
use super::get_user_from_session;

impl LorebookService {
    pub async fn export_lorebook(
        &self,
        auth_session: &AuthSession<AuthBackend>,
        user_dek: Option<&SecretBox<Vec<u8>>>,
        lorebook_id: Uuid,
    ) -> Result<crate::models::lorebook_dtos::ExportedLorebook, AppError> {
        let _user = get_user_from_session(auth_session)?;

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
        let _user = get_user_from_session(auth_session)?;

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
        let user = get_user_from_session(auth_session)?;

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

                            let params = crate::services::embeddings::LorebookEntryParams {
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
        let _user = get_user_from_session(auth_session)?;

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
}
