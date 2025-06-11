use super::*;
use super::get_user_from_session;

impl LorebookService {
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
        let user = get_user_from_session(auth_session)?;
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
        let user = get_user_from_session(auth_session)?;
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
        let user = get_user_from_session(auth_session)?;
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
        let user = get_user_from_session(auth_session)?;
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
        let user = get_user_from_session(auth_session)?;
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
}
