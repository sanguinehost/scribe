use std::sync::Arc;

use diesel::{prelude::*, result::Error as DieselError};
use secrecy::{ExposeSecret, SecretBox};
use serde_json::json;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::{
    AppState,
    errors::AppError,
    models::{
        characters::Character,
        chats::{
            Chat,
            MessageRole,
            // ChatSessionSettings, // Removed, settings are part of Chat struct
            // HistoryManagementStrategy, // Removed, strategy is a field in Chat struct
            NewChat, // Changed from DbInsertableChatSession
        },
    },
    schema::{characters, chat_session_lorebooks, chat_sessions, users::dsl as users_dsl},
    state::DbPool,
};

use super::message_handling::save_message;
/// Creates a new chat session, verifies character ownership, and adds the character's first message if available.
#[instrument(skip(state, user_dek_secret_box), err)]
pub async fn create_session_and_maybe_first_message(
    state: Arc<AppState>,
    user_id: Uuid,
    character_id: Uuid,
    active_custom_persona_id: Option<Uuid>,
    lorebook_ids: Option<Vec<Uuid>>,
    user_dek_secret_box: Option<Arc<SecretBox<Vec<u8>>>>,
) -> Result<Chat, AppError> {
    let pool: DbPool = state.pool.clone();
    let conn = pool.get().await?;
    // Clone user_dek_secret_box and lorebook_ids for use inside the 'move' closure
    let user_dek_for_closure = user_dek_secret_box.clone();
    let lorebook_ids_for_closure = lorebook_ids.clone();
    let (created_session, first_mes_ciphertext_opt, first_mes_nonce_opt) = conn.interact(move |conn| {
        conn.transaction(|transaction_conn| {
            let mut effective_active_persona_id = active_custom_persona_id;

            if effective_active_persona_id.is_none() {
                info!(%user_id, "No active_custom_persona_id provided, checking for user's default persona.");
                match crate::schema::users::table // Corrected path to users table
                    .filter(users_dsl::id.eq(user_id))
                    .select(users_dsl::default_persona_id)
                    .first::<Option<Uuid>>(transaction_conn) // users_dsl for column access
                    .optional()
                {
                    Ok(Some(Some(default_id))) => {
                        info!(%user_id, default_persona_id = %default_id, "Found user's default persona. Using it for this session.");
                        effective_active_persona_id = Some(default_id);
                    }
                    Ok(Some(None)) => {
                        info!(%user_id, "User has no default persona set.");
                    }
                    Ok(None) => {
                        warn!(%user_id, "User not found when trying to fetch default persona. This should not happen.");
                    }
                    Err(e) => {
                        error!(%user_id, error = ?e, "Error fetching user's default persona. Proceeding without it.");
                    }
                }
            }

            info!(%character_id, %user_id, ?effective_active_persona_id, "Verifying character ownership and fetching character details, potentially persona details");
            let character: Character = characters::table
                .filter(characters::id.eq(character_id))
                .select(Character::as_select())
                .first::<Character>(transaction_conn)
                .map_err(|e| match e {
                    DieselError::NotFound => AppError::NotFound("Character not found".into()),
                    _ => AppError::DatabaseQueryError(e.to_string()),
                })?;

            if character.user_id != user_id {
                error!(%character_id, %user_id, owner_id=%character.user_id, "User does not own character");
                return Err(AppError::Forbidden);
            }

            // Sanitize character.name by removing NULL bytes
            let sanitized_character_name = character.name.replace('\0', "");
            if sanitized_character_name.is_empty() {
                error!(%character_id, "Character name is empty or consists only of invalid characters after sanitization.");
                return Err(AppError::BadRequest("Character name cannot be empty or consist only of invalid characters.".to_string()));
            }

            info!(%character_id, %user_id, "Inserting new chat session");
            let new_session_id = Uuid::new_v4();
            // Encrypt the title
            let (title_ciphertext, title_nonce) = if let Some(ref dek_arc) = user_dek_for_closure {
                match crate::crypto::encrypt_gcm(sanitized_character_name.as_bytes(), dek_arc) {
                    Ok((ciphertext, nonce)) => (Some(ciphertext), Some(nonce)),
                    Err(e) => {
                        error!(error = ?e, "Failed to encrypt chat title");
                        return Err(AppError::EncryptionError("Failed to encrypt title".to_string()));
                    }
                }
            } else {
                error!("No DEK available for title encryption");
                return Err(AppError::EncryptionError("No encryption key available".to_string()));
            };
            let new_chat_for_insert = NewChat { // Changed to NewChat
                id: new_session_id,
                user_id,
                character_id,
                // Use encrypted title
                title_ciphertext,
                title_nonce,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                history_management_strategy: "message_window".to_string(),
                history_management_limit: 20,
                model_name: "gemini-2.5-pro-preview-03-25".to_string(),
                visibility: Some("private".to_string()),
                active_custom_persona_id: effective_active_persona_id,
                active_impersonated_character_id: None,
            };

            diesel::insert_into(chat_sessions::table)
                .values(&new_chat_for_insert)
                .execute(transaction_conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            // Determine the system prompt to use
            let mut final_system_prompt_str: Option<String> = None;

            if let Some(persona_id) = effective_active_persona_id {
                use crate::schema::user_personas;
                match user_personas::table
                    .filter(user_personas::id.eq(persona_id))
                    .filter(user_personas::user_id.eq(user_id)) // Ensure user owns persona
                    .select(crate::models::user_personas::UserPersona::as_select())
                    .first::<crate::models::user_personas::UserPersona>(transaction_conn)
                    .optional() // Persona might not be found or user might not own it
                {
                    Ok(Some(persona)) => {
                        if let Some(ref sp_bytes_vec) = persona.system_prompt {
                            if let (Some(sp_nonce_vec), Some(dek_arc)) = (&persona.system_prompt_nonce, &user_dek_for_closure) { // Use cloned DEK
                                match crate::crypto::decrypt_gcm(sp_bytes_vec, sp_nonce_vec, dek_arc.as_ref()) {
                                    Ok(decrypted_secret_vec) => { // ExposeSecret trait needed here
                                        match String::from_utf8(decrypted_secret_vec.expose_secret().to_vec()) {
                                            Ok(decrypted_sp_str) => {
                                                if !decrypted_sp_str.trim().is_empty() {
                                                    final_system_prompt_str = Some(decrypted_sp_str.replace('\0', ""));
                                                    info!(%persona_id, "Using DECRYPTED system prompt from active persona.");
                                                } else {
                                                    info!(%persona_id, "Decrypted persona system_prompt is empty. Skipping.");
                                                }
                                            }
                                            Err(e) => {
                                                error!(%persona_id, error = ?e, "DECRYPTED Persona system_prompt is not valid UTF-8. Skipping.");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!(%persona_id, error = ?e, "Failed to DECRYPT persona system_prompt. Skipping.");
                                    }
                                }
                            } else if persona.system_prompt_nonce.is_none() && user_dek_for_closure.is_none() { // Only attempt plaintext if nonce AND DEK are missing
                                // Attempt to use as plaintext if nonce is missing AND DEK is not available (implying it might be intentionally plaintext)
                                match String::from_utf8(sp_bytes_vec.clone()) {
                                    Ok(plaintext_sp_str) => {
                                        if !plaintext_sp_str.trim().is_empty() {
                                            final_system_prompt_str = Some(plaintext_sp_str.replace('\0', ""));
                                            warn!(%persona_id, "Using persona system_prompt as PLAINTEXT (nonce and DEK were missing).");
                                        } else {
                                            info!(%persona_id, "Persona system_prompt (plaintext, no nonce/DEK) is empty. Skipping.");
                                        }
                                    }
                                    Err(e) => {
                                        error!(%persona_id, error = ?e, "Persona system_prompt (plaintext, no nonce/DEK) is not valid UTF-8. Skipping.");
                                    }
                                }
                            } else {
                                // This case covers:
                                // 1. Nonce is Some, DEK is None (cannot decrypt)
                                // 2. Nonce is None, DEK is Some (inconsistent state, cannot assume plaintext or decrypt)
                                info!(%persona_id, nonce_present = persona.system_prompt_nonce.is_some(), dek_present = user_dek_for_closure.is_some(), "Persona system_prompt could not be used (cannot decrypt or inconsistent state). Skipping.");
                            }
                        } else {
                            info!(%persona_id, "Persona system_prompt (bytes) is None. Skipping.");
                        }
                    }
                    Ok(None) => {
                        warn!(%persona_id, %user_id, "Active persona not found or not owned by user. Will fall back to character prompt.");
                    }
                    Err(e) => {
                        error!(%persona_id, error = ?e, "Failed to query active persona. Will fall back to character prompt.");
                        // Do not return error, just log and fall back
                    }
                }
            }

            // If no persona prompt was set (or no persona active), use character's prompt logic
            if final_system_prompt_str.is_none() {
                info!("No persona system prompt active, deriving from character.");
                final_system_prompt_str = character.system_prompt.as_ref()
                    .and_then(|val| if val.is_empty() { None } else { Some(String::from_utf8_lossy(val).to_string().replace('\0', "")) })
                    .or_else(|| character.persona.as_ref().and_then(|val| if val.is_empty() { None } else { Some(String::from_utf8_lossy(val).to_string().replace('\0', "")) }))
                    .or_else(|| character.description.as_ref().and_then(|val| if val.is_empty() { None } else { Some(String::from_utf8_lossy(val).to_string().replace('\0', "")) }));
            }

            // Set the system prompt on the chat session if one was determined
            if let Some(prompt_to_set) = &final_system_prompt_str {
                if !prompt_to_set.trim().is_empty() {
                    // Encrypt the system prompt
                    if let Some(ref dek_arc) = user_dek_for_closure {
                        match crate::crypto::encrypt_gcm(prompt_to_set.as_bytes(), dek_arc) {
                            Ok((ciphertext, nonce)) => {
                                diesel::update(chat_sessions::table.filter(chat_sessions::id.eq(new_session_id)))
                                    .set((
                                        chat_sessions::system_prompt_ciphertext.eq(Some(ciphertext)),
                                        chat_sessions::system_prompt_nonce.eq(Some(nonce)),
                                    ))
                                    .execute(transaction_conn)
                                    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                            },
                            Err(e) => {
                                error!(error = ?e, "Failed to encrypt system prompt");
                                return Err(AppError::EncryptionError("Failed to encrypt system prompt".to_string()));
                            }
                        }
                    } else {
                        error!("No DEK available for system prompt encryption");
                        return Err(AppError::EncryptionError("No encryption key available".to_string()));
                    }
                }
            }
            // Insert lorebook associations if provided
            if let Some(ref ids) = lorebook_ids_for_closure { // Changed to `ref ids` to borrow
                if !ids.is_empty() {
                    debug!(session_id = %new_session_id, user_id = %user_id, lorebook_ids = ?ids, "Preparing to associate lorebooks. Provided IDs: {:?}", ids);
                    // Validate lorebook IDs
                    for lorebook_id_to_check in ids {
                        use crate::schema::lorebooks::dsl as lorebooks_dsl;
                        match lorebooks_dsl::lorebooks
                            .filter(lorebooks_dsl::id.eq(lorebook_id_to_check))
                            .select((lorebooks_dsl::id, lorebooks_dsl::user_id))
                            .first::<(Uuid, Uuid)>(transaction_conn)
                            .optional()
                        {
                            Ok(Some((_, owner_id))) => {
                                if owner_id != user_id {
                                    error!(session_id = %new_session_id, lorebook_id = %lorebook_id_to_check, owner_id = %owner_id, "User does not own lorebook.");
                                    return Err(AppError::Forbidden); // Or a more specific error like AppError::LorebookAccessDenied
                                }
                            }
                            Ok(None) => {
                                error!(session_id = %new_session_id, lorebook_id = %lorebook_id_to_check, "Lorebook not found.");
                                return Err(AppError::NotFound(format!("Lorebook with ID {} not found.", lorebook_id_to_check)));
                            }
                            Err(e) => {
                                error!(session_id = %new_session_id, lorebook_id = %lorebook_id_to_check, error = ?e, "Error querying lorebook.");
                                return Err(AppError::DatabaseQueryError(e.to_string()));
                            }
                        }
                    }
                    info!(session_id = %new_session_id, lorebook_ids = ?ids, "Associating lorebooks with chat session after validation");
                    // Clone ids again here for into_iter as it was only borrowed before
                    let new_associations: Vec<_> = ids.clone().into_iter().map(|lorebook_id| {
                        (
                            chat_session_lorebooks::dsl::chat_session_id.eq(new_session_id),
                            chat_session_lorebooks::dsl::lorebook_id.eq(lorebook_id),
                            chat_session_lorebooks::dsl::user_id.eq(user_id),
                            // created_at and updated_at will use DB defaults
                        )
                    }).collect();
                    diesel::insert_into(chat_session_lorebooks::table)
                        .values(new_associations)
                        .execute(transaction_conn)
                        .map_err(|e| {
                            error!(session_id = %new_session_id, error = ?e, "Failed to insert chat session lorebook associations");
                            AppError::DatabaseQueryError(format!("Failed to associate lorebooks: {}", e))
                        })?;
                }
            }

            let fully_created_session: Chat = chat_sessions::table
                .filter(chat_sessions::id.eq(new_session_id))
                .select(Chat::as_select())
                .first(transaction_conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            // Note: system_prompt is now stored encrypted in the database
            // and will be decrypted when needed via service methods
            Ok((fully_created_session, character.first_mes, character.first_mes_nonce))
        })
    })
    .await??;

    if let (Some(first_message_ciphertext), Some(first_message_nonce)) =
        (first_mes_ciphertext_opt, first_mes_nonce_opt)
    {
        if !first_message_ciphertext.is_empty() && !first_message_nonce.is_empty() {
            match &user_dek_secret_box {
                Some(dek_sb_arc) => {
                    match crate::crypto::decrypt_gcm(
                        &first_message_ciphertext,
                        &first_message_nonce,
                        &**dek_sb_arc,
                    ) {
                        Ok(plaintext_secret_vec) => {
                            match String::from_utf8(plaintext_secret_vec.expose_secret().to_vec()) {
                                Ok(content_str) => {
                                    if !content_str.trim().is_empty() {
                                        info!(session_id = %created_session.id, "Character has non-empty decrypted first_mes, saving via save_message");
                                        let _ = save_message(
                                            // Direct call, assuming 'use' brings it into scope
                                            state.clone(),
                                            created_session.id,
                                            user_id, // user_id of the session creator
                                            MessageRole::Assistant, // message_type_enum
                                            &content_str, // content
                                            Some("assistant".to_string()), // role_str
                                            Some(json!([{"text": content_str}])), // parts
                                            None,    // attachments
                                            user_dek_secret_box.clone(),
                                            &created_session.model_name,
                                        )
                                        .await?;
                                        info!(session_id = %created_session.id, "Successfully called save_message for first_mes");
                                    } else {
                                        info!(session_id = %created_session.id, "Character first_mes (decrypted) is empty, skipping save.");
                                    }
                                }
                                Err(e) => {
                                    error!(session_id = %created_session.id, error = ?e, "Failed to convert decrypted first_mes to UTF-8");
                                }
                            }
                        }
                        Err(e) => {
                            error!(session_id = %created_session.id, error = ?e, "Failed to decrypt character first_mes for new session");
                        }
                    }
                }
                None => {
                    warn!(session_id = %created_session.id, "Character has encrypted first_mes but no user DEK provided. Skipping first_mes.");
                }
            }
        } else {
            info!(session_id = %created_session.id, "Character first_mes ciphertext or nonce is empty, skipping save.");
        }
    } else {
        info!(session_id = %created_session.id, "Character first_mes or nonce is None, skipping save.");
    }

    Ok(created_session)
}
/// Lists chat sessions for a given user.
#[instrument(skip(pool), err)]
pub async fn list_sessions_for_user(pool: &DbPool, user_id: Uuid) -> Result<Vec<Chat>, AppError> {
    // ChatSession is aliased as Chat
    let conn = pool.get().await?;
    conn.interact(move |conn| {
        chat_sessions::table
            .filter(chat_sessions::user_id.eq(user_id))
            .select(Chat::as_select()) // ChatSession is aliased as Chat
            .order(chat_sessions::updated_at.desc())
            .load::<Chat>(conn) // ChatSession is aliased as Chat
            .map_err(|e| {
                error!("Failed to load chat sessions for user {}: {}", user_id, e);
                AppError::DatabaseQueryError(e.to_string())
            })
    })
    .await?
}
/// Gets a specific chat session by ID, verifying ownership.
#[instrument(skip(pool), err)]
pub async fn get_chat_session_by_id(
    pool: &DbPool,
    user_id: Uuid,
    session_id: Uuid,
) -> Result<Chat, AppError> {
    let conn = pool.get().await?;
    conn.interact(move |conn| {
        info!(%session_id, %user_id, "Attempting to fetch chat session details by ID");
        let session_result = chat_sessions::table
            .filter(chat_sessions::id.eq(session_id))
            .select(Chat::as_select())
            .first::<Chat>(conn) // Use first to get a single result
            .optional()?; // Use optional to handle not found case gracefully

        match session_result {
            Some(session) => {
                if session.user_id == user_id {
                    info!(%session_id, %user_id, "Session found and ownership verified");
                    Ok(session)
                } else {
                    // User does not own the session, treat as not found
                    warn!(%session_id, %user_id, owner_id=%session.user_id, "User attempted to access session owned by another user");
                    Err(AppError::NotFound(
                        "Chat session not found or permission denied".into(),
                    ))
                }
            }
            None => {
                // Session ID does not exist
                warn!(%session_id, %user_id, "Chat session not found by ID");
                Err(AppError::NotFound(
                    "Chat session not found or permission denied".into(),
                ))
            }
        }
    })
    .await? // First '?' handles InteractError
    // Second '?' handles the AppError from the inner closure (Ok/Err)
}
