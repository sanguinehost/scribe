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

use super::message_handling::{save_message, SaveMessageParams};

/// Helper function to determine the effective active persona ID
#[allow(clippy::cognitive_complexity)]
fn determine_effective_persona_id(
    user_id: Uuid,
    active_custom_persona_id: Option<Uuid>,
    conn: &mut PgConnection,
) -> Option<Uuid> {
    if active_custom_persona_id.is_some() {
        return active_custom_persona_id;
    }

    info!(%user_id, "No active_custom_persona_id provided, checking for user's default persona.");
    match crate::schema::users::table
        .filter(users_dsl::id.eq(user_id))
        .select(users_dsl::default_persona_id)
        .first::<Option<Uuid>>(conn)
        .optional()
    {
        Ok(Some(Some(default_id))) => {
            info!(%user_id, default_persona_id = %default_id, "Found user's default persona. Using it for this session.");
            Some(default_id)
        }
        Ok(Some(None)) => {
            info!(%user_id, "User has no default persona set.");
            None
        }
        Ok(None) => {
            warn!(%user_id, "User not found when trying to fetch default persona. This should not happen.");
            None
        }
        Err(e) => {
            error!(%user_id, error = ?e, "Error fetching user's default persona. Proceeding without it.");
            None
        }
    }
}

/// Helper function to extract system prompt from persona
#[allow(clippy::cognitive_complexity)]
fn extract_persona_system_prompt(
    persona_id: Uuid,
    user_id: Uuid,
    user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    conn: &mut PgConnection,
) -> Option<String> {
    use crate::schema::user_personas;
    
    let persona = match user_personas::table
        .filter(user_personas::id.eq(persona_id))
        .filter(user_personas::user_id.eq(user_id))
        .select(crate::models::user_personas::UserPersona::as_select())
        .first::<crate::models::user_personas::UserPersona>(conn)
        .optional()
    {
        Ok(Some(persona)) => persona,
        Ok(None) => {
            warn!(%persona_id, %user_id, "Active persona not found or not owned by user. Will fall back to character prompt.");
            return None;
        }
        Err(e) => {
            error!(%persona_id, error = ?e, "Failed to query active persona. Will fall back to character prompt.");
            return None;
        }
    };

    let sp_bytes_vec = persona.system_prompt.as_ref()?;
    
    if let (Some(sp_nonce_vec), Some(dek_arc)) = (&persona.system_prompt_nonce, user_dek) {
        // Try to decrypt
        match crate::crypto::decrypt_gcm(sp_bytes_vec, sp_nonce_vec, dek_arc) {
            Ok(decrypted_secret_vec) => {
                match String::from_utf8(decrypted_secret_vec.expose_secret().clone()) {
                    Ok(decrypted_sp_str) => {
                        if decrypted_sp_str.trim().is_empty() {
                            info!(%persona_id, "Decrypted persona system_prompt is empty. Skipping.");
                            None
                        } else {
                            info!(%persona_id, "Using DECRYPTED system prompt from active persona.");
                            Some(decrypted_sp_str.replace('\0', ""))
                        }
                    }
                    Err(e) => {
                        error!(%persona_id, error = ?e, "DECRYPTED Persona system_prompt is not valid UTF-8. Skipping.");
                        None
                    }
                }
            }
            Err(e) => {
                error!(%persona_id, error = ?e, "Failed to DECRYPT persona system_prompt. Skipping.");
                None
            }
        }
    } else if persona.system_prompt_nonce.is_none() && user_dek.is_none() {
        // Try as plaintext
        match String::from_utf8(sp_bytes_vec.clone()) {
            Ok(plaintext_sp_str) => {
                if plaintext_sp_str.trim().is_empty() {
                    info!(%persona_id, "Persona system_prompt (plaintext, no nonce/DEK) is empty. Skipping.");
                    None
                } else {
                    warn!(%persona_id, "Using persona system_prompt as PLAINTEXT (nonce and DEK were missing).");
                    Some(plaintext_sp_str.replace('\0', ""))
                }
            }
            Err(e) => {
                error!(%persona_id, error = ?e, "Persona system_prompt (plaintext, no nonce/DEK) is not valid UTF-8. Skipping.");
                None
            }
        }
    } else {
        info!(%persona_id, nonce_present = persona.system_prompt_nonce.is_some(), dek_present = user_dek.is_some(), "Persona system_prompt could not be used (cannot decrypt or inconsistent state). Skipping.");
        None
    }
}

/// Helper function to determine system prompt from character or persona
fn determine_system_prompt(
    character: &Character,
    persona_id: Option<Uuid>,
    user_id: Uuid,
    user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    conn: &mut PgConnection,
) -> Option<String> {
    // Try persona first if available
    if let Some(pid) = persona_id {
        if let Some(persona_prompt) = extract_persona_system_prompt(pid, user_id, user_dek, conn) {
            return Some(persona_prompt);
        }
    }

    // Fall back to character prompts
    info!("No persona system prompt active, deriving from character.");
    character.system_prompt.as_ref()
        .and_then(|val| if val.is_empty() { None } else { Some(String::from_utf8_lossy(val).to_string().replace('\0', "")) })
        .or_else(|| character.persona.as_ref().and_then(|val| if val.is_empty() { None } else { Some(String::from_utf8_lossy(val).to_string().replace('\0', "")) }))
        .or_else(|| character.description.as_ref().and_then(|val| if val.is_empty() { None } else { Some(String::from_utf8_lossy(val).to_string().replace('\0', "")) }))
}

/// Helper function to validate and associate lorebooks
#[allow(clippy::cognitive_complexity)]
fn validate_and_associate_lorebooks(
    session_id: Uuid,
    user_id: Uuid,
    lorebook_ids: &[Uuid],
    conn: &mut PgConnection,
) -> Result<(), AppError> {
    if lorebook_ids.is_empty() {
        return Ok(());
    }

    debug!(session_id = %session_id, user_id = %user_id, lorebook_ids = ?lorebook_ids, "Preparing to associate lorebooks. Provided IDs: {:?}", lorebook_ids);
    
    // Validate lorebook ownership
    for lorebook_id_to_check in lorebook_ids {
        use crate::schema::lorebooks::dsl as lorebooks_dsl;
        match lorebooks_dsl::lorebooks
            .filter(lorebooks_dsl::id.eq(lorebook_id_to_check))
            .select((lorebooks_dsl::id, lorebooks_dsl::user_id))
            .first::<(Uuid, Uuid)>(conn)
            .optional()
        {
            Ok(Some((_, owner_id))) => {
                if owner_id != user_id {
                    error!(session_id = %session_id, lorebook_id = %lorebook_id_to_check, owner_id = %owner_id, "User does not own lorebook.");
                    return Err(AppError::Forbidden);
                }
            }
            Ok(None) => {
                error!(session_id = %session_id, lorebook_id = %lorebook_id_to_check, "Lorebook not found.");
                return Err(AppError::NotFound(format!("Lorebook with ID {lorebook_id_to_check} not found.")));
            }
            Err(e) => {
                error!(session_id = %session_id, lorebook_id = %lorebook_id_to_check, error = ?e, "Error querying lorebook.");
                return Err(AppError::DatabaseQueryError(e.to_string()));
            }
        }
    }

    // Create associations
    info!(session_id = %session_id, lorebook_ids = ?lorebook_ids, "Associating lorebooks with chat session after validation");
    let new_associations: Vec<_> = lorebook_ids.iter().map(|&lorebook_id| {
        (
            chat_session_lorebooks::dsl::chat_session_id.eq(session_id),
            chat_session_lorebooks::dsl::lorebook_id.eq(lorebook_id),
            chat_session_lorebooks::dsl::user_id.eq(user_id),
        )
    }).collect();
    
    diesel::insert_into(chat_session_lorebooks::table)
        .values(new_associations)
        .execute(conn)
        .map_err(|e| {
            error!(session_id = %session_id, error = ?e, "Failed to insert chat session lorebook associations");
            AppError::DatabaseQueryError(format!("Failed to associate lorebooks: {e}"))
        })?;

    Ok(())
}
/// Creates a new chat session, verifies character ownership, and adds the character's first message if available.
#[allow(clippy::cognitive_complexity)]
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
            let effective_active_persona_id = determine_effective_persona_id(
                user_id,
                active_custom_persona_id,
                transaction_conn,
            );

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
                // Additional optional fields
                temperature: None,
                max_output_tokens: None,
                frequency_penalty: None,
                presence_penalty: None,
                top_k: None,
                top_p: None,
                seed: None,
                stop_sequences: None,
                gemini_thinking_budget: None,
                gemini_enable_code_execution: None,
                system_prompt_ciphertext: None,
                system_prompt_nonce: None,
            };

            diesel::insert_into(chat_sessions::table)
                .values(&new_chat_for_insert)
                .execute(transaction_conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            // Determine the system prompt to use
            let final_system_prompt_str = determine_system_prompt(
                &character,
                effective_active_persona_id,
                user_id,
                user_dek_for_closure.as_ref(),
                transaction_conn,
            );

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
            if let Some(ref ids) = lorebook_ids_for_closure {
                validate_and_associate_lorebooks(new_session_id, user_id, ids, transaction_conn)?;
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
                        dek_sb_arc,
                    ) {
                        Ok(plaintext_secret_vec) => {
                            match String::from_utf8(plaintext_secret_vec.expose_secret().clone()) {
                                Ok(content_str) => {
                                    if content_str.trim().is_empty() {
                                        info!(session_id = %created_session.id, "Character first_mes (decrypted) is empty, skipping save.");
                                    } else {
                                        info!(session_id = %created_session.id, "Character has non-empty decrypted first_mes, saving via save_message");
                                        let _ = save_message(SaveMessageParams {
                                            state: state.clone(),
                                            session_id: created_session.id,
                                            user_id, // user_id of the session creator
                                            message_type_enum: MessageRole::Assistant,
                                            content: &content_str,
                                            role_str: Some("assistant".to_string()),
                                            parts: Some(json!([{"text": content_str}])),
                                            attachments: None,
                                            user_dek_secret_box: user_dek_secret_box.clone(),
                                            model_name: created_session.model_name.clone(),
                                        })
                                        .await?;
                                        info!(session_id = %created_session.id, "Successfully called save_message for first_mes");
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
/// Validates session ownership
fn validate_session_ownership(
    session: Chat,
    user_id: Uuid,
    session_id: Uuid,
) -> Result<Chat, AppError> {
    if session.user_id == user_id {
        info!(%session_id, %user_id, "Session found and ownership verified");
        Ok(session)
    } else {
        warn!(%session_id, %user_id, owner_id=%session.user_id, "User attempted to access session owned by another user");
        Err(AppError::NotFound(
            "Chat session not found or permission denied".into(),
        ))
    }
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
            .first::<Chat>(conn)
            .optional()?;

        session_result.map_or_else(|| {
            warn!(%session_id, %user_id, "Chat session not found by ID");
            Err(AppError::NotFound(
                "Chat session not found or permission denied".into(),
            ))
        }, |session| validate_session_ownership(session, user_id, session_id))
    })
    .await?
}
