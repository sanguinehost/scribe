// backend/src/services/chat_service.rs

use bigdecimal::BigDecimal;
use diesel::prelude::*;
use diesel::{RunQueryDsl, SelectableHelper};
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde_json::Value;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;

use crate::{
    errors::AppError,
    models::{
        characters::Character,
        chats::{
            Chat, ChatMessage as DbChatMessage, ChatSettingsResponse,
            DbInsertableChatMessage, MessageRole, NewChat, SettingsTuple,
            UpdateChatSettingsRequest,
        },
    },
    schema::{characters, chat_messages, chat_sessions},
    services::history_manager,
    state::{AppState, DbPool},
};
use std::sync::Arc;

// Type alias for the history tuple returned for generation
pub type HistoryForGeneration = Vec<(MessageRole, String)>;

// Type alias for the full data needed for generation, including the model name
// AND the unsaved user message struct
// NOTE: HistoryForGeneration here will now contain the *managed* history.
pub type GenerationDataWithUnsavedUserMessage = (
    HistoryForGeneration,    // Managed history BEFORE the new user message
    Option<String>,          // system_prompt
    Option<BigDecimal>,      // temperature
    Option<i32>,             // max_output_tokens
    Option<BigDecimal>,      // frequency_penalty
    Option<BigDecimal>,      // presence_penalty
    Option<i32>,             // top_k
    Option<BigDecimal>,      // top_p
    Option<BigDecimal>,      // repetition_penalty
    Option<BigDecimal>,      // min_p
    Option<BigDecimal>,      // top_a
    Option<i32>,             // seed
    Option<Value>,           // logit_bias
    String,                  // model_name (Fetched from DB)
    // -- Gemini Specific Options --
    Option<i32>,             // gemini_thinking_budget
    Option<bool>,            // gemini_enable_code_execution
    DbInsertableChatMessage, // The user message struct, ready to be saved
    // History Management Settings (still returned for potential future use/logging)
    String,                  // history_management_strategy
    i32,                     // history_management_limit
);

/// Creates a new chat session, verifies character ownership, and adds the character's first message if available.
#[instrument(skip(state), err)]
pub async fn create_session_and_maybe_first_message(
    state: Arc<AppState>,
    user_id: Uuid,
    character_id: Uuid,
) -> Result<Chat, AppError> {
    let pool = state.pool.clone();
    let conn = pool.get().await?;
    let (created_session, first_mes_opt) = conn.interact(move |conn| {
        conn.transaction(|transaction_conn| {
            info!(%character_id, %user_id, "Verifying character ownership and fetching character details");
            // Fetch the full character first to get all necessary details
            let character_result: Result<Character, DieselError> = characters::table
                .filter(characters::id.eq(character_id))
                .select(Character::as_select())
                .first::<Character>(transaction_conn);

            let character: Character = match character_result {
                Ok(char) => {
                    info!(character_id=%char.id, ?char.description, ?char.persona, ?char.system_prompt, "Fetched character details");
                    char
                }
                Err(DieselError::NotFound) => {
                    error!(%character_id, "Character not found during session creation");
                    return Err(AppError::NotFound("Character not found".into()));
                }
                Err(e) => {
                    error!(error = ?e, %character_id, "Failed to fetch character details during session creation");
                    return Err(AppError::DatabaseQueryError(e.to_string()));
                }
            };

            // Verify ownership
            if character.user_id != user_id {
                error!(%character_id, %user_id, owner_id=%character.user_id, "User does not own character");
                return Err(AppError::Forbidden);
            }

            info!(%character_id, %user_id, "Inserting new chat session");
            let new_session_id = Uuid::new_v4(); // Generate ID upfront
            let new_chat_for_insert = NewChat {
                id: new_session_id, // Use pre-generated ID
                user_id,
                character_id,
                title: Some(character.name.clone()), // Use character name as default title, wrapped in Some()
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                history_management_strategy: "message_window".to_string(), // Default
                history_management_limit: 20, // Default
                // Use a sensible default model or if Character had a preferred model, use that.
                // For now, keeping the existing default from NewChat.
                // If Character model is extended with a default_model_name, it could be used here:
                // model_name: character.default_model_name.clone().unwrap_or_else(|| "gemini-2.5-pro-preview-03-25".to_string()),
                model_name: "gemini-2.5-pro-preview-03-25".to_string(),
                visibility: Some("private".to_string()), // Default
            };

            // Insert the new chat session record
            diesel::insert_into(chat_sessions::table)
                .values(&new_chat_for_insert)
                .execute(transaction_conn)
                .map_err(|e| {
                    error!(error = ?e, "Failed to insert new chat session initial record");
                    AppError::DatabaseQueryError(e.to_string())
                })?;
            
            info!(session_id = %new_session_id, "Initial chat session record inserted.");

            // Determine the effective system prompt for the session
            // Priority: character.system_prompt > character.persona > character.description
            let effective_system_prompt = character.system_prompt.clone()
                .or_else(|| character.persona.clone())
                .or_else(|| character.description.clone());

            info!(?effective_system_prompt, "Determined effective system prompt for new session.");

            // Update the newly created session with the character's system_prompt
            if let Some(prompt_to_set) = &effective_system_prompt { // Borrow prompt_to_set
                if !prompt_to_set.trim().is_empty() {
                    match diesel::update(chat_sessions::table.filter(chat_sessions::id.eq(new_session_id)))
                        .set(chat_sessions::system_prompt.eq(prompt_to_set)) // Pass borrowed
                        .execute(transaction_conn) {
                            Ok(rows_updated) => info!(session_id = %new_session_id, %rows_updated, "DB system_prompt update successful."),
                            Err(e) => {
                                error!(error = ?e, session_id = %new_session_id, "Failed to update session with character system_prompt");
                                return Err(AppError::DatabaseQueryError(e.to_string()));
                            }
                        }
                } else {
                    info!(session_id = %new_session_id, "Effective system prompt was empty/whitespace, DB update for system_prompt skipped.");
                }
            } else {
                info!(session_id = %new_session_id, "No effective system prompt derived, DB update for system_prompt skipped.");
            }
            
            // Fetch the fully constituted session (now including the system_prompt)
            let mut fully_created_session: Chat = chat_sessions::table
                .filter(chat_sessions::id.eq(new_session_id))
                .select(Chat::as_select())
                .first(transaction_conn)
                .map_err(|e| {
                    error!(error = ?e, session_id = %new_session_id, "Failed to fetch newly created/updated session");
                    AppError::DatabaseQueryError(e.to_string())
                })?;
            
            info!(db_system_prompt_after_fetch = ?fully_created_session.system_prompt, "Chat session system_prompt from DB after fetch/update attempt.");

            // Manually set the system_prompt in the returned object if it was derived and set in DB
            // This ensures the returned object is consistent with the DB state immediately after this transaction.
            if let Some(ref esp_content) = effective_system_prompt {
                if !esp_content.trim().is_empty() {
                    fully_created_session.system_prompt = Some(esp_content.clone()); // Explicit clone of esp_content
                    info!(final_struct_system_prompt = ?fully_created_session.system_prompt, "Assigned non-empty effective_system_prompt to struct.");
                } else {
                    // Effective prompt was Some(" ") or Some(""), ensure struct reflects None
                    fully_created_session.system_prompt = None;
                    info!(final_struct_system_prompt = ?fully_created_session.system_prompt, "Effective_system_prompt was empty/whitespace, struct prompt set to None.");
                }
            } else {
                // Effective prompt was None, struct prompt (from DB) should be None
                info!(final_struct_system_prompt = ?fully_created_session.system_prompt, "Effective_system_prompt was None, struct prompt remains as fetched from DB (should be None).");
            }
            
            info!(session_id = %fully_created_session.id, "Chat session fully created and configured in DB, returning.");
            Ok((fully_created_session, character.first_mes))
        })
    })
    .await??; // Double '?' for InteractError and then AppError from closure

    if let Some(first_message_content) = first_mes_opt {
        if !first_message_content.trim().is_empty() {
            info!(session_id = %created_session.id, "Character has non-empty first_mes, saving via save_message");
            let _ = save_message(
                state.clone(),
                created_session.id,
                user_id,
                MessageRole::Assistant,
                first_message_content,
            ).await?;
            info!(session_id = %created_session.id, "Successfully called save_message for first_mes");
        } else {
            info!(session_id = %created_session.id, "Character first_mes is empty, skipping save.");
        }
    } else {
        info!(session_id = %created_session.id, "Character first_mes is None, skipping save.");
    }

    Ok(created_session)
}

/// Lists chat sessions for a given user.
#[instrument(skip(pool), err)]
pub async fn list_sessions_for_user(
    pool: &DbPool,
    user_id: Uuid,
) -> Result<Vec<Chat>, AppError> { // Renamed ChatSession to Chat
    let conn = pool.get().await?;
    conn.interact(move |conn| {
        chat_sessions::table
            .filter(chat_sessions::user_id.eq(user_id))
            .select(Chat::as_select()) // Renamed ChatSession to Chat
            .order(chat_sessions::updated_at.desc())
            .load::<Chat>(conn) // Renamed ChatSession to Chat
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
/// Gets messages for a specific chat session, verifying ownership.
#[instrument(skip(pool), err)]
pub async fn get_messages_for_session(
    pool: &DbPool,
    user_id: Uuid,
    session_id: Uuid,
) -> Result<Vec<DbChatMessage>, AppError> {
    let conn = pool.get().await?;
    conn.interact(move |conn| {
        let session_owner_id = chat_sessions::table
            .filter(chat_sessions::id.eq(session_id))
            .select(chat_sessions::user_id)
            .first::<Uuid>(conn)
            .optional()?;

        match session_owner_id {
            Some(owner_id) => {
                if owner_id != user_id {
                    Err(AppError::Forbidden) // Keep as unit variant
                } else {
                    chat_messages::table
                        .filter(chat_messages::session_id.eq(session_id))
                        .select(<DbChatMessage as SelectableHelper<diesel::pg::Pg>>::as_select())
                        .order(chat_messages::created_at.asc())
                        .load::<DbChatMessage>(conn)
                        .map_err(|e| {
                            error!("Failed to load messages for session {}: {}", session_id, e);
                            AppError::DatabaseQueryError(e.to_string())
                        })
                }
            }
            None => Err(AppError::NotFound("Chat session not found".into())),
        }
    })
    .await?
}

/// Internal helper to save a chat message within a transaction.
#[instrument(skip(conn), err)]
fn save_chat_message_internal(
    conn: &mut PgConnection,
    message: DbInsertableChatMessage,
) -> Result<DbChatMessage, AppError> {
    match diesel::insert_into(chat_messages::table)
        .values(&message)
        .returning(DbChatMessage::as_select())
        .get_result::<DbChatMessage>(conn)
    {
        Ok(inserted_message) => {
            info!(message_id = %inserted_message.id, session_id = %inserted_message.session_id, "Chat message successfully inserted");
            Ok(inserted_message)
        }
        Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => {
            warn!(session_id = %message.chat_id, role=%message.role, "Attempted to insert duplicate chat message (UniqueViolation), ignoring.");
            Err(AppError::Conflict(
                "Potential duplicate message detected".to_string(),
            ))
        }
        Err(e) => {
            error!(session_id = %message.chat_id, error = ?e, "Error inserting chat message into database");
            Err(AppError::DatabaseQueryError(e.to_string()))
        }
    }
}

/// Saves a single chat message (user or assistant) and triggers background embedding.
#[instrument(skip(state), err)]
pub async fn save_message(
    state: Arc<AppState>,
    session_id: Uuid,
    user_id: Uuid,
    role: MessageRole,
    content: String,
) -> Result<DbChatMessage, AppError> {
    let pool = state.pool.clone();
    let saved_message_result = pool
        .get()
        .await?
        .interact(move |conn| {
            let new_message = DbInsertableChatMessage::new(session_id, user_id, role, content);
            save_chat_message_internal(conn, new_message)
        })
        .await?;

    if let Ok(saved_message) = &saved_message_result {
        let state_clone = state.clone();
        let message_clone = saved_message.clone();
        tokio::spawn(async move {
            info!(message_id = %message_clone.id, "Spawning background task for message embedding");
            let embedding_pipeline_service = state_clone.embedding_pipeline_service.clone();

            let message_id_for_tracker = message_clone.id;
            if let Err(e) = embedding_pipeline_service.process_and_embed_message(state_clone.clone(), message_clone).await {
                error!(error = %e, "Background embedding task failed");
            } else {
                info!("Background embedding task completed successfully");
            }

             let tracker_arc = state_clone.embedding_call_tracker.clone();
             tracker_arc.lock().await.push(message_id_for_tracker);
             info!(message_id = %message_id_for_tracker, "Notified embedding tracker");

        });
    }

    saved_message_result
}

/// Fetches session settings, history, applies history management, and prepares the user message struct.
#[instrument(skip(pool, user_message_content), err)]
pub async fn get_session_data_for_generation(
    pool: &DbPool,
    user_id: Uuid,
    session_id: Uuid,
    user_message_content: String,
    // Removed default_model_name parameter
) -> Result<GenerationDataWithUnsavedUserMessage, AppError> {
    let conn = pool.get().await?;
    conn.interact(move |conn| {
        info!(%session_id, %user_id, "Fetching session data for generation");

        // 1. Fetch session and check existence/ownership
        let session_owner_id = chat_sessions::table
            .filter(chat_sessions::id.eq(session_id))
            .select(chat_sessions::user_id)
            .first::<Uuid>(conn)
            .optional()?;

        match session_owner_id {
            None => {
                warn!(%session_id, %user_id, "Chat session not found for generation");
                return Err(AppError::NotFound("Chat session not found".into()));
            }
            Some(owner_id) if owner_id != user_id => {
                warn!(%session_id, %user_id, owner_id=%owner_id, "User mismatch for generation");
                return Err(AppError::Forbidden); // Keep as unit variant
            }
            Some(_) => {
                info!(%session_id, %user_id, "Session ownership verified for generation");
            }
        }

        info!(%session_id, "Fetching chat settings for generation");
        // Fetch all settings including history management
        let settings: (
            Option<String>,     // system_prompt
            Option<BigDecimal>, // temperature
            Option<i32>,        // max_output_tokens
            Option<BigDecimal>, // frequency_penalty
            Option<BigDecimal>, // presence_penalty
            Option<i32>,        // top_k
            Option<BigDecimal>, // top_p
            Option<BigDecimal>, // repetition_penalty
            Option<BigDecimal>, // min_p
            Option<BigDecimal>, // top_a
            Option<i32>,        // seed
            Option<Value>,      // logit_bias
            String,             // history_management_strategy
            i32,                // history_management_limit
            String,             // model_name (Fetch this!)
            // -- Gemini Specific Options --
            Option<i32>,        // gemini_thinking_budget
            Option<bool>,       // gemini_enable_code_execution
        ) = chat_sessions::table
            .filter(chat_sessions::id.eq(session_id))
            .select((
                chat_sessions::system_prompt,
                chat_sessions::temperature,
                chat_sessions::max_output_tokens,
                chat_sessions::frequency_penalty,
                chat_sessions::presence_penalty,
                chat_sessions::top_k,
                chat_sessions::top_p,
                chat_sessions::repetition_penalty,
                chat_sessions::min_p,
                chat_sessions::top_a,
                chat_sessions::seed,
                chat_sessions::logit_bias,
                chat_sessions::history_management_strategy,
                chat_sessions::history_management_limit,
                chat_sessions::model_name, // Add model_name to select
                // -- Gemini Specific Options --
                chat_sessions::gemini_thinking_budget,
                chat_sessions::gemini_enable_code_execution,
            ))
            .first(conn)?;

        let ( system_prompt, temperature, max_tokens, frequency_penalty, presence_penalty, top_k, top_p, repetition_penalty, min_p, top_a, seed, logit_bias, history_management_strategy, history_management_limit, model_name, gemini_thinking_budget, gemini_enable_code_execution ) = settings; // Destructure model_name and new Gemini fields

        info!(%session_id, "Fetching full message history");
        // Fetch the full history as DbChatMessage structs
        let full_db_history = chat_messages::table
            .filter(chat_messages::session_id.eq(session_id))
            .order(chat_messages::created_at.asc())
            .select(DbChatMessage::as_select()) // Select the full struct
            .load::<DbChatMessage>(conn)?;

        // --- Apply History Management ---
        // Clone full_db_history here to avoid moving it before the debug log below.
        let managed_db_history = history_manager::manage_history(
            full_db_history.clone(), // Clone here
            &history_management_strategy, // Pass as reference
            history_management_limit,
        );
        debug!(%session_id, strategy=%history_management_strategy, limit=%history_management_limit, original_len=full_db_history.len(), managed_len=managed_db_history.len(), "History management applied");

        // Convert managed history to the tuple format needed for the prompt builder
        let managed_history_for_prompt: HistoryForGeneration = managed_db_history
            .into_iter()
            .map(|msg| (msg.message_type, msg.content))
            .collect();

        // Prepare the user message struct (don't save it here)
        let user_db_message_to_save = DbInsertableChatMessage::new(
            session_id,
            user_id,
            MessageRole::User,
            user_message_content, // This is String
        );

        Ok((
            managed_history_for_prompt, // Return the managed history
            system_prompt,
            temperature,
            max_tokens,
            frequency_penalty,
            presence_penalty,
            top_k,
            top_p,
            repetition_penalty,
            min_p,
            top_a,
            seed,
            logit_bias,
            model_name.clone(), // Explicitly clone String
            // -- Gemini Specific Options --
            gemini_thinking_budget,
            gemini_enable_code_execution,
            user_db_message_to_save,
            history_management_strategy.clone(), // Explicitly clone String
            history_management_limit,
        ))
    })
    .await?
}

/// Gets chat settings for a specific session, verifying ownership.
#[instrument(skip(pool), err)]
pub async fn get_session_settings(
    pool: &DbPool,
    user_id: Uuid,
    session_id: Uuid,
) -> Result<ChatSettingsResponse, AppError> {
    let conn = pool.get().await?;
    conn.interact(move |conn| {
        let settings_tuple = chat_sessions::table
            .filter(chat_sessions::id.eq(session_id))
            .filter(chat_sessions::user_id.eq(user_id))
            .select((
                chat_sessions::system_prompt,
                chat_sessions::temperature,
                chat_sessions::max_output_tokens,
                chat_sessions::frequency_penalty,
                chat_sessions::presence_penalty,
                chat_sessions::top_k,
                chat_sessions::top_p,
                chat_sessions::repetition_penalty,
                chat_sessions::min_p,
                chat_sessions::top_a,
                chat_sessions::seed,
                chat_sessions::logit_bias,
                chat_sessions::history_management_strategy,
                chat_sessions::history_management_limit,
                chat_sessions::model_name,
                // -- Gemini Specific Options --
                chat_sessions::gemini_thinking_budget,
                chat_sessions::gemini_enable_code_execution,
            ))
            .first::<SettingsTuple>(conn)
            .optional()?;

            match settings_tuple {
                Some(tuple) => {
                    let (
                        system_prompt,
                        temperature,
                        max_output_tokens,
                        frequency_penalty,
                        presence_penalty,
                        top_k,
                        top_p,
                        repetition_penalty,
                        min_p,
                        top_a,
                        seed,
                        logit_bias,
                        history_management_strategy,
                        history_management_limit,
                        model_name,
                        // -- Gemini Specific Options --
                        gemini_thinking_budget,
                        gemini_enable_code_execution,
                    ) = tuple;
                    Ok(ChatSettingsResponse {
                        system_prompt,
                        temperature,
                        max_output_tokens,
                        frequency_penalty,
                        presence_penalty,
                        top_k,
                        top_p,
                        repetition_penalty,
                        min_p,
                        top_a,
                        seed,
                        logit_bias,
                        history_management_strategy,
                        history_management_limit,
                        model_name,
                        // -- Gemini Specific Options --
                        gemini_thinking_budget,
                        gemini_enable_code_execution,
                    })
                }
                None => Err(AppError::NotFound(
                    "Chat session not found or permission denied".into(),
                )),
            }
    })
    .await?
}

/// Updates chat settings for a specific session, verifying ownership.
#[instrument(skip(pool, payload), err)]
pub async fn update_session_settings(
    pool: &DbPool,
    user_id: Uuid,
    session_id: Uuid,
    payload: UpdateChatSettingsRequest,
) -> Result<ChatSettingsResponse, AppError> {
    let conn = pool.get().await?;
    conn.interact(move |conn| {
        conn.transaction(|transaction_conn| {
            let owner_id_result = chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select(chat_sessions::user_id)
                .first::<Uuid>(transaction_conn)
                .optional()?;

            match owner_id_result {
                Some(owner_id) => {
                    if owner_id != user_id {
                        error!(
                            "User {} attempted to update settings for session {} owned by {}",
                            user_id, session_id, owner_id
                        );
                        return Err(AppError::Forbidden); // Keep as unit variant
                    }

                    let update_target =
                        chat_sessions::table.filter(chat_sessions::id.eq(session_id));

                    let updated_settings_tuple: SettingsTuple = diesel::update(update_target)
                        .set(&payload)
                        .returning((
                            chat_sessions::system_prompt,
                            chat_sessions::temperature,
                            chat_sessions::max_output_tokens,
                            chat_sessions::frequency_penalty,
                            chat_sessions::presence_penalty,
                            chat_sessions::top_k,
                            chat_sessions::top_p,
                            chat_sessions::repetition_penalty,
                            chat_sessions::min_p,
                            chat_sessions::top_a,
                            chat_sessions::seed,
                            chat_sessions::logit_bias,
                            chat_sessions::history_management_strategy,
                            chat_sessions::history_management_limit,
                            chat_sessions::model_name,
                            // -- Gemini Specific Options --
                            chat_sessions::gemini_thinking_budget,
                            chat_sessions::gemini_enable_code_execution,
                        ))
                        .get_result::<SettingsTuple>(transaction_conn) // Explicit type annotation
                        .map_err(|e| {
                            error!(error = ?e, "Failed to update chat session settings");
                            AppError::DatabaseQueryError(e.to_string())
                        })?;

                    info!(%session_id, "Chat session settings updated successfully");

                    let (
                        system_prompt,
                        temperature,
                        max_output_tokens,
                        frequency_penalty,
                        presence_penalty,
                        top_k,
                        top_p,
                        repetition_penalty,
                        min_p,
                        top_a,
                        seed,
                        logit_bias,
                        history_management_strategy,
                        history_management_limit,
                        model_name,
                        // -- Gemini Specific Options --
                        gemini_thinking_budget,
                        gemini_enable_code_execution,
                    ) = updated_settings_tuple;
                    Ok(ChatSettingsResponse {
                        system_prompt,
                        temperature,
                        max_output_tokens,
                        frequency_penalty,
                        presence_penalty,
                        top_k,
                        top_p,
                        repetition_penalty,
                        min_p,
                        top_a,
                        seed,
                        logit_bias,
                        history_management_strategy,
                        history_management_limit,
                        model_name,
                        // -- Gemini Specific Options --
                        gemini_thinking_budget,
                        gemini_enable_code_execution,
                    })
                }
                None => {
                    error!("Chat session {} not found for update", session_id);
                    Err(AppError::NotFound("Chat session not found".into()))
                }
            }
        })
    })
    .await?
}
