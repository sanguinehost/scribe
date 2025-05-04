// backend/src/services/chat_service.rs

use bigdecimal::BigDecimal;
use diesel::prelude::*;
use diesel::{RunQueryDsl, SelectableHelper}; // Added RunQueryDsl and SelectableHelper
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use serde_json::Value;
use tracing::{debug, error, info, instrument, warn}; // Added debug
use uuid::Uuid;

use crate::{
    errors::AppError,
    models::{
        characters::Character,
        chats::{
            Chat, ChatMessage as DbChatMessage, ChatSettingsResponse, // Renamed ChatSession to Chat
            DbInsertableChatMessage, MessageRole, NewChat, SettingsTuple, // Renamed NewChatSession to NewChat, Added SettingsTuple
            UpdateChatSettingsRequest,
        },
    },
    schema::{characters, chat_messages, chat_sessions},
    services::history_manager, // Import the new service
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
    String,                  // model_name
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
) -> Result<Chat, AppError> { // Renamed ChatSession to Chat
    let pool = state.pool.clone();
    let conn = pool.get().await?;
    let (created_session, first_mes_opt) = conn.interact(move |conn| {
        conn.transaction(|transaction_conn| {
            info!(%character_id, %user_id, "Verifying character ownership");
            let character_owner_id: Option<Uuid> = characters::table
                .filter(characters::id.eq(character_id))
                .select(characters::user_id)
                .first::<Uuid>(transaction_conn)
                .optional()?;

            match character_owner_id {
                Some(owner_id) => {
                    if owner_id != user_id {
                        error!(%character_id, %user_id, %owner_id, "User does not own character");
                        return Err(AppError::Forbidden); // Keep as unit variant
                    }
                    info!(%character_id, %user_id, "Inserting new chat session");
                    let new_session = NewChat { // Renamed NewChatSession to NewChat
                        id: Uuid::new_v4(), // NewChat needs an ID
                        user_id,
                        character_id,
                        title: None, // Add default fields for NewChat
                        created_at: chrono::Utc::now(),
                        updated_at: chrono::Utc::now(),
                        history_management_strategy: "message_window".to_string(), // Default
                        history_management_limit: 20, // Default
                        visibility: Some("private".to_string()), // Default
                    };
                    let created_session: Chat = diesel::insert_into(chat_sessions::table) // Renamed ChatSession to Chat
                        .values(&new_session)
                        .returning(Chat::as_select()) // Renamed ChatSession to Chat
                        .get_result(transaction_conn)
                        .map_err(|e| {
                            error!(error = ?e, "Failed to insert new chat session");
                            AppError::DatabaseQueryError(e.to_string())
                        })?;
                    info!(session_id = %created_session.id, "Chat session created");

                    info!(%character_id, session_id = %created_session.id, "Fetching character details for first_mes");
                    let character: Character = characters::table
                        .filter(characters::id.eq(character_id))
                        .select(Character::as_select())
                        .first::<Character>(transaction_conn)
                        .map_err(|e| {
                            error!(error = ?e, %character_id, "Failed to fetch full character details during session creation");
                            match e {
                                DieselError::NotFound => AppError::InternalServerError(anyhow::anyhow!("Character inconsistency during session creation").to_string()),
                                _ => AppError::DatabaseQueryError(e.to_string()),
                            }
                        })?;

                    Ok((created_session, character.first_mes))
                }
                None => {
                    error!(%character_id, "Character not found during session creation");
                    Err(AppError::NotFound("Character not found".into()))
                }
            }
        })
    })
    .await??;

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
    default_model_name: String,
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
            ))
            .first(conn)?;

        let ( system_prompt, temperature, max_tokens, frequency_penalty, presence_penalty, top_k, top_p, repetition_penalty, min_p, top_a, seed, logit_bias, history_management_strategy, history_management_limit ) = settings;

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
            &history_management_strategy,
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
            user_message_content,
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
            default_model_name,
            user_db_message_to_save,
            history_management_strategy, // Still return these for logging/info
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
