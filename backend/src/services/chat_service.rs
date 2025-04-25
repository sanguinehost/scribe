// backend/src/services/chat_service.rs

use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use uuid::Uuid;
use bigdecimal::BigDecimal;
use serde_json::Value;
use tracing::{error, info, instrument, warn}; // Removed debug

use crate::{
    errors::AppError,
    models::{
        chats::{
            ChatSession, NewChatSession, ChatMessage as DbChatMessage, MessageRole,
            NewChatMessage, DbInsertableChatMessage, SettingsTuple, ChatSettingsResponse,
            UpdateChatSettingsRequest,
        },
        characters::Character,
    },
    schema::{characters, chat_messages, chat_sessions}, // Removed self
    state::{AppState, DbPool}, // Use DbPool from state, Add AppState
    services::embedding_pipeline::process_and_embed_message, // Import the pipeline function
};
use std::sync::Arc; // Add Arc for AppState

// Type alias for the history tuple returned for generation
pub type HistoryForGeneration = Vec<(MessageRole, String)>;

// Type alias for the full data needed for generation, including the model name
// AND the unsaved user message struct
pub type GenerationDataWithUnsavedUserMessage = (
    HistoryForGeneration, // Existing history BEFORE the new user message
    Option<String>,      // system_prompt
    Option<BigDecimal>,  // temperature
    Option<i32>,         // max_output_tokens
    Option<BigDecimal>,  // frequency_penalty
    Option<BigDecimal>,  // presence_penalty
    Option<i32>,         // top_k
    Option<BigDecimal>,  // top_p
    Option<BigDecimal>,  // repetition_penalty
    Option<BigDecimal>,  // min_p
    Option<BigDecimal>,  // top_a
    Option<i32>,         // seed
    Option<Value>,       // logit_bias
    String,              // model_name
    DbInsertableChatMessage, // The user message struct, ready to be saved
);


/// Creates a new chat session, verifies character ownership, and adds the character's first message if available.
#[instrument(skip(pool), err)]
pub async fn create_session_and_maybe_first_message(
    pool: &DbPool,
    user_id: Uuid,
    character_id: Uuid,
) -> Result<ChatSession, AppError> {
    let conn = pool.get().await?;
    conn.interact(move |conn| {
        conn.transaction(|transaction_conn| {
            info!(%character_id, %user_id, "Verifying character ownership");
            let character_owner_id = characters::table
                .filter(characters::id.eq(character_id))
                .select(characters::user_id)
                .first::<Uuid>(transaction_conn)
                .optional()?;

            match character_owner_id {
                Some(owner_id) => {
                    if owner_id != user_id {
                        error!(%character_id, %user_id, owner_id=%owner_id, "User does not own character");
                        return Err(AppError::Forbidden);
                    }
                    info!(%character_id, %user_id, "Inserting new chat session");
                    let new_session = NewChatSession { user_id, character_id };
                    let created_session: ChatSession = diesel::insert_into(chat_sessions::table)
                        .values(&new_session)
                        .returning(ChatSession::as_select())
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

                    if let Some(first_message_content) = character.first_mes {
                        if !first_message_content.trim().is_empty() {
                            info!(session_id = %created_session.id, "Character has first_mes, adding as initial assistant message");
                            let first_message = DbInsertableChatMessage::new(
                                created_session.id,
                                user_id,
                                MessageRole::Assistant,
                                first_message_content,
                            );
                            diesel::insert_into(chat_messages::table)
                                .values(&first_message)
                                .execute(transaction_conn)
                                .map_err(|e| {
                                    error!(error = ?e, session_id = %created_session.id, "Failed to insert first_mes");
                                    AppError::DatabaseQueryError(e.to_string())
                                })?;
                            info!(session_id = %created_session.id, "Successfully inserted first_mes");
                        } else {
                            info!(session_id = %created_session.id, "Character first_mes is empty, skipping initial message.");
                        }
                    } else {
                         info!(session_id = %created_session.id, "Character first_mes is None, skipping initial message.");
                    }
                    Ok(created_session)
                }
                None => {
                    error!(%character_id, "Character not found during session creation");
                    Err(AppError::NotFound("Character not found".into()))
                }
            }
        })
    })
    .await? // Propagate interact error
}

/// Lists chat sessions for a given user.
#[instrument(skip(pool), err)]
pub async fn list_sessions_for_user(
    pool: &DbPool,
    user_id: Uuid,
) -> Result<Vec<ChatSession>, AppError> {
    let conn = pool.get().await?;
    conn.interact(move |conn| {
        chat_sessions::table
            .filter(chat_sessions::user_id.eq(user_id))
            .select(ChatSession::as_select())
            .order(chat_sessions::updated_at.desc())
            .load::<ChatSession>(conn)
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
                    Err(AppError::Forbidden)
                } else {
                    chat_messages::table
                        .filter(chat_messages::session_id.eq(session_id))
                        .select(DbChatMessage::as_select())
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
/// This function is NOT async and expects to be run within `interact`.
#[instrument(skip(conn), err)]
fn save_chat_message_internal(
    conn: &mut PgConnection,
    message: DbInsertableChatMessage,
) -> Result<DbChatMessage, AppError> {
    match diesel::insert_into(chat_messages::table)
        .values(&message)
        .returning(DbChatMessage::as_select())
        .get_result(conn)
    {
        Ok(inserted_message) => {
            // Corrected chat_id to session_id
            info!(message_id = %inserted_message.id, session_id = %inserted_message.session_id, "Chat message successfully inserted");
            Ok(inserted_message)
        },
        Err(DieselError::DatabaseError(DatabaseErrorKind::UniqueViolation, _)) => {
            warn!(session_id = %message.chat_id, role=%message.role, "Attempted to insert duplicate chat message (UniqueViolation), ignoring.");
            // Consider returning the existing message if needed, or just signal conflict
            Err(AppError::Conflict("Potential duplicate message detected".to_string()))
        }
        Err(e) => {
            error!(session_id = %message.chat_id, error = ?e, "Error inserting chat message into database");
            Err(AppError::DatabaseQueryError(e.to_string()))
        }
    }
}

/// Saves a single chat message (user or assistant) and triggers background embedding.
/// This is intended for saving the final assistant response outside the main generation transaction.
#[instrument(skip(state), err)] // Update skip attribute
pub async fn save_message(
    state: Arc<AppState>, // Change pool to state
    session_id: Uuid,
    user_id: Uuid, // Change from Option<Uuid> to Uuid
    role: MessageRole,
    content: String,
) -> Result<DbChatMessage, AppError> {
    let pool = state.pool.clone(); // Get pool from state
    let saved_message_result = pool.get().await?.interact(move |conn| {
        let new_message = DbInsertableChatMessage::new(session_id, user_id, role, content);
        save_chat_message_internal(conn, new_message)
    })
    .await?; // This double '?' propagates interact error then the inner Result

    // After successfully saving, spawn the embedding task asynchronously
    if let Ok(saved_message) = &saved_message_result {
        let state_clone = state.clone();
        let message_clone = saved_message.clone(); // Clone the message data for the task
        tokio::spawn(async move {
            info!(message_id = %message_clone.id, "Spawning background task for message embedding");
            if let Err(e) = process_and_embed_message(state_clone, message_clone).await {
                error!(error = %e, "Background embedding task failed");
                // TODO: Consider adding monitoring or retry logic for failed background tasks
            } else {
                info!("Background embedding task completed successfully");
            }
        });
    }

    saved_message_result // Return the original result (Ok or Err)
}


/// Fetches session settings, history, and prepares the user message struct, returning data needed for generation.
#[instrument(skip(pool, user_message_content), err)]
pub async fn get_session_data_for_generation(
    pool: &DbPool,
    user_id: Uuid,
    session_id: Uuid,
    user_message_content: String,
    default_model_name: String, // Pass default model name
) -> Result<GenerationDataWithUnsavedUserMessage, AppError> { // Updated return type
    let conn = pool.get().await?;
    conn.interact(move |conn| {
        // No transaction needed here anymore as we don't save the message
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
                return Err(AppError::Forbidden);
            }
            Some(_) => {
                info!(%session_id, %user_id, "Session ownership verified for generation");
            }
        }

        info!(%session_id, "Fetching chat settings for generation");
        let settings: SettingsTuple = chat_sessions::table
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
            ))
            .first::<SettingsTuple>(conn)?;
        let ( system_prompt, temperature, max_tokens, frequency_penalty, presence_penalty, top_k, top_p, repetition_penalty, min_p, top_a, seed, logit_bias ) = settings;

        info!(%session_id, "Fetching message history for generation (excluding current user message)");
        let history = chat_messages::table
            .filter(chat_messages::session_id.eq(session_id))
            .order(chat_messages::created_at.asc())
            .select((chat_messages::message_type, chat_messages::content))
            .load::<(MessageRole, String)>(conn)?;

        // info!(%session_id, "Saving user message before generation"); // Removed save
        // Prepare the user message struct, but don't save it here
        let user_db_message_to_save = DbInsertableChatMessage::new(
            session_id,
            user_id, // Pass user_id directly, not Some(user_id)
            MessageRole::User,
            user_message_content, // Use directly, no clone needed now
        );
        // let saved_user_message = save_chat_message_internal(transaction_conn, user_db_message)?; // Removed save

        let mut full_history = history;
        // We do NOT add the current user message to the history passed to the LLM yet,
        // as the handler will add it after potentially prepending RAG context.

        // Prepend system prompt if it exists and is not empty
        if let Some(ref prompt) = system_prompt {
            if !prompt.trim().is_empty() {
                full_history.insert(0, (MessageRole::System, prompt.clone()));
            }
        }

        Ok((
            full_history, // History *without* the current user message
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
            user_db_message_to_save, // Return the unsaved user message struct
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
            // Explicitly select columns
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
            ))
            .first::<SettingsTuple>(conn)
            .optional()?; // Use optional to handle NotFound

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
                })
            }
            None => Err(AppError::NotFound("Chat session not found or permission denied".into())),
        }
    })
    .await?
}

/// Updates chat settings for a specific session, verifying ownership.
/// Assumes payload has already been validated by the handler.
#[instrument(skip(pool, payload), err)]
pub async fn update_session_settings(
    pool: &DbPool,
    user_id: Uuid,
    session_id: Uuid,
    payload: UpdateChatSettingsRequest, // Pass the validated payload
) -> Result<ChatSettingsResponse, AppError> {
    let conn = pool.get().await?;
    conn.interact(move |conn| {
        conn.transaction(|transaction_conn| {
            // 1. Verify ownership
            let session_details = chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                // Remove model_name from select
                .select((chat_sessions::user_id, chat_sessions::title, chat_sessions::system_prompt, chat_sessions::temperature, chat_sessions::max_output_tokens, chat_sessions::frequency_penalty, chat_sessions::presence_penalty, chat_sessions::top_k, chat_sessions::top_p, chat_sessions::repetition_penalty, chat_sessions::min_p, chat_sessions::top_a, chat_sessions::seed, chat_sessions::logit_bias /*, chat_sessions::model_name */ ))
                .first::<(
                    Uuid, // user_id
                    Option<String>, // title
                    Option<String>, // system_prompt
                    Option<BigDecimal>, // temperature
                    Option<i32>, // max_output_tokens
                    Option<BigDecimal>, // frequency_penalty
                    Option<BigDecimal>, // presence_penalty
                    Option<i32>, // top_k
                    Option<BigDecimal>, // top_p
                    Option<BigDecimal>, // repetition_penalty
                    Option<BigDecimal>, // min_p
                    Option<BigDecimal>, // top_a
                    Option<i32>, // seed
                    Option<Value> // logit_bias
                    // Option<String> // model_name (removed)
                )>(transaction_conn)
                .optional()?;

            match session_details {
                Some((owner_id, _, _, _, _, _, _, _, _, _, _, _, _, _)) => {
                    if owner_id != user_id {
                        error!("User {} attempted to update settings for session {} owned by {}", user_id, session_id, owner_id);
                        return Err(AppError::Forbidden);
                    }

                    // 2. Perform the update explicitly setting columns
                    let update_target = chat_sessions::table.filter(chat_sessions::id.eq(session_id));

                    // Using the original update method which relies on AsChangeset derived on the payload struct
                    let updated_settings_tuple: SettingsTuple = diesel::update(update_target)
                        .set(payload) // Use the payload struct directly (requires AsChangeset derive)
                        .returning((
                            // Return the fields needed for ChatSettingsResponse
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
                        ))
                        .get_result(transaction_conn)
                        .map_err(|e| {
                            error!(error = ?e, "Failed to update chat session settings");
                            AppError::DatabaseQueryError(e.to_string())
                        })?;

                    info!(%session_id, "Chat session settings updated successfully");

                    // Manually map the returned tuple to ChatSettingsResponse
                    let (system_prompt, temperature, max_output_tokens, frequency_penalty, presence_penalty, top_k, top_p, repetition_penalty, min_p, top_a, seed, logit_bias) = updated_settings_tuple;
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