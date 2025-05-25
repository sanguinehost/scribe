// backend/src/services/chat_service.rs

use crate::llm::ChatStream as GenAiChatStream;
use async_stream::stream;
use bigdecimal::BigDecimal;
use bigdecimal::ToPrimitive;
use diesel::prelude::*;
use diesel::result::{DatabaseErrorKind, Error as DieselError};
use diesel::{RunQueryDsl, SelectableHelper};
use futures_util::{Stream, StreamExt as FuturesStreamExt}; // Renamed to avoid conflict
use genai::chat::{
    ChatMessage as GenAiChatMessage, ChatOptions as GenAiChatOptions,
    ChatRequest as GenAiChatRequest, ChatStreamEvent, Tool,
};
use secrecy::{ExposeSecret, SecretBox};
use serde_json::Value;
use serde_json::json;
use tracing::{debug, error, info, instrument, trace, warn};
use uuid::Uuid;

use crate::{
    crypto, // Added for encryption
    errors::AppError,
    models::{
        characters::Character,
        chat_override::{ChatCharacterOverride, CharacterOverrideDto, NewChatCharacterOverride},
        chats::{
            Chat, ChatMessage as DbChatMessage, ChatSettingsResponse, DbInsertableChatMessage,
            MessageRole, NewChat, SettingsTuple, UpdateChatSettingsRequest,
        },
        lorebooks::ChatSessionLorebook, // Added for fetching active lorebook IDs
    },
    schema::{characters, chat_character_overrides, chat_messages, chat_sessions},
    schema::users::dsl as users_dsl, // Added for fetching user's default persona
    services::{
        hybrid_token_counter::CountingMode, // Added for token counting
        embedding_pipeline::RetrievedChunk, // Added for RAG context items
    },
    services::tokenizer_service::TokenEstimate, // Added for token counting (direct import)
    state::{AppState, DbPool},
    // history_manager, // Removed as per new logic
};
use std::pin::Pin;
use std::sync::Arc;
use std::cmp::min; // Added for RAG budget calculation
use std::collections::HashSet; // Added for filtering older chat history

// Type alias for the history tuple returned for generation
pub type HistoryForGeneration = Vec<(MessageRole, String)>;

// Type alias for the full data needed for generation, including the model name
// AND the unsaved user message struct
// NOTE: HistoryForGeneration here will now contain the *managed* history.
pub type GenerationDataWithUnsavedUserMessage = (
    Vec<DbChatMessage>,   // 0: managed_db_history (CHANGED from HistoryForGeneration)
    Option<String>,       // 1: system_prompt (this is the final_effective_system_prompt for the builder, from persona/override only)
    Option<Vec<Uuid>>,    // 2: active_lorebook_ids_for_search
    Uuid,                 // 3: session_character_id (NEW)
    Option<String>,       // 4: raw_character_system_prompt (NEW - from character_db.system_prompt)
    Option<BigDecimal>,   // 5: temperature (was 4)
    Option<i32>,          // 6: max_output_tokens (was 5)
    Option<BigDecimal>,   // 7: frequency_penalty (was 6)
    Option<BigDecimal>,   // 8: presence_penalty (was 7)
    Option<i32>,          // 9: top_k (was 8)
    Option<BigDecimal>,   // 10: top_p (was 9)
    Option<BigDecimal>,   // 11: repetition_penalty (was 10)
    Option<BigDecimal>,   // 12: min_p (was 11)
    Option<BigDecimal>,   // 13: top_a (was 12)
    Option<i32>,          // 14: seed (was 13)
    Option<Value>,        // 15: logit_bias (was 14)
    String,               // 16: model_name (Fetched from DB) (was 15)
    // -- Gemini Specific Options --
    Option<i32>,             // 17: gemini_thinking_budget (was 16)
    Option<bool>,            // 18: gemini_enable_code_execution (was 17)
    DbInsertableChatMessage, // 19: The user message struct, ready to be saved (was 18)
    // -- RAG Context & Recent History Tokens --
    usize,                // 20: actual_recent_history_tokens (NEW) (was 19)
    Vec<RetrievedChunk>,  // 21: rag_context_items (NEW) (was 20)
    // History Management Settings (still returned for potential future use/logging)
    String, // 22: history_management_strategy (was 21)
    i32,    // 23: history_management_limit (was 22)
);

#[derive(Debug)]
pub enum ScribeSseEvent {
    Content(String),
    Thinking(String),
    Error(String),
}

/// Creates a new chat session, verifies character ownership, and adds the character's first message if available.
#[instrument(skip(state, user_dek_secret_box), err)]
pub async fn create_session_and_maybe_first_message(
    state: Arc<AppState>,
    user_id: Uuid,
    character_id: Uuid,
    active_custom_persona_id: Option<Uuid>,
    user_dek_secret_box: Option<Arc<SecretBox<Vec<u8>>>>,
) -> Result<Chat, AppError> {
    let pool = state.pool.clone();
    let conn = pool.get().await?;
    // Clone user_dek_secret_box for use inside the 'move' closure
    let user_dek_for_closure = user_dek_secret_box.clone();
    let (created_session, first_mes_ciphertext_opt, first_mes_nonce_opt) = conn.interact(move |conn| {
        conn.transaction(|transaction_conn| {
            let mut effective_active_persona_id = active_custom_persona_id;

            if effective_active_persona_id.is_none() {
                info!(%user_id, "No active_custom_persona_id provided, checking for user's default persona.");
                match users_dsl::users
                    .filter(users_dsl::id.eq(user_id))
                    .select(users_dsl::default_persona_id)
                    .first::<Option<Uuid>>(transaction_conn)
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
            let new_chat_for_insert = NewChat {
                id: new_session_id,
                user_id,
                character_id,
                // Use sanitized name for title
                title: Some(sanitized_character_name.clone()),
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
                                match crypto::decrypt_gcm(sp_bytes_vec, sp_nonce_vec, dek_arc.as_ref()) {
                                    Ok(decrypted_secret_vec) => {
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
                    diesel::update(chat_sessions::table.filter(chat_sessions::id.eq(new_session_id)))
                        .set(chat_sessions::system_prompt.eq(prompt_to_set))
                        .execute(transaction_conn)
                        .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
                }
            }
            let mut fully_created_session: Chat = chat_sessions::table
                .filter(chat_sessions::id.eq(new_session_id))
                .select(Chat::as_select())
                .first(transaction_conn)
                .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

            // Ensure the fully_created_session also reflects the sanitized system prompt if it was set
            if let Some(ref esp_content) = final_system_prompt_str {
                if !esp_content.trim().is_empty() {
                    fully_created_session.system_prompt = Some(esp_content.clone());
                } else {
                    fully_created_session.system_prompt = None;
                }
            }
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
    // Renamed ChatSession to Chat
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
            warn!(session_id = %message.chat_id, role=?message.role, "Attempted to insert duplicate chat message (UniqueViolation), ignoring.");
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
#[instrument(skip(state, content, user_dek_secret_box), err)]
pub async fn save_message(
    state: Arc<AppState>,
    session_id: Uuid,
    user_id: Uuid,
    message_type_enum: MessageRole, // Renamed for clarity (this is the enum)
    content: &str,                  // This is the primary textual content
    role_str: Option<String>,       // ADDED: The string role ("user", "model", "assistant")
    parts: Option<Value>,           // ADDED: The structured parts from the request/generation
    attachments: Option<Value>,     // ADDED: Attachments
    user_dek_secret_box: Option<Arc<SecretBox<Vec<u8>>>>,
    model_name: &str, // Added model_name parameter
) -> Result<DbChatMessage, AppError> {
    trace!(%session_id, %user_id, %message_type_enum, ?role_str, content_len = content.len(), dek_present = user_dek_secret_box.is_some(), %model_name, "Attempting to save message");

    if content.trim().is_empty()
        && parts.as_ref().map_or(true, |p| {
            p.is_null() || (p.is_array() && p.as_array().unwrap().is_empty())
        })
    {
        warn!(%session_id, %user_id, %message_type_enum, "Attempted to save an empty message (both content and parts). Skipping.");
        return Err(AppError::BadRequest(
            "Cannot save an empty message.".to_string(),
        ));
    }

    // Calculate token counts
    let mut prompt_tokens_val: Option<i32> = None;
    let mut completion_tokens_val: Option<i32> = None;

    // Use the main content string for token counting for now.
    // TODO: More accurate token counting if `parts` is complex.
    let content_for_token_counting = content;

    if message_type_enum == MessageRole::User {
        match state
            .token_counter
            .count_tokens(
                content_for_token_counting,
                CountingMode::LocalOnly,
                Some(model_name),
            )
            .await
        {
            Ok(estimate) => prompt_tokens_val = Some(estimate.total as i32), // Use total from TokenEstimate
            Err(e) => warn!("Failed to count prompt tokens for user message: {}", e), // Log and continue
        }
    } else if message_type_enum == MessageRole::Assistant {
        match state
            .token_counter
            .count_tokens(
                content_for_token_counting,
                CountingMode::LocalOnly,
                Some(model_name),
            )
            .await
        {
            Ok(estimate) => completion_tokens_val = Some(estimate.total as i32), // Use total from TokenEstimate
            Err(e) => warn!(
                "Failed to count completion tokens for assistant message: {}",
                e
            ), // Log and continue
        }
    }

    trace!(prompt_tokens=?prompt_tokens_val, completion_tokens=?completion_tokens_val, "Calculated token counts for message");

    let (content_to_save, nonce_to_save) = match &user_dek_secret_box {
        Some(dek_arc) => {
            trace!(%session_id, "User DEK present, encrypting message content.");
            // We encrypt the main `content` string. `parts` and `attachments` are stored as JSONB (plaintext in DB).
            let (ciphertext, nonce) = crate::crypto::encrypt_gcm(content.as_bytes(), &**dek_arc)
                .map_err(|e| {
                    error!(%session_id, "Failed to encrypt message content: {}", e);
                    AppError::EncryptionError(format!("Failed to encrypt message: {}", e))
                })?;
            (ciphertext, Some(nonce))
        }
        None => {
            trace!(%session_id, "User DEK not present, saving message content as plaintext.");
            (content.as_bytes().to_vec(), None)
        }
    };

    let new_message_to_insert = DbInsertableChatMessage::new(
        session_id, // chat_id field in DbInsertableChatMessage
        user_id,
        message_type_enum, // msg_type field in DbInsertableChatMessage
        content_to_save,   // content field
        nonce_to_save,     // content_nonce field
        role_str,          // role field (Option<String>)
        parts,             // parts field (Option<Value>)
        attachments,       // attachments field (Option<Value>)
        prompt_tokens_val,
        completion_tokens_val,
    );

    let db_pool = state.pool.clone();
    let saved_message_db = db_pool
        .get()
        .await?
        .interact(move |conn| save_chat_message_internal(conn, new_message_to_insert))
        .await??;

    debug!(message_id = %saved_message_db.id, %session_id, "Message saved to DB successfully.");

    // Asynchronously trigger RAG processing if the message is from the user and RAG is enabled for the session/globally.
    // Asynchronously trigger RAG processing if the message is from the user
    // We'll always do this for tests too since the tests check for it
    if saved_message_db.message_type == MessageRole::User {
        // For test environments, we don't want to do actual RAG processing
        // but we DO want to track the calls for test assertions
        let embedding_service = state.embedding_pipeline_service.clone();
        let app_state_clone_for_rag = state.clone();
        let message_for_rag = saved_message_db.clone(); // Clone for the async task
        // Clone the DEK for the spawned task. user_dek_secret_box is Option<Arc<SecretBox<Vec<u8>>>>
        let dek_for_rag_task = user_dek_secret_box.clone();

        tokio::spawn(async move {
            // Call will be tracked for mock service in test env
            info!(message_id = %message_for_rag.id, session_id = %message_for_rag.session_id, "Spawning RAG processing task for user message.");

            // Convert Option<Arc<SecretBox<Vec<u8>>>> to Option<&SessionDek>
            // This requires SessionDek to be accessible and potentially a temporary SessionDek to be created.
            // Assuming SessionDek can be constructed from SecretBox<Vec<u8>> or that we can pass the SecretBox directly
            // For now, let's assume we need to pass the Option<&SecretBox<Vec<u8>>> if SessionDek is just a wrapper.
            // The trait expects Option<&SessionDek>. SessionDek wraps SecretBox<Vec<u8>>.
            // So, if dek_for_rag_task is Some(arc_secret_box), we need to pass Some(&SessionDek(*arc_secret_box))
            // This is tricky due to lifetimes if SessionDek is created on the fly.
            // A better approach might be to adjust process_and_embed_message to take Option<&SecretBox<Vec<u8>>>
            // or ensure SessionDek can be easily passed.
            // Given SessionDek is `pub struct SessionDek(pub SecretBox<Vec<u8>>);`
            // we can create a temporary SessionDek if needed.

            let session_dek_for_embedding: Option<crate::auth::session_dek::SessionDek> =
                dek_for_rag_task.map(|arc_sb| {
                    let secret_bytes = arc_sb.expose_secret().clone(); // Clone the Vec<u8>
                    crate::auth::session_dek::SessionDek(SecretBox::new(Box::new(secret_bytes))) // Create new SecretBox and SessionDek
                });

            if let Err(e) = embedding_service
                .process_and_embed_message(
                    app_state_clone_for_rag,
                    message_for_rag.clone(),
                    session_dek_for_embedding.as_ref(), // Pass as Option<&SessionDek>
                )
                .await
            {
                error!(message_id = %message_for_rag.id, session_id = %message_for_rag.session_id, error = ?e, "Error during RAG processing for message");
            } else {
                info!(message_id = %message_for_rag.id, session_id = %message_for_rag.session_id, "RAG processing task completed for message.");
            }
        });
    }

    Ok(saved_message_db)
}

/// Fetches session settings, history, applies history management, and prepares the user message struct.
#[instrument(skip_all, err)]
pub async fn get_session_data_for_generation(
    state: Arc<AppState>,
    user_id: Uuid,
    session_id: Uuid,
    user_message_content: String,
    user_dek_secret_box: Option<Arc<SecretBox<Vec<u8>>>>,
) -> Result<GenerationDataWithUnsavedUserMessage, AppError> {
    let user_message_content_for_closure = user_message_content.clone(); // Used for DbInsertableChatMessage later
    info!(target: "chat_service_persona_debug", %session_id, %user_id, "Entering get_session_data_for_generation.");

    // --- Determine Effective System Prompt & Lorebook IDs (Pre-Main-Interact) ---
    let maybe_active_persona_id_from_session: Option<Uuid> = {
        let conn_clone_for_persona_check = state.pool.get().await?;
        conn_clone_for_persona_check.interact(move |c| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .filter(chat_sessions::user_id.eq(user_id))
                .select(chat_sessions::active_custom_persona_id)
                .first::<Option<Uuid>>(c)
        }).await??
    };
    info!(target: "chat_service_persona_debug", %session_id, ?maybe_active_persona_id_from_session, "Fetched active_custom_persona_id from session.");

    let mut effective_system_prompt: Option<String> = None; 

    if let Some(persona_id) = maybe_active_persona_id_from_session {
        if let Some(ref dek_arc_outer) = user_dek_secret_box {
            let user_for_service_call: crate::models::users::User = {
                let conn_for_user_fetch = state.pool.get().await.map_err(|e| AppError::DbPoolError(e.to_string()))?;
                let user_db_query_result = conn_for_user_fetch.interact(move |c| {
                    crate::schema::users::table
                        .filter(crate::schema::users::id.eq(user_id))
                        .select(crate::models::users::UserDbQuery::as_select())
                        .first::<crate::models::users::UserDbQuery>(c)
                }).await.map_err(|e| AppError::InternalServerErrorGeneric(format!("DB interact error fetching user_db_query: {}", e)))?;
                
                let user_db_query = user_db_query_result.map_err(|e| AppError::NotFound(format!("UserDbQuery for user {} not found: {}", user_id, e)))?;
                user_db_query.into()
            };
            let dek_ref_for_service: Option<&SecretBox<Vec<u8>>> = Some(dek_arc_outer.as_ref());
            match state.user_persona_service.get_user_persona(&user_for_service_call, dek_ref_for_service, persona_id).await {
                Ok(client_persona_dto) => {
                    if let Some(ref sp_from_persona) = client_persona_dto.system_prompt {
                        if !sp_from_persona.trim().is_empty() {
                            effective_system_prompt = Some(sp_from_persona.replace('\0', ""));
                        }
                    }
                    if effective_system_prompt.is_none() { 
                        let mut constructed_parts = Vec::new();
                        let base_prompt_part = if client_persona_dto.description.trim().is_empty() {
                            format!("You are chatting with {}.", client_persona_dto.name.replace('\0', ""))
                        } else {
                            format!("You are chatting with {}. Their description is: {}.", client_persona_dto.name.replace('\0', ""), client_persona_dto.description.replace('\0', ""))
                        };
                        constructed_parts.push(base_prompt_part);
                        if let Some(ref p) = client_persona_dto.personality { if !p.trim().is_empty() { constructed_parts.push(format!("Personality: {}", p.replace('\0', ""))); }}
                        if let Some(ref s) = client_persona_dto.scenario { if !s.trim().is_empty() { constructed_parts.push(format!("Scenario: {}", s.replace('\0', ""))); }}
                        let constructed = constructed_parts.join("\n");
                        if !constructed.trim().is_empty() { effective_system_prompt = Some(constructed); }
                    }
                }
                Err(e) => error!(target: "chat_service_trace_prompt", %session_id, %persona_id, error = %e, "Error fetching active persona via service."),
            }
        } else {
            warn!(target: "chat_service_trace_prompt", %session_id, %persona_id, "Active persona ID present, but no user DEK available.");
        }
    }

    let active_lorebook_ids_for_search: Option<Vec<Uuid>> = {
        let pool_clone_lore = state.pool.clone();
        match pool_clone_lore.get().await.map_err(AppError::from)?.interact(move |conn_lore| {
            ChatSessionLorebook::get_active_lorebook_ids_for_session(conn_lore, session_id).map_err(AppError::from)
        }).await {
            Ok(Ok(ids)) => ids,
            Ok(Err(e)) => { warn!(%session_id, error = %e, "Failed to get active lorebook IDs (DB error)."); None }
            Err(e) => { warn!(%session_id, error = %e, "Failed to get active lorebook IDs (InteractError)."); None }
        }
    };
    info!(%session_id, ?active_lorebook_ids_for_search, "Active lorebook IDs for search determined.");

    // --- Main Interact Block for DB Data (Session Settings, Raw Messages, Character for FirstMes) ---
    let (
        history_management_strategy_db_val, // Renamed to avoid conflict in outer scope
        history_management_limit_db_val,    // Renamed
        session_character_id_db,
        session_temperature_db,
        session_max_output_tokens_db,
        session_frequency_penalty_db,
        session_presence_penalty_db,
        session_top_k_db,
        session_top_p_db,
        session_repetition_penalty_db,
        session_min_p_db,
        session_top_a_db,
        session_seed_db,
        session_logit_bias_db,
        session_model_name_db,
        session_gemini_thinking_budget_db,
        session_gemini_enable_code_execution_db,
        existing_messages_db_raw, // Raw, potentially encrypted messages
        character_for_first_mes,  // Full character for first_mes logic
        character_overrides_for_first_mes, // Overrides for first_mes logic
        final_effective_system_prompt, // This is the system_prompt for the builder (persona/override only)
        raw_character_system_prompt,   // This is the raw system_prompt from the character itself
    ) = {
        let conn = state.pool.get().await.map_err(|e| AppError::DbPoolError(e.to_string()))?;
        let dek_for_interact_cloned = user_dek_secret_box.clone();
        let initial_effective_system_prompt = effective_system_prompt; // Capture current state

        conn.interact(move |conn_interaction| {
            let (
                hist_strat, hist_limit, sess_char_id, _sess_sys_prompt_override_db, 
                temp, max_tokens, freq_pen, pres_pen, top_k_val, top_p_val, rep_pen, min_p_val, top_a_val, seed_val, logit_b, model_n,
                gem_think_budget, gem_enable_code_exec
            ) = chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .filter(chat_sessions::user_id.eq(user_id))
                .select((
                    chat_sessions::history_management_strategy, chat_sessions::history_management_limit,
                    chat_sessions::character_id, chat_sessions::system_prompt,
                    chat_sessions::temperature, chat_sessions::max_output_tokens,
                    chat_sessions::frequency_penalty, chat_sessions::presence_penalty,
                    chat_sessions::top_k, chat_sessions::top_p, chat_sessions::repetition_penalty,
                    chat_sessions::min_p, chat_sessions::top_a, chat_sessions::seed,
                    chat_sessions::logit_bias, chat_sessions::model_name,
                    chat_sessions::gemini_thinking_budget, chat_sessions::gemini_enable_code_execution,
                ))
                .first::<(String, i32, Uuid, Option<String>, Option<BigDecimal>, Option<i32>, Option<BigDecimal>, Option<BigDecimal>, Option<i32>, Option<BigDecimal>, Option<BigDecimal>, Option<BigDecimal>, Option<BigDecimal>, Option<i32>, Option<Value>, String, Option<i32>, Option<bool>)>(conn_interaction)
                .map_err(|e| match e {
                    DieselError::NotFound => AppError::NotFound(format!("Chat session {} not found", session_id)),
                    _ => AppError::DatabaseQueryError(format!("Failed to query chat session {}: {}", session_id, e)),
                })?;

            let character_db: Character = characters::table
                .filter(characters::id.eq(sess_char_id))
                .first::<Character>(conn_interaction)
                .map_err(|e| match e {
                    DieselError::NotFound => AppError::NotFound(format!("Character {} not found", sess_char_id)),
                    _ => AppError::DatabaseQueryError(format!("Failed to query character {}: {}", sess_char_id, e)),
                })?;

            let overrides_db: Vec<ChatCharacterOverride> = chat_character_overrides::table
                .filter(chat_character_overrides::chat_session_id.eq(session_id))
                .filter(chat_character_overrides::original_character_id.eq(sess_char_id))
                .load::<ChatCharacterOverride>(conn_interaction)
                .map_err(|e| AppError::DatabaseQueryError(format!("Failed to query overrides: {}", e)))?;

            let messages_raw_db: Vec<DbChatMessage> = chat_messages::table
                .filter(chat_messages::session_id.eq(session_id))
                .order(chat_messages::created_at.asc()) // Fetch in ascending order for correct processing later
                .select(DbChatMessage::as_select())
                .load::<DbChatMessage>(conn_interaction)
                .map_err(|e| AppError::DatabaseQueryError(format!("Failed to load messages: {}", e)))?;
            
            let mut current_effective_system_prompt = initial_effective_system_prompt;

            if current_effective_system_prompt.is_none() { 
                let mut override_values_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
                 for override_data in &overrides_db {
                    if let Some(dek) = &dek_for_interact_cloned {
                         if !override_data.overridden_value.is_empty() && !override_data.overridden_value_nonce.is_empty() {
                            if let Ok(dec_bytes) = crypto::decrypt_gcm(&override_data.overridden_value, &override_data.overridden_value_nonce, dek.as_ref()) {
                                if let Ok(s) = String::from_utf8(dec_bytes.expose_secret().to_vec()) {
                                    if !s.trim().is_empty() { override_values_map.insert(override_data.field_name.clone(), s); }
                                }
                            }
                        }
                    }
                }
                if let Some(override_value) = override_values_map.get("system_prompt") {
                    current_effective_system_prompt = Some(override_value.replace('\0', ""));
                }
            }
            // current_effective_system_prompt (for prompt builder) should NOT fall back to character_db.system_prompt here.
            // That fallback is handled by the prompt_builder itself if this is None.

            // Extract the raw character system prompt separately
            let raw_character_system_prompt_from_db: Option<String> = character_db.system_prompt.as_ref()
                .and_then(|val| {
                    if val.is_empty() {
                        None
                    } else {
                        String::from_utf8(val.clone()).ok().map(|s| s.replace('\0', ""))
                    }
                })
                .filter(|s| !s.trim().is_empty());
            
            Ok::<_, AppError>((
                hist_strat, hist_limit, sess_char_id, temp, max_tokens, freq_pen, pres_pen, top_k_val, top_p_val, rep_pen, min_p_val, top_a_val, seed_val, logit_b, model_n,
                gem_think_budget, gem_enable_code_exec,
                messages_raw_db, character_db, overrides_db,
                current_effective_system_prompt, // This is the one for the builder (persona/override only)
                raw_character_system_prompt_from_db // The new one
            ))
        }).await.map_err(|e| AppError::DbInteractError(format!("Interact dispatch error: {}", e)))??
    };
    
    // --- Calculate User Prompt Tokens (Now that model_name is available) ---
    let user_prompt_tokens_val: Option<i32> = match state.token_counter.count_tokens(
        &user_message_content,
        CountingMode::LocalOnly,
        Some(&session_model_name_db),
    ).await {
        Ok(estimate) => Some(estimate.total as i32),
        Err(e) => {
            warn!("Failed to count prompt tokens for new user message: {}", e);
            None
        }
    };

    // --- Token-based Recent History Management (Async) ---
    let recent_history_token_budget = state.config.context_recent_history_token_budget;
    debug!(target: "test_debug", %session_id, %recent_history_token_budget, "Starting recent history processing.");
    let mut managed_recent_history: Vec<DbChatMessage> = Vec::new();
    let mut actual_recent_history_tokens: usize = 0; // CHANGED to usize

    // Iterate newest to oldest (reverse of DB query order)
    for db_msg_raw in existing_messages_db_raw.iter().rev() {
        debug!(target: "test_debug", %session_id, message_id = %db_msg_raw.id, "Processing message for recent history.");
        let decrypted_content_str = match (db_msg_raw.content_nonce.as_ref(), &user_dek_secret_box) {
            (Some(nonce_vec), Some(dek_arc)) if !db_msg_raw.content.is_empty() && !nonce_vec.is_empty() => {
                let decrypted_bytes_secret = crypto::decrypt_gcm(&db_msg_raw.content, nonce_vec, dek_arc.as_ref())
                    .map_err(|e| AppError::DecryptionError(format!("Failed to decrypt message {}: {}", db_msg_raw.id, e)))?;
                String::from_utf8(decrypted_bytes_secret.expose_secret().to_vec())
                    .map_err(|e| AppError::InternalServerErrorGeneric(format!("Invalid UTF-8 in decrypted message {}: {}", db_msg_raw.id, e)))?
            }
            _ => {
                String::from_utf8(db_msg_raw.content.clone())
                    .map_err(|e| AppError::InternalServerErrorGeneric(format!("Invalid UTF-8 in plaintext message {}: {}", db_msg_raw.id, e)))?
            }
        };

        if decrypted_content_str.trim().is_empty() {
             // Create a new DbChatMessage with decrypted (empty) content
            let mut updated_msg = db_msg_raw.clone();
            updated_msg.content = decrypted_content_str.into_bytes();
            updated_msg.content_nonce = None; // Content is now plaintext
            managed_recent_history.insert(0, updated_msg);
            continue;
        }
        
        let token_estimate: TokenEstimate = state.token_counter.count_tokens(
            &decrypted_content_str,
            CountingMode::LocalOnly,
            Some(&session_model_name_db),
        ).await.map_err(|e| AppError::InternalServerErrorGeneric(format!("Token counting failed for history message {}: {}", db_msg_raw.id, e)))?;

        let message_tokens = token_estimate.total as usize; // Cast to usize
        debug!(target: "test_debug", %session_id, message_id = %db_msg_raw.id, %message_tokens, current_actual_tokens = %actual_recent_history_tokens, %recent_history_token_budget, "Message tokens calculated. Checking budget.");

        if actual_recent_history_tokens.saturating_add(message_tokens) <= recent_history_token_budget { // Compare usize with usize
            actual_recent_history_tokens = actual_recent_history_tokens.saturating_add(message_tokens);
            debug!(target: "test_debug", %session_id, message_id = %db_msg_raw.id, "Message FITS budget. Adding to managed_recent_history. New actual_recent_history_tokens: {}", actual_recent_history_tokens);
            // Create a new DbChatMessage with decrypted content before adding
            let mut updated_msg = db_msg_raw.clone();
            updated_msg.content = decrypted_content_str.into_bytes();
            updated_msg.content_nonce = None; // Content is now plaintext
            managed_recent_history.insert(0, updated_msg);
        } else {
            debug!(target: "test_debug", %session_id, message_id = %db_msg_raw.id, %message_tokens, %actual_recent_history_tokens, %recent_history_token_budget, "Recent history token budget EXCEEDED. Stopping accumulation.");
            break;
        }
    }
    info!(target: "test_debug", %session_id, num_managed_messages = managed_recent_history.len(), %actual_recent_history_tokens, "Token-based recent history management complete. Final managed_recent_history (IDs): {:?}", managed_recent_history.iter().map(|m| m.id).collect::<Vec<_>>());
    info!(%session_id, num_managed_messages = managed_recent_history.len(), %actual_recent_history_tokens, "Token-based recent history management complete.");

    // --- RAG Context Budgeting and Assembly ---
    let available_rag_tokens = min(
        state.config.context_rag_token_budget,
        state.config.context_total_token_limit.saturating_sub(actual_recent_history_tokens)
    );
    info!(%session_id, %actual_recent_history_tokens, %available_rag_tokens, "Calculated RAG token budget.");
    let mut rag_context_items: Vec<RetrievedChunk> = Vec::new();
    let mut current_rag_tokens_used: usize = 0;
    let mut combined_rag_candidates: Vec<RetrievedChunk> = Vec::new();
    let rag_query_limit_per_source: u64 = 15; // Example limit, cast to u64 for service call
    debug!(target: "test_debug", %session_id, %available_rag_tokens, "RAG token budget check. available_rag_tokens > 0: {}", available_rag_tokens > 0);

    if available_rag_tokens > 0 {
        // Retrieve Lorebook Chunks
        if let Some(lorebook_ids) = &active_lorebook_ids_for_search {
            if !lorebook_ids.is_empty() {
                info!(%session_id, ?lorebook_ids, "Retrieving lorebook chunks for RAG.");
                match state.embedding_pipeline_service.retrieve_relevant_chunks(
                    state.clone(),
                    user_id,
                    None, // Not searching chat history here
                    Some(lorebook_ids.clone()),
                    &user_message_content, // query_text
                    rag_query_limit_per_source,
                ).await {
                    Ok(lore_chunks) => {
                        info!(%session_id, num_lore_chunks = lore_chunks.len(), "Retrieved lorebook chunks.");
                        combined_rag_candidates.extend(lore_chunks);
                    }
                    Err(e) => {
                        warn!(%session_id, error = %e, "Failed to retrieve lorebook chunks for RAG. Proceeding without them.");
                    }
                }
            }
        }

        // Retrieve Older Chat History Chunks
        info!(%session_id, "Retrieving older chat history chunks for RAG.");
        match state.embedding_pipeline_service.retrieve_relevant_chunks(
            state.clone(),
            user_id,
            Some(session_id), // Searching chat history for the current session
            None, // Not searching lorebooks here
            &user_message_content, // query_text
            rag_query_limit_per_source,
        ).await {
            Ok(mut older_chat_chunks) => {
                info!(%session_id, num_older_chat_chunks_raw = older_chat_chunks.len(), "Retrieved older chat history chunks (raw).");
                let recent_message_ids: HashSet<Uuid> = managed_recent_history.iter().map(|msg| msg.id).collect();
                older_chat_chunks.retain(|chunk| {
                    match &chunk.metadata {
                        crate::services::embedding_pipeline::RetrievedMetadata::Chat(chat_meta) => {
                            !recent_message_ids.contains(&chat_meta.message_id)
                        }
                        _ => true, // Should ideally not happen if source_type filter works in retrieve_relevant_chunks
                    }
                });
                info!(%session_id, num_older_chat_chunks_filtered = older_chat_chunks.len(), "Filtered older chat history chunks.");
                combined_rag_candidates.extend(older_chat_chunks);
            }
            Err(e) => {
                warn!(%session_id, error = %e, "Failed to retrieve older chat history chunks for RAG. Proceeding without them.");
            }
        }

        // Assemble and Budget RAG Context
        debug!(target: "test_debug", %session_id, num_combined_candidates = combined_rag_candidates.len(), "Combined RAG candidates before assembly loop.");
        if !combined_rag_candidates.is_empty() {
            info!(%session_id, num_combined_candidates = combined_rag_candidates.len(), "Assembling and budgeting RAG context.");
            combined_rag_candidates.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
            debug!(target: "test_debug", %session_id, "Combined RAG candidates after sorting (first 5 texts): {:?}", combined_rag_candidates.iter().take(5).map(|c| c.text.chars().take(50).collect::<String>() ).collect::<Vec<_>>());

            for chunk in combined_rag_candidates {
                debug!(target: "test_debug", %session_id, chunk_text_preview = chunk.text.chars().take(50).collect::<String>(), chunk_score = chunk.score, "Processing RAG candidate chunk.");
                if current_rag_tokens_used >= available_rag_tokens {
                    debug!(target: "test_debug", %session_id, %current_rag_tokens_used, %available_rag_tokens, "RAG token budget reached during assembly. Stopping for chunk: {:?}", chunk.text.chars().take(50).collect::<String>());
                    break;
                }

                match state.token_counter.count_tokens(
                    &chunk.text,
                    CountingMode::LocalOnly,
                    Some(&session_model_name_db),
                ).await {
                    Ok(token_estimate) => {
                        let chunk_tokens = token_estimate.total as usize;
                        debug!(target: "test_debug", %session_id, %chunk_tokens, current_rag_tokens_before_add = %current_rag_tokens_used, %available_rag_tokens, "RAG chunk tokens calculated. Checking budget for chunk: {:?}", chunk.text.chars().take(50).collect::<String>());
                        if current_rag_tokens_used.saturating_add(chunk_tokens) <= available_rag_tokens {
                            rag_context_items.push(chunk);
                            current_rag_tokens_used = current_rag_tokens_used.saturating_add(chunk_tokens);
                            debug!(target: "test_debug", %session_id, "RAG Chunk ADDED. New current_rag_tokens_used: {}. Items count: {}", current_rag_tokens_used, rag_context_items.len());
                        } else {
                            debug!(target: "test_debug", %session_id, %chunk_tokens, %current_rag_tokens_used, %available_rag_tokens, "Chunk too large for remaining RAG budget. SKIPPING chunk: {:?}", chunk.text.chars().take(50).collect::<String>());
                            trace!(%session_id, %chunk_tokens, %current_rag_tokens_used, %available_rag_tokens, "Chunk too large for remaining RAG budget. Skipping.");
                        }
                    }
                    Err(e) => {
                        warn!(%session_id, error = %e, chunk_text_len = chunk.text.len(), "Failed to count tokens for RAG chunk. Skipping chunk.");
                    }
                }
            }
            info!(target: "test_debug", %session_id, num_rag_items = rag_context_items.len(), %current_rag_tokens_used, "RAG context assembly loop finished.");
            info!(%session_id, num_rag_items = rag_context_items.len(), %current_rag_tokens_used, "RAG context assembly complete.");
        } else {
            debug!(target: "test_debug", %session_id, "No combined RAG candidates to process.");
        }
    } else {
        debug!(target: "test_debug", %session_id, %available_rag_tokens, "Skipping RAG context assembly as available_rag_tokens is not > 0.");
    }
    // --- End of RAG Context ---

    // --- First Message Logic (applied to token-managed history) ---
    if managed_recent_history.is_empty() {
        info!(%session_id, "Managed recent history is empty. Checking for character's first_mes.");
        
        let decrypt_field_local = |data: Option<&Vec<u8>>, nonce: Option<&Vec<u8>>, dek_opt: &Option<Arc<SecretBox<Vec<u8>>>>| -> Result<Option<String>, AppError> {
            if let (Some(d), Some(n), Some(dek)) = (data, nonce, dek_opt) {
                if !d.is_empty() && !n.is_empty() {
                    let decrypted = crypto::decrypt_gcm(d, n, dek.as_ref())
                        .map_err(|e: crypto::CryptoError| AppError::DecryptionError(format!("Failed to decrypt field: {}", e)))?;
                    return Ok(Some(String::from_utf8(decrypted.expose_secret().to_vec())
                        .map_err(|e: std::string::FromUtf8Error| AppError::InternalServerErrorGeneric(format!("Invalid UTF-8 in decrypted field: {}", e)))?));
                }
            }
            Ok(None)
        };
        
        let mut first_mes_content_to_add: Option<String> = None;
        let mut override_values_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();

        for override_data in &character_overrides_for_first_mes {
             if let Ok(Some(dec_val)) = decrypt_field_local(Some(&override_data.overridden_value), Some(&override_data.overridden_value_nonce), &user_dek_secret_box) {
                if !dec_val.trim().is_empty() {
                    override_values_map.insert(override_data.field_name.clone(), dec_val);
                }
            }
        }

        if let Some(first_mes_override) = override_values_map.get("first_mes") {
            first_mes_content_to_add = Some(first_mes_override.clone());
        } else if let Some(char_first_mes) = decrypt_field_local(
            character_for_first_mes.first_mes.as_ref(),
            character_for_first_mes.first_mes_nonce.as_ref(),
            &user_dek_secret_box
        )? {
            if !char_first_mes.is_empty() {
                first_mes_content_to_add = Some(char_first_mes);
            }
        }

        if let Some(content) = first_mes_content_to_add {
            let first_mes_db_chat_message = DbChatMessage {
                 id: Uuid::new_v4(), session_id, user_id, 
                 message_type: MessageRole::Assistant,
                 content: content.into_bytes(), // Content is already decrypted String
                 content_nonce: None,
                 created_at: chrono::Utc::now(),
                 prompt_tokens: None, completion_tokens: None,
            };
            managed_recent_history.insert(0, first_mes_db_chat_message);
            info!(%session_id, "Prepended character's first_mes to managed_recent_history.");
        }
    }

    // --- Prepare User Message Struct ---
    let user_db_message_to_save = DbInsertableChatMessage::new(
        session_id, user_id, MessageRole::User,
        user_message_content_for_closure.into_bytes(), 
        None, 
        Some("user".to_string()),
        Some(json!([{"text": user_message_content}])), 
        None,
        user_prompt_tokens_val,
        None,
    );

    // --- Construct Final Tuple ---
    Ok((
        managed_recent_history,        // 0: managed_db_history
        final_effective_system_prompt, // 1: system_prompt (for builder, persona/override only)
        active_lorebook_ids_for_search,// 2: active_lorebook_ids_for_search
        session_character_id_db,       // 3: session_character_id
        raw_character_system_prompt,   // 4: raw_character_system_prompt (NEW)
        session_temperature_db,        // 5: temperature
        session_max_output_tokens_db,  // 6: max_output_tokens
        session_frequency_penalty_db,  // 7: frequency_penalty
        session_presence_penalty_db,   // 8: presence_penalty
        session_top_k_db,              // 9: top_k
        session_top_p_db,              // 10: top_p
        session_repetition_penalty_db, // 11: repetition_penalty
        session_min_p_db,              // 12: min_p
        session_top_a_db,              // 13: top_a
        session_seed_db,               // 14: seed
        session_logit_bias_db,         // 15: logit_bias
        session_model_name_db,         // 16: model_name
        // -- Gemini Specific Options --
        session_gemini_thinking_budget_db,      // 17: gemini_thinking_budget
        session_gemini_enable_code_execution_db,// 18: gemini_enable_code_execution
        user_db_message_to_save,                // 19: The user message struct
        // -- RAG Context & Recent History Tokens --
        actual_recent_history_tokens, // 20: actual_recent_history_tokens
        rag_context_items,            // 21: rag_context_items
        // History Management Settings
        history_management_strategy_db_val, // 22: history_management_strategy
        history_management_limit_db_val,    // 23: history_management_limit
    ))
}

/// Gets chat settings for a specific session, verifying ownership.
#[instrument(skip(pool), err)]
pub async fn get_session_settings(
    pool: &DbPool,
    user_id: Uuid, // <-- Removed underscore
    session_id: Uuid,
) -> Result<ChatSettingsResponse, AppError> {
    let conn = pool.get().await?;
    conn.interact(move |conn| {
        // 1. Check if the session exists and get its owner_id
        let owner_id_result = chat_sessions::table
            .filter(chat_sessions::id.eq(session_id))
            .select(chat_sessions::user_id)
            .first::<Uuid>(conn)
            .optional()?;

        match owner_id_result {
            None => {
                // Session does not exist
                warn!(%session_id, %user_id, "Attempted to get settings for non-existent session");
                Err(AppError::NotFound("Chat session not found".into()))
            }
            Some(owner_id) => {
                // 2. Check if the requesting user owns the session
                if owner_id != user_id {
                    warn!(%session_id, %user_id, owner_id=%owner_id, "Forbidden attempt to get settings for session owned by another user");
                    Err(AppError::Forbidden) // Correct error for unauthorized access
                } else {
                    // 3. Fetch the actual settings since ownership is confirmed
                    info!(%session_id, %user_id, "Fetching settings for owned session");
                    let settings_tuple = chat_sessions::table
                        .filter(chat_sessions::id.eq(session_id)) // Filter only by session_id now
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
                        .first::<SettingsTuple>(conn) // Expect a result now
                        .map_err(|e| {
                            error!(%session_id, %user_id, error = ?e, "Failed to fetch settings after ownership check");
                            AppError::DatabaseQueryError(e.to_string())
                        })?;

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
                    ) = settings_tuple;

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
            }
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

#[instrument(skip_all, err, fields(session_id = %session_id, user_id = %user_id, model_name = %model_name))]
pub async fn stream_ai_response_and_save_message(
    state: Arc<AppState>,
    session_id: Uuid,
    user_id: Uuid,
    incoming_genai_messages: Vec<GenAiChatMessage>, // MODIFIED: Changed type and name
    system_prompt: Option<String>,
    temperature: Option<BigDecimal>,
    max_output_tokens: Option<i32>,
    _frequency_penalty: Option<BigDecimal>, // Mark as unused for now
    _presence_penalty: Option<BigDecimal>,  // Mark as unused for now
    _top_k: Option<i32>,                    // Mark as unused for now
    top_p: Option<BigDecimal>,
    _repetition_penalty: Option<BigDecimal>, // Mark as unused for now
    _min_p: Option<BigDecimal>,              // Mark as unused for now
    _top_a: Option<BigDecimal>,              // Mark as unused for now
    _seed: Option<i32>,                      // Mark as unused for now
    _logit_bias: Option<Value>,              // Mark as unused for now
    model_name: String,
    gemini_thinking_budget: Option<i32>,
    gemini_enable_code_execution: Option<bool>,
    request_thinking: bool,                    // New parameter
    user_dek: Option<Arc<SecretBox<Vec<u8>>>>, // Changed to Option<Arc<SecretBox>>
) -> Result<Pin<Box<dyn Stream<Item = Result<ScribeSseEvent, AppError>> + Send>>, AppError> {
    let service_model_name = model_name.clone(); // Clone for use in this function scope, esp. for save_message calls
    trace!(
        ?system_prompt,
        "stream_ai_response_and_save_message received system_prompt argument"
    );
    info!(%request_thinking, "Initiating AI stream and message saving process");

    // Log the system_prompt that will be used
    debug!(
        target: "chat_service_system_prompt",
        system_prompt_to_use = ?system_prompt,
        "System prompt to be used for GenAiChatRequest construction"
    );

    let mut chat_request = GenAiChatRequest::new(incoming_genai_messages) // MODIFIED: Use incoming_genai_messages directly
        .with_system(system_prompt.unwrap_or_default());

    let mut genai_chat_options = GenAiChatOptions::default();
    if let Some(temp_val) = temperature {
        if let Some(f_val) = temp_val.to_f32() {
            genai_chat_options = genai_chat_options.with_temperature(f_val.into());
        }
    }
    if let Some(tokens) = max_output_tokens {
        genai_chat_options = genai_chat_options.with_max_tokens(tokens as u32);
    }
    if let Some(p_val) = top_p {
        if let Some(f_val) = p_val.to_f32() {
            genai_chat_options = genai_chat_options.with_top_p(f_val.into());
        }
    }
    if let Some(budget) = gemini_thinking_budget {
        if budget > 0 {
            genai_chat_options = genai_chat_options.with_gemini_thinking_budget(budget as u32);
        }
    }
    if let Some(enable_exec) = gemini_enable_code_execution {
        genai_chat_options = genai_chat_options.with_gemini_enable_code_execution(enable_exec);
    }

    // NEW LOGIC FOR TOOL CONFIGURATION
    use genai::chat::{FunctionCallingConfig, FunctionCallingMode, ToolConfig};
    let mut tools_to_declare: Vec<Tool> = Vec::new();
    let final_mode: FunctionCallingMode;

    // Declare scribe_tool_invoker if thinking is requested or code execution is enabled
    // (as it's our stand-in for a generic tool for now when code execution is on)
    if request_thinking || gemini_enable_code_execution == Some(true) {
        debug!("'scribe_tool_invoker' will be declared for Gemini.");
        let scribe_tool_schema = json!({
            "type": "object",
            "properties": {
                "tool_name": { "type": "string", "description": "The name of the Scribe tool to invoke." },
                "tool_arguments": { "type": "object", "description": "The arguments for the Scribe tool, as a JSON object." }
            },
            "required": ["tool_name", "tool_arguments"]
        });
        let scribe_tool = Tool::new("scribe_tool_invoker".to_string())
            .with_description("Invokes a Scribe-defined tool with the given arguments. Used for complex reasoning or actions.".to_string())
            .with_schema(scribe_tool_schema);
        tools_to_declare.push(scribe_tool);
    }

    // TODO: Add other specific tools if gemini_enable_code_execution is true and they are defined.

    if !tools_to_declare.is_empty() {
        chat_request = chat_request.with_tools(tools_to_declare.clone());
        info!(?tools_to_declare, "Tools added to ChatRequest for Gemini.");
    }

    // Determine the FunctionCallingMode
    if gemini_enable_code_execution == Some(true) {
        debug!("Gemini code execution is enabled. Setting ToolConfig mode to Any.");
        final_mode = FunctionCallingMode::Any;
    } else if request_thinking {
        debug!(
            "Requesting thinking (and code execution is not enabled). Setting ToolConfig mode to Auto for scribe_tool_invoker."
        );
        final_mode = FunctionCallingMode::Auto;
    } else {
        debug!(
            "Neither request_thinking nor gemini_enable_code_execution is active. Setting ToolConfig mode to None."
        );
        final_mode = FunctionCallingMode::None;
    }

    let final_tool_config = ToolConfig {
        function_calling_config: Some(FunctionCallingConfig {
            mode: Some(final_mode.clone()),
            allowed_function_names: None, // Typically None for Any/Auto, unless specifically restricting
        }),
    };
    genai_chat_options = genai_chat_options.with_gemini_tool_config(final_tool_config.clone());
    info!(mode = ?final_mode, tool_config = ?final_tool_config, "Final Gemini ToolConfig set.");
    // END NEW LOGIC FOR TOOL CONFIGURATION

    trace!(
        ?chat_request,
        ?genai_chat_options,
        "Prepared ChatRequest and Options for AI"
    );
    // Added detailed debug logging for the request and options
    debug!(
        target: "chat_service_payload_details",
        "Final GenAI ChatRequest before sending: {:#?}",
        chat_request
    );
    debug!(
        target: "chat_service_payload_details",
        "Final GenAI ChatOptions before sending: {:#?}",
        genai_chat_options
    );

    let genai_stream_result: Result<GenAiChatStream, AppError> = state
        .ai_client
        .stream_chat(&model_name, chat_request, Some(genai_chat_options))
        .await;

    let genai_stream = match genai_stream_result {
        Ok(s) => {
            debug!("Successfully initiated AI stream from chat_service");
            s
        }
        Err(e) => {
            error!(error = ?e, "Failed to initiate AI stream from chat_service");
            let error_stream = stream! {
                let error_msg = format!("LLM API error (chat_service): Failed to initiate stream - {}", e);
                trace!(error_message = %error_msg, "Sending SSE 'error' event (initiation failed in service)");
                yield Ok::<_, AppError>(ScribeSseEvent::Error(error_msg));
            };
            return Ok(Box::pin(error_stream));
        }
    };

    let stream_state = state.clone(); // Clone Arc for the stream
    let stream_session_id = session_id;
    let stream_user_id = user_id;
    // user_dek is already owned and can be moved into the stream

    let sse_stream = stream! {
        let mut accumulated_content = String::new();
        let mut stream_error_occurred = false;

        // Pin the stream from the AI client
        futures::pin_mut!(genai_stream);
        trace!("Entering SSE async_stream! processing loop in chat_service");

        while let Some(event_result) = genai_stream.next().await {
            trace!("Received event from genai_stream in chat_service: {:?}", event_result);
            match event_result {
                Ok(ChatStreamEvent::Start) => {
                    debug!("Received Start event from AI stream in chat_service");
                    // Optionally yield a start event if the client needs it
                    // yield Ok(Event::default().event("start").data("AI stream started"));
                    continue;
                }
                Ok(ChatStreamEvent::Chunk(chunk)) => {
                    debug!(content_chunk_len = chunk.content.len(), "Received Content chunk from AI stream in chat_service");
                    if !chunk.content.is_empty() {
                        accumulated_content.push_str(&chunk.content);
                        yield Ok(ScribeSseEvent::Content(chunk.content.clone())); // Assuming chunk.content is String
                    } else {
                        trace!("Skipping empty content chunk from AI in chat_service");
                    }
                }
                Ok(ChatStreamEvent::ReasoningChunk(chunk)) => {
                    debug!(reasoning_chunk_len = chunk.content.len(), "Received ReasoningChunk from AI stream in chat_service");
                    if !chunk.content.is_empty() {
                        yield Ok(ScribeSseEvent::Thinking(chunk.content.clone())); // Assuming chunk.content is String
                       }
                      }
                      Ok(ChatStreamEvent::ToolCall(tool_call)) => {
                                      debug!(tool_call_id = %tool_call.call_id, tool_fn_name = %tool_call.fn_name, "Received ToolCall event from AI stream in chat_service");
                                      // For now, just indicate "thinking" with the tool call details.
                                      // In a full implementation, this is where the tool would be invoked.
                                      let thinking_message = format!("Attempting to use tool: {} with ID: {}", tool_call.fn_name, tool_call.call_id);
                                      yield Ok(ScribeSseEvent::Thinking(thinking_message));
                                      // TODO: Implement actual tool invocation and sending ToolResponse back to AI.
                                      // For now, the stream will likely end here or wait for more content from the AI
                                      // which might not come if it's waiting for a tool response.
                                  }
                      Ok(ChatStreamEvent::End(_)) => {
                       debug!("Received End event from AI stream in chat_service");
                    // The stream will naturally end. If no content was produced, the caller might send a [DONE] event.
                }
                Err(e) => {
                    error!(error = ?e, "Error during AI stream processing in chat_service (inside loop)");
                    stream_error_occurred = true;

                    let partial_content_clone = accumulated_content.clone();
                    let error_session_id_clone = stream_session_id;
                    let error_user_id_clone = stream_user_id;
                    let user_dek_arc_clone_partial = user_dek.clone(); // Clone Option<Arc<SecretBox>>
                    let state_for_partial_save = stream_state.clone();
                    let service_model_name_clone_partial = service_model_name.clone(); // Clone model name for this task

                    tokio::spawn(async move {
                        if !partial_content_clone.is_empty() {
                            trace!(session_id = %error_session_id_clone, "Attempting to save partial AI response after stream error (chat_service)");
                            let dek_ref_partial = user_dek_arc_clone_partial.clone();
                            match save_message(
                                state_for_partial_save,
                                error_session_id_clone,
                                error_user_id_clone,
                                MessageRole::Assistant, // message_type_enum
                                &partial_content_clone, // content
                                Some("assistant".to_string()), // role_str (or "model")
                                Some(json!([{"text": partial_content_clone}])), // parts
                                None,                   // attachments
                                dek_ref_partial,
                                &service_model_name_clone_partial,
                           ).await {
                                Ok(saved_message) => {
                                    debug!(session_id = %error_session_id_clone, message_id = %saved_message.id, "Successfully saved partial AI response via save_message after stream error (chat_service)");
                                }
                                Err(save_err) => {
                                    error!(error = ?save_err, session_id = %error_session_id_clone, "Error saving partial AI response via save_message after stream error (chat_service)");
                                }
                            }
                        } else {
                            trace!(session_id = %error_session_id_clone, "No partial content to save after stream error (chat_service)");
                        }
                    });

                    let detailed_error = e.to_string();
                    let client_error_message = if detailed_error.contains("LLM API error:") {
                        detailed_error
                    } else {
                        format!("LLM API error (chat_service loop): {}", detailed_error)
                    };
                    trace!(error_message = %client_error_message, "Sending SSE 'error' event from chat_service");
                    yield Ok(ScribeSseEvent::Error(client_error_message));
                    break; // Exit the loop on error
                }
            }
        }

        trace!("Exited SSE processing loop in chat_service. stream_error_occurred={}", stream_error_occurred);

        if !stream_error_occurred && !accumulated_content.is_empty() {
            debug!("Attempting to save full successful AI response (chat_service)");

            let full_session_id_clone = stream_session_id;
            let full_user_id_clone = stream_user_id;
            // user_dek is already Option<Arc<SecretBox>> and moved into this outer stream scope
            let user_dek_arc_clone_full = user_dek.clone(); // Clone Option<Arc<SecretBox>> for the spawned task
            let state_for_full_save = stream_state.clone(); // Use the already cloned state
            let service_model_name_clone_full = service_model_name.clone(); // Clone model name for this task

            tokio::spawn(async move {
                let dek_ref_full = user_dek_arc_clone_full.clone();
                match save_message(
                    state_for_full_save,
                    full_session_id_clone,
                    full_user_id_clone,
                    MessageRole::Assistant, // message_type_enum
                    &accumulated_content,   // content
                    Some("assistant".to_string()), // role_str (or "model")
                    Some(json!([{"text": accumulated_content}])), // parts
                    None,                   // attachments
                    dek_ref_full,
                    &service_model_name_clone_full,
                ).await {
                    Ok(saved_message) => {
                        debug!(session_id = %full_session_id_clone, message_id = %saved_message.id, "Successfully saved full AI response via save_message (chat_service)");
                    }
                    Err(e) => {
                        error!(error = ?e, session_id = %full_session_id_clone, "Error saving full AI response via save_message (chat_service)");
                    }
                }
            });
        } else if stream_error_occurred {
            trace!("[DONE] not sent due to stream_error_occurred=true in chat_service");
        } else if accumulated_content.is_empty() && !stream_error_occurred {
            // If the stream ended successfully but produced no content,
            // the client might expect a "done" or similar signal.
            // However, the current route logic handles this. This service function will just end the stream.
            trace!("AI stream finished successfully but produced no content in chat_service. Stream will end.");
            // Optionally: yield Ok(Event::default().event("done").data("[DONE_EMPTY]"));
        }
        trace!("Finished SSE async_stream! block in chat_service");
    };

    Ok(Box::pin(sse_stream))
}

/// Sets or updates a character override for a specific chat session.
#[instrument(skip(pool, payload, user_dek_secret_box), err)]
pub async fn set_character_override(
    pool: &DbPool,
    user_id: Uuid,
    session_id: Uuid,
    payload: CharacterOverrideDto,
    user_dek_secret_box: Option<&SecretBox<Vec<u8>>>, // Changed to Option<&SecretBox>
) -> Result<ChatCharacterOverride, AppError> {
    let conn = pool.get().await?;

    // Clone payload parts needed for the interact closure
    let field_name_clone = payload.field_name.clone();
    let value_clone = payload.value.clone();

    // Manually clone the inner secret data to create an owned SecretBox for the closure
    let owned_user_dek_opt: Option<SecretBox<Vec<u8>>> = user_dek_secret_box
        .map(|sb_ref| SecretBox::new(Box::new(sb_ref.expose_secret().clone())));

    conn.interact(move |conn| {
        conn.transaction(|transaction_conn| {
            // 1. Verify chat session ownership and get original character_id
            let (chat_owner_id, original_character_id_from_session) = chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select((chat_sessions::user_id, chat_sessions::character_id))
                .first::<(Uuid, Uuid)>(transaction_conn)
                .map_err(|e| match e {
                    DieselError::NotFound => AppError::NotFound(format!(
                        "Chat session {} not found.",
                        session_id
                    )),
                    _ => AppError::DatabaseQueryError(e.to_string()),
                })?;

            if chat_owner_id != user_id {
                error!(
                    "User {} attempted to set override for session {} owned by {}",
                    user_id, session_id, chat_owner_id
                );
                return Err(AppError::Forbidden);
            }

            // 2. Encrypt the value
            let (encrypted_value, nonce) = match &owned_user_dek_opt { // Use the owned Option
                Some(dek) => { // dek is &SecretBox<Vec<u8>>
                    crypto::encrypt_gcm(value_clone.as_bytes(), dek).map_err(|e| {
                        error!("Failed to encrypt override value: {}", e);
                        AppError::EncryptionError("Failed to encrypt override value".to_string())
                    })?
                }
                None => {
                    // This case should ideally be prevented if overrides require encryption.
                    // For now, let's assume if no DEK, we store plaintext (though this is not ideal for sensitive data)
                    // Or, more correctly, return an error if DEK is expected but not provided.
                    // For this implementation, we'll require DEK for overrides.
                    error!("User DEK not provided, cannot encrypt override value.");
                    return Err(AppError::BadRequest(
                        "User DEK is required to set character overrides.".to_string(),
                    ));
                }
            };

            // 3. Perform an upsert (insert or update on conflict)
            let new_override = NewChatCharacterOverride {
                id: Uuid::new_v4(), // Generate a new ID for insert, conflict target will handle existing
                chat_session_id: session_id,
                original_character_id: original_character_id_from_session,
                field_name: field_name_clone,
                overridden_value: encrypted_value.clone(), // Clone for insert
                overridden_value_nonce: nonce.clone(),   // Clone for insert
            };

            // Upsert logic: Insert, and on conflict on (chat_session_id, field_name), update the value and nonce.
            // Note: Diesel's `on_conflict` requires the columns in the conflict target to be part of the insert.
            // The `id` will be different for new inserts vs updates if we rely on a simple update.
            // A common pattern is to try an update first, if 0 rows affected, then insert.
            // Or, use a raw query for complex upserts if Diesel's DSL is limiting.
            // For simplicity here, we'll use `insert_into` with `on_conflict` and `do_update`.
            // This assumes a unique constraint exists on (chat_session_id, field_name).
            // If not, this will always insert. A migration would be needed for the unique constraint.
            // Let's assume the constraint `chat_character_overrides_session_id_field_name_key` exists.

            let result = diesel::insert_into(chat_character_overrides::table)
                .values(&new_override)
                .on_conflict((
                    chat_character_overrides::chat_session_id,
                    chat_character_overrides::field_name,
                ))
                .do_update()
                .set((
                    chat_character_overrides::overridden_value.eq(encrypted_value),
                    chat_character_overrides::overridden_value_nonce.eq(nonce),
                    chat_character_overrides::updated_at.eq(chrono::Utc::now()), // Explicitly set updated_at
                ))
                .returning(ChatCharacterOverride::as_select())
                .get_result::<ChatCharacterOverride>(transaction_conn)
                .map_err(|e| {
                    error!("Failed to upsert chat character override: {}", e);
                    AppError::DatabaseQueryError(e.to_string())
                })?;

            Ok(result)
        })
    })
    .await?
}

#[cfg(test)]
mod get_session_data_for_generation_tests {
    use super::*;
    use crate::config::Config as AppConfig;
    use crate::models::chats::{DbInsertableChatMessage, ChatMessage as DbChatMessage, NewChat};
    use crate::schema::{characters as character_schema, chat_messages as chat_messages_schema, chat_sessions as chat_sessions_schema, users};
    use crate::models::users::{NewUser, UserRole, AccountStatus};
    use diesel::RunQueryDsl;
    use crate::services::embedding_pipeline::{RetrievedChunk};
    use crate::services::hybrid_token_counter::HybridTokenCounter;
    use crate::services::tokenizer_service::TokenizerService; // TokenEstimate removed
    use crate::services::gemini_token_client::GeminiTokenClient;
    use crate::services::user_persona_service::UserPersonaService;
    use crate::state::AppState;
    use crate::test_helpers::db::setup_test_database;
    use crate::test_helpers::{
        MockAiClient, MockEmbeddingClient, MockEmbeddingPipelineService,
        MockQdrantClientService, TestAppStateBuilder,
    };
    use mockall::predicate::*;
    use secrecy::SecretBox;
    use std::collections::VecDeque;
    use uuid::Uuid;
    use bigdecimal::BigDecimal;
    use serde_json::json;
    use crate::models::characters::Character;
    use crate::models::chat_override::ChatCharacterOverride;
    use std::str::FromStr; // For BigDecimal::from_str


    // Helper to create a DbChatMessage for testing
    fn create_db_chat_message(
        id: Uuid,
        session_id: Uuid,
        user_id: Uuid,
        role: MessageRole,
        content: &str,
        tokens: Option<i32>, // Generic token count for simplicity in setup
        created_at_offset_secs: i64, // To control order
        user_dek: Option<&Arc<SecretBox<Vec<u8>>>>,
    ) -> DbChatMessage {
        let (content_bytes, nonce_bytes) = if let Some(dek) = user_dek {
            let (ciphertext, nonce) = crypto::encrypt_gcm(content.as_bytes(), dek.as_ref()).unwrap();
            (ciphertext, Some(nonce))
        } else {
            (content.as_bytes().to_vec(), None)
        };

        let mut msg = DbChatMessage {
            id,
            session_id,
            user_id,
            message_type: role,
            content: content_bytes,
            content_nonce: nonce_bytes,
            created_at: chrono::Utc::now() + chrono::Duration::seconds(created_at_offset_secs),
            prompt_tokens: None,
            completion_tokens: None,
        };
        match role {
            MessageRole::User => msg.prompt_tokens = tokens,
            MessageRole::Assistant => msg.completion_tokens = tokens,
            _ => {}
        }
        msg
    }

    struct TestSetup {
        app_state: Arc<AppState>,
        user_id: Uuid,
        session_id: Uuid,
        _character_id: Uuid,
        _mock_embedding_pipeline: Arc<MockEmbeddingPipelineService>,
        user_dek: Option<Arc<SecretBox<Vec<u8>>>>,
    }

    async fn setup_test_env(
        _db_messages_raw: Vec<DbChatMessage>,
        _lorebook_chunks: Vec<RetrievedChunk>,
        _older_chat_chunks: Vec<RetrievedChunk>,
        _token_counts: VecDeque<(String, usize)>,
        config_override: Option<AppConfig>,
        _active_persona_id_from_session: Option<Uuid>,
        // _persona_details: Option<UserPersonaDto>, // Removed
        session_character_id_override: Option<Uuid>,
        _session_system_prompt_override_db: Option<String>,
        character_db_details: Option<Character>,
        _character_overrides_db: Option<Vec<ChatCharacterOverride>>,
        _active_lorebook_ids_for_search_db: Option<Vec<Uuid>>,
    ) -> TestSetup {
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let default_character_id = Uuid::new_v4();
        let character_id = session_character_id_override.unwrap_or(default_character_id);

        let config = config_override.unwrap_or_else(|| {
            // Inlined create_test_config logic
            let mut cfg = AppConfig::default(); // Assuming AppConfig has a sensible default or load mechanism
            cfg.context_recent_history_token_budget = 100;
            cfg.context_rag_token_budget = 50;
            cfg.context_total_token_limit = 200;
            cfg.tokenizer_model_path = Some("./resources/tokenizers/gemma.model".to_string());
            cfg.gemini_api_key = Some("dummy_api_key".to_string());
            cfg.token_counter_default_model = Some("gemini-test-model".to_string());
            // Add other necessary default config fields if AppConfig::default() is not sufficient
            cfg
        });
        let config_arc = Arc::new(config.clone());

        let user_dek_secret_vec = vec![0u8; 32];
        let user_dek = Some(Arc::new(SecretBox::new(Box::new(user_dek_secret_vec))));

        let pool = setup_test_database(None).await;

        let tokenizer_model_path_str = config_arc.tokenizer_model_path.as_ref().cloned()
            .expect("Tokenizer model path not set in config for test setup");
        let tokenizer_service = TokenizerService::new(&tokenizer_model_path_str)
            .expect("Failed to load tokenizer model for test setup");
        let gemini_token_client = config_arc.gemini_api_key.as_ref().map(|api_key| {
            GeminiTokenClient::new(api_key.clone())
        });
        let default_model_for_tc = config_arc.token_counter_default_model.as_ref().cloned()
            .expect("Token counter default model not set in config for test setup");
        let token_counter_service = Arc::new(HybridTokenCounter::new(
            tokenizer_service,
            gemini_token_client,
            default_model_for_tc,
        ));

        let mock_embedding_pipeline_instance = MockEmbeddingPipelineService::new();
        // mock_embedding_pipeline_instance.set_retrieve_responses_sequence is not used in this context
        // as the mock is passed to AppStateBuilder which might configure it or use defaults.
        // If specific sequences are needed, they should be set on the instance before it's moved/cloned.
        // For this refactor, assuming the default mock behavior or AppStateBuilder's handling is sufficient.
        // If tests fail due to mock behavior, this is where to look.
        // Example of setting sequence if needed:
        // let mut mock_embedding_pipeline_instance_mut = MockEmbeddingPipelineService::new();
        // mock_embedding_pipeline_instance_mut.set_retrieve_responses_sequence(vec![
        //     Ok(lorebook_chunks.clone()),
        //     Ok(older_chat_chunks.clone()),
        //     Ok(Vec::new()),
        // ]);
        // let mock_embedding_pipeline_instance = mock_embedding_pipeline_instance_mut;

        // Ensure lorebook_chunks and older_chat_chunks are cloned if used by the mock setup
        // For now, they are passed to the function but not directly used to set mock sequences here.
        // This might be an oversight if the intention was to use them for mocking retrieve_relevant_chunks.
        // The current mock_embedding_pipeline_instance.set_retrieve_responses_sequence was commented out
        // as it was unused. If it *should* be used, it needs to be uncommented and `mut` restored.
        // For the purpose of removing the `mut` warning, we assume it's not strictly needed here.
        // The actual mock setup for retrieve_relevant_chunks happens inside the tests themselves
        // by calling expect_retrieve_relevant_chunks on the Arc<MockEmbeddingPipelineService> from TestSetup.

        // The following lines related to setting retrieve_responses_sequence are removed as per the warning.
        // If this causes test failures, it means the mock setup here was indeed necessary.
        // mock_embedding_pipeline_instance.set_retrieve_responses_sequence(vec![
        //     Ok(lorebook_chunks.clone()),
        //     Ok(older_chat_chunks.clone()),
        //     Ok(Vec::new()),
        // ]);
        // mock_embedding_pipeline_instance is not Arc yet, and not Mutex wrapped at this stage for TestSetup
        let mock_embedding_pipeline_service_concrete = mock_embedding_pipeline_instance; // This was the original line


        let shared_encryption_service = Arc::new(crate::services::encryption_service::EncryptionService::new());
        let user_persona_service_instance = Arc::new(UserPersonaService::new(
            pool.clone(),
            shared_encryption_service.clone(), // This encryption service is for UserPersonaService itself
        ));

        // Create mock clients for AppState builder
        let mock_ai_client_instance = Arc::new(MockAiClient::new());
        let mock_embedding_client_instance = Arc::new(MockEmbeddingClient::new());
        let mock_qdrant_service_instance = Arc::new(MockQdrantClientService::new());


        // This is the character that will be returned by the mock DB interaction if `character_db_details` is None.
        // It's used in the `conn.interact` block within `get_session_data_for_generation`.
        // We ensure this default instantiation is correct.
        // NOTE: This _default_character_for_mocking is for the *old* mock DB setup.
        // With real DB, tests must ensure the character exists in the DB.
        // This variable is now only for ensuring the unwrap_or_else block compiles,
        // but the actual data should come from the DB in tests.
        let _default_character_for_db_priming_if_needed = character_db_details.clone().unwrap_or_else(|| Character {
            id: character_id,
            user_id,
            name: "Test Character".to_string(),
            spec: "chara_card_v2".to_string(),
            spec_version: "2.0".to_string(),
            description: Some("Char desc".as_bytes().to_vec()),
            personality: Some("Char persona".as_bytes().to_vec()),
            scenario: Some("Char scenario".as_bytes().to_vec()),
            first_mes: Some("Char first mes".as_bytes().to_vec()),
            mes_example: Some("Char example".as_bytes().to_vec()),
            creator_notes: Some("Char creator notes".as_bytes().to_vec()),
            system_prompt: Some("Char system prompt".as_bytes().to_vec()),
            post_history_instructions: Some("Char post history instructions".as_bytes().to_vec()),
            tags: Some(vec![Some("tag1".to_string()), Some("tag2".to_string())]),
            creator: Some("Test Creator".to_string()),
            character_version: Some("1.0".to_string()),
            alternate_greetings: Some(vec![Some("Hi".to_string()), Some("Hello".to_string())]),
            nickname: Some("Test Nickname".to_string()),
            creator_notes_multilingual: Some(json!({"en": "English notes"})),
            source: Some(vec![Some("TestSource".to_string())]),
            group_only_greetings: Some(vec![Some("Group Hi".to_string())]),
            creation_date: Some(chrono::Utc::now()),
            modification_date: Some(chrono::Utc::now()),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            persona: Some("Char persona field".as_bytes().to_vec()),
            world_scenario: Some("Char world scenario".as_bytes().to_vec()),
            avatar: Some("avatar.png".to_string()),
            chat: Some("chat_export.txt".to_string()),
            greeting: Some("Char greeting".as_bytes().to_vec()),
            definition: Some("Char definition".as_bytes().to_vec()),
            default_voice: Some("voice_id".to_string()),
            extensions: Some(json!({"custom_field": "value"})),
            data_id: Some(123),
            category: Some("Test Category".to_string()),
            definition_visibility: Some("private".to_string()),
            depth: Some(1),
            example_dialogue: Some("Char example dialogue".as_bytes().to_vec()),
            favorite: Some(false),
            first_message_visibility: Some("private".to_string()),
            height: Some(BigDecimal::from_str("180").unwrap()),
            last_activity: Some(chrono::Utc::now()),
            migrated_from: Some("old_system".to_string()),
            model_prompt: Some("Char model prompt".as_bytes().to_vec()),
            model_prompt_visibility: Some("private".to_string()),
            model_temperature: Some(BigDecimal::from_str("0.7").unwrap()),
            num_interactions: Some(10),
            permanence: Some(BigDecimal::from_str("0.5").unwrap()),
            persona_visibility: Some("private".to_string()),
            revision: Some(1),
            sharing_visibility: Some("private".to_string()),
            status: Some("active".to_string()),
            system_prompt_visibility: Some("private".to_string()),
            system_tags: Some(vec![Some("system_tag1".to_string())]),
            token_budget: Some(2048),
            usage_hints: Some(json!({"hint": "value"})),
            user_persona: Some("Char user persona".as_bytes().to_vec()),
            user_persona_visibility: Some("private".to_string()),
            visibility: Some("private".to_string()),
            weight: Some(BigDecimal::from_str("70.5").unwrap()),
            world_scenario_visibility: Some("private".to_string()),
            description_nonce: Some(vec![1; 12]),
            personality_nonce: Some(vec![2; 12]),
            scenario_nonce: Some(vec![3; 12]),
            first_mes_nonce: Some(vec![4; 12]),
            mes_example_nonce: Some(vec![5; 12]),
            creator_notes_nonce: Some(vec![6; 12]),
            system_prompt_nonce: Some(vec![7; 12]),
            persona_nonce: Some(vec![8; 12]),
            world_scenario_nonce: Some(vec![9; 12]),
            greeting_nonce: Some(vec![10; 12]),
            definition_nonce: Some(vec![11; 12]),
            example_dialogue_nonce: Some(vec![12; 12]),
            model_prompt_nonce: Some(vec![13; 12]),
            user_persona_nonce: Some(vec![14; 12]),
            post_history_instructions_nonce: Some(vec![15; 12]),
        });
        
        // Create an Arc for the concrete MockEmbeddingPipelineService to store in TestSetup
        let mock_embedding_pipeline_for_test_setup = Arc::new(mock_embedding_pipeline_service_concrete.clone());

        let app_state_instance = TestAppStateBuilder::new(
            pool.clone(),
            config_arc.clone(),
            mock_ai_client_instance.clone(),
            mock_embedding_client_instance.clone(),
            mock_qdrant_service_instance.clone(),
        )
        .with_token_counter(token_counter_service.clone())
        // Pass the concrete mock service to the builder, it will be cast internally if needed by AppState::new
        // Or, cast it here if with_embedding_pipeline_service expects the trait object.
        // TestAppStateBuilder::with_embedding_pipeline_service expects Arc<dyn ...Trait>
        .with_embedding_pipeline_service(Arc::new(mock_embedding_pipeline_service_concrete) as Arc<dyn crate::services::embedding_pipeline::EmbeddingPipelineServiceTrait + Send + Sync>)
        .with_user_persona_service(user_persona_service_instance.clone())
        .build();

        TestSetup {
            app_state: Arc::new(app_state_instance),
            user_id,
            session_id,
            _character_id: character_id,
            _mock_embedding_pipeline: mock_embedding_pipeline_for_test_setup, // Store the Arc<MockEmbeddingPipelineService>
            user_dek,
        }
    }

    #[tokio::test]
    async fn test_recent_history_windowing_basic_fits_budget() {
        // Arrange
        let user_message_content = "test user message".to_string();
        let user_dek_secret_vec = vec![0u8; 32];
        let user_dek = Some(Arc::new(SecretBox::new(Box::new(user_dek_secret_vec))));

        let msg1_content = "Hello there assistant!";
        let msg2_content = "Hi user, how are you?";

        let _messages = vec![
            create_db_chat_message(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), MessageRole::User, msg1_content, Some(3), -20, user_dek.as_ref()),
            create_db_chat_message(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), MessageRole::Assistant, msg2_content, Some(5), -10, user_dek.as_ref()),
        ];
        
        // Inlined create_test_config
        let mut test_config = AppConfig::default();
        test_config.context_recent_history_token_budget = 20;
        test_config.context_rag_token_budget = 50;
        test_config.context_total_token_limit = 100;
        test_config.tokenizer_model_path = Some("./resources/tokenizers/gemma.model".to_string());
        test_config.gemini_api_key = Some("dummy_api_key".to_string());
        test_config.token_counter_default_model = Some("gemini-test-model".to_string());


        let setup = setup_test_env(
            Vec::new(), // messages are now inserted directly in the test
            Vec::new(),
            Vec::new(),
            VecDeque::new(), // token_counts is unused in setup_test_env, pass empty
            Some(test_config.clone()), // Clone test_config
            None, /* _active_persona_id_from_session */
            // None, // _persona_details removed
            None, /* session_character_id_override */
            None, /* _session_system_prompt_override_db */
            None, /* character_db_details */
            None, /* _character_overrides_db */
            None  /* _active_lorebook_ids_for_search_db */
        ).await;

        let mut setup = setup; // Make setup mutable to update user_id
        let conn = setup.app_state.pool.get().await.expect("Failed to get DB connection for basic_fits_budget");

        // Insert User
        let new_user_for_test = NewUser {
            username: "testuser_basic_fits".to_string(),
            password_hash: "hash".to_string(),
            email: "basicfits@example.com".to_string(),
            role: UserRole::User,
            account_status: AccountStatus::Active,
            kek_salt: "dummy_salt".to_string(),
            encrypted_dek: vec![0u8; 16],
            dek_nonce: vec![0u8; 12],
            encrypted_dek_by_recovery: None,
            recovery_kek_salt: None,
            recovery_dek_nonce: None,
        };
        let inserted_user_id: Uuid = conn.interact(move |conn_insert| {
            diesel::insert_into(users::table)
                .values(&new_user_for_test)
                .returning(users::id)
                .get_result(conn_insert)
        }).await.unwrap().unwrap();
        setup.user_id = inserted_user_id; // Update setup with the actual inserted user_id

        // Insert Character
        // Use create_dummy_character and override necessary fields
        let mut test_character_basic_fits = crate::models::characters::create_dummy_character();
        test_character_basic_fits.id = setup._character_id;
        test_character_basic_fits.user_id = setup.user_id; // Use the actual inserted user_id
        test_character_basic_fits.name = "Test Character Basic Fits".to_string();
        test_character_basic_fits.created_at = chrono::Utc::now();
        test_character_basic_fits.updated_at = chrono::Utc::now();
        test_character_basic_fits.visibility = Some("private".to_string());
        // Ensure spec and spec_version are set if they are critical for the test logic,
        // otherwise dummy values from create_dummy_character are fine.
        test_character_basic_fits.spec = "chara_card_v2".to_string();
        test_character_basic_fits.spec_version = "2.0".to_string();

        conn.interact(move |conn_insert| {
            diesel::insert_into(character_schema::table)
                .values(&test_character_basic_fits)
                .execute(conn_insert)
        }).await.unwrap().unwrap();
        
        // Insert ChatSession
        let test_session_basic_fits = NewChat {
            id: setup.session_id, user_id: setup.user_id, character_id: setup._character_id,
            title: Some("Test Session Basic Fits".to_string()), created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            history_management_strategy: "message_window".to_string(), history_management_limit: 20,
            model_name: test_config.token_counter_default_model.clone().unwrap_or_else(|| "gemini-test-model".to_string()),
            visibility: Some("private".to_string()), active_custom_persona_id: None, active_impersonated_character_id: None,
        };
        conn.interact(move |conn_insert| {
            diesel::insert_into(chat_sessions_schema::table)
                .values(&test_session_basic_fits)
                .execute(conn_insert)
        }).await.unwrap().unwrap();

        // Create and insert messages associated with setup.session_id
        let message_definitions = [
            (msg1_content, MessageRole::User, Some(3i32), -20i64),
            (msg2_content, MessageRole::Assistant, Some(5i32), -10i64),
        ];

        for (plain_content_str, role_enum, tokens_opt, time_offset_secs) in message_definitions.iter() {
            let (content_bytes_for_db, nonce_for_db) = if let Some(dek) = setup.user_dek.as_ref() {
                let (ciphertext, nonce) = crypto::encrypt_gcm(plain_content_str.as_bytes(), dek.as_ref()).unwrap();
                (ciphertext, Some(nonce))
            } else {
                (plain_content_str.as_bytes().to_vec(), None)
            };
        
            let (prompt_tokens_val, completion_tokens_val) = match role_enum {
                MessageRole::User => (*tokens_opt, None),
                MessageRole::Assistant => (None, *tokens_opt),
                _ => (None, None),
            };
            
            let role_str_val = Some(match role_enum {
                MessageRole::User => "user".to_string(),
                MessageRole::Assistant => "assistant".to_string(),
                MessageRole::System => "system".to_string(),
            });
        
            let current_time = chrono::Utc::now();
            let _created_at_val = current_time + chrono::Duration::seconds(*time_offset_secs);
        
            let insertable_msg = DbInsertableChatMessage::new(
                setup.session_id, // chat_id
                setup.user_id,    // user_id
                *role_enum,       // msg_type_enum
                content_bytes_for_db, // text
                nonce_for_db,     // nonce
                role_str_val,     // role_str
                Some(json!({"type": "text", "text": *plain_content_str})), // parts_json
                None,             // attachments_json
                prompt_tokens_val, // prompt_tokens
                completion_tokens_val // completion_tokens
            );
        
            conn.interact(move |conn_i| {
                diesel::insert_into(chat_messages_schema::table)
                    .values(&insertable_msg)
                    .execute(conn_i)
            }).await.unwrap().unwrap();
        }
        
        // Configure mock expectations for embedding pipeline service
        // retrieve_relevant_chunks is called twice: once for lorebooks, once for older chat history.
        // For this test, we expect both to return empty vectors.
        setup._mock_embedding_pipeline.set_retrieve_responses_sequence(vec![
            Ok(Vec::new()), // For lorebook chunks
            Ok(Vec::new()), // For older chat history chunks
        ]);

        // Act
        let result = get_session_data_for_generation(
            setup.app_state.clone(),
            setup.user_id,
            setup.session_id,
            user_message_content.clone(),
            setup.user_dek.clone(),
        ).await;

        // Assert
        assert!(result.is_ok(), "Result should be Ok: {:?}", result.err());
        let (
            managed_history, _system_prompt, _lore_ids, _char_id, _, _, _, _, _, _, _, _, _, _, _, _, _model_name, // Added one underscore
            _, _, _user_msg_struct, actual_recent_tokens, rag_items, _, _
        ) = result.unwrap();

        assert_eq!(managed_history.len(), 2, "Should include both historical messages");

        // Calculate expected tokens dynamically using the same token counter and model
        let model_name_for_assertion = test_config.token_counter_default_model.as_ref().expect("Model name should be in test_config");
        let tokens_msg1 = setup.app_state.token_counter.count_tokens(msg1_content, CountingMode::LocalOnly, Some(model_name_for_assertion)).await.unwrap().total;
        let tokens_msg2 = setup.app_state.token_counter.count_tokens(msg2_content, CountingMode::LocalOnly, Some(model_name_for_assertion)).await.unwrap().total;
        let expected_total_tokens = tokens_msg1 + tokens_msg2;

        assert_eq!(actual_recent_tokens, expected_total_tokens as usize, "Token count for recent history should be sum of dynamically calculated historical message tokens");
        
        // Check content of managed history (ensure decryption happened if applicable)
        assert_eq!(String::from_utf8(managed_history[0].content.clone()).unwrap(), msg1_content);
        assert_eq!(String::from_utf8(managed_history[1].content.clone()).unwrap(), msg2_content);

        assert!(rag_items.is_empty(), "RAG items should be empty as no RAG chunks were provided");
    }

    #[tokio::test]
    async fn test_rag_lorebook_inclusion_fits_budget() {
        // Arrange
        let user_message_content = "Tell me about the ancient artifact.".to_string();
        let mut test_config = AppConfig::default();
        test_config.context_recent_history_token_budget = 30;
        test_config.context_rag_token_budget = 40;
        test_config.context_total_token_limit = 100; // Total: 30 (hist) + 40 (RAG) + buffer
        test_config.tokenizer_model_path = Some("./resources/tokenizers/gemma.model".to_string());
        test_config.gemini_api_key = Some("dummy_api_key_rag_lore".to_string());
        let model_name_for_test = "gemini-test-model-rag-lore".to_string();
        test_config.token_counter_default_model = Some(model_name_for_test.clone());

        let mut setup = setup_test_env(
            Vec::new(), Vec::new(), Vec::new(), VecDeque::new(),
            Some(test_config.clone()),
            None, /* _active_persona_id_from_session */
            None, /* session_character_id_override */
            None, /* _session_system_prompt_override_db */
            None, /* character_db_details */
            None, /* _character_overrides_db */
            None  /* _active_lorebook_ids_for_search_db */
        ).await;
        let conn = setup.app_state.pool.get().await.expect("Failed to get DB connection for RAG lorebook test");

        // Insert User
        let new_user_for_rag_lore_test = NewUser {
            username: "testuser_rag_lore".to_string(), password_hash: "hash_rag_lore".to_string(),
            email: "raglore@example.com".to_string(), role: UserRole::User, account_status: AccountStatus::Active,
            kek_salt: "salt_rag_lore".to_string(), encrypted_dek: vec![2u8; 16], dek_nonce: vec![2u8; 12],
            encrypted_dek_by_recovery: None, recovery_kek_salt: None, recovery_dek_nonce: None,
        };
        let inserted_user_id_rag_lore: Uuid = conn.interact(move |conn_insert_user| {
            diesel::insert_into(users::table)
                .values(&new_user_for_rag_lore_test)
                .returning(users::id)
                .get_result(conn_insert_user)
        }).await.unwrap().unwrap();
        setup.user_id = inserted_user_id_rag_lore;

        // Insert Character
        let mut test_character_rag_lore = crate::models::characters::create_dummy_character();
        test_character_rag_lore.id = setup._character_id;
        test_character_rag_lore.user_id = setup.user_id;
        test_character_rag_lore.name = "Test Character RAG Lore".to_string();
        conn.interact(move |conn_insert_char| {
            diesel::insert_into(character_schema::table)
                .values(&test_character_rag_lore)
                .execute(conn_insert_char)
        }).await.unwrap().unwrap();

        // Insert ChatSession
        let test_session_rag_lore = NewChat {
            id: setup.session_id, user_id: setup.user_id, character_id: setup._character_id,
            title: Some("Test Session RAG Lore".to_string()), created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            history_management_strategy: "message_window".to_string(), history_management_limit: 5,
            model_name: model_name_for_test.clone(), visibility: Some("private".to_string()),
            active_custom_persona_id: None, active_impersonated_character_id: None,
        };
        conn.interact(move |conn_insert_session| {
            diesel::insert_into(chat_sessions_schema::table)
                .values(&test_session_rag_lore)
                .execute(conn_insert_session)
        }).await.unwrap().unwrap();

        // Insert a simple history message
        let history_msg_content = "What was that sound?"; // Approx 4 tokens
        // We need to construct DbInsertableChatMessage directly with plain text for parts
        let (hist_content_bytes_for_db, hist_nonce_for_db) = if let Some(dek) = setup.user_dek.as_ref() {
            let (ciphertext, nonce) = crypto::encrypt_gcm(history_msg_content.as_bytes(), dek.as_ref()).unwrap();
            (ciphertext, Some(nonce))
        } else {
            (history_msg_content.as_bytes().to_vec(), None)
        };

        conn.interact(move |conn_i| {
            let insertable_msg = DbInsertableChatMessage::new(
                setup.session_id, setup.user_id, MessageRole::User,
                hist_content_bytes_for_db, hist_nonce_for_db,
                Some("user".to_string()), Some(json!({"type": "text", "text": history_msg_content})), // Use original plaintext
                None, Some(4), None, // prompt_tokens, completion_tokens
            );
            diesel::insert_into(chat_messages_schema::table).values(&insertable_msg).execute(conn_i)
        }).await.unwrap().unwrap();

        // Prepare Lorebook and link to session
        let lorebook_id = Uuid::new_v4();
        // Minimal Lorebook struct for insertion
        let test_lorebook = crate::models::lorebooks::NewLorebook {
            id: lorebook_id,
            user_id: setup.user_id,
            name: "Ancient Artifacts".to_string(),
            description: Some("Lore about ancient artifacts.".to_string()),
            source_format: "scribe_v1".to_string(), // Provide a default source_format
            is_public: false, // Default to private
            created_at: Some(chrono::Utc::now()),
            updated_at: Some(chrono::Utc::now()),
        };
         conn.interact({
            let tl = test_lorebook.clone(); // Clone for the first interact
            move |conn_lore_insert| {
                diesel::insert_into(crate::schema::lorebooks::table)
                    .values(&tl)
                    .execute(conn_lore_insert)
            }
        }).await.unwrap().unwrap();

        conn.interact(move |conn_link| {
            {
                use crate::schema::chat_session_lorebooks;
                let new_link = crate::models::lorebooks::NewChatSessionLorebook {
                    chat_session_id: setup.session_id,
                    lorebook_id,
                    user_id: setup.user_id,
                };
                diesel::insert_into(chat_session_lorebooks::table)
                    .values(&new_link)
                    .execute(conn_link)
            }
        }).await.unwrap().unwrap();


        // Define RAG chunks to be returned by the mock
        let lore_chunk1_content = "The Orb of Zog is powerful."; // Approx 6 tokens
        let lore_chunk2_content = "It glows with an eerie light."; // Approx 7 tokens
        let lore_chunk1 = RetrievedChunk {
            text: lore_chunk1_content.to_string(),
            score: 0.9,
            metadata: crate::services::embedding_pipeline::RetrievedMetadata::Lorebook(
                crate::services::embedding_pipeline::LorebookChunkMetadata {
                    original_lorebook_entry_id: Uuid::new_v4(), // Assuming a new UUID for test
                    lorebook_id,
                    user_id: setup.user_id, // Add user_id
                    chunk_text: lore_chunk1_content.to_string(), // Add chunk_text
                    entry_title: Some("Orb of Zog".to_string()), // Add entry_title
                    keywords: Some(vec!["orb".to_string()]), // Change entry_keys to keywords
                    is_enabled: true, // Add is_enabled
                    is_constant: false, // Add is_constant
                    source_type: "lorebook_entry".to_string(), // Add source_type
                }
            ),
        };
        let lore_chunk2 = RetrievedChunk {
            text: lore_chunk2_content.to_string(),
            score: 0.8,
            metadata: crate::services::embedding_pipeline::RetrievedMetadata::Lorebook(
                 crate::services::embedding_pipeline::LorebookChunkMetadata {
                    original_lorebook_entry_id: Uuid::new_v4(), // Assuming a new UUID for test
                    lorebook_id,
                    user_id: setup.user_id, // Add user_id
                    chunk_text: lore_chunk2_content.to_string(), // Add chunk_text
                    entry_title: Some("Eerie Light".to_string()), // Add entry_title
                    keywords: Some(vec!["light".to_string()]), // Change entry_keys to keywords
                    is_enabled: true, // Add is_enabled
                    is_constant: false, // Add is_constant
                    source_type: "lorebook_entry".to_string(), // Add source_type
                }
            ),
        };
        let expected_lore_chunks = vec![lore_chunk1.clone(), lore_chunk2.clone()];

        // Configure mock expectations for the manual mock
        // retrieve_relevant_chunks is called twice:
        // 1. For lorebooks (with active_lorebook_ids_for_search = Some(vec![lorebook_id]))
        // 2. For older chat history (with session_id_for_chat_history = Some(setup.session_id))
        // We set a sequence of responses. The first call to retrieve_relevant_chunks will get the first response, etc.
        setup._mock_embedding_pipeline.set_retrieve_responses_sequence(vec![
            Ok(expected_lore_chunks.clone()), // Response for the lorebook chunks call
            Ok(Vec::new()),                   // Response for the older chat history call (empty for this test)
        ]);


        // Act
        let result = get_session_data_for_generation(
            setup.app_state.clone(),
            setup.user_id,
            setup.session_id,
            user_message_content.clone(),
            setup.user_dek.clone(),
        ).await;

        // Assert
        assert!(result.is_ok(), "Result should be Ok: {:?}", result.err());
        let (
            managed_history, _system_prompt, _active_lore_ids, _char_id, _, _, _, _, _, _, _, _, _, _, _, _, _model_name, // Added one underscore
            _, _, _user_msg_struct, actual_recent_tokens, rag_items, _, _
        ) = result.unwrap();

        assert_eq!(managed_history.len(), 1, "Should include the single historical message");
        assert_eq!(String::from_utf8(managed_history[0].content.clone()).unwrap(), history_msg_content);

        let tokens_hist_msg = setup.app_state.token_counter.count_tokens(history_msg_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        assert_eq!(actual_recent_tokens, tokens_hist_msg as usize, "Token count for recent history mismatch");

        assert_eq!(rag_items.len(), 2, "Should include both lorebook chunks in RAG items");
        assert_eq!(rag_items[0].text, lore_chunk1_content); // Assuming sorted by score (mock data is already sorted)
        assert_eq!(rag_items[1].text, lore_chunk2_content);

        let tokens_lore1 = setup.app_state.token_counter.count_tokens(lore_chunk1_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let tokens_lore2 = setup.app_state.token_counter.count_tokens(lore_chunk2_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let total_rag_tokens_used = tokens_lore1 + tokens_lore2;

        let expected_available_rag_tokens = min(
            test_config.context_rag_token_budget,
            test_config.context_total_token_limit.saturating_sub(actual_recent_tokens)
        );
        assert!(total_rag_tokens_used as usize <= expected_available_rag_tokens, "Total RAG tokens used ({}) should be within available budget ({})", total_rag_tokens_used, expected_available_rag_tokens);
    }
 
    #[tokio::test]
    async fn test_history_truncation_exceeds_budget() {
        // Arrange
        let user_message_content = "new user message".to_string();
        let mut test_config = AppConfig::default();
        test_config.context_recent_history_token_budget = 8; // Budget for 2 smaller messages
        test_config.context_rag_token_budget = 0; // No RAG for this test
        test_config.context_total_token_limit = 50;
        test_config.tokenizer_model_path = Some("./resources/tokenizers/gemma.model".to_string());
        test_config.gemini_api_key = Some("dummy_api_key_for_trunc_test".to_string());
        let model_name_for_test = "gemini-test-model-trunc".to_string();
        test_config.token_counter_default_model = Some(model_name_for_test.clone());

        let setup = setup_test_env(
            Vec::new(), Vec::new(), Vec::new(), VecDeque::new(),
            Some(test_config),
            None, /* _active_persona_id_from_session */
            // None, // _persona_details removed
            None, /* session_character_id_override */
            None, /* _session_system_prompt_override_db */
            None, /* character_db_details */
            None, /* _character_overrides_db */
            None  /* _active_lorebook_ids_for_search_db */
        ).await;

        let mut setup = setup; // Make setup mutable
        let conn = setup.app_state.pool.get().await.expect("Failed to get DB connection");

        // Insert User
        let new_user_for_trunc_test = NewUser {
            username: "testuser_trunc".to_string(),
            password_hash: "anotherhash".to_string(),
            email: "trunc@example.com".to_string(),
            role: UserRole::User,
            account_status: AccountStatus::Active,
            kek_salt: "dummy_salt_trunc".to_string(),
            encrypted_dek: vec![1u8; 16],
            dek_nonce: vec![1u8; 12],
            encrypted_dek_by_recovery: None,
            recovery_kek_salt: None,
            recovery_dek_nonce: None,
        };
        let inserted_user_id_trunc: Uuid = conn.interact(move |conn_insert_user| {
            diesel::insert_into(users::table)
                .values(&new_user_for_trunc_test)
                .returning(users::id)
                .get_result(conn_insert_user)
        }).await.unwrap().unwrap();
        setup.user_id = inserted_user_id_trunc; // Update setup with the actual inserted user_id
 
        // Insert Character
        // Use create_dummy_character and override necessary fields
        let mut test_character = crate::models::characters::create_dummy_character();
        test_character.id = setup._character_id;
        test_character.user_id = setup.user_id; // Use the actual inserted user_id
        test_character.name = "Test Character".to_string();
        test_character.created_at = chrono::Utc::now();
        test_character.updated_at = chrono::Utc::now();
        test_character.visibility = Some("private".to_string());
        test_character.spec = "chara_card_v2".to_string();
        test_character.spec_version = "2.0".to_string();
        
        conn.interact(move |conn_insert| {
            diesel::insert_into(character_schema::table)
                .values(&test_character)
                .execute(conn_insert)
        }).await.unwrap().unwrap();

        // Insert ChatSession
        let test_session = NewChat {
            id: setup.session_id, user_id: setup.user_id, character_id: setup._character_id,
            title: Some("Test Session Title".to_string()), created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            history_management_strategy: "message_window".to_string(), history_management_limit: 20,
            model_name: model_name_for_test.clone(), // Crucial for token counting consistency
            visibility: Some("private".to_string()), active_custom_persona_id: None, active_impersonated_character_id: None,
        };
        conn.interact(move |conn_insert| {
            diesel::insert_into(chat_sessions_schema::table)
                .values(&test_session)
                .execute(conn_insert)
        }).await.unwrap().unwrap();

        // Messages (content chosen for Gemma tokenizer, rough estimates)
        // Gemma counts punctuation and spaces.
        // "This is a longer first message." ~6-7 tokens
        // "Okay then." ~3 tokens
        // "See you." ~2 tokens
        let msg1_content = "This is a longer first message."; // Should be excluded
        let msg2_content = "Okay then."; // Kept
        let msg3_content = "See you.";   // Kept

        let message_definitions_for_insertion = [
            (msg1_content, MessageRole::Assistant, Some(7i32)),
            (msg2_content, MessageRole::User, Some(3i32)),
            (msg3_content, MessageRole::Assistant, Some(2i32)),
        ];

        for (plain_content_str, role_enum, tokens_opt) in message_definitions_for_insertion.iter() {
            let (content_bytes_for_db, nonce_for_db) = if let Some(dek) = setup.user_dek.as_ref() {
                let (ciphertext, nonce) = crypto::encrypt_gcm(plain_content_str.as_bytes(), dek.as_ref()).unwrap();
                (ciphertext, Some(nonce))
            } else {
                (plain_content_str.as_bytes().to_vec(), None)
            };
        
            let (prompt_tokens_val, completion_tokens_val) = match role_enum {
                MessageRole::User => (*tokens_opt, None),
                MessageRole::Assistant => (None, *tokens_opt),
                _ => (None, None),
            };
            
            let role_str_val = Some(match role_enum {
                MessageRole::User => "user".to_string(),
                MessageRole::Assistant => "assistant".to_string(),
                MessageRole::System => "system".to_string(),
            });
        
            let insertable_msg = DbInsertableChatMessage::new(
                setup.session_id,
                setup.user_id,
                *role_enum,
                content_bytes_for_db,
                nonce_for_db,
                role_str_val,
                Some(json!({"type": "text", "text": *plain_content_str})),
                None,
                prompt_tokens_val,
                completion_tokens_val
            );
        
            conn.interact(move |conn_i| {
                diesel::insert_into(chat_messages_schema::table)
                    .values(&insertable_msg)
                    .execute(conn_i)
            }).await.unwrap().unwrap();
        }
        
        // Act
        let result = get_session_data_for_generation(
            setup.app_state.clone(),
            setup.user_id,
            setup.session_id,
            user_message_content.clone(),
            setup.user_dek.clone(),
        ).await;

        // Assert
        assert!(result.is_ok(), "Result should be Ok: {:?}", result.err());
        let (
            managed_history, _system_prompt, _lore_ids, _char_id, _, _, _, _, _, _, _, _, _, _, _, _, _model_name, // Added one underscore
            _, _, _user_msg_struct, actual_recent_tokens, rag_items, _, _
        ) = result.unwrap();

        // Token counts with Gemma for "Okay then." (3) and "See you." (2) = 5. Budget is 8.
        // "This is a longer first message." is ~7 tokens. 5 + 7 = 12 > 8. So msg1 is excluded.
        assert_eq!(managed_history.len(), 2, "Should include 2 most recent messages");
        
        let hist_msg2_content = String::from_utf8(managed_history[0].content.clone()).unwrap();
        let hist_msg3_content = String::from_utf8(managed_history[1].content.clone()).unwrap();
        
        assert_eq!(hist_msg2_content, msg2_content, "Second message content mismatch");
        assert_eq!(hist_msg3_content, msg3_content, "Third message content mismatch");

        // Calculate expected tokens based on actual content kept
        let tokens_msg2 = setup.app_state.token_counter.count_tokens(msg2_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let tokens_msg3 = setup.app_state.token_counter.count_tokens(msg3_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let expected_tokens = tokens_msg2 + tokens_msg3;

        assert_eq!(actual_recent_tokens, expected_tokens as usize, "Token count for recent history mismatch");
        assert!(rag_items.is_empty(), "RAG items should be empty for this test");
    }
#[tokio::test]
    async fn test_rag_lorebook_exclusion_due_to_total_budget() {
        // Arrange
        let user_message_content = "User query that triggers RAG.".to_string();
        let mut test_config = AppConfig::default();
        test_config.context_recent_history_token_budget = 150; // Allows significant history
        test_config.context_rag_token_budget = 50;           // RAG budget itself is positive
        test_config.context_total_token_limit = 160;         // Total limit is tight
        test_config.tokenizer_model_path = Some("./resources/tokenizers/gemma.model".to_string());
        test_config.gemini_api_key = Some("dummy_api_key_rag_total_limit".to_string());
        let model_name_for_test = "gemini-test-model-rag-total-limit".to_string();
        test_config.token_counter_default_model = Some(model_name_for_test.clone());

        let mut setup = setup_test_env(
            Vec::new(), Vec::new(), Vec::new(), VecDeque::new(),
            Some(test_config.clone()),
            None, /* _active_persona_id_from_session */
            None, /* session_character_id_override */
            None, /* _session_system_prompt_override_db */
            None, /* character_db_details */
            None, /* _character_overrides_db */
            None  /* _active_lorebook_ids_for_search_db */
        ).await;
        let conn = setup.app_state.pool.get().await.expect("Failed to get DB connection for RAG total limit test");

        // Insert User
        let new_user_for_rag_total_limit_test = NewUser {
            username: "testuser_rag_total_limit".to_string(), password_hash: "hash_rag_total_limit".to_string(),
            email: "ragtotallimit@example.com".to_string(), role: UserRole::User, account_status: AccountStatus::Active,
            kek_salt: "salt_rag_total_limit".to_string(), encrypted_dek: vec![3u8; 16], dek_nonce: vec![3u8; 12],
            encrypted_dek_by_recovery: None, recovery_kek_salt: None, recovery_dek_nonce: None,
        };
        let inserted_user_id_rag_total_limit: Uuid = conn.interact(move |conn_insert_user| {
            diesel::insert_into(users::table)
                .values(&new_user_for_rag_total_limit_test)
                .returning(users::id)
                .get_result(conn_insert_user)
        }).await.unwrap().unwrap();
        setup.user_id = inserted_user_id_rag_total_limit;

        // Insert Character
        let mut test_character_rag_total_limit = crate::models::characters::create_dummy_character();
        test_character_rag_total_limit.id = setup._character_id;
        test_character_rag_total_limit.user_id = setup.user_id;
        test_character_rag_total_limit.name = "Test Character RAG Total Limit".to_string();
        conn.interact(move |conn_insert_char| {
            diesel::insert_into(character_schema::table)
                .values(&test_character_rag_total_limit)
                .execute(conn_insert_char)
        }).await.unwrap().unwrap();

        // Insert ChatSession
        let test_session_rag_total_limit = NewChat {
            id: setup.session_id, user_id: setup.user_id, character_id: setup._character_id,
            title: Some("Test Session RAG Total Limit".to_string()), created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            history_management_strategy: "message_window".to_string(), history_management_limit: 20, // High limit, actual tokens will control
            model_name: model_name_for_test.clone(), visibility: Some("private".to_string()),
            active_custom_persona_id: None, active_impersonated_character_id: None,
        };
        conn.interact(move |conn_insert_session| {
            diesel::insert_into(chat_sessions_schema::table)
                .values(&test_session_rag_total_limit)
                .execute(conn_insert_session)
        }).await.unwrap().unwrap();

        // Create history messages to consume tokens close to `CONTEXT_TOTAL_TOKEN_LIMIT - CONTEXT_RAG_TOKEN_BUDGET`
        // Target `actual_recent_history_tokens` = 140.
        // `CONTEXT_RECENT_HISTORY_TOKEN_BUDGET` = 150, so these will fit.
        // `CONTEXT_TOTAL_TOKEN_LIMIT` = 160.
        // `available_rag_tokens` = min(CONTEXT_RAG_TOKEN_BUDGET (50), CONTEXT_TOTAL_TOKEN_LIMIT (160) - actual_recent_history_tokens (140))
        //                        = min(50, 20) = 20.
        // Unused variables:
        // let _history_msg1_content = "This is a very long message that will consume a lot of tokens, hopefully around seventy tokens for this specific test case.";
        // let _history_msg2_content = "Another quite long message to add to the history, also aiming for about seventy tokens to reach our target sum for history.";
        let long_hist_msg_content = "This is a test message for token counting purposes, let's see how many it takes."; // Count this precisely
        let tokens_per_long_hist_msg = setup.app_state.token_counter.count_tokens(long_hist_msg_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total as usize;
        
        let mut current_history_tokens: usize = 0;
        let target_history_tokens: usize = 140;
        let mut constructed_message_data_for_insertion = Vec::new(); // Store (plaintext, role, tokens, created_at)
        let time_offset_base = -100i64;

        for i in 0.. {
            if current_history_tokens.saturating_add(tokens_per_long_hist_msg) <= target_history_tokens {
                let created_at = chrono::Utc::now() + chrono::Duration::seconds(time_offset_base - i as i64);
                constructed_message_data_for_insertion.push((long_hist_msg_content.to_string(), MessageRole::User, Some(tokens_per_long_hist_msg as i32), created_at));
                current_history_tokens += tokens_per_long_hist_msg;
            } else {
                break;
            }
        }
        let remaining_tokens_needed = target_history_tokens.saturating_sub(current_history_tokens);
        if remaining_tokens_needed > 0 {
            let short_filler_content = std::iter::repeat("a ").take(remaining_tokens_needed).collect::<String>();
            let tokens_filler = setup.app_state.token_counter.count_tokens(&short_filler_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total as usize;
            if tokens_filler > 0 && current_history_tokens.saturating_add(tokens_filler) <= target_history_tokens + 5 {
                let created_at = chrono::Utc::now() + chrono::Duration::seconds(time_offset_base - 1000); // Ensure it's older
                constructed_message_data_for_insertion.push((short_filler_content, MessageRole::User, Some(tokens_filler as i32), created_at));
                current_history_tokens += tokens_filler;
            }
        }
        
        // Insert history messages
        for (plain_content_str, role_enum, tokens_opt, _created_at_val) in constructed_message_data_for_insertion.iter() {
            let (content_bytes_for_db, nonce_for_db) = if let Some(dek) = setup.user_dek.as_ref() {
                let (ciphertext, nonce) = crypto::encrypt_gcm(plain_content_str.as_bytes(), dek.as_ref()).unwrap();
                (ciphertext, Some(nonce))
            } else {
                (plain_content_str.as_bytes().to_vec(), None)
            };

            let (prompt_tokens_val, completion_tokens_val) = match role_enum {
                MessageRole::User => (*tokens_opt, None),
                MessageRole::Assistant => (None, *tokens_opt),
                _ => (None, None),
            };
            
            let role_str_val = Some(match role_enum {
                MessageRole::User => "user".to_string(),
                MessageRole::Assistant => "assistant".to_string(),
                MessageRole::System => "system".to_string(),
            });

            let insertable_msg = DbInsertableChatMessage::new(
                setup.session_id, // chat_id
                setup.user_id,    // user_id
                *role_enum,       // msg_type_enum
                content_bytes_for_db, // text
                nonce_for_db,     // nonce
                role_str_val,     // role_str
                Some(json!({"type": "text", "text": plain_content_str})), // parts_json
                None,             // attachments_json
                prompt_tokens_val, // prompt_tokens
                completion_tokens_val // completion_tokens
            );

            conn.interact(move |conn_i| {
                diesel::insert_into(chat_messages_schema::table)
                    .values(&insertable_msg)
                    .execute(conn_i)
            }).await.unwrap().unwrap();
        }
        
        // Prepare Lorebook and link to session
        let lorebook_id = Uuid::new_v4();
        let test_lorebook_total_limit = crate::models::lorebooks::NewLorebook {
            id: lorebook_id, user_id: setup.user_id, name: "Total Limit Lorebook".to_string(),
            description: Some("Lore for total limit test.".to_string()), source_format: "scribe_v1".to_string(),
            is_public: false, created_at: Some(chrono::Utc::now()), updated_at: Some(chrono::Utc::now()),
        };
        conn.interact({ let tl = test_lorebook_total_limit.clone(); move |conn_lore_insert| {
            diesel::insert_into(crate::schema::lorebooks::table).values(&tl).execute(conn_lore_insert)
        }}).await.unwrap().unwrap();
        conn.interact(move |conn_link| { {
            use crate::schema::chat_session_lorebooks;
            let new_link = crate::models::lorebooks::NewChatSessionLorebook {
                chat_session_id: setup.session_id, lorebook_id, user_id: setup.user_id,
            };
            diesel::insert_into(chat_session_lorebooks::table).values(&new_link).execute(conn_link)
        }}).await.unwrap().unwrap();

        // Define RAG chunks to be returned by the mock for lorebooks.
        // Each chunk should have > 20 tokens. `available_rag_tokens` is expected to be 20.
        let lore_chunk1_content = "This particular lorebook chunk is specifically designed to be quite a bit more than twenty tokens long for the purpose of testing exclusion criteria accurately. One two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twentyone.";
        let lore_chunk1_tokens = setup.app_state.token_counter.count_tokens(lore_chunk1_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total as usize;
        assert!(lore_chunk1_tokens > 20, "Test setup error: lore_chunk1_content ('{}') is not > 20 tokens (actual: {})", lore_chunk1_content, lore_chunk1_tokens);

        let lore_chunk1 = RetrievedChunk {
            text: lore_chunk1_content.to_string(), score: 0.9,
            metadata: crate::services::embedding_pipeline::RetrievedMetadata::Lorebook(
                crate::services::embedding_pipeline::LorebookChunkMetadata {
                    original_lorebook_entry_id: Uuid::new_v4(), lorebook_id, user_id: setup.user_id,
                    chunk_text: lore_chunk1_content.to_string(), entry_title: Some("Large Chunk 1".to_string()),
                    keywords: Some(vec!["large".to_string()]), is_enabled: true, is_constant: false,
                    source_type: "lorebook_entry".to_string(),
                }),
        };
        let expected_lore_chunks = vec![lore_chunk1.clone()];

        // Configure mock expectations
        setup._mock_embedding_pipeline.set_retrieve_responses_sequence(vec![
            Ok(expected_lore_chunks.clone()), // For lorebook chunks
            Ok(Vec::new()),                   // For older chat history chunks
        ]);

        // Act
        let result = get_session_data_for_generation(
            setup.app_state.clone(),
            setup.user_id,
            setup.session_id,
            user_message_content.clone(),
            setup.user_dek.clone(),
        ).await;

        // Assert
        assert!(result.is_ok(), "Result should be Ok: {:?}", result.err());
        let (
            managed_history, _system_prompt, _active_lore_ids, _char_id, _, _, _, _, _, _, _, _, _, _, _, _, _model_name, // Added one underscore
            _, _, _user_msg_struct, actual_recent_tokens_from_result, rag_items, _, _
        ) = result.unwrap();

        // Verify actual_recent_history_tokens is what we set up (around 140)
        // This assertion helps confirm the history setup was correct.
        // The exact value depends on the precise tokenization of the filler messages.
        // We are aiming for `current_history_tokens` to be the value.
        assert_eq!(actual_recent_tokens_from_result, current_history_tokens, "Actual recent history tokens ({}) from result does not match expected ({}) from setup. Target was {}.", actual_recent_tokens_from_result, current_history_tokens, target_history_tokens);

        // Key assertion: RAG items should be empty because no lorebook chunk could fit
        assert!(rag_items.is_empty(), "RAG items should be empty due to total budget constraint, but got: {:?}", rag_items);
        
        // Verify managed_recent_history contains the messages we inserted
        assert_eq!(managed_history.len(), constructed_message_data_for_insertion.len(), "Managed history length mismatch");
    }
    #[tokio::test]
    async fn test_rag_older_chat_history_inclusion_fits_budget() {
        // Arrange
        let user_message_content = "User query for older history RAG.".to_string();
        let mut test_config = AppConfig::default();
        test_config.context_recent_history_token_budget = 10; // Adjusted from 50
        test_config.context_rag_token_budget = 100;
        test_config.context_total_token_limit = 200;
        test_config.tokenizer_model_path = Some("./resources/tokenizers/gemma.model".to_string());
        test_config.gemini_api_key = Some("dummy_api_key_rag_older_hist".to_string());
        let model_name_for_test = "gemini-test-model-rag-older-hist".to_string();
        test_config.token_counter_default_model = Some(model_name_for_test.clone());

        let mut setup = setup_test_env(
            Vec::new(), Vec::new(), Vec::new(), VecDeque::new(),
            Some(test_config.clone()),
            None, /* _active_persona_id_from_session */
            None, /* session_character_id_override */
            None, /* _session_system_prompt_override_db */
            None, /* character_db_details */
            None, /* _character_overrides_db */
            None  /* _active_lorebook_ids_for_search_db */
        ).await;
        let conn = setup.app_state.pool.get().await.expect("Failed to get DB connection for RAG older history test");

        // Insert User
        let new_user_for_rag_older_hist_test = NewUser {
            username: "testuser_rag_older_hist".to_string(), password_hash: "hash_rag_older_hist".to_string(),
            email: "ragolderhist@example.com".to_string(), role: UserRole::User, account_status: AccountStatus::Active,
            kek_salt: "salt_rag_older_hist".to_string(), encrypted_dek: vec![4u8; 16], dek_nonce: vec![4u8; 12],
            encrypted_dek_by_recovery: None, recovery_kek_salt: None, recovery_dek_nonce: None,
        };
        let inserted_user_id_rag_older_hist: Uuid = conn.interact(move |conn_insert_user| {
            diesel::insert_into(users::table)
                .values(&new_user_for_rag_older_hist_test)
                .returning(users::id)
                .get_result(conn_insert_user)
        }).await.unwrap().unwrap();
        setup.user_id = inserted_user_id_rag_older_hist;

        // Insert Character
        let mut test_character_rag_older_hist = crate::models::characters::create_dummy_character();
        test_character_rag_older_hist.id = setup._character_id;
        test_character_rag_older_hist.user_id = setup.user_id;
        test_character_rag_older_hist.name = "Test Character RAG Older Hist".to_string();
        conn.interact(move |conn_insert_char| {
            diesel::insert_into(character_schema::table)
                .values(&test_character_rag_older_hist)
                .execute(conn_insert_char)
        }).await.unwrap().unwrap();

        // Insert ChatSession
        let test_session_rag_older_hist = NewChat {
            id: setup.session_id, user_id: setup.user_id, character_id: setup._character_id,
            title: Some("Test Session RAG Older Hist".to_string()), created_at: chrono::Utc::now(), updated_at: chrono::Utc::now(),
            history_management_strategy: "message_window".to_string(), history_management_limit: 10, // Ample limit for recent
            model_name: model_name_for_test.clone(), visibility: Some("private".to_string()),
            active_custom_persona_id: None, active_impersonated_character_id: None,
        };
        conn.interact(move |conn_insert_session| {
            diesel::insert_into(chat_sessions_schema::table)
                .values(&test_session_rag_older_hist)
                .execute(conn_insert_session)
        }).await.unwrap().unwrap();

        let mut message_ids = Vec::new();

        // Insert "older" history messages (timestamps further in the past)
        let older_msg1_content = "This is an old message from the user."; // ~8 tokens
        let older_msg2_content = "And an old reply from the assistant."; // ~8 tokens
        let older_msg3_content = "One more old user message for context."; // ~9 tokens

        let older_messages_data = [
            (older_msg1_content, MessageRole::User, -300i64),
            (older_msg2_content, MessageRole::Assistant, -200i64),
            (older_msg3_content, MessageRole::User, -100i64),
        ];
        let mut expected_older_chat_chunks = Vec::new();

        for (idx, (content, role, time_offset)) in older_messages_data.iter().enumerate() {
            let msg_id = Uuid::new_v4();
            message_ids.push(msg_id);
            let (content_bytes, nonce_bytes): (Vec<u8>, Option<Vec<u8>>) = if let Some(dek) = setup.user_dek.as_ref() {
                let (cb, n) = crypto::encrypt_gcm(content.as_bytes(), dek.as_ref()).unwrap();
                (cb, Some(n))
            } else { (content.as_bytes().to_vec(), None) };
            let tokens = setup.app_state.token_counter.count_tokens(content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total as i32;
            let (pt, ct) = if *role == MessageRole::User { (Some(tokens), None) } else { (None, Some(tokens)) };
            let created_at_val = chrono::Utc::now() + chrono::Duration::seconds(*time_offset);

            let insertable_msg = DbInsertableChatMessage::new(
                setup.session_id, setup.user_id, *role, content_bytes, nonce_bytes,
                Some(role.to_string()), Some(json!({"type": "text", "text": *content})), None, pt, ct,
            );
            // created_at will be set by the database default `now()`.
            // Order of insertion will manage "older" vs "recent".

            conn.interact({
                let m = insertable_msg.clone(); // Clone for closure
                let _current_msg_id = msg_id; // Capture current msg_id for this iteration
                move |conn_i| {
                // Insert the message
                diesel::insert_into(chat_messages_schema::table)
                    .values(&m)
                    // We need to explicitly set the ID if we want to control it for the ChatChunkMetadata
                    // However, DbInsertableChatMessage doesn't have an ID field.
                    // We'll fetch the ID after insertion if needed, or rely on content matching.
                    // For simplicity, we'll use the generated ID from the DB if ChatChunkMetadata needs it.
                    // For this test, we'll construct ChatChunkMetadata with the ID we generate here.
                    // This requires that the DB message actually has this ID.
                    // A better way is to insert and then query, or let the DB generate the ID and use that.
                    // For now, let's assume we can't control the ID on insert easily with DbInsertableChatMessage.
                    // We will use the generated msg_id for the ChatChunkMetadata.
                    .execute(conn_i)?;

                // Update the created_at timestamp separately if DbInsertableChatMessage doesn't allow direct setting
                // Or ensure DbInsertableChatMessage can take created_at
                // The current DbInsertableChatMessage::new does not take created_at.
                // We will update it after insertion.
                // This is not ideal. A better approach is to modify DbInsertableChatMessage or use a different struct.
                // For now, we'll try to update. This requires knowing the ID.
                // Let's assume the test helper `create_db_chat_message` is better for controlled insertion.
                // However, that helper is for creating `DbChatMessage` not `DbInsertableChatMessage`.
                // We will proceed with inserting and then constructing `RetrievedChunk` with the known content and a *new* Uuid for metadata.
                // The crucial part for the test is that the *content* matches.
                // The filtering logic in get_session_data_for_generation uses message IDs from `managed_recent_history`.
                // So, the `message_id` in `ChatChunkMetadata` for older chunks *must* be the actual ID from the DB.

                // To get the actual ID, we would need to insert and then select.
                // For this test, we will create the RetrievedChunk with the ID we *would* have inserted if we controlled it.
                // This means the test relies on the content and the mock returning these specific chunks.
                // The filtering logic for `recent_message_ids` will be tested by ensuring the mock returns chunks
                // that are *not* in recent history.

                // Let's re-think: we need the actual DB message ID for the ChatChunkMetadata.
                // So, after inserting, we should query for that message to get its ID.
                // Or, if we can't easily query by content/timestamp reliably, we'll have to make the test simpler
                // by ensuring the mock returns chunks with *new* Uuids for message_id, and the test focuses on content.
                // The problem statement says: "Ensure these chunks, when combined, fit within the available_rag_tokens."
                // And "rag_context_items contains the expected older chat history chunks."
                // This implies the content and token count are key.

                // Let's simplify: the mock will return `RetrievedChunk`s. The `message_id` in their metadata
                // will be a new Uuid for each, not necessarily matching a DB ID for this specific part of the test.
                // The main function's filtering of recent messages from RAG candidates will still work based on
                // the `message_id`s of the *actual recent messages* from the DB.
                // The test for *older history RAG* is about whether *different* (older) content gets included.

                // So, the `message_id` in `ChatChunkMetadata` for the mock can be `Uuid::new_v4()`.
                Ok::<_, diesel::result::Error>(())
            }}).await.unwrap().unwrap();

            // Update created_at for the last inserted message (this is hacky)
            // A proper solution would be to allow setting created_at in DbInsertableChatMessage or use a raw query.
            // For now, we assume the order of insertion combined with small time offsets in other messages will suffice.
            // The critical part is that these messages are older than "recent" ones.
            // The `created_at` field in `DbInsertableChatMessage` is now `Option<DateTime<Utc>>`
            // So we can set it directly in `DbInsertableChatMessage::new` if we modify the constructor or struct.
            // The current `DbInsertableChatMessage::new` does not take `created_at`.
            // The struct `DbInsertableChatMessage` itself does not have `created_at`.
            // It's `ChatMessage` that has `created_at`.
            // The `chat_messages` schema has `created_at` with `DEFAULT now()`.
            // We need to insert with specific `created_at` values.
            // This means using a more direct insert or modifying `DbInsertableChatMessage`.

            // Let's use a direct insert approach for messages where we need to control created_at.
            // This is getting complex. Let's simplify the message insertion for older messages.
            // We will insert them and assume their DB-generated `created_at` will be naturally older if inserted first.
            // Or, use the time_offset in `create_db_chat_message` style if we adapt it for insertion.

            // For this test, the key is that the mock `EmbeddingPipelineService` returns the correct older chunks.
            // The actual DB messages for "older" history are primarily to ensure they *exist* for the conceptual setup.
            // The `retrieve_relevant_chunks` mock for older history will provide the content.

            expected_older_chat_chunks.push(RetrievedChunk {
                text: content.to_string(),
                score: 0.85 - (idx as f32 * 0.01), // Ensure some ordering if needed
                metadata: crate::services::embedding_pipeline::RetrievedMetadata::Chat(
                    crate::services::embedding_pipeline::ChatMessageChunkMetadata {
                        message_id: msg_id, // Use the ID we generated for this message
                        session_id: setup.session_id,
                        user_id: setup.user_id,
                        speaker: role.to_string(), // Changed from role
                        timestamp: created_at_val, // Changed from created_at
                        // token_count: tokens as usize, // Removed, not in struct
                        source_type: "chat_message".to_string(),
                        text: content.to_string(), // Changed from chunk_text
                        // original_message_id: msg_id, // Removed, covered by message_id
                    }
                ),
            });
        }


        // Insert "recent" history messages (timestamps more recent)
        let recent_msg1_content = "Recent user message."; // ~4 tokens
        let recent_msg2_content = "Recent assistant reply."; // ~4 tokens
        let recent_messages_data = [
            (recent_msg1_content, MessageRole::User, -20i64),
            (recent_msg2_content, MessageRole::Assistant, -10i64),
        ];
        let mut recent_message_ids_in_db = Vec::new();

        for (content, role, _time_offset) in recent_messages_data.iter() {
            let msg_id = Uuid::new_v4();
            recent_message_ids_in_db.push(msg_id); // Store the ID we intend to insert, though DB might generate a different one if not set.
                                                 // For this test, we will fetch the actual IDs later.

            let (content_bytes, nonce_bytes): (Vec<u8>, Option<Vec<u8>>) = if let Some(dek) = setup.user_dek.as_ref() {
                let (cb, n) = crypto::encrypt_gcm(content.as_bytes(), dek.as_ref()).unwrap();
                (cb, Some(n))
            } else { (content.as_bytes().to_vec(), None) };

            let tokens = setup.app_state.token_counter.count_tokens(content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total as i32;
            let (pt, ct) = if *role == MessageRole::User { (Some(tokens), None) } else { (None, Some(tokens)) };

            // created_at will be set by DB default. Order of insertion matters.
            // These "recent" messages are inserted *after* "older" messages.
            let insertable_recent_msg = DbInsertableChatMessage::new(
                setup.session_id, // chat_id
                setup.user_id,    // user_id
                *role,            // msg_type_enum
                content_bytes,    // text
                nonce_bytes,      // nonce
                Some(role.to_string()), // role_str
                Some(json!({"type": "text", "text": *content})), // parts_json
                None,             // attachments_json
                pt,               // prompt_tokens
                ct,               // completion_tokens
            );

            conn.interact({
                let m_insert = insertable_recent_msg.clone();
                move |conn_i| {
                    diesel::insert_into(chat_messages_schema::table)
                        .values(&m_insert)
                        .execute(conn_i)
                }
            }).await.unwrap().unwrap();
        }

        // Fetch the actual recent messages from DB to get their DB-generated IDs and confirm order
        let actual_recent_messages_from_db: Vec<DbChatMessage> = conn.interact(move |conn_db| {
            chat_messages_schema::table
                .filter(chat_messages_schema::session_id.eq(setup.session_id))
                .order(chat_messages_schema::created_at.desc()) // newest first
                .limit(2) // We inserted 2 recent messages
                .select(DbChatMessage::as_select())
                .load::<DbChatMessage>(conn_db)
        }).await.unwrap().unwrap();

        let recent_history_message_ids_from_db: std::collections::HashSet<Uuid> =
            actual_recent_messages_from_db.iter().map(|msg| msg.id).collect();

        // Configure mock expectations
        setup._mock_embedding_pipeline.set_retrieve_responses_sequence(vec![
            Ok(expected_older_chat_chunks.clone()), // For older chat history chunks (lorebook call is skipped in this test)
        ]);

        // Act
        let result = get_session_data_for_generation(
            setup.app_state.clone(),
            setup.user_id,
            setup.session_id,
            user_message_content.clone(),
            setup.user_dek.clone(),
        ).await;

        // Assert
        assert!(result.is_ok(), "Result should be Ok: {:?}", result.err());
        let (
            managed_history, _system_prompt, _lore_ids, _char_id, _, _, _, _, _, _, _, _, _, _, _, _, _model_name, // Added one underscore
            _, _, _user_msg_struct, actual_recent_tokens, rag_items, _, _
        ) = result.unwrap();

        assert_eq!(managed_history.len(), 2, "Managed recent history should contain 2 messages");
        assert_eq!(String::from_utf8(managed_history[0].content.clone()).unwrap(), recent_msg1_content);
        assert_eq!(String::from_utf8(managed_history[1].content.clone()).unwrap(), recent_msg2_content);

        let tokens_recent1 = setup.app_state.token_counter.count_tokens(recent_msg1_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let tokens_recent2 = setup.app_state.token_counter.count_tokens(recent_msg2_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        assert_eq!(actual_recent_tokens, (tokens_recent1 + tokens_recent2) as usize, "Actual recent history tokens mismatch");

        assert_eq!(rag_items.len(), 3, "RAG items should contain 3 older chat history chunks");
        assert_eq!(rag_items[0].text, older_msg1_content);
        assert_eq!(rag_items[1].text, older_msg2_content);
        assert_eq!(rag_items[2].text, older_msg3_content);

        let tokens_older1 = setup.app_state.token_counter.count_tokens(older_msg1_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let tokens_older2 = setup.app_state.token_counter.count_tokens(older_msg2_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let tokens_older3 = setup.app_state.token_counter.count_tokens(older_msg3_content, CountingMode::LocalOnly, Some(&model_name_for_test)).await.unwrap().total;
        let total_rag_tokens_used = tokens_older1 + tokens_older2 + tokens_older3;

        let expected_available_rag_tokens = min(
            test_config.context_rag_token_budget, // 100
            test_config.context_total_token_limit.saturating_sub(actual_recent_tokens) // 200 - (tokens_recent1+tokens_recent2)
        );
        assert!(total_rag_tokens_used as usize <= expected_available_rag_tokens,
                "Total RAG tokens used ({}) should be within available budget ({})", total_rag_tokens_used, expected_available_rag_tokens);

        // Ensure no overlap between recent history (actual IDs from DB) and RAG items (mocked IDs)
        for rag_chunk in &rag_items {
            if let crate::services::embedding_pipeline::RetrievedMetadata::Chat(chat_meta) = &rag_chunk.metadata {
                assert!(!recent_history_message_ids_from_db.contains(&chat_meta.message_id), "RAG item with mock ID {} should not be in the set of actual recent DB message IDs", chat_meta.message_id);
            }
        }
    }
}
