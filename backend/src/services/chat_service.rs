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
    errors::AppError,
    models::{
        characters::Character,
        chat_override::{ChatCharacterOverride, CharacterOverrideDto, NewChatCharacterOverride},
        chats::{
            Chat, ChatMessage as DbChatMessage, ChatSettingsResponse, DbInsertableChatMessage,
            MessageRole, NewChat, SettingsTuple, UpdateChatSettingsRequest,
        },
        lorebooks::ChatSessionLorebook, // Added for fetching active lorebook IDs
        user_personas::UserPersonaDataForClient, // Correct DTO name
    },
    schema::{characters, chat_character_overrides, chat_messages, chat_sessions},
    services::{
        history_manager,
    },
    services::hybrid_token_counter::CountingMode, // Added for token counting
    state::{AppState, DbPool},
    crypto, // Added for encryption
    schema::users::dsl as users_dsl, // Added for fetching user's default persona
};
use std::pin::Pin;
use std::sync::Arc;

// Type alias for the history tuple returned for generation
pub type HistoryForGeneration = Vec<(MessageRole, String)>;

// Type alias for the full data needed for generation, including the model name
// AND the unsaved user message struct
// NOTE: HistoryForGeneration here will now contain the *managed* history.
pub type GenerationDataWithUnsavedUserMessage = (
    Vec<DbChatMessage>,   // 0: managed_db_history (CHANGED from HistoryForGeneration)
    Option<String>,       // 1: system_prompt
    Option<Vec<Uuid>>,    // 2: active_lorebook_ids_for_search
    Uuid,                 // 3: session_character_id (NEW)
    Option<BigDecimal>,   // 4: temperature
    Option<i32>,          // max_output_tokens
    Option<BigDecimal>,   // frequency_penalty
    Option<BigDecimal>,   // presence_penalty
    Option<i32>,          // top_k
    Option<BigDecimal>,   // top_p
    Option<BigDecimal>,   // repetition_penalty
    Option<BigDecimal>,   // min_p
    Option<BigDecimal>,   // top_a
    Option<i32>,          // seed
    Option<Value>,        // logit_bias
    String,               // model_name (Fetched from DB)
    // -- Gemini Specific Options --
    Option<i32>,             // gemini_thinking_budget
    Option<bool>,            // gemini_enable_code_execution
    DbInsertableChatMessage, // The user message struct, ready to be saved
    // History Management Settings (still returned for potential future use/logging)
    String, // history_management_strategy
    i32,    // history_management_limit
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
            Ok(estimate) => prompt_tokens_val = Some(estimate.total as i32),
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
            Ok(estimate) => completion_tokens_val = Some(estimate.total as i32),
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
    state: Arc<AppState>, // Changed from pool to state
    user_id: Uuid,
    session_id: Uuid,
    user_message_content: String, // This will be cloned for the closure
    user_dek_secret_box: Option<Arc<SecretBox<Vec<u8>>>>,
) -> Result<GenerationDataWithUnsavedUserMessage, AppError> {
    let user_message_content_for_closure = user_message_content.clone();
    info!(target: "chat_service_persona_debug", %session_id, %user_id, "Entering get_session_data_for_generation.");
    let conn = state.pool.get().await.map_err(|e| {
        // Use state.pool
        error!(error = ?e, "Failed to get DB connection from pool");
        AppError::DbPoolError(e.to_string())
    })?;

    // Clone the Arc for moving into the interact closure if it exists
    let dek_for_interact: Option<Arc<SecretBox<Vec<u8>>>> = user_dek_secret_box.clone();
    info!(target: "chat_service_persona_debug", %session_id, dek_present_initial = user_dek_secret_box.is_some(), "Initial DEK presence for get_session_data_for_generation.");

    // Calculate prompt tokens for the current user message outside the interact block
    let user_prompt_tokens = match state
        .token_counter
        .count_tokens(
            &user_message_content,
            CountingMode::LocalOnly,
            None, // We don't have model_name yet, will count with default
        )
        .await
    {
        Ok(estimate) => Some(estimate.total as i32),
        Err(e) => {
            warn!(
                "Failed to count prompt tokens for new user message in get_session_data_for_generation: {}",
                e
            );
            None
        }
    };
    trace!(
        ?user_prompt_tokens,
        "Calculated prompt tokens for current user message"
    );

    // Fetch session's active_custom_persona_id first to potentially fetch persona details
    let maybe_active_persona_id_from_session: Option<Uuid> = {
        let conn_clone_for_persona_check = state.pool.get().await?; // Get a new connection
        conn_clone_for_persona_check.interact(move |c| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .filter(chat_sessions::user_id.eq(user_id))
                .select(chat_sessions::active_custom_persona_id)
                .first::<Option<Uuid>>(c)
        }).await?? // Propagate InteractError then DB error
    };
    info!(target: "chat_service_persona_debug", %session_id, ?maybe_active_persona_id_from_session, "Fetched active_custom_persona_id from session.");

    let mut effective_system_prompt: Option<String> = None;

    let db_persona_for_prompt: Option<UserPersonaDataForClient> =
        if let Some(persona_id) = maybe_active_persona_id_from_session {
            info!(target: "chat_service_persona_debug", %session_id, %persona_id, dek_present_for_persona_fetch = user_dek_secret_box.is_some(), "Attempting to fetch persona details.");
            if let Some(ref dek_arc_outer) = user_dek_secret_box { // dek_arc_outer is Option<Arc<SecretBox<Vec<u8>>>>
                debug!(target: "chat_service_trace_prompt", %session_id, %persona_id, "Session has active_custom_persona_id and DEK. Fetching persona.");

                let user_for_service_call: crate::models::users::User = {
                    let conn_for_user_fetch = state.pool.get().await.map_err(|e| {
                        error!("Failed to get DB connection for user fetch: {}", e);
                        AppError::DbPoolError(e.to_string())
                    })?;
                    let user_db_query_result = conn_for_user_fetch.interact(move |c| {
                        crate::schema::users::table
                            .filter(crate::schema::users::id.eq(user_id))
                            .select(crate::models::users::UserDbQuery::as_select())
                            .first::<crate::models::users::UserDbQuery>(c)
                    }).await.map_err(|e| {
                        error!("DB interact error fetching user_db_query for {}: {}", user_id, e);
                        AppError::InternalServerErrorGeneric(format!("DB interact error fetching user_db_query: {}", e))
                    })?; // Propagate interact error first
                    
                    let user_db_query = user_db_query_result.map_err(|e| { // Then handle Diesel error
                        error!("Failed to fetch user_db_query for {} for persona check: {}", user_id, e);
                        AppError::NotFound(format!("UserDbQuery for user {} not found for persona check: {}", user_id, e))
                    })?;
                    user_db_query.into()
                };
                
                // Correctly get Option<&SecretBox<Vec<u8>>> from Option<Arc<SecretBox<Vec<u8>>>>
                let dek_ref_for_service: Option<&SecretBox<Vec<u8>>> = Some(dek_arc_outer.as_ref());

                let persona_service_result = state.user_persona_service.get_user_persona(&user_for_service_call, dek_ref_for_service, persona_id).await;
                info!(target: "chat_service_persona_debug", %session_id, %persona_id, "Result from user_persona_service.get_user_persona: {:?}", persona_service_result);

                match persona_service_result {
                    Ok(client_persona_dto) => { // Renamed to avoid confusion
                        info!(target: "chat_service_persona_debug", %session_id, %persona_id, "Successfully fetched persona DTO: {:?}", client_persona_dto);
                        Some(client_persona_dto)
                    }
                    Err(e) => {
                        error!(target: "chat_service_trace_prompt", %session_id, %persona_id, error = %e, "Error fetching active persona via service. Will try overrides or character default.");
                        None
                    }
                }
            } else {
                warn!(target: "chat_service_trace_prompt", %session_id, %persona_id, "Active persona ID present, but no user DEK available. Cannot fetch/decrypt custom persona.");
                info!(target: "chat_service_persona_debug", %session_id, %persona_id, "No DEK available for persona fetch, returning None for db_persona_for_prompt.");
                None
            }
        } else {
            info!(target: "chat_service_persona_debug", %session_id, "No active_custom_persona_id in session, db_persona_for_prompt is None.");
            None
        };

    if let Some(ref persona_dto) = db_persona_for_prompt {
        info!(target: "chat_service_persona_debug", %session_id, persona_id = %persona_dto.id, "Processing fetched persona DTO: Name='{}', Desc='{}'", persona_dto.name, persona_dto.description);
        debug!(target: "chat_service_trace_prompt", %session_id, persona_id = %persona_dto.id, "Found active persona. Checking its system_prompt field first.");
        if let Some(ref sp_from_persona) = persona_dto.system_prompt {
            if !sp_from_persona.trim().is_empty() {
                effective_system_prompt = Some(sp_from_persona.replace('\0', ""));
                info!(target: "chat_service_trace_prompt", %session_id, persona_id = %persona_dto.id, "Using non-empty system_prompt directly from active persona.");
                debug!(target: "chat_service_trace_prompt", %session_id, persona_id = %persona_dto.id, persona_direct_prompt_content = %effective_system_prompt.as_deref().unwrap_or_default());
            } else {
                warn!(target: "chat_service_trace_prompt", %session_id, persona_id = %persona_dto.id, "Active persona's system_prompt field is present but empty. Attempting to construct prompt from other fields.");
            }
        } else {
            warn!(target: "chat_service_trace_prompt", %session_id, persona_id = %persona_dto.id, "Active persona's system_prompt field is None. Attempting to construct prompt from other fields.");
        }

        // If persona's system_prompt was None or empty, try constructing one
        if effective_system_prompt.is_none() {
            debug!(target: "chat_service_trace_prompt", %session_id, persona_id = %persona_dto.id, "Constructing system prompt from persona name, description, personality, and scenario.");
            let mut constructed_parts = Vec::new();

            // Name and Description are mandatory for the base message.
            // UserPersonaDataForClient has `name: String` and `description: String` (non-optional)
            // Ensure description is not empty before adding "Their description is: "
            let base_prompt_part = if persona_dto.description.trim().is_empty() {
                format!("You are chatting with {}.", persona_dto.name.replace('\0', ""))
            } else {
                format!("You are chatting with {}. Their description is: {}.",
                    persona_dto.name.replace('\0', ""),
                    persona_dto.description.replace('\0', "")
                )
            };
            constructed_parts.push(base_prompt_part);

            if let Some(ref personality) = persona_dto.personality {
                if !personality.trim().is_empty() {
                    constructed_parts.push(format!("Personality: {}", personality.replace('\0', "")));
                }
            }
            if let Some(ref scenario) = persona_dto.scenario {
                if !scenario.trim().is_empty() {
                    constructed_parts.push(format!("Scenario: {}", scenario.replace('\0', "")));
                }
            }
            // TODO: Consider adding other fields like first_mes, mes_example, post_history_instructions if relevant for system prompt context

            let constructed_prompt_full = constructed_parts.join("\n");
            if !constructed_prompt_full.trim().is_empty() {
                effective_system_prompt = Some(constructed_prompt_full);
                info!(target: "chat_service_trace_prompt", %session_id, persona_id = %persona_dto.id, "Using constructed system prompt from persona details.");
                debug!(target: "chat_service_trace_prompt", %session_id, persona_id = %persona_dto.id, persona_constructed_prompt_content = %effective_system_prompt.as_deref().unwrap_or_default());
            } else {
                warn!(target: "chat_service_trace_prompt", %session_id, persona_id = %persona_dto.id, "Constructed prompt from persona details is empty. Will fall back to overrides or character default.");
            }
        }
    } else if maybe_active_persona_id_from_session.is_some() {
        warn!(target: "chat_service_trace_prompt", %session_id, persona_id = %maybe_active_persona_id_from_session.unwrap(), "Active persona_id specified in session, but persona DTO could not be loaded/used. Will try overrides or character default.");
    } else {
        debug!(target: "chat_service_trace_prompt", %session_id, "No active_custom_persona_id in session. Will try overrides or character default.");
    }
    info!(target: "chat_service_persona_debug", %session_id, "Final effective_system_prompt before interact block: {:?}", effective_system_prompt);
    // It's important to understand if `db_persona_for_prompt` (which is UserPersonaDataForClient)
    // is passed to the PromptBuilder or if only `effective_system_prompt` is used.
    // For now, we log what `effective_system_prompt` becomes.
    // If the full persona details (name, desc, etc.) are needed beyond the system prompt,
    // `db_persona_for_prompt` itself would need to be passed along or its fields incorporated differently.
    info!(target: "chat_service_persona_debug", %session_id, "db_persona_for_prompt (UserPersonaDataForClient) that might be used by PromptBuilder: {:?}", db_persona_for_prompt);


    // Fetch active lorebook IDs for the session
    let active_lorebook_ids_for_search: Option<Vec<Uuid>> = {
        let pool_clone_lore = state.pool.clone();
        let session_id_clone_lore = session_id;
        // This structure uses .await outside the main conn.interact block, which is correct.
        match pool_clone_lore.get().await.map_err(AppError::from)?.interact(move |conn_lore| {
            ChatSessionLorebook::get_active_lorebook_ids_for_session(conn_lore, session_id_clone_lore)
                .map_err(AppError::from)
        }).await { // This await is on the result of interact, which is fine here.
            Ok(Ok(ids)) => {
                info!(%session_id, num_ids = ids.as_ref().map_or(0, |v| v.len()), "Successfully fetched active lorebook IDs for RAG search.");
                ids
            },
            Ok(Err(e)) => {
                warn!(%session_id, error = %e, "Failed to get active lorebook IDs for RAG (DB error inside interact). Proceeding without them.");
                None
            }
            Err(e) => { // This is InteractError
                warn!(%session_id, error = %e, "Failed to get active lorebook IDs for RAG (InteractError). Proceeding without them.");
                None
            }
        }
    };
    info!(%session_id, ?active_lorebook_ids_for_search, "Active lorebook IDs for search determined.");

    let generation_data_result = conn.interact(move |conn_interaction| {
        info!(%session_id, %user_id, "Fetching session data for generation");

        // Fetch chat session details including character_id and session-specific system_prompt
        let (
            history_management_strategy,
            history_management_limit,
            session_character_id, // Renamed from character_id to avoid conflict
            _session_system_prompt, // This is the override from chat_sessions
            session_temperature,
            session_max_output_tokens,
            session_frequency_penalty,
            session_presence_penalty,
            session_top_k,
            session_top_p,
            session_repetition_penalty,
            session_min_p,
            session_top_a,
            session_seed,
            session_logit_bias,
            session_model_name,
            // -- Gemini Specific Options --
            session_gemini_thinking_budget,
            session_gemini_enable_code_execution,
        ) = chat_sessions::table
            .filter(chat_sessions::id.eq(session_id))
            .filter(chat_sessions::user_id.eq(user_id))
            .select((
                chat_sessions::history_management_strategy,
                chat_sessions::history_management_limit,
                chat_sessions::character_id, // Fetch character_id
                chat_sessions::system_prompt, // Session specific system_prompt
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
                chat_sessions::model_name,
                chat_sessions::gemini_thinking_budget,
                chat_sessions::gemini_enable_code_execution,
            ))
            .first::<(
                String,
                i32,
                Uuid, // Type for character_id
                Option<String>, // Type for session_system_prompt
                Option<BigDecimal>,
                Option<i32>,
                Option<BigDecimal>,
                Option<BigDecimal>,
                Option<i32>,
                Option<BigDecimal>,
                Option<BigDecimal>,
                Option<BigDecimal>,
                Option<BigDecimal>,
                Option<i32>,
                Option<Value>,
                String,
                Option<i32>,
                Option<bool>,
            )>(conn_interaction)
            .map_err(|e| {
                error!("Failed to fetch chat session details: {:?}", e);
                match e {
                    DieselError::NotFound => AppError::NotFound(format!("Chat session {} not found for user {}", session_id, user_id)),
                    _ => AppError::DatabaseQueryError(format!("Failed to query chat session {}: {}", session_id, e)),
                }
            })?;

        // Fetch the character details
        let character: Character = characters::table
            .filter(characters::id.eq(session_character_id))
            .first::<Character>(conn_interaction)
            .map_err(|e| {
                error!("Failed to fetch character {} for session {}: {:?}", session_character_id, session_id, e);
                match e {
                    DieselError::NotFound => AppError::NotFound(format!("Character {} not found", session_character_id)),
                    _ => AppError::DatabaseQueryError(format!("Failed to query character {}: {}", session_character_id, e)),
                }
            })?;

        // Fetch character overrides from the database
        let character_overrides: Vec<ChatCharacterOverride> = chat_character_overrides::table
            .filter(chat_character_overrides::chat_session_id.eq(session_id))
            .filter(chat_character_overrides::original_character_id.eq(session_character_id))
            .load::<ChatCharacterOverride>(conn_interaction)
            .map_err(|e| {
                warn!("Failed to fetch character overrides for session {}: {:?}", session_id, e);
                AppError::DatabaseQueryError(format!("Failed to query character overrides for session {}: {}", session_id, e))
            })?;
            
        info!(
            %session_id, 
            %session_character_id, 
            override_count = character_overrides.len(),
            "Fetched character overrides for session"
        );

        // Helper function (or closure) for decrypting a character field
        let decrypt_char_field = |data: Option<&Vec<u8>>, nonce: Option<&Vec<u8>>, field_name: &str| -> Result<Option<String>, AppError> {
            match (data, nonce, &dek_for_interact) {
                (Some(d), Some(n), Some(dek)) if !d.is_empty() && !n.is_empty() => {
                    trace!(character_id = %character.id, field_name, "Attempting to decrypt character field");
                    let decrypted_bytes = crate::crypto::decrypt_gcm(d, n, dek.as_ref())
                        .map_err(|e| {
                            error!(character_id = %character.id, field_name, error = ?e, "Failed to decrypt character field");
                            AppError::DecryptionError(format!("Failed to decrypt {} for character {}: {}", field_name, character.id, e))
                        })?;
                    String::from_utf8(decrypted_bytes.expose_secret().to_vec())
                        .map(Some)
                        .map_err(|e| {
                            error!(character_id = %character.id, field_name, error = ?e, "Invalid UTF-8 in decrypted character field");
                            AppError::InternalServerErrorGeneric(format!("Invalid UTF-8 in {} for character {}: {}", field_name, character.id, e))
                        })
                }
                (Some(_), Some(_), None) => { // Data and nonce exist, but no DEK
                    trace!(character_id = %character.id, field_name, "Character field is encrypted, but no DEK available for decryption.");
                    Ok(Some("[Encrypted Data]".to_string())) // Placeholder for encrypted data when no DEK
                }
                (Some(d), None, _) if !d.is_empty() => { // Data exists but no nonce (should not happen for encrypted fields)
                    trace!(character_id = %character.id, field_name, "Character field has data but no nonce, treating as plaintext if possible or erroring.");
                    String::from_utf8(d.clone())
                        .map(Some)
                        .map_err(|e| AppError::InternalServerErrorGeneric(format!("Invalid UTF-8 in non-nonced field {} for character {}: {}", field_name, character.id, e)))
                }
                _ => Ok(None), // No data or other cases
            }
        };
        
        // Helper function to decrypt override values
        let decrypt_override = |override_data: &ChatCharacterOverride| -> Result<Option<String>, AppError> {
            match &dek_for_interact {
                Some(dek) if !override_data.overridden_value.is_empty() && !override_data.overridden_value_nonce.is_empty() => {
                    trace!(field_name = %override_data.field_name, "Attempting to decrypt character override");
                    let decrypted_bytes = crate::crypto::decrypt_gcm(
                        &override_data.overridden_value,
                        &override_data.overridden_value_nonce,
                        dek.as_ref(),
                    ).map_err(|e| {
                        error!(field_name = %override_data.field_name, error = ?e, "Failed to decrypt character override");
                        AppError::DecryptionError(format!("Failed to decrypt override for {}: {}", override_data.field_name, e))
                    })?;
                    
                    String::from_utf8(decrypted_bytes.expose_secret().to_vec())
                        .map(Some)
                        .map_err(|e| {
                            error!(field_name = %override_data.field_name, error = ?e, "Invalid UTF-8 in decrypted override");
                            AppError::InternalServerErrorGeneric(format!("Invalid UTF-8 in override for {}: {}", override_data.field_name, e))
                        })
                },
                _ => {
                    warn!(field_name = %override_data.field_name, "Cannot decrypt override: missing DEK or invalid override data for session {}", session_id);
                    Ok(None)
                }
            }
        };
        
        // Create a map of field_name -> decrypted_value for the overrides
        let mut override_values: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        for override_data in &character_overrides {
            if let Ok(Some(decrypted_value)) = decrypt_override(override_data) {
                if !decrypted_value.is_empty() { // Only insert non-empty decrypted overrides
                    info!(
                        %session_id,
                        field_name = %override_data.field_name, 
                        "Successfully decrypted and storing non-empty character override"
                    );
                    override_values.insert(override_data.field_name.clone(), decrypted_value);
                } else {
                    info!(
                        %session_id,
                        field_name = %override_data.field_name, 
                        "Decrypted character override is empty, not storing"
                    );
                }
            }
        }
        
        // Logic for persona prompt already handled above, effective_system_prompt is already set or None

        // 2. If no persona prompt, check character overrides for system_prompt
        if effective_system_prompt.is_none() {
            debug!(target: "chat_service_trace_prompt", %session_id, "No effective_system_prompt from persona. Checking character overrides for 'system_prompt'.");
            if let Some(override_value) = override_values.get("system_prompt") {
                if !override_value.trim().is_empty() {
                    effective_system_prompt = Some(override_value.replace('\0', ""));
                    info!(target: "chat_service_trace_prompt", %session_id, "Using overridden system_prompt for generation.");
                     debug!(target: "chat_service_trace_prompt", %session_id, overridden_prompt_content = %effective_system_prompt.as_deref().unwrap_or_default());
                } else {
                    debug!(target: "chat_service_trace_prompt", %session_id, "Override for 'system_prompt' is empty. Will try character default.");
                }
            } else {
                debug!(target: "chat_service_trace_prompt", %session_id, "No override found for 'system_prompt'. Will try character default.");
            }
        }

        // 3. If still no prompt, use character's default system_prompt
        if effective_system_prompt.is_none() {
            debug!(target: "chat_service_trace_prompt", %session_id, "No effective_system_prompt from persona or overrides. Using character's default system_prompt.");
            if let Some(ref char_sp_bytes) = character.system_prompt {
                match String::from_utf8(char_sp_bytes.clone()) { // Clone for logging
                    Ok(char_sp_str) => {
                        if !char_sp_str.trim().is_empty() {
                            effective_system_prompt = Some(char_sp_str.replace('\0', ""));
                            info!(target: "chat_service_trace_prompt", %session_id, character_id = %character.id, "Using character's default system_prompt for generation.");
                            debug!(target: "chat_service_trace_prompt", %session_id, character_id = %character.id, character_prompt_content = %effective_system_prompt.as_deref().unwrap_or_default());
                        } else {
                             warn!(target: "chat_service_trace_prompt", %session_id, character_id = %character.id, "Character's default system_prompt is empty. No system prompt will be used.");
                             effective_system_prompt = None; // Explicitly set to None
                        }
                    }
                    Err(e) => {
                        error!(target: "chat_service_trace_prompt", %session_id, character_id = %character.id, error = %e, "Failed to convert character's default system_prompt from UTF-8. No system prompt will be used.");
                        effective_system_prompt = None; // Explicitly set to None
                    }
                }
            } else {
                warn!(target: "chat_service_trace_prompt", %session_id, character_id = %character.id, "Character's default system_prompt is None in DB. No system prompt will be used.");
                effective_system_prompt = None; // Explicitly set to None
            }
        }

        // Fetch existing messages for the session
        let existing_messages_db: Vec<DbChatMessage> = chat_messages::table
            .filter(chat_messages::session_id.eq(session_id))
            .order(chat_messages::created_at.asc())
            .select(DbChatMessage::as_select())
            .load::<DbChatMessage>(conn_interaction)
            .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;
        trace!(%session_id, num_existing_messages = existing_messages_db.len(), "Fetched existing messages from DB");

        // Decrypt messages if DEK is available
        let mut decrypted_history_tuples: HistoryForGeneration = Vec::new();
        for db_msg in existing_messages_db {
            let content_str = match (db_msg.content_nonce.as_ref(), &dek_for_interact) {
                (Some(nonce_vec), Some(dek_arc)) => {
                    trace!(message_id = %db_msg.id, "Attempting to decrypt message with DEK for session {}", session_id);
                    let decrypted_bytes_secret = crate::crypto::decrypt_gcm(
                        &db_msg.content,
                        nonce_vec,
                        dek_arc.as_ref(),
                    )
                    .map_err(|e| {
                        error!(message_id = %db_msg.id, error = ?e, "Failed to decrypt message content for session {}", session_id);
                        AppError::DecryptionError(format!("Failed to decrypt message {}: {}", db_msg.id, e))
                    })?;
                    String::from_utf8(decrypted_bytes_secret.expose_secret().to_vec()).map_err(|e| {
                        error!(message_id = %db_msg.id, error = ?e, "Failed to convert decrypted message to UTF-8 for session {}", session_id);
                        AppError::InternalServerErrorGeneric(format!("Invalid UTF-8 in decrypted message {}: {}", db_msg.id, e))
                    })?
                }
                _ => {
                    trace!(message_id = %db_msg.id, "No DEK or nonce, treating message as plaintext for session {}", session_id);
                    String::from_utf8(db_msg.content.clone()).map_err(|e| {
                        error!(message_id = %db_msg.id, error = ?e, "Failed to convert plaintext message to UTF-8 (should be valid) for session {}", session_id);
                        AppError::InternalServerErrorGeneric(format!("Invalid UTF-8 in plaintext message {}: {}", db_msg.id, e))
                    })?
                }
            };
            decrypted_history_tuples.push((db_msg.message_type, content_str));
        }
        trace!(%session_id, num_decrypted_messages = decrypted_history_tuples.len(), "Finished decrypting/processing existing messages");
        let decrypted_messages_for_manager: Vec<crate::models::chats::ChatMessage> = decrypted_history_tuples
            .iter()
            .map(|(role, content)| {
                crate::models::chats::ChatMessage {
                    id: Uuid::new_v4(),
                    session_id,
                    message_type: role.clone(),
                    content: content.as_bytes().to_vec(),
                    content_nonce: None,
                    created_at: chrono::Utc::now(),
                    user_id,
                    prompt_tokens: None,
                    completion_tokens: None,
                }
            })
            .collect();
        let mut managed_history_msgs = history_manager::manage_history( // Made mutable
            decrypted_messages_for_manager,
            &history_management_strategy,
            history_management_limit,
        );
        trace!(%session_id, num_managed_db_history_items = managed_history_msgs.len(), "History management applied to DB messages");

        // Check if this is the first user message (no existing messages from DB, empty managed_history_msgs)
        // If so, prepend the character's first_mes as the first assistant message to managed_history_msgs
        if managed_history_msgs.is_empty() {
            info!(%session_id, "No existing messages in DB history - checking for character's first_mes (with override) to include in managed_history_msgs");
            
            let mut first_mes_content_to_add: Option<String> = None;

            if let Some(first_mes_override) = override_values.get("first_mes") {
                if !first_mes_override.is_empty() {
                    info!(%session_id, "Using character's non-empty first_mes override for history");
                    first_mes_content_to_add = Some(first_mes_override.clone());
                }
            } else if let Some(char_first_mes) = decrypt_char_field(character.first_mes.as_ref(), character.first_mes_nonce.as_ref(), "first_mes")? {
                if !char_first_mes.is_empty() {
                    info!(%session_id, "Using character's non-empty original first_mes for history");
                    first_mes_content_to_add = Some(char_first_mes);
                }
            }

            if let Some(content) = first_mes_content_to_add {
                let first_mes_db_chat_message = DbChatMessage {
                    id: Uuid::new_v4(), // Transient ID for this context
                    session_id,
                    user_id, // user_id of the session/requester
                    message_type: MessageRole::Assistant,
                    content: content.as_bytes().to_vec(),
                    content_nonce: None, // Content is plaintext here, no nonce needed for this transient message
                    created_at: chrono::Utc::now(), // Timestamp for this transient representation
                    prompt_tokens: None, // Not applicable or calculated for first_mes in this context
                    completion_tokens: None, // Not applicable for first_mes
                };
                info!(%session_id, "Prepending character's first_mes as DbChatMessage to managed_history_msgs");
                managed_history_msgs.insert(0, first_mes_db_chat_message);
            }
        }

        // --- START: RAG Context for Current User Message ---
        let final_system_prompt_with_rag = effective_system_prompt.clone(); // Start with the base system prompt

        if !user_message_content_for_closure.trim().is_empty() {
            // const RAG_CONTEXT_FOR_SYSTEM_PROMPT_LIMIT: u64 = 5; // Define a limit for chunks - This was unused here
            info!(%session_id, "Retrieving RAG context for current user message to augment system prompt (placeholder in interact block).");
            
            // This block needs to be async, so we'll handle it outside the interact block if direct async calls are not possible inside.
            // For now, assuming this interact block is the place for DB calls, and RAG retrieval might need to be adjusted.
            // However, `state.embedding_pipeline_service.retrieve_relevant_chunks` is async.
            // This means this RAG retrieval part needs to happen *before* this `conn.interact` block,
            // or the `interact` block needs to be structured differently if it's only for sync Diesel calls.

            // Let's assume we can call async functions if `conn_interaction` is not used by them.
            // This part will be executed outside the `conn.interact` block later if needed.
            // For now, placing logic here to see structure.
            // THIS WILL BE MOVED OUTSIDE THE INTERACT BLOCK
        }
        // --- END: RAG Context for Current User Message (LOGIC TO BE MOVED) ---

        // The block for fetching active_lorebook_ids_for_search has been moved before the main interact call.


        // Token counting has been moved above and done outside the interact block
        // We'll use the tokens that were already counted
        let user_db_message_to_save = DbInsertableChatMessage::new(
            session_id,
            user_id,
            MessageRole::User,
            user_message_content_for_closure.clone().into_bytes(),
            None, // Nonce for user message (plaintext here, encrypted in save_message)
            Some("user".to_string()), // role_str: ADDED
            Some(json!([{"text": user_message_content_for_closure.clone()}])), // parts_json: Now uses the original user_message_content
            None,                       // attachments_json: ADDED
            user_prompt_tokens, // prompt_tokens
            None,               // completion_tokens (None for user message)
        );
        Ok::<GenerationDataWithUnsavedUserMessage, AppError>((
            managed_history_msgs, // Return Vec<DbChatMessage>
            final_system_prompt_with_rag, // Use the potentially RAG-augmented system prompt
            active_lorebook_ids_for_search.clone(), // Pass the fetched lorebook IDs
            session_character_id, // Pass session_character_id
            session_temperature,
            session_max_output_tokens,
            session_frequency_penalty,
            session_presence_penalty,
            session_top_k,
            session_top_p,
            session_repetition_penalty,
            session_min_p,
            session_top_a,
            session_seed,
            session_logit_bias,
            session_model_name,
            session_gemini_thinking_budget,
            session_gemini_enable_code_execution,
            user_db_message_to_save,
            history_management_strategy,
            history_management_limit,
            // active_lorebook_ids_for_search, // This was duplicated, remove one. The one at index 2 is correct.
        ))
    })
    .await // Outer await for interact
    .map_err(|e| AppError::DbInteractError(format!("Interact dispatch error: {}", e)))?;
    
    // The RAG context augmentation for the *current user message* was previously here.
    // However, the `build_prompt_with_rag` function is now responsible for all RAG,
    // including context from the current user message and history.
    // So, the logic that was here (lines 1182-1265 in the original file) is now redundant
    // because `build_prompt_with_rag` (called from routes/chat.rs) will handle it.
    // The `final_system_prompt_with_rag` from the interact block is the one we want.
    // The `active_lorebook_ids_for_search` is correctly part of the tuple from the interact block.

    // The tuple returned by generation_data_result already contains all necessary fields.
    // No further modification of final_system_prompt_with_rag is needed here.
    generation_data_result // Directly return the result from interact
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
