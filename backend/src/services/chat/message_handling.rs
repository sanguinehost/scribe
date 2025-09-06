use std::sync::Arc;

use diesel::{
    prelude::*,
    result::{DatabaseErrorKind, Error as DieselError},
}; // Added DatabaseErrorKind
use secrecy::{ExposeSecret, SecretBox};
use serde_json::Value; // Added Value
use tracing::{debug, error, info, instrument, trace, warn}; // Added trace
use uuid::Uuid; // Added SecretBox, ExposeSecret

use crate::{
    AppState, // Added AppState
    crypto,   // Added crypto
    errors::AppError,
    models::chats::{
        ChatMessage,
        DbInsertableChatMessage,
        MessageRole, // Changed NewChatMessagePayload to NewChatMessage
    },
    schema::{chat_messages, chat_sessions},
    services::{
        chat::message_variants,
        hybrid_token_counter::CountingMode,
    },
    state::DbPool, // Changed db::Db to state::DbPool
};

// This function will be in a sibling module
// This might be unused if not called
/// Gets messages for a specific chat session, verifying ownership.
#[instrument(skip(pool), err)]
pub async fn get_messages_for_session(
    pool: &DbPool, // Already correct
    user_id: Uuid,
    session_id: Uuid,
) -> Result<Vec<ChatMessage>, AppError> {
    // Changed DbChatMessage to ChatMessage
    let conn = pool.get().await?;
    conn.interact(move |conn| {
        let session_owner_id = chat_sessions::table
            .filter(chat_sessions::id.eq(session_id))
            .select(chat_sessions::user_id)
            .first::<Uuid>(conn)
            .optional()?;

        session_owner_id.map_or_else(
            || Err(AppError::NotFound("Chat session not found".into())),
            |owner_id| {
                if owner_id == user_id {
                    chat_messages::table
                        .filter(chat_messages::session_id.eq(session_id))
                        .select(<ChatMessage as SelectableHelper<diesel::pg::Pg>>::as_select()) // Changed DbChatMessage
                        .order(chat_messages::created_at.asc())
                        .load::<ChatMessage>(conn) // Changed DbChatMessage
                        .map_err(|e| {
                            error!("Failed to load messages for session {}: {}", session_id, e);
                            AppError::DatabaseQueryError(e.to_string())
                        })
                } else {
                    Err(AppError::Forbidden(
                        "Access denied to chat session".to_string(),
                    ))
                }
            },
        )
    })
    .await?
}
/// Internal helper to save a chat message within a transaction.
#[instrument(skip(conn), err)]
pub fn save_chat_message_internal(
    // Made function public
    conn: &mut PgConnection,
    message: DbInsertableChatMessage,
) -> Result<ChatMessage, AppError> {
    // Changed DbChatMessage to ChatMessage
    match diesel::insert_into(chat_messages::table)
        .values(&message)
        .returning(ChatMessage::as_select()) // Changed DbChatMessage
        .get_result::<ChatMessage>(conn) // Changed DbChatMessage
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
/// Parameters for saving a chat message.
pub struct SaveMessageParams<'a> {
    pub state: Arc<AppState>,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub message_type_enum: MessageRole, // Renamed for clarity (this is the enum)
    pub content: &'a str,               // This is the primary textual content
    pub role_str: Option<String>,       // ADDED: The string role ("user", "model", "assistant")
    pub parts: Option<Value>,           // ADDED: The structured parts from the request/generation
    pub attachments: Option<Value>,     // ADDED: Attachments
    pub user_dek_secret_box: Option<Arc<SecretBox<Vec<u8>>>>,
    pub model_name: String,                // Added model_name parameter
    pub raw_prompt_debug: Option<&'a str>, // Raw prompt for debugging (only for AI responses)
    pub status: crate::models::chats::MessageStatus, // Status of the message (streaming, completed, failed, partial)
    pub error_message: Option<String>,               // Error message if status is failed
    pub variant_of: Option<Uuid>, // If provided, create a variant of this message instead of new message
}

/// Saves a single chat message (user or assistant) and triggers background embedding.
#[instrument(skip(params), err)]
pub async fn save_message(params: SaveMessageParams<'_>) -> Result<ChatMessage, AppError> {
    let SaveMessageParams {
        state,
        session_id,
        user_id,
        message_type_enum,
        content,
        role_str,
        parts,
        attachments,
        user_dek_secret_box,
        model_name,
        raw_prompt_debug,
        status,
        error_message,
        variant_of,
    } = params;
    
    // Clone model_name early for later use in token tracking
    let model_name_for_tracking = model_name.clone();

    // Changed DbChatMessage to ChatMessage
    trace!(%session_id, %user_id, %message_type_enum, ?role_str, content_len = content.len(), dek_present = user_dek_secret_box.is_some(), %model_name, "Attempting to save message");

    if content.trim().is_empty()
        && parts
            .as_ref()
            .is_none_or(|p| p.is_null() || (p.is_array() && p.as_array().unwrap().is_empty()))
    {
        warn!(%session_id, %user_id, %message_type_enum, "Attempted to save an empty message (both content and parts). Skipping.");
        return Err(AppError::BadRequest(
            "Cannot save an empty message.".to_string(),
        ));
    }

    // CRITICAL FIX: If variant_of is provided, create ONLY a variant, don't save a new message
    if let Some(parent_message_id) = variant_of {
        info!(parent_message_id = %parent_message_id, "Creating variant instead of new message");
        
        if let Some(dek_arc) = &user_dek_secret_box {
            // Create the variant using the existing function
            let variant_result = message_variants::create_message_variant(
                state.clone(),
                parent_message_id,
                content, // Use the content directly (create_message_variant handles encryption)
                user_id,
                dek_arc,
            ).await;
            
            match variant_result {
                Ok(_variant) => {
                    info!(parent_message_id = %parent_message_id, "Successfully created message variant");
                    
                    // Return the parent message with updated variant metadata
                    // We need to fetch the updated parent message to return it
                    let pool = state.pool.clone();
                    let updated_parent = pool
                        .get()
                        .await
                        .map_err(|e| AppError::DbPoolError(e.to_string()))?
                        .interact(move |conn| {
                            use crate::schema::chat_messages::dsl::*;
                            chat_messages
                                .filter(id.eq(parent_message_id))
                                .filter(user_id.eq(user_id))
                                .select(ChatMessage::as_select())
                                .first::<ChatMessage>(conn)
                                .map_err(|e| AppError::DatabaseQueryError(format!("Parent message not found: {e}")))
                        })
                        .await
                        .map_err(|e| AppError::InternalServerErrorGeneric(e.to_string()))??;
                        
                    return Ok(updated_parent);
                },
                Err(e) => {
                    error!(parent_message_id = %parent_message_id, error = ?e, "Failed to create message variant");
                    return Err(e);
                }
            }
        } else {
            error!(parent_message_id = %parent_message_id, "Cannot create variant without user DEK");
            return Err(AppError::BadRequest("Cannot create variant without encryption key".to_string()));
        }
    }

    // Calculate token counts
    let mut prompt_tokens_val: Option<i32> = None;
    let mut completion_tokens_val: Option<i32> = None;

    if message_type_enum == MessageRole::User {
        // For user messages, count tokens for just the user's input content
        match state
            .token_counter
            .count_tokens(content, CountingMode::LocalOnly, Some(&model_name))
            .await
        {
            Ok(estimate) => {
                prompt_tokens_val = Some(i32::try_from(estimate.total).unwrap_or(i32::MAX));
            }
            Err(e) => warn!("Failed to count prompt tokens for user message: {}", e), // Log and continue
        }
    } else if message_type_enum == MessageRole::Assistant {
        // For assistant messages, count tokens for the assistant's response content
        match state
            .token_counter
            .count_tokens(content, CountingMode::LocalOnly, Some(&model_name))
            .await
        {
            Ok(estimate) => {
                completion_tokens_val = Some(i32::try_from(estimate.total).unwrap_or(i32::MAX));
            }
            Err(e) => warn!(
                "Failed to count completion tokens for assistant message: {}",
                e
            ), // Log and continue
        }

        // For assistant messages, if raw_prompt_debug is provided, count tokens for the full prompt
        // that was sent to the AI (including system prompt, RAG context, history, etc.)
        if let Some(raw_prompt) = raw_prompt_debug {
            info!(%session_id, raw_prompt_length = raw_prompt.len(), 
                  "Counting tokens for full AI prompt (system + RAG + history + user input)");

            match state
                .token_counter
                .count_tokens(raw_prompt, CountingMode::LocalOnly, Some(&model_name))
                .await
            {
                Ok(estimate) => {
                    // Override the prompt_tokens with the full prompt token count
                    prompt_tokens_val = Some(i32::try_from(estimate.total).unwrap_or(i32::MAX));
                    info!(%session_id, prompt_tokens = estimate.total, 
                          "Counted tokens for full AI prompt (system + RAG + history + user input)");
                }
                Err(e) => warn!(
                    "Failed to count full prompt tokens for assistant message: {}",
                    e
                ),
            }
        }
    }

    trace!(prompt_tokens=?prompt_tokens_val, completion_tokens=?completion_tokens_val, "Calculated token counts for message");

    let (content_to_save, nonce_to_save) = if let Some(dek_arc) = &user_dek_secret_box {
        trace!(%session_id, "User DEK present, encrypting message content.");
        // We encrypt the main `content` string. `parts` and `attachments` are stored as JSONB (plaintext in DB).
        let (ciphertext, nonce) = crypto::encrypt_gcm(content.as_bytes(), dek_arc) // Use imported crypto
            .map_err(|e| {
                error!(%session_id, "Failed to encrypt message content: {}", e);
                AppError::EncryptionError(format!("Failed to encrypt message: {e}"))
            })?;
        (ciphertext, Some(nonce))
    } else {
        trace!(%session_id, "User DEK not present, saving message content as plaintext.");
        (content.as_bytes().to_vec(), None)
    };

    let mut new_message_to_insert = DbInsertableChatMessage::new(
        session_id, // chat_id field in DbInsertableChatMessage
        user_id,
        message_type_enum, // msg_type field in DbInsertableChatMessage
        content_to_save,   // content field
        nonce_to_save,     // content_nonce field
        model_name,        // model_name field
    )
    .with_status(status);

    if let Some(err_msg) = error_message {
        new_message_to_insert = new_message_to_insert.with_error_message(err_msg);
    }

    if let Some(role) = role_str {
        new_message_to_insert = new_message_to_insert.with_role(role);
    }
    if let Some(parts_val) = parts {
        new_message_to_insert = new_message_to_insert.with_parts(parts_val);
    }
    if let Some(attachments_val) = attachments {
        new_message_to_insert = new_message_to_insert.with_attachments(attachments_val);
    }
    new_message_to_insert =
        new_message_to_insert.with_token_counts(prompt_tokens_val, completion_tokens_val);

    // Encrypt and add raw prompt debug information if provided and user has DEK
    if let Some(raw_prompt) = raw_prompt_debug {
        info!(%session_id, raw_prompt_length = raw_prompt.len(), "Raw prompt debug provided for encryption");
        if let Some(dek_arc) = &user_dek_secret_box {
            trace!(%session_id, "Encrypting raw prompt debug information");
            match crypto::encrypt_gcm(raw_prompt.as_bytes(), dek_arc) {
                Ok((raw_prompt_ciphertext, raw_prompt_nonce)) => {
                    info!(%session_id, ciphertext_length = raw_prompt_ciphertext.len(), nonce_length = raw_prompt_nonce.len(), "Successfully encrypted raw prompt debug");
                    new_message_to_insert = new_message_to_insert
                        .with_raw_prompt(Some(raw_prompt_ciphertext), Some(raw_prompt_nonce));
                }
                Err(e) => {
                    error!(%session_id, "Failed to encrypt raw prompt debug: {}", e);
                    // We don't fail the message save due to raw prompt encryption error
                    // Raw prompt is debug information, not critical
                }
            }
        } else {
            warn!(%session_id, "Raw prompt debug provided but no DEK available, skipping encryption");
        }
    } else {
        info!(%session_id, "No raw prompt debug provided for this message");
    }

    let db_pool: DbPool = state.pool.clone(); // Ensure DbPool type
    let saved_message_db = db_pool
        .get()
        .await?
        .interact(move |conn| save_chat_message_internal(conn, new_message_to_insert))
        .await??;

    debug!(message_id = %saved_message_db.id, %session_id, "Message saved to DB successfully.");

    // Update cumulative token counts for both chat session and user
    // Convert Option<i32> to i32, defaulting to 0 for None values
    let prompt_tokens = prompt_tokens_val.unwrap_or(0);
    let completion_tokens = completion_tokens_val.unwrap_or(0);

    // Only update if we have at least some tokens to count
    if prompt_tokens > 0 || completion_tokens > 0 {
        info!(session_id = %session_id, user_id = %user_id, prompt_tokens = prompt_tokens, completion_tokens = completion_tokens, "Updating cumulative token counts");
        
        // Calculate estimated cost in cents based on model pricing
        let estimated_cost_cents = calculate_token_cost_cents(prompt_tokens, completion_tokens, &model_name_for_tracking);
        
        let db_pool_for_tokens: DbPool = state.pool.clone();
        let session_id_for_tokens = session_id;
        let user_id_for_tokens = user_id;
        
        // Spawn async task to update token counts to avoid blocking message save
        tokio::spawn(async move {
            if let Err(e) = update_cumulative_token_counts(
                &db_pool_for_tokens,
                session_id_for_tokens,
                user_id_for_tokens,
                prompt_tokens,
                completion_tokens,
                estimated_cost_cents,
            ).await {
                error!(session_id = %session_id_for_tokens, user_id = %user_id_for_tokens, error = ?e, "Failed to update cumulative token counts");
            } else {
                info!(session_id = %session_id_for_tokens, user_id = %user_id_for_tokens, "Successfully updated cumulative token counts");
            }
        });
    } else {
        debug!(session_id = %session_id, "No token counts to update (both prompt_tokens and completion_tokens are 0)");
    }

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
                    crate::auth::session_dek::SessionDek(SecretBox::new(Box::new(secret_bytes))) // Create new SecretBox and SessionDek, changed back to Box::new
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

/// Calculate estimated cost in cents based on model pricing
fn calculate_token_cost_cents(prompt_tokens: i32, completion_tokens: i32, model_name: &str) -> i32 {
    // Gemini pricing (per 1M tokens) - Updated with correct official pricing
    let (input_cost, output_cost) = match model_name {
        "gemini-2.5-flash" | "gemini-2.5-flash-lite" => (0.3, 2.5),
        "gemini-2.5-pro" => (1.25, 10.0), // For prompts <= 200k tokens
        "gemini-2.5-flash-lite-preview" => (0.1, 0.4),
        _ => {
            // Default to flash pricing for unknown models
            warn!("Unknown model '{}', using gemini-2.5-flash pricing", model_name);
            (0.3, 2.5)
        }
    };

    // Calculate cost in dollars and convert to cents
    let input_cost_dollars = (prompt_tokens as f64 / 1_000_000.0) * input_cost;
    let output_cost_dollars = (completion_tokens as f64 / 1_000_000.0) * output_cost;
    let total_cost_dollars = input_cost_dollars + output_cost_dollars;
    let total_cost_cents = (total_cost_dollars * 100.0).round() as i32;

    trace!(model_name = model_name, prompt_tokens = prompt_tokens, completion_tokens = completion_tokens, 
           input_cost_dollars = input_cost_dollars, output_cost_dollars = output_cost_dollars, 
           total_cost_cents = total_cost_cents, "Calculated token cost");

    total_cost_cents
}

/// Update cumulative token counts for both chat session and user
async fn update_cumulative_token_counts(
    pool: &crate::PgPool,
    session_id: uuid::Uuid,
    user_id: uuid::Uuid,
    prompt_tokens: i32,
    completion_tokens: i32,
    estimated_cost_cents: i32,
) -> Result<(), AppError> {
    use crate::schema::{chat_sessions, users};
    use diesel::prelude::*;
    
    let conn = pool.get().await?;
    
    conn.interact(move |conn| {
        // Start a transaction to ensure atomicity
        conn.transaction::<_, diesel::result::Error, _>(|conn| {
            // Update chat session cumulative counts
            diesel::update(chat_sessions::table.find(session_id))
                .set((
                    chat_sessions::total_prompt_tokens.eq(
                        chat_sessions::total_prompt_tokens + prompt_tokens
                    ),
                    chat_sessions::total_completion_tokens.eq(
                        chat_sessions::total_completion_tokens + completion_tokens
                    ),
                    chat_sessions::estimated_cost_cents.eq(
                        chat_sessions::estimated_cost_cents + estimated_cost_cents
                    ),
                    chat_sessions::tokens_counted_at.eq(diesel::dsl::now),
                ))
                .execute(conn)?;

            // Update user cumulative counts
            diesel::update(users::table.find(user_id))
                .set((
                    users::total_prompt_tokens.eq(
                        users::total_prompt_tokens + (prompt_tokens as i64)
                    ),
                    users::total_completion_tokens.eq(
                        users::total_completion_tokens + (completion_tokens as i64)
                    ),
                    users::total_token_cost_cents.eq(
                        users::total_token_cost_cents + (estimated_cost_cents as i64)
                    ),
                    users::token_usage_updated_at.eq(diesel::dsl::now),
                ))
                .execute(conn)?;

            Ok(())
        })
    })
    .await
    .map_err(AppError::from)?
    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

    Ok(())
}
