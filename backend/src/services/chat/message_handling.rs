use std::sync::Arc;

use diesel::{
    prelude::*,
    result::{DatabaseErrorKind, Error as DieselError},
}; // Added DatabaseErrorKind
use secrecy::{ExposeSecret, SecretBox};
use serde_json::Value; // Added Value
use tracing::{debug, error, info, instrument, trace, warn}; // Added trace
                                                            // Added SecretBox, ExposeSecret

use crate::{
    crypto, // Added crypto
    errors::AppError,
    models::chats::{
        ChatMessage,
        DbInsertableChatMessage,
        MessageRole, // Changed NewChatMessagePayload to NewChatMessage
    },
    schema::{chat_messages, chat_sessions},
    services::{chat::message_variants, hybrid_token_counter::CountingMode},
    state::DbPool, // Changed db::Db to state::DbPool
    AppState,      // Added AppState
};

/// Get hardcoded pricing for a model when config file is unavailable.
/// Returns (input_rate_per_million, output_rate_per_million) in dollars.
fn get_hardcoded_pricing(model_name: &str) -> (f64, f64) {
    match model_name {
        "gemini-3-pro-preview" => (2.00, 12.00),
        "gemini-3-flash-preview" => (0.50, 3.00),
        "gemini-2.5-flash-lite" | "gemini-2.5-flash-lite-preview-09-2025" => (0.10, 0.40),
        "gemini-2.5-flash" | "gemini-2.5-flash-preview-09-2025" => (0.30, 2.50),
        "gemini-2.5-pro" => (1.25, 10.00),
        "gemini-2.0-flash-experimental" => (0.10, 0.40),
        _ => {
            tracing::warn!(
                "Unknown model '{}', using gemini-2.5-flash-lite pricing as fallback",
                model_name
            );
            (0.10, 0.40)
        }
    }
}

// This function will be in a sibling module
// This might be unused if not called
/// Gets messages for a specific chat session, verifying ownership.
#[instrument(skip(pool), err)]
pub async fn get_messages_for_session(
    pool: &DbPool, // Already correct
    user_id: crate::db::DbId,
    session_id: crate::db::DbId,
) -> Result<Vec<ChatMessage>, AppError> {
    // Changed DbChatMessage to ChatMessage
    crate::db::with_conn(pool, move |conn| {
        let session_owner_id = chat_sessions::table
            .filter(chat_sessions::id.eq(session_id))
            .select(chat_sessions::user_id)
            .first::<crate::db::DbId>(conn)
            .optional()?;

        session_owner_id.map_or_else(
            || Err(AppError::NotFound("Chat session not found".into())),
            |owner_id| {
                if owner_id == user_id {
                    // Load full ChatMessage using as_select() to avoid SQLite tuple size limits
                    chat_messages::table
                        .filter(chat_messages::session_id.eq(session_id))
                        .order(chat_messages::created_at.asc())
                        .select(ChatMessage::as_select())
                        .load::<ChatMessage>(conn)
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
    .await
}
/// Internal helper to save a chat message within a transaction.
#[instrument(skip(conn), err)]
pub fn save_chat_message_internal(
    // Made function public
    conn: &mut crate::DbConnection,
    message: DbInsertableChatMessage,
) -> Result<ChatMessage, AppError> {
    debug!(
        ?message,
        "Attempting to insert chat message into database (save_chat_message_internal)"
    );

    #[cfg(feature = "postgres-backend")]
    {
        use diesel::prelude::*;
        match diesel::insert_into(chat_messages::table)
            .values(&message)
            .returning(ChatMessage::as_select())
            .get_result::<ChatMessage>(conn)
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

    #[cfg(feature = "sqlite-backend")]
    {
        use diesel::prelude::*;
        // SQLite doesn't support RETURNING, so we generate ID first then query back
        let new_id = crate::db::DbId::new_v4();

        match diesel::insert_into(chat_messages::table)
            .values(&message)
            .execute(conn)
        {
            Ok(_) => {
                // Query back the inserted message - use the session_id and timestamp as a proxy
                // since we don't have the generated ID
                match chat_messages::table
                    .filter(chat_messages::session_id.eq(message.chat_id))
                    .order(chat_messages::created_at.desc())
                    .select(ChatMessage::as_select())
                    .first::<ChatMessage>(conn)
                {
                    Ok(inserted_message) => {
                        info!(
                            message_id = %inserted_message.id,
                            session_id = %inserted_message.session_id,
                            prompt_tokens = ?inserted_message.prompt_tokens,
                            completion_tokens = ?inserted_message.completion_tokens,
                            "Chat message successfully inserted (SQLite query returned)"
                        );
                        Ok(inserted_message)
                    }
                    Err(e) => {
                        error!(session_id = %message.chat_id, error = ?e, "Error querying inserted chat message");
                        Err(AppError::DatabaseQueryError(e.to_string()))
                    }
                }
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
}
/// Parameters for saving a chat message.
pub struct SaveMessageParams<'a> {
    pub state: Arc<AppState>,
    pub session_id: crate::db::DbId,
    pub user_id: crate::db::DbId,
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
    pub variant_of: Option<crate::db::DbId>, // If provided, create a variant of this message instead of new message
    pub charge_credits: bool, // Whether to charge credits for this message (false for free tier Flash within limits)
    pub credits_cost_override: Option<crate::db::DbDecimal>, // Optional override for credits_cost calculation (from pre-calculated actual_credit_cost)
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
        charge_credits,
        credits_cost_override,
    } = params;

    // Clone model_name early for later use in token tracking
    let model_name_for_tracking = model_name.clone();

    // Changed DbChatMessage to ChatMessage
    trace!(%session_id, %user_id, %message_type_enum, ?role_str, content_len = content.len(), dek_present = user_dek_secret_box.is_some(), %model_name, "Attempting to save message");
    debug!(
        session_id = %session_id,
        user_id = %user_id,
        message_type = ?message_type_enum,
        role = ?role_str,
        content_len = content.len(),
        model_name = %model_name,
        status = ?status,
        "Detailed save_message params"
    );

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

    // Calculate token counts FIRST (before variant check)
    // This ensures variants get their own token counts
    let mut prompt_tokens_val: Option<i32> = None;
    let mut completion_tokens_val: Option<i32> = None;

    // Always calculate token counts (needed for frontend streaming completion even if free)
    // For user messages, count tokens for just the user's input content
    if message_type_enum == MessageRole::User {
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

    // CRITICAL FIX: If variant_of is provided, create ONLY a variant, don't save a new message
    if let Some(parent_message_id) = variant_of {
        info!(parent_message_id = %parent_message_id, "Creating variant instead of new message");

        if let Some(dek_arc) = &user_dek_secret_box {
            // Create the variant using the existing function, now with token counts AND raw_prompt
            let variant_result = message_variants::create_message_variant(
                state.clone(),
                parent_message_id,
                content, // Use the content directly (create_message_variant handles encryption)
                user_id,
                dek_arc,
                prompt_tokens_val,
                completion_tokens_val,
                Some(model_name.clone()),
                raw_prompt_debug, // Pass through the raw_prompt for the variant
                None, // game_state will be updated later by narrative service if applicable
            )
            .await;

            match variant_result {
                Ok(_variant) => {
                    info!(parent_message_id = %parent_message_id, "Successfully created message variant");

                    // Return the parent message with updated variant metadata
                    // We need to fetch the updated parent message to return it
                    let pool = state.pool.clone();
                    let updated_parent = crate::db::with_conn(&pool, move |conn| {
                        use crate::schema::chat_messages::dsl::*;
                        // Load full ChatMessage using as_select() to avoid SQLite tuple size limits
                        chat_messages
                            .filter(id.eq(parent_message_id))
                            .filter(user_id.eq(user_id))
                            .select(ChatMessage::as_select())
                            .first::<ChatMessage>(conn)
                            .map_err(|e| {
                                AppError::DatabaseQueryError(format!(
                                    "Parent message not found: {e}"
                                ))
                            })
                    })
                    .await?;

                    return Ok(updated_parent);
                }
                Err(e) => {
                    error!(parent_message_id = %parent_message_id, error = ?e, "Failed to create message variant");
                    return Err(e);
                }
            }
        } else {
            error!(parent_message_id = %parent_message_id, "Cannot create variant without user DEK");
            return Err(AppError::BadRequest(
                "Cannot create variant without encryption key".to_string(),
            ));
        }
    }

    // ALWAYS calculate actual cost (base Google API cost) - no feature flags
    // This ensures cost tracking works in local deployments without payment feature
    let (actual_cost_dollars, modified_cost_dollars, credit_cost_val, credits_charged_val) =
        if prompt_tokens_val.is_some() || completion_tokens_val.is_some() {
            // Try to load token-based pricing from config, with multiple path fallbacks
            let config_paths = [
                "backend/config/subscription_tiers.json",
                "config/subscription_tiers.json",
                "../backend/config/subscription_tiers.json",
            ];

            let mut config_content = String::new();
            for path in &config_paths {
                if let Ok(content) = std::fs::read_to_string(path) {
                    config_content = content;
                    tracing::debug!("Loaded pricing config from: {}", path);
                    break;
                }
            }

            // Helper to parse JSON value that might be string or number
            fn parse_json_f64(val: &serde_json::Value, default: f64) -> f64 {
                if let Some(n) = val.as_f64() {
                    n
                } else if let Some(s) = val.as_str() {
                    s.parse::<f64>().unwrap_or(default)
                } else {
                    default
                }
            }

            let prompt_tokens = prompt_tokens_val.unwrap_or(0);
            let completion_tokens = completion_tokens_val.unwrap_or(0);

            // Get pricing rates - try config first, fall back to hardcoded values
            let (input_rate_per_million, output_rate_per_million) = if !config_content.is_empty() {
                if let Ok(tiers_config) = serde_json::from_str::<crate::DbJson>(&config_content) {
                    let token_pricing = &tiers_config["credit_system"]["token_pricing"];
                    let base_costs = &token_pricing["base_api_costs"][&model_name];

                    if !base_costs.is_null() {
                        (
                            parse_json_f64(&base_costs["input_per_million"], 0.1),
                            parse_json_f64(&base_costs["output_per_million"], 0.4),
                        )
                    } else {
                        // Model not in config, use hardcoded fallback
                        tracing::warn!(
                            "Model '{}' not found in pricing config, using hardcoded pricing",
                            model_name
                        );
                        get_hardcoded_pricing(&model_name)
                    }
                } else {
                    tracing::warn!("Failed to parse pricing config JSON, using hardcoded pricing");
                    get_hardcoded_pricing(&model_name)
                }
            } else {
                tracing::warn!(
                    "Could not load pricing config from any path, using hardcoded pricing"
                );
                get_hardcoded_pricing(&model_name)
            };

            // Apply tiered pricing for Gemini 3 Pro if tokens exceed 200k
            let (effective_input_rate, effective_output_rate) =
                if model_name == "gemini-3-pro-preview" && prompt_tokens > 200_000 {
                    (4.00, 18.00)
                } else {
                    (input_rate_per_million, output_rate_per_million)
                };

            // Calculate BASE API cost (NO markup) - ALWAYS calculated
            let input_cost_dollars = (prompt_tokens as f64 / 1_000_000.0) * effective_input_rate;
            let output_cost_dollars =
                (completion_tokens as f64 / 1_000_000.0) * effective_output_rate;
            let actual_cost = input_cost_dollars + output_cost_dollars;

            tracing::info!(
                model_name = %model_name,
                prompt_tokens = prompt_tokens,
                completion_tokens = completion_tokens,
                input_rate = effective_input_rate,
                output_rate = effective_output_rate,
                actual_cost_dollars = actual_cost,
                "Calculated message cost"
            );

            // Calculate modified cost and credit cost ONLY if payment feature is enabled
            #[cfg(feature = "payment")]
            {
                // Get markup percentage (default 20%)
                let markup_percentage = 20.0; // Hardcoded for simplicity
                let markup_multiplier = 1.0 + (markup_percentage / 100.0);

                // Modified cost = actual cost + markup
                let modified_cost = actual_cost * markup_multiplier;

                // Credit cost: credits derived from MARKED-UP cost
                // 1 credit = $0.02 (based on Paddle pricing: 250 credits = $5)
                let credit_cost = (modified_cost / 0.02).ceil() as i32;

                // Credits charged: only if charge_credits flag is set
                let credits_charged = if charge_credits { credit_cost } else { 0 };

                trace!(
                    model_name = %model_name,
                    prompt_tokens = prompt_tokens,
                    completion_tokens = completion_tokens,
                    actual_cost_dollars = actual_cost,
                    markup_percentage = markup_percentage,
                    modified_cost_dollars = modified_cost,
                    credit_cost = credit_cost,
                    credits_charged = credits_charged,
                    "Calculated all cost values with payment feature enabled"
                );

                (actual_cost, modified_cost, credit_cost, credits_charged)
            }

            #[cfg(not(feature = "payment"))]
            {
                trace!(
                    model_name = %model_name,
                    prompt_tokens = prompt_tokens,
                    completion_tokens = completion_tokens,
                    actual_cost_dollars = actual_cost,
                    "Calculated actual cost (payment feature disabled)"
                );

                // No payment feature: only actual cost is calculated
                (actual_cost, 0.0, 0, 0)
            }
        } else {
            (0.0, 0.0, 0, 0)
        };

    // SQLite uses f64 directly, PostgreSQL uses BigDecimal
    #[cfg(feature = "sqlite-backend")]
    let actual_cost_bd = {
        use bigdecimal::BigDecimal;
        use std::convert::TryFrom;
        BigDecimal::try_from(actual_cost_dollars)
            .map(crate::db::DbDecimal::from)
            .unwrap_or_else(|_| crate::db::DbDecimal::from(0))
    };
    #[cfg(feature = "sqlite-backend")]
    let modified_cost_bd = {
        use bigdecimal::BigDecimal;
        use std::convert::TryFrom;
        BigDecimal::try_from(modified_cost_dollars)
            .map(crate::db::DbDecimal::from)
            .unwrap_or_else(|_| crate::db::DbDecimal::from(0))
    };
    #[cfg(feature = "sqlite-backend")]
    let actual_charge_bd = crate::db::DbDecimal::from(0); // TODO: Implement actual charge tracking

    #[cfg(feature = "postgres-backend")]
    {
        use bigdecimal::BigDecimal;
        use std::str::FromStr;
    }
    #[cfg(feature = "postgres-backend")]
    let actual_cost_bd = credits_cost_override.clone().unwrap_or_else(|| {
        use bigdecimal::BigDecimal;
        use std::str::FromStr;
        BigDecimal::from_str(&actual_cost_dollars.to_string())
            .map(crate::db::DbDecimal::from)
            .unwrap_or_else(|_| crate::db::DbDecimal::from(0))
    });
    #[cfg(feature = "postgres-backend")]
    let modified_cost_bd = {
        use bigdecimal::BigDecimal;
        use std::str::FromStr;
        BigDecimal::from_str(&modified_cost_dollars.to_string())
            .map(crate::db::DbDecimal::from)
            .unwrap_or_else(|_| crate::db::DbDecimal::from(0))
    };
    #[cfg(feature = "postgres-backend")]
    let actual_charge_bd = crate::db::DbDecimal::from(0); // TODO: Implement actual charge tracking

    // For backwards compatibility with old code
    #[cfg(all(feature = "payment", feature = "sqlite-backend"))]
    let (credits_cost, credits_charged) = (credit_cost_val, credits_charged_val);
    #[cfg(all(feature = "payment", feature = "postgres-backend"))]
    let (credits_cost, credits_charged) = (actual_cost_bd.clone(), credits_charged_val);

    #[cfg(all(not(feature = "payment"), feature = "sqlite-backend"))]
    let (credits_cost, credits_charged) = (0_i32, 0);
    #[cfg(all(not(feature = "payment"), feature = "postgres-backend"))]
    let (credits_cost, credits_charged) = (actual_cost_bd.clone(), 0);

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

    // Generate new ID for SQLite (no DEFAULT in schema)
    let message_id = crate::db::DbId::new();

    #[cfg(feature = "sqlite-backend")]
    let mut new_message_to_insert = DbInsertableChatMessage::new(
        message_id, // id field - CRITICAL for SQLite (7 args total)
        session_id, // chat_id field in DbInsertableChatMessage
        user_id,
        message_type_enum, // msg_type field in DbInsertableChatMessage
        content_to_save,   // content field
        nonce_to_save,     // content_nonce field
        model_name,        // model_name field
    )
    .with_status(status);

    #[cfg(feature = "postgres-backend")]
    let mut new_message_to_insert = DbInsertableChatMessage::new(
        session_id, // chat_id field (6 args total - no id)
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
        new_message_to_insert = new_message_to_insert.with_parts(parts_val.into());
    }
    if let Some(attachments_val) = attachments {
        new_message_to_insert = new_message_to_insert.with_attachments(attachments_val.into());
    }
    new_message_to_insert =
        new_message_to_insert.with_token_counts(prompt_tokens_val, completion_tokens_val);

    // Clone cost values early for later use in spawned task (before they're moved into with_cost_tracking)
    #[cfg(all(feature = "payment", feature = "postgres-backend"))]
    let actual_cost_bd_clone = actual_cost_bd.clone();
    #[cfg(all(feature = "payment", feature = "postgres-backend"))]
    let modified_cost_bd_clone = modified_cost_bd.clone();
    #[cfg(all(feature = "payment", feature = "postgres-backend"))]
    let actual_charge_bd_clone = actual_charge_bd.clone();

    // SQLite uses f64, but update_cumulative_token_counts expects DbDecimal
    #[cfg(feature = "sqlite-backend")]
    let actual_cost_bd_clone = {
        use bigdecimal::BigDecimal;
        use std::str::FromStr;
        let bd = BigDecimal::from_str(&actual_cost_bd.to_string())
            .unwrap_or_else(|_| BigDecimal::from(0));
        crate::db::DbDecimal::from_bigdecimal(bd)
    };
    #[cfg(feature = "sqlite-backend")]
    let modified_cost_bd_clone = {
        use bigdecimal::BigDecimal;
        use std::str::FromStr;
        let bd = BigDecimal::from_str(&modified_cost_bd.to_string())
            .unwrap_or_else(|_| BigDecimal::from(0));
        crate::db::DbDecimal::from_bigdecimal(bd)
    };
    #[cfg(feature = "sqlite-backend")]
    let actual_charge_bd_clone = {
        use bigdecimal::BigDecimal;
        use std::str::FromStr;
        let bd = BigDecimal::from_str(&actual_charge_bd.to_string())
            .unwrap_or_else(|_| BigDecimal::from(0));
        crate::db::DbDecimal::from_bigdecimal(bd)
    };

    // Set all cost tracking fields using the new method
    new_message_to_insert = new_message_to_insert.with_cost_tracking(
        actual_cost_bd.clone(),
        modified_cost_bd.clone(),
        credit_cost_val,
        actual_charge_bd.clone(),
        credits_charged_val,
    );

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
    let saved_message_db = crate::db::with_conn(&db_pool, move |conn| {
        save_chat_message_internal(conn, new_message_to_insert)
    })
    .await?;

    debug!(message_id = %saved_message_db.id, %session_id, "Message saved to DB successfully.");

    // Update cumulative token counts for both chat session and user
    // Convert Option<i32> to i32, defaulting to 0 for None values
    let prompt_tokens = prompt_tokens_val.unwrap_or(0);
    let completion_tokens = completion_tokens_val.unwrap_or(0);

    // Only update if we have at least some tokens to count
    if prompt_tokens > 0 || completion_tokens > 0 {
        info!(session_id = %session_id, user_id = %user_id, prompt_tokens = prompt_tokens, completion_tokens = completion_tokens, "Updating cumulative token counts");

        // Calculate estimated cost in cents based on model pricing
        let estimated_cost_cents =
            calculate_token_cost_cents(prompt_tokens, completion_tokens, &model_name_for_tracking);

        let db_pool_for_tokens: DbPool = state.pool.clone();
        let session_id_for_tokens = session_id;
        let user_id_for_tokens = user_id;

        // Clone config for payment tracking outside the spawned task
        #[cfg(feature = "payment")]
        let state_config_for_payment = state.config.clone();

        // Calculate costs for this task
        let actual_cost_for_task = actual_cost_bd;
        let modified_cost_for_task = modified_cost_bd;
        let credit_cost_for_task = credit_cost_val;
        // Calculate charge for this task (using the modified cost which includes markup)
        let actual_charge_for_task = actual_charge_bd;
        let credits_charged_for_task = credits_charged_val;

        // Spawn async task to update token counts to avoid blocking message save
        tokio::spawn(async move {
            let update_result = update_cumulative_token_counts(
                &db_pool_for_tokens,
                session_id_for_tokens,
                user_id_for_tokens,
                prompt_tokens,
                completion_tokens,
                estimated_cost_cents,
                actual_cost_for_task,
                modified_cost_for_task,
                credit_cost_for_task,
                actual_charge_for_task,
                credits_charged_for_task,
            )
            .await;

            if let Err(e) = update_result {
                error!(session_id = %session_id_for_tokens, user_id = %user_id_for_tokens, error = ?e, "Failed to update cumulative token counts");
            } else {
                info!(session_id = %session_id_for_tokens, user_id = %user_id_for_tokens, "Successfully updated cumulative token counts");
            }

            // Also track usage in payment_usage_tracking table for billing
            #[cfg(feature = "payment")]
            {
                use crate::services::payment::usage_tracking_service::{
                    UsageMetadata, UsageTrackingService,
                };
                use crate::services::EncryptionService;
                use std::collections::HashMap;

                let total_tokens = prompt_tokens + completion_tokens;
                if total_tokens > 0 {
                    let model_name_clone = model_name_for_tracking.clone();

                    let track_result = crate::db::with_conn(&db_pool_for_tokens, move |conn| {
                        let usage_service = UsageTrackingService::new(
                            (*state_config_for_payment).clone(),
                            EncryptionService::new(),
                        );

                        // Create metadata about this token usage
                        let mut model_usage = HashMap::new();
                        model_usage.insert(model_name_clone, total_tokens);

                        let mut feature_usage = HashMap::new();
                        feature_usage.insert("chat_message".to_string(), 1);

                        let metadata = UsageMetadata {
                            model_usage,
                            feature_usage,
                            request_count: 1,
                            last_activity: crate::DbTimestamp::now(),
                        };

                        usage_service
                            .track_usage_sync(
                                conn,
                                user_id_for_tokens,
                                None, // subscription_id will be looked up by the service
                                total_tokens,
                                Some(metadata),
                            )
                            .map_err(|e| {
                                crate::errors::AppError::DatabaseQueryError(format!(
                                    "Failed to track usage: {}",
                                    e
                                ))
                            })
                    })
                    .await;

                    match track_result {
                        Ok(_) => {
                            info!(session_id = %session_id_for_tokens, user_id = %user_id_for_tokens, total_tokens = total_tokens, "Successfully tracked payment usage");
                        }
                        Err(e) => {
                            error!(session_id = %session_id_for_tokens, user_id = %user_id_for_tokens, error = ?e, "Failed to track payment usage");
                        }
                    }
                }
            }
        });
    } else {
        debug!(session_id = %session_id, "No token counts to update (both prompt_tokens and completion_tokens are 0)");
    }

    // Asynchronously trigger RAG processing if the message is from the user and RAG is enabled for the session/globally.
    // Asynchronously trigger RAG processing for all completed messages
    if saved_message_db.status == "completed" {
        let embedding_service = state.embedding_pipeline_service.clone();
        let app_state_clone_for_rag = state.clone();
        let message_for_rag = saved_message_db.clone(); // Clone for the async task
                                                        // Clone the DEK for the spawned task. user_dek_secret_box is Option<Arc<SecretBox<Vec<u8>>>>
        let dek_for_rag_task = user_dek_secret_box.clone();

        tokio::spawn(async move {
            info!(message_id = %message_for_rag.id, session_id = %message_for_rag.session_id, message_type = ?message_for_rag.message_type, "Spawning RAG processing task for message.");

            let session_dek_for_embedding: Option<crate::auth::session_dek::SessionDek> =
                dek_for_rag_task.map(|arc_sb| {
                    let secret_bytes = arc_sb.expose_secret().clone(); // Clone the Vec<u8>
                    crate::auth::session_dek::SessionDek(SecretBox::new(Box::new(secret_bytes)))
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
            warn!(
                "Unknown model '{}', using gemini-2.5-flash pricing",
                model_name
            );
            (0.3, 2.5)
        }
    };

    // Calculate cost in dollars and convert to cents
    let input_cost_dollars = (prompt_tokens as f64 / 1_000_000.0) * input_cost;
    let output_cost_dollars = (completion_tokens as f64 / 1_000_000.0) * output_cost;
    let total_cost_dollars = input_cost_dollars + output_cost_dollars;
    let total_cost_cents = (total_cost_dollars * 100.0).round() as i32;

    trace!(
        model_name = model_name,
        prompt_tokens = prompt_tokens,
        completion_tokens = completion_tokens,
        input_cost_dollars = input_cost_dollars,
        output_cost_dollars = output_cost_dollars,
        total_cost_cents = total_cost_cents,
        "Calculated token cost"
    );

    total_cost_cents
}

async fn update_cumulative_token_counts(
    pool: &crate::db::DbPool,
    session_id: crate::db::DbId,
    user_id: crate::db::DbId,
    prompt_tokens: i32,
    completion_tokens: i32,
    estimated_cost_cents: i32,
    actual_cost: crate::db::DbDecimal,
    modified_cost: crate::db::DbDecimal,
    credit_cost: i32,
    actual_charge: crate::db::DbDecimal,
    _credits_charged: i32,
) -> Result<(), AppError> {
    use crate::schema::{chat_sessions, users};
    use diesel::prelude::*;

    tracing::debug!(
        session_id = %session_id,
        prompt_tokens = prompt_tokens,
        completion_tokens = completion_tokens,
        actual_cost = ?actual_cost,
        modified_cost = ?modified_cost,
        "Updating cumulative token counts"
    );

    crate::db::with_conn(pool, move |conn| {
        // Start a transaction to ensure atomicity
        conn.transaction::<_, diesel::result::Error, _>(|conn| {
            // Prepare values for update based on backend
            #[cfg(feature = "sqlite-backend")]
            let (actual_cost_val, modified_cost_val, actual_charge_val, credits_used_delta) = {
                use bigdecimal::ToPrimitive;
                let cost_f64 = actual_cost.to_f64().unwrap_or(0.0);
                (
                    cost_f64,
                    modified_cost.to_f64().unwrap_or(0.0),
                    actual_charge.to_f64().unwrap_or(0.0),
                    cost_f64 as i32,
                )
            };

            #[cfg(feature = "postgres-backend")]
            let (actual_cost_val, modified_cost_val, actual_charge_val, credits_used_delta) = (
                actual_cost.clone(),
                modified_cost,
                actual_charge,
                actual_cost,
            );

            // Update chat session cumulative counts
            diesel::update(chat_sessions::table.find(session_id))
                .set((
                    chat_sessions::total_prompt_tokens
                        .eq(chat_sessions::total_prompt_tokens + prompt_tokens),
                    chat_sessions::total_completion_tokens
                        .eq(chat_sessions::total_completion_tokens + completion_tokens),
                    chat_sessions::estimated_cost_cents
                        .eq(chat_sessions::estimated_cost_cents + estimated_cost_cents),
                    // NEW: Track all four cost values properly
                    chat_sessions::total_actual_cost
                        .eq(chat_sessions::total_actual_cost + actual_cost_val.clone()),
                    chat_sessions::total_modified_cost
                        .eq(chat_sessions::total_modified_cost + modified_cost_val.clone()),
                    chat_sessions::total_credit_cost
                        .eq(chat_sessions::total_credit_cost + credit_cost),
                    chat_sessions::total_actual_charge
                        .eq(chat_sessions::total_actual_charge + actual_charge_val.clone()),
                    // Keep total_credits_used for backwards compatibility (uses actual_cost)
                    // Note: total_credits_used in SQLite schema is Integer, in Postgres it is Numeric.
                    // We use credits_used_delta which is typed correctly for each backend.
                    chat_sessions::total_credits_used
                        .eq(chat_sessions::total_credits_used + credits_used_delta),
                    chat_sessions::tokens_counted_at.eq(diesel::dsl::now),
                ))
                .execute(conn)?;

            // Update user cumulative counts
            // Note: PostgreSQL uses i64 (BigInt), SQLite uses i32 (Integer) for DbInt
            #[cfg(feature = "postgres-backend")]
            let (prompt_db, completion_db, cost_db) = (
                prompt_tokens as i64,
                completion_tokens as i64,
                estimated_cost_cents as i64,
            );
            #[cfg(feature = "sqlite-backend")]
            let (prompt_db, completion_db, cost_db) = (
                prompt_tokens,        // Already i32, matches SQLite Integer
                completion_tokens,    // Already i32, matches SQLite Integer
                estimated_cost_cents, // Already i32, matches SQLite Integer
            );

            diesel::update(users::table.find(user_id))
                .set((
                    users::total_prompt_tokens.eq(users::total_prompt_tokens + prompt_db),
                    users::total_completion_tokens
                        .eq(users::total_completion_tokens + completion_db),
                    users::total_token_cost_cents.eq(users::total_token_cost_cents + cost_db),
                    users::token_usage_updated_at.eq(diesel::dsl::now),
                ))
                .execute(conn)?;

            Ok(())
        })
        .map_err(Into::into)
    })
    .await
    .map_err(|e| AppError::DatabaseQueryError(e.to_string()))?;

    Ok(())
}
