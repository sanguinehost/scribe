use std::{cmp::min, pin::Pin, sync::Arc};

use bigdecimal::{BigDecimal, ToPrimitive};
use diesel::{prelude::*, result::Error as DieselError};
use futures_util::Stream; // Required for stream_ai_response_and_save_message
use futures_util::StreamExt; // Required for .next() on streams
use genai::chat::{
    ChatMessage as GenAiChatMessage, ChatOptions as GenAiChatOptions,
    ChatRequest as GenAiChatRequest, ChatStreamEvent as GeminiResponseChunkAlias, ReasoningEffort,
};
use secrecy::{ExposeSecret, SecretBox};
use serde_json::Value;
// Required for stream_ai_response_and_save_message
use tracing::{debug, error, info, instrument, trace, warn}; // Added trace
use uuid::Uuid;

use crate::{
    // vector_db::qdrant_client::QdrantClient, // Moved to direct crate import below
    AppState,
    errors::AppError,
    models::{
        characters::Character,
        chat_override::ChatCharacterOverride,
        chats::DbInsertableChatMessage, // ChatMessage and MessageRole will be from super::types
        lorebooks::ChatSessionLorebook, // User is used by get_session_data_for_generation
    },
    schema::{characters, chat_character_overrides, chat_messages, chat_sessions},
    services::{
        embedding_pipeline::RetrievedChunk, // Corrected struct name
        // history_manager::HistoryManager, // Removed, manage_history is a free function
        hybrid_token_counter::CountingMode,
        tokenizer_service::TokenEstimate,
    },
};
// Corrected QdrantClient import

// These functions/types will be in sibling modules
use super::{
    message_handling::save_message,
    types::{
        ChatMessage as DbChatMessage, // To avoid conflict if generation.rs also imports it directly
        GenerationDataWithUnsavedUserMessage,
        MessageRole,
        ScribeSseEvent,
        // RetrievedChunk is also pub use'd by types.rs, but generation.rs imports it directly from embedding_pipeline
    },
};
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
        conn_clone_for_persona_check
            .interact(move |c| {
                chat_sessions::table
                    .filter(chat_sessions::id.eq(session_id))
                    .filter(chat_sessions::user_id.eq(user_id))
                    .select(chat_sessions::active_custom_persona_id)
                    .first::<Option<Uuid>>(c)
            })
            .await??
    };
    info!(target: "chat_service_persona_debug", %session_id, ?maybe_active_persona_id_from_session, "Fetched active_custom_persona_id from session.");

    let mut effective_system_prompt: Option<String> = None;

    if let Some(persona_id) = maybe_active_persona_id_from_session {
        if let Some(ref dek_arc_outer) = user_dek_secret_box {
            let user_for_service_call: crate::models::users::User = {
                let conn_for_user_fetch = state
                    .pool
                    .get()
                    .await
                    .map_err(|e| AppError::DbPoolError(e.to_string()))?;
                let user_db_query_result = conn_for_user_fetch
                    .interact(move |c| {
                        crate::schema::users::table
                            .filter(crate::schema::users::id.eq(user_id))
                            .select(crate::models::users::UserDbQuery::as_select())
                            .first::<crate::models::users::UserDbQuery>(c)
                    })
                    .await
                    .map_err(|e| {
                        AppError::InternalServerErrorGeneric(format!(
                            "DB interact error fetching user_db_query: {}",
                            e
                        ))
                    })?;

                let user_db_query = user_db_query_result.map_err(|e| {
                    AppError::NotFound(format!("UserDbQuery for user {} not found: {}", user_id, e))
                })?;
                user_db_query.into()
            };
            let dek_ref_for_service: Option<&SecretBox<Vec<u8>>> = Some(dek_arc_outer.as_ref());
            match state
                .user_persona_service
                .get_user_persona(&user_for_service_call, dek_ref_for_service, persona_id)
                .await
            {
                Ok(client_persona_dto) => {
                    if let Some(ref sp_from_persona) = client_persona_dto.system_prompt {
                        if !sp_from_persona.trim().is_empty() {
                            effective_system_prompt = Some(sp_from_persona.replace('\0', ""));
                        }
                    }
                    if effective_system_prompt.is_none() {
                        let mut constructed_parts = Vec::new();
                        let base_prompt_part = if client_persona_dto.description.trim().is_empty() {
                            format!(
                                "You are chatting with {}.",
                                client_persona_dto.name.replace('\0', "")
                            )
                        } else {
                            format!(
                                "You are chatting with {}. Their description is: {}.",
                                client_persona_dto.name.replace('\0', ""),
                                client_persona_dto.description.replace('\0', "")
                            )
                        };
                        constructed_parts.push(base_prompt_part);
                        if let Some(ref p) = client_persona_dto.personality {
                            if !p.trim().is_empty() {
                                constructed_parts
                                    .push(format!("Personality: {}", p.replace('\0', "")));
                            }
                        }
                        if let Some(ref s) = client_persona_dto.scenario {
                            if !s.trim().is_empty() {
                                constructed_parts
                                    .push(format!("Scenario: {}", s.replace('\0', "")));
                            }
                        }
                        let constructed = constructed_parts.join("\n");
                        if !constructed.trim().is_empty() {
                            effective_system_prompt = Some(constructed);
                        }
                    }
                }
                Err(e) => {
                    error!(target: "chat_service_trace_prompt", %session_id, %persona_id, error = %e, "Error fetching active persona via service.")
                }
            }
        } else {
            warn!(target: "chat_service_trace_prompt", %session_id, %persona_id, "Active persona ID present, but no user DEK available.");
        }
    }

    let active_lorebook_ids_for_search: Option<Vec<Uuid>> = {
        let pool_clone_lore = state.pool.clone();
        match pool_clone_lore
            .get()
            .await
            .map_err(AppError::from)?
            .interact(move |conn_lore| {
                ChatSessionLorebook::get_active_lorebook_ids_for_session(conn_lore, session_id)
                    .map_err(AppError::from)
            })
            .await
        {
            Ok(Ok(ids)) => ids,
            Ok(Err(e)) => {
                warn!(%session_id, error = %e, "Failed to get active lorebook IDs (DB error).");
                None
            }
            Err(e) => {
                warn!(%session_id, error = %e, "Failed to get active lorebook IDs (InteractError).");
                None
            }
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
    ): (
        String, // history_management_strategy
        i32,    // history_management_limit
        Uuid,   // session_character_id
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
        Option<Value>, // logit_bias
        String, // model_name
        Option<i32>, // gemini_thinking_budget
        Option<bool>, // gemini_enable_code_execution
        Vec<DbChatMessage>, // messages
        Character, // character
        Vec<ChatCharacterOverride>, // overrides
        Option<String>, // effective_system_prompt
        Option<String>, // raw_character_system_prompt
    ) = {
        let conn = state
            .pool
            .get()
            .await
            .map_err(|e| AppError::DbPoolError(e.to_string()))?;
        let dek_for_interact_cloned = user_dek_secret_box.clone();
        let initial_effective_system_prompt = effective_system_prompt; // Capture current state

        conn.interact(move |conn_interaction| {
            let (
                hist_strat,
                hist_limit,
                sess_char_id,
                _sess_sys_prompt_ciphertext,
                _sess_sys_prompt_nonce,
                temp,
                max_tokens,
                freq_pen,
                pres_pen,
                top_k_val,
                top_p_val,
                rep_pen,
                min_p_val,
                top_a_val,
                seed_val,
                logit_b,
                model_n,
                gem_think_budget,
                gem_enable_code_exec,
            ) = chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .filter(chat_sessions::user_id.eq(user_id))
                .select((
                    chat_sessions::history_management_strategy,
                    chat_sessions::history_management_limit,
                    chat_sessions::character_id,
                    chat_sessions::system_prompt_ciphertext,
                    chat_sessions::system_prompt_nonce,
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
                    Uuid,
                    Option<Vec<u8>>,
                    Option<Vec<u8>>,
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
                .map_err(|e| match e {
                    DieselError::NotFound => {
                        AppError::NotFound(format!("Chat session {} not found", session_id))
                    }
                    _ => AppError::DatabaseQueryError(format!(
                        "Failed to query chat session {}: {}",
                        session_id, e
                    )),
                })?;

            let character_db: Character = characters::table
                .filter(characters::id.eq(sess_char_id))
                .first::<Character>(conn_interaction)
                .map_err(|e| match e {
                    DieselError::NotFound => {
                        AppError::NotFound(format!("Character {} not found", sess_char_id))
                    }
                    _ => AppError::DatabaseQueryError(format!(
                        "Failed to query character {}: {}",
                        sess_char_id, e
                    )),
                })?;

            let overrides_db: Vec<ChatCharacterOverride> = chat_character_overrides::table
                .filter(chat_character_overrides::chat_session_id.eq(session_id))
                .filter(chat_character_overrides::original_character_id.eq(sess_char_id))
                .load::<ChatCharacterOverride>(conn_interaction)
                .map_err(|e| {
                    AppError::DatabaseQueryError(format!("Failed to query overrides: {}", e))
                })?;

            let messages_raw_db: Vec<DbChatMessage> = chat_messages::table
                .filter(chat_messages::session_id.eq(session_id))
                .order(chat_messages::created_at.asc()) // Fetch in ascending order for correct processing later
                .select(DbChatMessage::as_select())
                .load::<DbChatMessage>(conn_interaction)
                .map_err(|e| {
                    AppError::DatabaseQueryError(format!("Failed to load messages: {}", e))
                })?;

            let mut current_effective_system_prompt = initial_effective_system_prompt;

            if current_effective_system_prompt.is_none() {
                let mut override_values_map: std::collections::HashMap<String, String> =
                    std::collections::HashMap::new();
                for override_data in &overrides_db {
                    if let Some(dek) = &dek_for_interact_cloned {
                        if !override_data.overridden_value.is_empty()
                            && !override_data.overridden_value_nonce.is_empty()
                        {
                            if let Ok(dec_bytes) = crate::crypto::decrypt_gcm(
                                &override_data.overridden_value,
                                &override_data.overridden_value_nonce,
                                dek.as_ref(),
                            ) {
                                if let Ok(s) = String::from_utf8(dec_bytes.expose_secret().to_vec())
                                {
                                    if !s.trim().is_empty() {
                                        override_values_map
                                            .insert(override_data.field_name.clone(), s);
                                    }
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
            let raw_character_system_prompt_from_db: Option<String> = character_db
                .system_prompt
                .as_ref()
                .and_then(|val| {
                    if val.is_empty() {
                        None
                    } else {
                        String::from_utf8(val.clone())
                            .ok()
                            .map(|s| s.replace('\0', ""))
                    }
                })
                .filter(|s| !s.trim().is_empty());

            Ok::<_, AppError>((
                hist_strat,
                hist_limit,
                sess_char_id,
                temp,
                max_tokens,
                freq_pen,
                pres_pen,
                top_k_val,
                top_p_val,
                rep_pen,
                min_p_val,
                top_a_val,
                seed_val,
                logit_b,
                model_n,
                gem_think_budget,
                gem_enable_code_exec,
                messages_raw_db,
                character_db,
                overrides_db,
                current_effective_system_prompt, // This is the one for the builder (persona/override only)
                raw_character_system_prompt_from_db, // The new one
            ))
        })
        .await
        .map_err(|e| AppError::DbInteractError(format!("Interact dispatch error: {}", e)))??
    };

    // --- Calculate User Prompt Tokens (Now that model_name is available) ---
    let user_prompt_tokens_val: Option<i32> = match state
        .token_counter
        .count_tokens(
            &user_message_content,
            CountingMode::LocalOnly,
            Some(&session_model_name_db),
        )
        .await
    {
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
        let decrypted_content_str = match (db_msg_raw.content_nonce.as_ref(), &user_dek_secret_box)
        {
            (Some(nonce_vec), Some(dek_arc))
                if !db_msg_raw.content.is_empty() && !nonce_vec.is_empty() =>
            {
                let decrypted_bytes_secret =
                    crate::crypto::decrypt_gcm(&db_msg_raw.content, nonce_vec, dek_arc.as_ref())
                        .map_err(|e| {
                            AppError::DecryptionError(format!(
                                "Failed to decrypt message {}: {}",
                                db_msg_raw.id, e
                            ))
                        })?;
                String::from_utf8(decrypted_bytes_secret.expose_secret().to_vec()).map_err(|e| {
                    AppError::InternalServerErrorGeneric(format!(
                        "Invalid UTF-8 in decrypted message {}: {}",
                        db_msg_raw.id, e
                    ))
                })?
            }
            _ => String::from_utf8(db_msg_raw.content.clone()).map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "Invalid UTF-8 in plaintext message {}: {}",
                    db_msg_raw.id, e
                ))
            })?,
        };

        if decrypted_content_str.trim().is_empty() {
            // Create a new DbChatMessage with decrypted (empty) content
            let mut updated_msg = db_msg_raw.clone();
            updated_msg.content = decrypted_content_str.into_bytes();
            updated_msg.content_nonce = None; // Content is now plaintext
            managed_recent_history.insert(0, updated_msg);
            continue;
        }

        let token_estimate: TokenEstimate = state
            .token_counter
            .count_tokens(
                &decrypted_content_str,
                CountingMode::LocalOnly,
                Some(&session_model_name_db),
            )
            .await
            .map_err(|e| {
                AppError::InternalServerErrorGeneric(format!(
                    "Token counting failed for history message {}: {}",
                    db_msg_raw.id, e
                ))
            })?;

        let message_tokens = token_estimate.total as usize; // Cast to usize
        debug!(target: "test_debug", %session_id, message_id = %db_msg_raw.id, %message_tokens, current_actual_tokens = %actual_recent_history_tokens, %recent_history_token_budget, "Message tokens calculated. Checking budget.");

        if actual_recent_history_tokens.saturating_add(message_tokens)
            <= recent_history_token_budget
        {
            // Compare usize with usize
            actual_recent_history_tokens =
                actual_recent_history_tokens.saturating_add(message_tokens);
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
        state
            .config
            .context_total_token_limit
            .saturating_sub(actual_recent_history_tokens),
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
                match state
                    .embedding_pipeline_service
                    .retrieve_relevant_chunks(
                        state.clone(),
                        user_id,
                        None, // Not searching chat history here
                        Some(lorebook_ids.clone()),
                        &user_message_content, // query_text
                        rag_query_limit_per_source,
                    )
                    .await
                {
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
        match state
            .embedding_pipeline_service
            .retrieve_relevant_chunks(
                state.clone(),
                user_id,
                Some(session_id), // Searching chat history for the current session
                None,             // Not searching lorebooks here
                &user_message_content, // query_text
                rag_query_limit_per_source,
            )
            .await
        {
            Ok(mut older_chat_chunks) => {
                info!(%session_id, num_older_chat_chunks_raw = older_chat_chunks.len(), "Retrieved older chat history chunks (raw).");
                let recent_message_ids: std::collections::HashSet<Uuid> =
                    managed_recent_history.iter().map(|msg| msg.id).collect();
                debug!(target: "rag_debug", %session_id, num_recent_ids = recent_message_ids.len(), ?recent_message_ids, "Recent message IDs for RAG filtering determined.");

                debug!(target: "rag_debug", %session_id, num_raw_older_chunks = older_chat_chunks.len(), "Raw older chat RAG chunks before filtering:");
                for (i, chunk) in older_chat_chunks.iter().enumerate() {
                    if let crate::services::embedding_pipeline::RetrievedMetadata::Chat(chat_meta) =
                        &chunk.metadata
                    {
                        debug!(target: "rag_debug", %session_id, chunk_idx = i, message_id = %chat_meta.message_id, score = chunk.score, text_preview = %chunk.text.chars().take(100).collect::<String>(), "  Raw older chat RAG chunk");
                    } else {
                        debug!(target: "rag_debug", %session_id, chunk_idx = i, score = chunk.score, text_preview = %chunk.text.chars().take(100).collect::<String>(), metadata_type = ?chunk.metadata, "  Raw older RAG chunk (non-chat metadata)");
                    }
                }

                let initial_older_chunk_count = older_chat_chunks.len();
                older_chat_chunks.retain(|chunk| {
                    match &chunk.metadata {
                        crate::services::embedding_pipeline::RetrievedMetadata::Chat(chat_meta) => {
                            let is_recent = recent_message_ids.contains(&chat_meta.message_id);
                            if is_recent {
                                debug!(target: "rag_debug", %session_id, message_id = %chat_meta.message_id, score = chunk.score, "Filtering older RAG chat chunk (ID: {}) because it IS IN recent_message_ids.", chat_meta.message_id);
                            } else {
                                trace!(target: "rag_debug", %session_id, message_id = %chat_meta.message_id, score = chunk.score, "Keeping older RAG chat chunk (ID: {}) because it IS NOT IN recent_message_ids.", chat_meta.message_id);
                            }
                            !is_recent // Keep if NOT recent
                        }
                        crate::services::embedding_pipeline::RetrievedMetadata::Lorebook(lore_meta) => {
                            // This case should ideally not be hit if retrieve_relevant_chunks was called with Some(session_id) and None for lorebook_ids
                            warn!(target: "rag_debug", %session_id, lorebook_id = %lore_meta.lorebook_id, entry_id = %lore_meta.original_lorebook_entry_id, "Encountered unexpected Lorebook metadata when filtering older CHAT HISTORY RAG chunks. Keeping it by default.");
                            true
                        }
                        // Consider adding other specific metadata types if they exist and need special handling
                        // _ => {
                        //     warn!(target: "rag_debug", %session_id, metadata = ?chunk.metadata, "Encountered unknown metadata type when filtering older CHAT HISTORY RAG chunks. Keeping it by default.");
                        //     true
                        // }
                    }
                });
                debug!(target: "rag_debug", %session_id, %initial_older_chunk_count, final_older_chunk_count = older_chat_chunks.len(), "Older chat RAG chunks filtering complete.");
                info!(%session_id, num_older_chat_chunks_filtered = older_chat_chunks.len(), "Filtered older chat history chunks."); // Existing log, good for summary
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
            combined_rag_candidates.sort_by(|a, b| {
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            debug!(target: "test_debug", %session_id, "Combined RAG candidates after sorting (first 5 texts): {:?}", combined_rag_candidates.iter().take(5).map(|c| c.text.chars().take(50).collect::<String>() ).collect::<Vec<_>>());

            for chunk in combined_rag_candidates {
                debug!(target: "test_debug", %session_id, chunk_text_preview = chunk.text.chars().take(50).collect::<String>(), chunk_score = chunk.score, "Processing RAG candidate chunk.");
                if current_rag_tokens_used >= available_rag_tokens {
                    debug!(target: "test_debug", %session_id, %current_rag_tokens_used, %available_rag_tokens, "RAG token budget reached during assembly. Stopping for chunk: {:?}", chunk.text.chars().take(50).collect::<String>());
                    break;
                }

                match state
                    .token_counter
                    .count_tokens(
                        &chunk.text,
                        CountingMode::LocalOnly,
                        Some(&session_model_name_db),
                    )
                    .await
                {
                    Ok(token_estimate) => {
                        let chunk_tokens = token_estimate.total as usize;
                        debug!(target: "test_debug", %session_id, %chunk_tokens, current_rag_tokens_before_add = %current_rag_tokens_used, %available_rag_tokens, "RAG chunk tokens calculated. Checking budget for chunk: {:?}", chunk.text.chars().take(50).collect::<String>());
                        if current_rag_tokens_used.saturating_add(chunk_tokens)
                            <= available_rag_tokens
                        {
                            rag_context_items.push(chunk);
                            current_rag_tokens_used =
                                current_rag_tokens_used.saturating_add(chunk_tokens);
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

        let decrypt_field_local = |data: Option<&Vec<u8>>,
                                   nonce: Option<&Vec<u8>>,
                                   dek_opt: &Option<Arc<SecretBox<Vec<u8>>>>|
         -> Result<Option<String>, AppError> {
            if let (Some(d), Some(n), Some(dek)) = (data, nonce, dek_opt) {
                if !d.is_empty() && !n.is_empty() {
                    let decrypted = crate::crypto::decrypt_gcm(d, n, dek.as_ref()).map_err(
                        |e: crate::crypto::CryptoError| {
                            AppError::DecryptionError(format!("Failed to decrypt field: {}", e))
                        },
                    )?;
                    return Ok(Some(
                        String::from_utf8(decrypted.expose_secret().to_vec()).map_err(
                            |e: std::string::FromUtf8Error| {
                                AppError::InternalServerErrorGeneric(format!(
                                    "Invalid UTF-8 in decrypted field: {}",
                                    e
                                ))
                            },
                        )?,
                    ));
                }
            }
            Ok(None)
        };

        let mut first_mes_content_to_add: Option<String> = None;
        let mut override_values_map: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();

        for override_data in &character_overrides_for_first_mes {
            if let Ok(Some(dec_val)) = decrypt_field_local(
                Some(&override_data.overridden_value),
                Some(&override_data.overridden_value_nonce),
                &user_dek_secret_box,
            ) {
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
            &user_dek_secret_box,
        )? {
            if !char_first_mes.is_empty() {
                first_mes_content_to_add = Some(char_first_mes);
            }
        }

        if let Some(content) = first_mes_content_to_add {
            let first_mes_db_chat_message = DbChatMessage {
                id: Uuid::new_v4(),
                session_id,
                user_id,
                message_type: MessageRole::Assistant,
                content: content.into_bytes(), // Content is already decrypted String
                content_nonce: None,
                created_at: chrono::Utc::now(),
                prompt_tokens: None,
                completion_tokens: None,
            };
            managed_recent_history.insert(0, first_mes_db_chat_message);
            info!(%session_id, "Prepended character's first_mes to managed_recent_history.");
        }
    }

    // --- Prepare User Message Struct ---
    let user_db_message_to_save = DbInsertableChatMessage::new(
        session_id,
        user_id,
        MessageRole::User,
        user_message_content_for_closure.into_bytes(),
        None,
        Some("user".to_string()),
        Some(serde_json::json!([{"text": user_message_content}])),
        None,
        user_prompt_tokens_val,
        None,
    );

    // --- Construct Final Tuple ---
    Ok((
        managed_recent_history,         // 0: managed_db_history
        final_effective_system_prompt,  // 1: system_prompt (for builder, persona/override only)
        active_lorebook_ids_for_search, // 2: active_lorebook_ids_for_search
        session_character_id_db,        // 3: session_character_id
        raw_character_system_prompt,    // 4: raw_character_system_prompt (NEW)
        session_temperature_db,         // 5: temperature
        session_max_output_tokens_db,   // 6: max_output_tokens
        session_frequency_penalty_db,   // 7: frequency_penalty
        session_presence_penalty_db,    // 8: presence_penalty
        session_top_k_db,               // 9: top_k
        session_top_p_db,               // 10: top_p
        session_repetition_penalty_db,  // 11: repetition_penalty
        session_min_p_db,               // 12: min_p
        session_top_a_db,               // 13: top_a
        session_seed_db,                // 14: seed
        session_logit_bias_db,          // 15: logit_bias
        session_model_name_db,          // 16: model_name
        // -- Gemini Specific Options --
        session_gemini_thinking_budget_db, // 17: gemini_thinking_budget
        session_gemini_enable_code_execution_db, // 18: gemini_enable_code_execution
        user_db_message_to_save,           // 19: The user message struct
        // -- RAG Context & Recent History Tokens --
        actual_recent_history_tokens, // 20: actual_recent_history_tokens
        rag_context_items,            // 21: rag_context_items
        // History Management Settings
        history_management_strategy_db_val, // 22: history_management_strategy
        history_management_limit_db_val,    // 23: history_management_limit
    ))
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
) -> Result<std::pin::Pin<Box<dyn Stream<Item = Result<ScribeSseEvent, AppError>> + Send>>, AppError>
{
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
            genai_chat_options = genai_chat_options.with_reasoning_effort(ReasoningEffort::Budget(budget as u32));
        }
    }
    // `with_gemini_enable_code_execution` removed as it's no longer a direct ChatOption.
    // The `gemini_enable_code_execution` variable will still affect tool declaration logic below.

    // NEW LOGIC FOR TOOL CONFIGURATION
    let mut tools_to_declare: Vec<genai::chat::Tool> = Vec::new();

    // Declare scribe_tool_invoker if thinking is requested or code execution is enabled
    // (as it's our stand-in for a generic tool for now when code execution is on)
    if request_thinking || gemini_enable_code_execution == Some(true) {
        debug!("'scribe_tool_invoker' will be declared for Gemini.");
        let scribe_tool_schema = serde_json::json!({
            "type": "object",
            "properties": {
                "tool_name": { "type": "string", "description": "The name of the Scribe tool to invoke." },
                "tool_arguments": { "type": "object", "description": "The arguments for the Scribe tool, as a JSON object." }
            },
            "required": ["tool_name", "tool_arguments"]
        });
        let scribe_tool = genai::chat::Tool::new("scribe_tool_invoker".to_string())
            .with_description("Invokes a Scribe-defined tool with the given arguments. Used for complex reasoning or actions.".to_string())
            .with_schema(scribe_tool_schema);
        tools_to_declare.push(scribe_tool);
    }

    // TODO: Add other specific tools if gemini_enable_code_execution is true and they are defined.

    if !tools_to_declare.is_empty() {
        chat_request = chat_request.with_tools(tools_to_declare.clone());
        info!(?tools_to_declare, "Tools added to ChatRequest for Gemini.");
    }
    // END NEW LOGIC FOR TOOL CONFIGURATION
    // The explicit FunctionCallingMode, FunctionCallingConfig, and with_gemini_tool_config
    // have been removed as the new genai adapter handles tools via `ChatRequest::with_tools`.

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

    let genai_stream_result: Result<
        Pin<Box<dyn Stream<Item = Result<GeminiResponseChunkAlias, AppError>> + Send>>,
        AppError,
    > = state
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
            let error_stream = async_stream::stream! {
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

    let sse_stream = async_stream::stream! {
        let mut accumulated_content = String::new();
        let mut stream_error_occurred = false;

        // Pin the stream from the AI client
        futures::pin_mut!(genai_stream);
        trace!("Entering SSE async_stream! processing loop in chat_service");

        while let Some(event_result) = genai_stream.next().await {
            trace!("Received event from genai_stream in chat_service: {:?}", event_result);
            match event_result {
                Ok(GeminiResponseChunkAlias::Start) => {
                    debug!("Received Start event from AI stream in chat_service");
                    continue;
                }
                Ok(GeminiResponseChunkAlias::Chunk(chunk)) => {
                    debug!(content_chunk_len = chunk.content.len(), "Received Content chunk from AI stream in chat_service");
                    if !chunk.content.is_empty() {
                        accumulated_content.push_str(&chunk.content);
                        yield Ok(ScribeSseEvent::Content(chunk.content.clone()));
                    } else {
                        trace!("Skipping empty content chunk from AI in chat_service");
                    }
                }
                Ok(GeminiResponseChunkAlias::ReasoningChunk(chunk)) => {
                    debug!(reasoning_chunk_len = chunk.content.len(), "Received ReasoningChunk from AI stream in chat_service");
                    if !chunk.content.is_empty() {
                        yield Ok(ScribeSseEvent::Thinking(chunk.content.clone()));
                       }
                      }
                      // Ok(GeminiResponseChunkAlias::ToolCall(tool_call)) => { // Removed as ToolCall is not part of ChatStreamEvent for Gemini
                      //                 debug!(tool_call_id = %tool_call.call_id, tool_fn_name = %tool_call.fn_name, "Received ToolCall event from AI stream in chat_service");
                      //                 let thinking_message = format!("Attempting to use tool: {} with ID: {}", tool_call.fn_name, tool_call.call_id);
                      //                 yield Ok(ScribeSseEvent::Thinking(thinking_message));
                      //             }
                      Ok(GeminiResponseChunkAlias::End(_)) => {
                       debug!("Received End event from AI stream in chat_service");
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
                                Some(serde_json::json!([{"text": partial_content_clone}])), // parts
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
                    Some(serde_json::json!([{"text": accumulated_content}])), // parts
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
