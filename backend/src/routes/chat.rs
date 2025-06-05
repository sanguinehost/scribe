// backend/src/routes/chat.rs

use crate::auth::session_dek::SessionDek;
use crate::auth::user_store::Backend as AuthBackend;
// use crate::crypto; // Added for decryption - will be needed later
use crate::errors::AppError;
use crate::models::characters::{Character, CharacterMetadata}; // Added Character
use crate::models::chat_override::{CharacterOverrideDto, ChatCharacterOverride};
use crate::models::chats::CreateChatSessionPayload;
use crate::models::chats::{
    Chat,
    GenerateChatRequest,
    MessageRole,
    SuggestedActionItem,
    SuggestedActionsRequest,
    SuggestedActionsResponse, // Corrected DbChatMessage to ChatMessage
};
use crate::prompt_builder;
use crate::routes::chats::{get_chat_settings_handler, update_chat_settings_handler};
use crate::schema::{self as app_schema, chat_sessions}; // Added app_schema for characters table
use crate::services::chat;
use crate::services::chat::types::ScribeSseEvent;
use crate::services::LorebookService;
use secrecy::ExposeSecret; // Added for ExposeSecret
// RetrievedMetadata is no longer directly used in this file for RAG string construction
// use crate::services::embedding_pipeline::RetrievedMetadata;
// RetrievedChunk is used by prompt_builder, not directly here.
// use crate::services::embedding_pipeline::RetrievedChunk;
use crate::state::AppState;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse, Sse,
        sse::{Event, KeepAlive},
    },
    routing::{get, post},
};
use axum_login::AuthSession;
use bigdecimal::ToPrimitive;
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper, prelude::*};
use futures_util::StreamExt;
use genai::chat::{
    ChatMessage as GenAiChatMessage, ChatOptions, ChatRequest, ChatResponseFormat, ChatRole,
    JsonSpec, MessageContent, ReasoningEffort,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::field;
use tracing::{debug, error, info, instrument, trace, warn};
use uuid::Uuid;
use validator::Validate;

// Define CurrentAuthSession type alias
type CurrentAuthSession = AuthSession<AuthBackend>;

// const RAG_CHUNK_LIMIT: u64 = 7; // No longer needed here, handled by prompt_builder

// Placeholder for response struct if it was missing
// Removed unused struct PlaceholderResponse
// #[derive(Serialize)]
// struct PlaceholderResponse { message: String }

#[derive(Deserialize, Debug)]
struct ChatGenerateQueryParams {
    #[serde(default)]
    request_thinking: bool,
}

#[derive(Serialize, Debug)] // Added derive Debug
pub struct ChatSessionWithDekResponse {
    // Made pub
    pub id: Uuid,
    pub user_id: Uuid,
    pub character_id: Uuid,
    pub title: Option<String>,
    pub dek_present: bool, // Simpler representation of DEK presence
}

#[instrument(skip_all, fields(user_id = field::Empty, character_id = field::Empty))]
pub async fn create_chat_session_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    session_dek: SessionDek, // Renamed from _session_dek as it will be used
    Json(payload): Json<CreateChatSessionPayload>,
) -> Result<(StatusCode, Json<Chat>), AppError> {
    info!("Attempting to create new chat session");

    let user = auth_session.user.as_ref().ok_or_else(|| {
        error!("User not found in session during chat creation");
        AppError::Unauthorized("User not found in session".to_string())
    })?;
    let user_id = user.id;
    tracing::Span::current().record("user_id", tracing::field::display(user_id));
    tracing::Span::current().record(
        "character_id",
        tracing::field::display(payload.character_id),
    );
    if let Some(persona_id) = payload.active_custom_persona_id {
        tracing::Span::current().record(
            "active_custom_persona_id",
            tracing::field::display(persona_id),
        );
    }

    debug!(user_id = %user_id, character_id = %payload.character_id, active_custom_persona_id=?payload.active_custom_persona_id, "User, character, and persona ID extracted");

    // Fetch character's associated lorebooks
    let lorebook_service = LorebookService::new(
        state.pool.clone(),
        state.encryption_service.clone(),
        state.qdrant_service.clone(),
    );
    
    let character_lorebooks = lorebook_service
        .list_character_lorebooks(&auth_session, payload.character_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to fetch character lorebooks: {}. Proceeding without them.", e);
            Vec::new()
        });
    
    let lorebook_ids = if character_lorebooks.is_empty() {
        None
    } else {
        let ids: Vec<Uuid> = character_lorebooks.iter().map(|lb| lb.id).collect();
        tracing::info!("Automatically associating {} lorebooks with new chat session", ids.len());
        Some(ids)
    };

    // Call the service function to create the chat session
    let created_chat_session = chat::session_management::create_session_and_maybe_first_message(
        state.into(),
        user_id,
        payload.character_id,
        payload.active_custom_persona_id, // Pass the new field
        lorebook_ids, // Pass the character's associated lorebooks
        Some(Arc::new(session_dek.0)), // Pass the DEK, wrapped in Arc for the service
    )
    .await?;

    info!(chat_id = %created_chat_session.id, "Chat session created successfully via service");
    Ok((StatusCode::CREATED, Json(created_chat_session)))
}

#[instrument(skip_all, fields(session_id = %session_id_str, user_id = field::Empty, chat_id = field::Empty, message_id = field::Empty))]
pub async fn generate_chat_response(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    session_dek: SessionDek,
    Path(session_id_str): Path<String>,
    Query(query_params): Query<ChatGenerateQueryParams>,
    headers: HeaderMap,
    Json(payload): Json<GenerateChatRequest>,
) -> Result<impl IntoResponse, AppError> {
    info!("Received request to generate chat response with history");
    payload.validate()?;
    trace!(payload = ?payload, query_params = ?query_params, "Received validated payload and query params");

    let state_arc = Arc::new(state);

    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("User not found in session".to_string()))?;

    tracing::debug!(user_id = %user.id, user_dek_from_auth_session_is_some = user.dek.is_some(), "generate_chat_response: Checked user.dek from auth_session (expected None or unused).");

    let user_id_value = user.id;
    let session_dek_arc = Arc::new(session_dek.0); // MODIFIED: Create Arc for SessionDek

    debug!(%user_id_value, "Using SessionDek from extractor (now in Arc) for chat generation.");

    let session_id = Uuid::parse_str(&session_id_str)
        .map_err(|_| AppError::BadRequest("Invalid session UUID format".to_string()))?;
    debug!(%session_id, "Parsed session ID");

    // Fetch chat session owner ID for authorization check
    let chat_session_owner_id = state_arc
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select(chat_sessions::user_id)
                .first::<Uuid>(conn)
            // .map_err(AppError::from) // Let the outer error handling manage this
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!(
                "Interact dispatch error checking session owner: {e}"
            ))
        })? // Handle interact error
        .map_err(|e_db| match e_db {
            // Handle DB error from the closure
            diesel::result::Error::NotFound => {
                AppError::NotFound(format!("Chat session {session_id} not found."))
            }
            _ => AppError::DatabaseQueryError(format!(
                "Failed to query chat session owner for {session_id}: {e_db}"
            )),
        })?;

    if chat_session_owner_id != user_id_value {
        error!(%session_id, expected_owner = %user_id_value, actual_owner = %chat_session_owner_id, "User forbidden from accessing chat session.");
        return Err(AppError::Forbidden);
    }
    debug!(%session_id, "User authorized for chat session");

    // Extract the current user message content from the payload
    let current_user_api_message = payload.history.last().cloned().ok_or_else(|| {
        error!(%session_id, "Payload history is empty, cannot extract current user message.");
        AppError::BadRequest("Request payload must contain at least one message.".to_string())
    })?;

    if current_user_api_message.role.to_lowercase() != "user" {
        error!(%session_id, "Last message in payload history is not from user.");
        return Err(AppError::BadRequest(
            "The last message in the payload's history must be from the 'user'.".to_string(),
        ));
    }
    let current_user_content = current_user_api_message.content;
    trace!(%session_id, "Extracted current user message content for generation.");

    // Get comprehensive data for generation from chat_service
    let (
        managed_db_history,               // 0: Vec<DbChatMessage>
        system_prompt_from_service,       // 1: Option<String> (persona/override only)
        _active_lorebook_ids_for_search,  // 2: Option<Vec<Uuid>> - Now handled by prompt_builder
        session_character_id,             // 3: Uuid
        raw_character_system_prompt, // 4: Option<String> (NEW - from character_db.system_prompt)
        gen_temperature,             // 5: Option<BigDecimal> (was 4)
        gen_max_output_tokens,       // 6: Option<i32> (was 5)
        gen_frequency_penalty,       // 7: Option<BigDecimal> (was 6)
        gen_presence_penalty,        // 8: Option<BigDecimal> (was 7)
        gen_top_k,                   // 9: Option<i32> (was 8)
        gen_top_p,                   // 10: Option<BigDecimal> (was 9)
        gen_seed,                    // 11: Option<i32> (was 13)
        gen_model_name_from_service, // 12: String (was 15)
        gen_gemini_thinking_budget,  // 13: Option<i32> (was 16)
        gen_gemini_enable_code_execution, // 14: Option<bool> (was 17)
        user_message_struct_to_save, // 15: DbInsertableChatMessage (was 18)
        // -- New RAG related fields --
        _actual_recent_history_tokens_from_service, // 16: usize (NEW) - Handled by prompt_builder (was 19)
        rag_context_items_from_service, // 17: Vec<RetrievedChunk> (NEW) - Passed to prompt_builder (was 20)
        // -- Original history management settings --
        _hist_management_strategy, // 18: String (was 21)
        _hist_management_limit,    // 19: i32 (was 22)
    ) = chat::generation::get_session_data_for_generation(
        state_arc.clone(),
        user_id_value,
        session_id,
        current_user_content.clone(),
        Some(session_dek_arc.clone()), // Use Arc clone
    )
    .await?;

    debug!(
        %session_id,
        system_prompt_len = system_prompt_from_service.as_ref().map_or(0, String::len),
        gen_temp = ?gen_temperature,
        gen_max_tokens = ?gen_max_output_tokens,
        gen_top_p = ?gen_top_p,
        gen_model_name = %gen_model_name_from_service,
        rag_items_count = rag_context_items_from_service.len(),
        %session_character_id,
        "Retrieved data for generation from chat_service."
    );

    // Fetch Character model from DB
    let character_db_model = state_arc
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            app_schema::characters::table
                .filter(app_schema::characters::id.eq(session_character_id))
                .filter(app_schema::characters::user_id.eq(user_id_value))
                .select(Character::as_select())
                .first::<Character>(conn)
        })
        .await
        .map_err(|e| {
            error!(error = %e, "Interact dispatch error fetching character model");
            AppError::InternalServerErrorGeneric(format!(
                "Interact dispatch error fetching character {session_character_id}: {e}"
            ))
        })?
        .map_err(|e_db| {
            if e_db == diesel::result::Error::NotFound {
                error!(%session_character_id, %user_id_value, "Character not found for user");
                AppError::NotFound(format!(
                    "Character {session_character_id} not found for user {user_id_value}"
                ))
            } else {
                error!(error = %e_db, %session_character_id, "Failed to query character");
                AppError::DatabaseQueryError(format!(
                    "Failed to query character {session_character_id}: {e_db}"
                ))
            }
        })?;

    let character_metadata_for_prompt_builder = CharacterMetadata {
        id: character_db_model.id,
        user_id: character_db_model.user_id,
        name: character_db_model.name.clone(),
        description: character_db_model.description.clone(),
        description_nonce: character_db_model.description_nonce.clone(),
        first_mes: character_db_model.first_mes.clone(),
        created_at: character_db_model.created_at,
        updated_at: character_db_model.updated_at,
    };
    trace!(%session_id, character_id = %character_metadata_for_prompt_builder.id, "Constructed CharacterMetadata for prompt builder.");

    let model_to_use = payload
        .model
        .clone()
        .unwrap_or_else(|| gen_model_name_from_service.clone());
    debug!(%model_to_use, "Determined final model to use for AI calls.");

    // Convert DbChatMessage history to GenAiChatMessage history
    let mut gen_ai_recent_history: Vec<GenAiChatMessage> = Vec::new();
    for db_msg in managed_db_history {
        // managed_db_history is Vec<DbChatMessage>
        // Content in managed_db_history from get_session_data_for_generation should already be decrypted
        let content_str = String::from_utf8_lossy(&db_msg.content).into_owned();
        let chat_role = match db_msg.message_type {
            MessageRole::User => ChatRole::User,
            MessageRole::Assistant => ChatRole::Assistant,
            MessageRole::System => ChatRole::System, // Should not happen in recent history
        };
        gen_ai_recent_history.push(GenAiChatMessage {
            role: chat_role,
            content: MessageContent::from_text(content_str),
            options: None,
        });
    }

    // Extract text for later use in saving to DB
    let current_user_content_text = current_user_content.clone();

    // Prepare current user message as GenAiChatMessage
    let current_user_genai_message = GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::from_text(current_user_content),
        options: None,
    };

    // Call the new prompt builder
    let (final_system_prompt_str, final_genai_message_list) =
        match prompt_builder::build_final_llm_prompt(prompt_builder::PromptBuildParams {
            config: state_arc.config.clone(),
            token_counter: state_arc.token_counter.clone(),
            recent_history: gen_ai_recent_history,
            rag_items: rag_context_items_from_service,
            system_prompt_base: system_prompt_from_service, // This is the system_prompt_base (persona/override only)
            raw_character_system_prompt, // This is the new raw_character_system_prompt
            character_metadata: Some(&character_metadata_for_prompt_builder),
            current_user_message: current_user_genai_message,
            model_name: model_to_use.clone(),
            user_dek: Some(&*session_dek_arc), // Add DEK for character description decryption
        })
        .await
        {
            Ok(prompt_data) => prompt_data,
            Err(e) => {
                error!(%session_id, error = ?e, "Failed to build final LLM prompt");
                return Err(e);
            }
        };

    trace!(history_len = final_genai_message_list.len(), %session_id, "Prepared final message list for AI using new prompt builder.");

    let accept_header = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    let request_thinking = query_params.request_thinking;
    debug!(%session_id, %request_thinking, "request_thinking value from query parameters");

    // The system_prompt_from_service is now part of final_system_prompt_str
    // The old final_system_prompt logic is removed.

    match accept_header {
        v if v.contains(mime::TEXT_EVENT_STREAM.as_ref()) => {
            info!(%session_id, "Handling streaming SSE request. request_thinking={}", request_thinking);

            // Explicitly save the user's message before streaming AI response
            // user_message_struct_to_save is DbInsertableChatMessage
            // save_message expects content: &str, role_str: Option<String>, parts: Option<Value>, attachments: Option<Value>

            // The content for save_message should be the original current_user_content (String)
            // The role_str, parts, attachments should come from user_message_struct_to_save if they are correctly populated there.
            // DbInsertableChatMessage has role, parts, attachments as Option<String>, Option<Value>, Option<Value>
            // However, user_message_struct_to_save.content is Vec<u8> (potentially encrypted or raw bytes of current_user_content)

            match chat::message_handling::save_message(chat::message_handling::SaveMessageParams {
                state: state_arc.clone(),
                session_id,
                user_id: user_id_value,
                message_type_enum: MessageRole::User,
                content: &current_user_content_text,
                role_str: user_message_struct_to_save.role.clone(),
                parts: user_message_struct_to_save.parts.clone(),
                attachments: user_message_struct_to_save.attachments.clone(),
                user_dek_secret_box: Some(session_dek_arc.clone()),
                model_name: model_to_use.clone(),
                raw_prompt_debug: None, // User messages don't need raw prompt debug
            })
            .await
            {
                Ok(saved_user_msg) => {
                    debug!(message_id = %saved_user_msg.id, session_id = %session_id, "Successfully saved user message via chat_service (SSE path)");
                }
                Err(e) => {
                    error!(error = ?e, session_id = %session_id, "Error saving user message via chat_service (SSE path)");
                    // Decide if we should return an error or try to stream AI response anyway
                    // For now, let's return the error to make it visible.
                    return Err(e);
                }
            }

            // The assistant's message will be saved by stream_ai_response_and_save_message.

            let dek_for_stream_service = session_dek_arc.clone();
            match chat::generation::stream_ai_response_and_save_message(
                chat::generation::StreamAiParams {
                    state: state_arc.clone(),
                    session_id,
                    user_id: user_id_value,
                    incoming_genai_messages: final_genai_message_list.clone(),
                    system_prompt: Some(final_system_prompt_str.clone()),
                    temperature: gen_temperature,
                    max_output_tokens: gen_max_output_tokens,
                    frequency_penalty: gen_frequency_penalty,
                    presence_penalty: gen_presence_penalty,
                    top_k: gen_top_k,
                    top_p: gen_top_p,
                    stop_sequences: None,
                    seed: gen_seed,
                    model_name: model_to_use.clone(),
                    gemini_thinking_budget: gen_gemini_thinking_budget,
                    gemini_enable_code_execution: gen_gemini_enable_code_execution,
                    request_thinking,
                    user_dek: Some(dek_for_stream_service),
                },
            )
            .await
            {
                Ok(service_stream) => {
                    debug!(%session_id, "Successfully obtained stream from chat_service::stream_ai_response_and_save_message");
                    let final_stream = async_stream::stream! {
                        let mut content_produced = false;
                        let mut error_from_service_stream = false;
                        futures::pin_mut!(service_stream);

                        while let Some(event_result) = service_stream.next().await {
                            match event_result {
                                Ok(scribe_event) => {
                                    let axum_sse_event = match scribe_event {
                                        ScribeSseEvent::Content(data) => {
                                            if !data.is_empty() { content_produced = true; }
                                            Event::default().event("content").data(data)
                                        }
                                        ScribeSseEvent::Thinking(data) => {
                                            Event::default().event("thinking").data(data)
                                        }
                                        ScribeSseEvent::Error(data) => {
                                            error_from_service_stream = true;
                                            Event::default().event("error").data(data)
                                        }
                                    };
                                    yield Ok(axum_sse_event);
                                }
                                Err(e) => {
                                    error_from_service_stream = true;
                                    yield Err(e);
                                }
                            }
                        }
                        if error_from_service_stream {
                            debug!(%session_id, "Service stream ended with an error or an error event was already sent. Not sending additional [DONE] event.");
                        } else if content_produced {
                            debug!(%session_id, "Service stream ended, sending [DONE] event because content was produced.");
                            yield Ok(Event::default().event("done").data("[DONE]"));
                        } else {
                            debug!(%session_id, "Service stream ended without producing content (and no error), sending [DONE_EMPTY] event.");
                            yield Ok(Event::default().event("done").data("[DONE_EMPTY]"));
                        }
                    };
                    Ok(Sse::new(Box::pin(final_stream))
                        .keep_alive(KeepAlive::default())
                        .into_response())
                }
                Err(e) => {
                    error!(error = ?e, %session_id, "Error calling chat_service::stream_ai_response_and_save_message");
                    let error_stream = async_stream::stream! {
                        let error_msg = format!("Service error: Failed to initiate AI processing - {e}");
                        trace!(%session_id, error_message = %error_msg, "Sending SSE 'error' event (service call failed)");
                        yield Ok::<_, AppError>(Event::default().event("error").data(error_msg));
                    };
                    Ok(Sse::new(Box::pin(error_stream))
                        .keep_alive(KeepAlive::default())
                        .into_response())
                }
            }
        }
        v if v.contains(mime::APPLICATION_JSON.as_ref()) => {
            info!(%session_id, "Handling non-streaming JSON request. request_thinking={}", request_thinking);

            // _user_message_to_save_for_db from get_session_data_for_generation contains the structured user message.
            // For JSON path, we save the user message explicitly before calling AI.
            // The content is current_user_content.

            let dek_for_user_save_json = session_dek_arc.clone();
            let _user_saved_message = match chat::message_handling::save_message(
                chat::message_handling::SaveMessageParams {
                    state: state_arc.clone(),
                    session_id,
                    user_id: user_id_value,
                    message_type_enum: MessageRole::User,
                    content: &current_user_content_text,
                    role_str: Some("user".to_string()),
                    parts: Some(json!([{"text": current_user_content_text}])),
                    attachments: None,
                    user_dek_secret_box: Some(dek_for_user_save_json),
                    model_name: model_to_use.clone(),
                    raw_prompt_debug: None, // User messages don't need raw prompt debug
                },
            )
            .await
            {
                Ok(saved_msg) => {
                    debug!(message_id = %saved_msg.id, session_id = %session_id, "Successfully saved user message via chat_service (JSON path)");
                    saved_msg
                }
                Err(e) => {
                    error!(error = ?e, session_id = %session_id, "Error saving user message via chat_service (JSON path)");
                    return Err(e);
                }
            };

            // RAG context is handled by build_final_llm_prompt.
            // The old RAG logic here is removed.

            let chat_request = ChatRequest::new(final_genai_message_list.clone())
                .with_system(final_system_prompt_str.clone());

            let mut chat_options = ChatOptions::default();
            if let Some(temp_bd) = gen_temperature {
                if let Some(temp_f32) = temp_bd.to_f32() {
                    chat_options = chat_options.with_temperature(temp_f32.into());
                }
            }
            if let Some(tokens_i32) = gen_max_output_tokens {
                // tokens_i32 is Option<i32>
                if let Ok(tokens_u32) = u32::try_from(tokens_i32) {
                    chat_options = chat_options.with_max_tokens(tokens_u32);
                } else {
                    warn!("max_output_tokens is invalid ({}), ignoring", tokens_i32);
                }
            }
            if let Some(p_bd) = gen_top_p {
                // p_bd is Option<BigDecimal>
                if let Some(p_f32) = p_bd.to_f32() {
                    chat_options = chat_options.with_top_p(p_f32.into());
                }
            }
            // Add other gen_... parameters to chat_options as needed
            if let Some(budget_i32) = gen_gemini_thinking_budget {
                // budget_i32 is Option<i32>
                if budget_i32 > 0 {
                    if let Ok(budget_u32) = u32::try_from(budget_i32) {
                        chat_options =
                            chat_options.with_reasoning_effort(ReasoningEffort::Budget(budget_u32));
                    } else {
                        warn!("gemini_thinking_budget overflow ({}), ignoring", budget_i32);
                    }
                } else {
                    warn!(
                        "gemini_thinking_budget is not positive ({}), ignoring",
                        budget_i32
                    );
                }
            }
            // `with_gemini_enable_code_execution` removed as it's no longer a direct ChatOption.
            // The `gen_gemini_enable_code_execution` variable is still available if needed for other logic.

            // TODO: Add other gen_ parameters like top_k, frequency_penalty etc. if supported by ChatOptions

            trace!(%session_id, chat_request = ?chat_request, chat_options = ?chat_options, "Prepared ChatRequest and Options for AI (non-streaming, JSON path)");

            match state_arc
                .ai_client
                .exec_chat(&model_to_use, chat_request, Some(chat_options))
                .await
            {
                Ok(chat_response) => {
                    debug!(%session_id, "Received successful non-streaming AI response (JSON path)");

                    let response_content = chat_response
                        .contents
                        .into_iter()
                        .next()
                        .and_then(|content| match content {
                            genai::chat::MessageContent::Text(text) => Some(text),
                            _ => None,
                        })
                        .unwrap_or_default();

                    trace!(%session_id, ?response_content, "Full non-streaming AI response (JSON path)");

                    if response_content.is_empty() {
                        warn!(session_id = %session_id, "Skipping save for empty AI content (JSON path)");
                    } else {
                        let dek_for_ai_save_json = session_dek_arc.clone();
                        let state_for_ai_save = state_arc.clone();
                        let response_content_for_save = response_content.clone();
                        tokio::spawn(async move {
                            match chat::message_handling::save_message(
                                chat::message_handling::SaveMessageParams {
                                    state: state_for_ai_save,
                                    session_id,
                                    user_id: user_id_value,
                                    message_type_enum: MessageRole::Assistant,
                                    content: &response_content_for_save,
                                    role_str: Some("assistant".to_string()),
                                    parts: Some(json!([{"text": response_content_for_save}])),
                                    attachments: None,
                                    user_dek_secret_box: Some(dek_for_ai_save_json),
                                    model_name: model_to_use.clone(),
                                    raw_prompt_debug: None, // Non-stream AI responses don't include raw prompt debug
                                },
                            )
                            .await
                            {
                                Ok(saved_message) => {
                                    debug!(session_id = %session_id, message_id = %saved_message.id, "Successfully saved AI message via chat_service (JSON path)");
                                }
                                Err(e) => {
                                    error!(error = ?e, session_id = %session_id, "Error saving AI message via chat_service (JSON path)");
                                }
                            }
                        });
                    }

                    let response_payload = json!({
                        "message_id": Uuid::new_v4(), // This is a response ID, not related to DB message ID
                        "content": response_content
                    });
                    trace!(%session_id, response_payload = ?response_payload, "Sending non-streaming JSON response");

                    Ok(Json(response_payload).into_response())
                }
                Err(e) => {
                    error!(error = ?e, %session_id, "AI generation failed for non-streaming request (JSON path)");
                    Err(e) // Convert genai::Error to AppError
                }
            }
        }
        _ => {
            // Fallback to SSE if Accept header is not recognized or empty
            info!(%session_id, "Accept header '{}' not recognized or empty, defaulting to SSE.", accept_header);

            // This is largely a copy of the SSE path above.
            let dek_for_fallback_stream_service = session_dek_arc.clone(); // MODIFIED: Use Arc clone
            match chat::generation::stream_ai_response_and_save_message(
                chat::generation::StreamAiParams {
                    state: state_arc.clone(),
                    session_id,
                    user_id: user_id_value,
                    incoming_genai_messages: final_genai_message_list.clone(),
                    system_prompt: Some(final_system_prompt_str.clone()),
                    temperature: gen_temperature,
                    max_output_tokens: gen_max_output_tokens,
                    frequency_penalty: gen_frequency_penalty,
                    presence_penalty: gen_presence_penalty,
                    top_k: gen_top_k,
                    top_p: gen_top_p,
                    stop_sequences: None,
                    seed: gen_seed,
                    model_name: model_to_use.clone(),
                    gemini_thinking_budget: gen_gemini_thinking_budget,
                    gemini_enable_code_execution: gen_gemini_enable_code_execution,
                    request_thinking,
                    user_dek: Some(dek_for_fallback_stream_service),
                },
            )
            .await
            {
                Ok(service_stream) => {
                    debug!(%session_id, "Successfully obtained stream from chat_service (fallback SSE)");
                    let final_stream = async_stream::stream! {
                        let mut content_produced = false;
                        let mut error_from_service_stream = false;
                        futures::pin_mut!(service_stream);

                        while let Some(event_result) = service_stream.next().await {
                            match event_result {
                                Ok(scribe_event) => {
                                    let axum_sse_event = match scribe_event {
                                        ScribeSseEvent::Content(data) => {
                                            if !data.is_empty() { content_produced = true; }
                                            Event::default().event("content").data(data)
                                        }
                                        ScribeSseEvent::Thinking(data) => {
                                            Event::default().event("thinking").data(data)
                                        }
                                        ScribeSseEvent::Error(data) => {
                                            error_from_service_stream = true;
                                            Event::default().event("error").data(data)
                                        }
                                    };
                                    yield Ok(axum_sse_event);
                                }
                                Err(e) => {
                                    error_from_service_stream = true;
                                    yield Err(e);
                                }
                            }
                        }
                        if error_from_service_stream {
                             debug!(%session_id, "Service stream ended with error (fallback). Not sending additional [DONE] event.");
                        } else if content_produced {
                             debug!(%session_id, "Service stream ended (fallback), sending [DONE] event.");
                             yield Ok(Event::default().event("done").data("[DONE]"));
                        } else {
                             debug!(%session_id, "Service stream ended without content (fallback), sending [DONE_EMPTY] event.");
                             yield Ok(Event::default().event("done").data("[DONE_EMPTY]"));
                        }
                    };
                    Ok(Sse::new(Box::pin(final_stream))
                        .keep_alive(KeepAlive::default())
                        .into_response())
                }
                Err(e) => {
                    error!(error = ?e, %session_id, "Error calling chat_service (fallback SSE)");
                    let error_stream = async_stream::stream! {
                        let error_msg = format!("Service error (fallback): Failed to initiate AI processing - {e}");
                        yield Ok::<_, AppError>(Event::default().event("error").data(error_msg));
                    };
                    Ok(Sse::new(Box::pin(error_stream))
                        .keep_alive(KeepAlive::default())
                        .into_response())
                }
            }
        }
    }
}

pub fn chat_routes(state: AppState) -> Router<AppState> {
    info!("Entering chat_routes");
    Router::new()
        .route("/create_session", post(create_chat_session_handler))
        .route(
            "/:session_id/suggested-actions",
            post(generate_suggested_actions),
        )
        .route("/ping", get(ping_handler))
        .route(
            "/:chat_id/settings",
            get(get_chat_settings_handler).put(update_chat_settings_handler),
        )
        .route("/:session_id_str/generate", post(generate_chat_response))
        .route(
            "/overrides/:session_id",
            post(create_or_update_chat_character_override_handler).with_state(state.clone()),
        )
        .with_state(state)
}

async fn ping_handler() -> &'static str {
    "pong_from_chat_routes"
}

#[instrument(skip(state, auth_session, _payload), fields(session_id = %session_id))] // _payload as it's not used
pub async fn generate_suggested_actions(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(session_id): Path<Uuid>,
    session_dek: SessionDek,
    Json(_payload): Json<SuggestedActionsRequest>, // _payload as it's an empty struct now
) -> Result<Json<SuggestedActionsResponse>, AppError> {
    info!(
        "Entering generate_suggested_actions for session_id: {}",
        session_id
    );

    let state_arc = Arc::new(state);
    let session_dek_arc = Arc::new(session_dek.0);

    let user = auth_session.user.ok_or_else(|| {
        error!(
            "User not found in session for suggested actions (session_id: {})",
            session_id
        );
        AppError::Unauthorized("User not found in session".to_string())
    })?;
    let user_id = user.id;
    debug!(user_id = %user_id, session_id = %session_id, "User and session_id extracted");

    // Fetch chat session owner ID for authorization check
    let chat_session_owner_id = state_arc
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select(chat_sessions::user_id)
                .first::<Uuid>(conn)
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!(
                "Interact dispatch error checking session owner: {e}"
            ))
        })?
        .map_err(|e_db| match e_db {
            diesel::result::Error::NotFound => {
                AppError::NotFound(format!("Chat session {session_id} not found."))
            }
            _ => AppError::DatabaseQueryError(format!(
                "Failed to query chat session owner for {session_id}: {e_db}"
            )),
        })?;

    if chat_session_owner_id != user_id {
        error!(%session_id, expected_owner = %user_id, actual_owner = %chat_session_owner_id, "User forbidden from accessing chat session for suggested actions.");
        return Err(AppError::Forbidden);
    }
    debug!(%session_id, "User authorized for chat session");

    // Placeholder content for get_session_data_for_generation as we are not saving a new user message here.
    let current_user_content_for_service_call = String::new(); // Or a system message like "System: Requesting suggestions."

    let (
        managed_db_history,
        system_prompt_from_service,
        _active_lorebook_ids_for_search,
        session_character_id,
        raw_character_system_prompt,
        gen_temperature,        // We might use a fixed temp for suggestions
        _gen_max_output_tokens, // We use fixed max_tokens for suggestions
        _gen_frequency_penalty,
        _gen_presence_penalty,
        _gen_top_k,
        _gen_top_p,
        _gen_seed,
        _gen_model_name_from_service, // We might use a fixed model for suggestions
        _gen_gemini_thinking_budget,
        _gen_gemini_enable_code_execution,
        _user_message_struct_to_save, // Not saving a user message here
        _actual_recent_history_tokens_from_service,
        _rag_context_items_from_service, // RAG not typically used for suggestions
        _hist_management_strategy,
        _hist_management_limit,
    ) = chat::generation::get_session_data_for_generation(
        state_arc.clone(),
        user_id,
        session_id,
        current_user_content_for_service_call,
        Some(session_dek_arc.clone()),
    )
    .await?;

    debug!(%session_id, "Fetched session data for suggestions. History items: {}", managed_db_history.len());

    // Fetch Character model from DB
    let character_db_model = state_arc
        .pool
        .get()
        .await?
        .interact(move |conn| {
            app_schema::characters::table
                .filter(app_schema::characters::id.eq(session_character_id))
                .filter(app_schema::characters::user_id.eq(user_id)) // Ensure user owns character
                .select(Character::as_select())
                .first::<Character>(conn)
        })
        .await??; // Double question mark for interact and then DB result

    let character_metadata_for_prompt_builder = CharacterMetadata {
        id: character_db_model.id,
        user_id: character_db_model.user_id,
        name: character_db_model.name.clone(),
        description: character_db_model.description.clone(),
        description_nonce: character_db_model.description_nonce.clone(),
        first_mes: character_db_model.first_mes.clone(), // Assuming first_mes is already decrypted or plaintext
        created_at: character_db_model.created_at,
        updated_at: character_db_model.updated_at,
    };

    // Construct context for the suggestion prompt
    let mut suggestion_context_parts: Vec<String> = Vec::new();

    let decrypted_first_mes_str = match (
        &character_db_model.first_mes,
        &character_db_model.first_mes_nonce,
    ) {
        (Some(fm_bytes), Some(fm_nonce_bytes))
            if !fm_bytes.is_empty() && !fm_nonce_bytes.is_empty() =>
        {
            crate::crypto::decrypt_gcm(fm_bytes, fm_nonce_bytes, &session_dek_arc).map_or_else(
                |e| {
                    error!("Failed to decrypt first_mes: {}. Using empty string.", e);
                    String::new()
                },
                |decrypted_secret_vec| {
                    String::from_utf8(
                    decrypted_secret_vec.expose_secret().clone(),
                )
                .unwrap_or_else(|e| {
                    error!(
                        "Failed to convert decrypted first_mes to UTF-8: {}. Using empty string.",
                        e
                    );
                    String::new()
                })
                },
            )
        }
        (Some(fm_bytes), None) if !fm_bytes.is_empty() => {
            // No nonce, assume plaintext (less secure, but might be intended for some characters)
            String::from_utf8_lossy(fm_bytes).into_owned()
        }
        _ => String::new(), // No first_mes or empty
    };

    if !decrypted_first_mes_str.is_empty() {
        suggestion_context_parts.push(format!(
            "Character Introduction: \"{decrypted_first_mes_str}\""
        ));
    }

    // Use last 2-3 messages from history for context
    let history_for_prompt = managed_db_history.iter().rev().take(3).rev(); // Take last 3, then reverse to chronological
    for msg in history_for_prompt {
        // managed_db_history content is already decrypted by get_session_data_for_generation
        let content_str = String::from_utf8_lossy(&msg.content).into_owned();
        match msg.message_type {
            MessageRole::User => {
                suggestion_context_parts.push(format!("User: \"{content_str}\""));
            }
            MessageRole::Assistant => {
                suggestion_context_parts.push(format!("Assistant: \"{content_str}\""));
            }
            MessageRole::System => {} // Usually don't include system messages directly in this context
        }
    }

    let context_str_for_suggestions = suggestion_context_parts.join("\n");
    let prompt_text_for_llm_suggestions = format!(
        "Based on this conversation snippet:\n\n{context_str_for_suggestions}\n\nWhat are 2-4 concise follow-up actions or questions the user might say next? These should be suitable for buttons."
    );
    trace!(%session_id, "Constructed prompt for LLM suggested actions: {}", prompt_text_for_llm_suggestions);

    let suggestion_request_genai_message = GenAiChatMessage {
        role: ChatRole::User, // We are "asking" the LLM on behalf of the system/user for suggestions
        content: MessageContent::Text(prompt_text_for_llm_suggestions),
        options: None,
    };

    // Convert DbChatMessage history (already decrypted) to GenAiChatMessage history for prompt builder
    // This history is what *precedes* our special suggestion_request_genai_message
    let mut gen_ai_processed_history: Vec<GenAiChatMessage> = Vec::new();
    for db_msg in managed_db_history {
        // This is the full relevant history
        let content_str = String::from_utf8_lossy(&db_msg.content).into_owned();
        let chat_role = match db_msg.message_type {
            MessageRole::User => ChatRole::User,
            MessageRole::Assistant => ChatRole::Assistant,
            MessageRole::System => ChatRole::System,
        };
        gen_ai_processed_history.push(GenAiChatMessage {
            role: chat_role,
            content: MessageContent::from_text(content_str),
            options: None,
        });
    }

    // Model for suggestions - can be from settings or fixed. Using fixed for now.
    let model_for_suggestions = "gemini-2.5-flash-preview-05-20".to_string(); // Or use gen_model_name_from_service if desired

    let (final_system_prompt_for_suggestions, final_messages_for_suggestions_llm) =
        match prompt_builder::build_final_llm_prompt(prompt_builder::PromptBuildParams {
            config: state_arc.config.clone(),
            token_counter: state_arc.token_counter.clone(),
            recent_history: gen_ai_processed_history, // The actual chat history
            rag_items: Vec::new(),                    // No RAG for suggestions
            system_prompt_base: system_prompt_from_service,
            raw_character_system_prompt,
            character_metadata: Some(&character_metadata_for_prompt_builder),
            current_user_message: suggestion_request_genai_message, // Our special message asking for suggestions
            model_name: model_for_suggestions.clone(),
            user_dek: Some(&*session_dek_arc), // Add DEK for character description decryption
        })
        .await
        {
            Ok(prompt_data) => prompt_data,
            Err(e) => {
                error!(%session_id, error = ?e, "Failed to build final LLM prompt for suggestions");
                return Err(e);
            }
        };

    let chat_request = ChatRequest::new(final_messages_for_suggestions_llm)
        .with_system(final_system_prompt_for_suggestions);

    let suggested_actions_schema_value = json!({
        "type": "ARRAY",
        "items": {
            "type": "OBJECT",
            "properties": {
                "action": {
                    "type": "STRING",
                    "description": "A concise suggested action or question."
                }
            },
            "required": ["action"]
        }
    });

    let chat_options = ChatOptions::default()
        .with_temperature(
            gen_temperature
                .and_then(|t| t.to_f32())
                .unwrap_or(0.7)
                .into(),
        ) // Use session temp or default
        .with_max_tokens(150) // Fixed max tokens for suggestions
        .with_response_format(ChatResponseFormat::JsonSpec(JsonSpec {
            name: "suggested_actions".to_string(),
            description: Some("A list of suggested follow-up actions or questions.".to_string()),
            schema: suggested_actions_schema_value,
        }));

    trace!(%session_id, model = %model_for_suggestions, ?chat_request, ?chat_options, "Sending request to Gemini for suggested actions");

    let gemini_response = state_arc
        .ai_client
        .exec_chat(&model_for_suggestions, chat_request, Some(chat_options))
        .await
        .map_err(|e| {
            error!(%session_id, "Gemini API error for suggested actions: {:?}", e);
            AppError::AiServiceError(format!("Gemini API error: {e}"))
        })?;

    debug!(%session_id, "Received response from Gemini for suggested actions");
    trace!(%session_id, ?gemini_response, "Full Gemini response object for suggested actions");

    let response_text = if let Some(text) = gemini_response.first_content_text_as_str() {
        text.to_string()
    } else {
        error!(%session_id, "Gemini response for suggested actions did not contain text content or was empty.");
        return Err(AppError::InternalServerErrorGeneric(
            "AI response was empty or not in the expected format".to_string(),
        ));
    };
    trace!(%session_id, "Gemini response text for suggested actions: {}", response_text);

    let suggestions: Vec<SuggestedActionItem> =
        serde_json::from_str(&response_text).map_err(|e| {
            error!(
                %session_id,
                "Failed to parse Gemini JSON response into expected structure for suggested actions: {:?}. Response text: {}",
                e,
                response_text
            );
            AppError::InternalServerErrorGeneric("Failed to parse structured response from AI".to_string())
        })?;

    info!(%session_id, "Successfully generated {} suggested actions", suggestions.len());

    Ok(Json(SuggestedActionsResponse { suggestions }))
}

#[instrument(skip_all, err)]
pub async fn get_chat_session_with_dek(
    State(state): State<AppState>,
    Path(chat_id): Path<Uuid>,
    auth_session: CurrentAuthSession, // Use CurrentAuthSession
) -> Result<Json<ChatSessionWithDekResponse>, AppError> {
    let pool = state.pool.clone();
    let user = auth_session.user.ok_or_else(|| {
        error!("User not found in session for chat_id: {}", chat_id);
        AppError::Unauthorized("User not found in session".to_string())
    })?;

    let chat_session_db = pool
        .get()
        .await?
        .interact(move |conn| {
            crate::schema::chat_sessions::table
                .filter(crate::schema::chat_sessions::id.eq(chat_id))
                .filter(crate::schema::chat_sessions::user_id.eq(user.id))
                .select(Chat::as_select())
                .first::<Chat>(conn)
                .optional()
        })
        .await??;

    if let Some(session_db) = chat_session_db {
        let dek_present = user.dek.is_some();

        // Decrypt title if possible
        let decrypted_title = match (
            session_db.title_ciphertext.as_ref(),
            session_db.title_nonce.as_ref(),
            user.dek.as_ref(),
        ) {
            (Some(ciphertext), Some(nonce), Some(dek_wrapped))
                if !ciphertext.is_empty() && !nonce.is_empty() =>
            {
                crate::crypto::decrypt_gcm(ciphertext, nonce, &dek_wrapped.0).map_or_else(
                    |_| Some("[Decryption Failed]".to_string()),
                    |plaintext_secret| {
                        String::from_utf8(plaintext_secret.expose_secret().clone())
                            .map_or_else(|_| Some("[Invalid UTF-8]".to_string()), Some)
                    },
                )
            }
            _ => None,
        };

        Ok(Json(ChatSessionWithDekResponse {
            id: session_db.id,
            user_id: session_db.user_id,
            character_id: session_db.character_id,
            title: decrypted_title,
            dek_present,
        }))
    } else {
        Err(AppError::NotFound("Chat session not found".to_string()))
    }
}

#[instrument(skip_all, fields(user_id = field::Empty, chat_session_id = %session_id, field_name = %payload.field_name))]
pub async fn create_or_update_chat_character_override_handler(
    State(state): State<AppState>,
    auth_session: CurrentAuthSession,
    session_dek: SessionDek,
    Path(session_id): Path<Uuid>,
    Json(payload): Json<CharacterOverrideDto>,
) -> Result<impl IntoResponse, AppError> {
    info!("Attempting to create or update chat character override via handler");
    payload.validate()?; // Validate DTO

    let user = auth_session.user.ok_or_else(|| {
        error!("User not found in session during override creation/update");
        AppError::Unauthorized("User not found in session".to_string())
    })?;
    let user_id = user.id;
    tracing::Span::current().record("user_id", tracing::field::display(user_id));

    // 1. Verify ownership of the chat_session and get original_character_id
    let chat_session_details = state
        .pool
        .get()
        .await?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select((chat_sessions::user_id, chat_sessions::character_id))
                .first::<(Uuid, Uuid)>(conn)
                .optional()
        })
        .await??
        .ok_or_else(|| AppError::NotFound(format!("Chat session {session_id} not found")))?;

    if chat_session_details.0 != user_id {
        error!(
            "User {} attempted to modify overrides for chat session {} owned by {}",
            user_id, session_id, chat_session_details.0
        );
        return Err(AppError::Forbidden);
    }
    let original_character_id = chat_session_details.1;

    // 2. Call the ChatOverrideService to handle the logic
    let upserted_override: ChatCharacterOverride = state
        .chat_override_service // Use the service from AppState
        .create_or_update_chat_override(
            session_id,
            original_character_id,
            user_id,            // Pass user_id for logging/future checks in service
            payload.field_name, // field_name is already a String
            payload.value,      // value is already a String
            &session_dek,
        )
        .await?;

    info!(override_id = %upserted_override.id, "Chat character override created/updated successfully via handler calling service");

    Ok(Json(upserted_override))
}
