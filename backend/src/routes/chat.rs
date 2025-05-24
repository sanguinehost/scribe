// backend/src/routes/chat.rs

use crate::auth::session_dek::SessionDek;
use crate::auth::user_store::Backend as AuthBackend;
use crate::errors::AppError;
// Unused import: crate::models::characters::Character;
use crate::models::chats::CreateChatSessionPayload;
// Unused import: crate::models::chats::NewChat;
use crate::models::chats::{
    Chat, GenerateChatRequest, MessageRole, SuggestedActionItem, SuggestedActionsRequest,
    SuggestedActionsResponse,
};
use crate::models::chat_override::{CharacterOverrideDto, ChatCharacterOverride};
use crate::routes::chats::{get_chat_settings_handler, update_chat_settings_handler};
use crate::schema::chat_sessions;
use crate::services::chat_service::{self, ScribeSseEvent};
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
// Unused import: chrono::Utc;
use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper, prelude::*};
use futures_util::StreamExt;
use genai::chat::{
    ChatMessage as GenAiChatMessage, ChatOptions, ChatRequest, ChatResponseFormat, ChatRole,
    JsonSpec, MessageContent,
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

    let user = auth_session.user.ok_or_else(|| {
        error!("User not found in session during chat creation");
        AppError::Unauthorized("User not found in session".to_string())
    })?;
    let user_id = user.id;
    tracing::Span::current().record("user_id", &tracing::field::display(user_id));
    tracing::Span::current().record(
        "character_id",
        &tracing::field::display(payload.character_id),
    );
    if let Some(persona_id) = payload.active_custom_persona_id {
        tracing::Span::current().record(
            "active_custom_persona_id",
            &tracing::field::display(persona_id),
        );
    }

    debug!(user_id = %user_id, character_id = %payload.character_id, active_custom_persona_id=?payload.active_custom_persona_id, "User, character, and persona ID extracted");

    // Call the service function to create the chat session
    let created_chat_session = chat_service::create_session_and_maybe_first_message(
        state.into(),
        user_id,
        payload.character_id,
        payload.active_custom_persona_id, // Pass the new field
        Some(Arc::new(session_dek.0)),    // Pass the DEK, wrapped in Arc for the service
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
                "Interact dispatch error checking session owner: {}",
                e
            ))
        })? // Handle interact error
        .map_err(|e_db| match e_db {
            // Handle DB error from the closure
            diesel::result::Error::NotFound => {
                AppError::NotFound(format!("Chat session {} not found.", session_id))
            }
            _ => AppError::DatabaseQueryError(format!(
                "Failed to query chat session owner for {}: {}",
                session_id, e_db
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
    let current_user_content = current_user_api_message.content.clone();
    trace!(%session_id, "Extracted current user message content for generation.");

    // Get comprehensive data for generation from chat_service
    let (
        managed_history_tuples,
        system_prompt_from_service,
        gen_temperature,
        gen_max_output_tokens,
        gen_frequency_penalty,
        gen_presence_penalty,
        gen_top_k,
        gen_top_p,
        gen_repetition_penalty,
        gen_min_p,
        gen_top_a,
        gen_seed,
        gen_logit_bias,
        gen_model_name_from_service,
        gen_gemini_thinking_budget,
        gen_gemini_enable_code_execution,
        user_message_struct_to_save, // RENAMED from _user_message_to_save_for_db
        _hist_management_strategy,
        _hist_management_limit,
    ) = chat_service::get_session_data_for_generation(
        state_arc.clone(),
        user_id_value,
        session_id,
        current_user_content.clone(),
        Some(session_dek_arc.clone()), // Use Arc clone
    )
    .await?;

    debug!(
        %session_id,
        system_prompt_len = system_prompt_from_service.as_ref().map_or(0, |s| s.len()),
        gen_temp = ?gen_temperature,
        gen_max_tokens = ?gen_max_output_tokens,
        gen_top_p = ?gen_top_p,
        gen_model_name = %gen_model_name_from_service,
        "Retrieved data for generation from chat_service."
    );

    // Determine the model to use: payload overrides service, otherwise use service's model
    let model_to_use = payload.model.clone().unwrap_or(gen_model_name_from_service);
    debug!(%model_to_use, "Determined final model to use for AI calls.");

    // Prepare GenAI history (managed history + current user message)
    let mut genai_history: Vec<GenAiChatMessage> = managed_history_tuples
        .into_iter()
        .map(|(role, content)| {
            match role {
                MessageRole::User => GenAiChatMessage::user(MessageContent::from_text(content)),
                MessageRole::Assistant => {
                    GenAiChatMessage::assistant(MessageContent::from_text(content))
                }
                MessageRole::System => GenAiChatMessage::system(MessageContent::from_text(content)), // MODIFIED: Handle System role
            }
        })
        .collect();
    genai_history.push(GenAiChatMessage::user(MessageContent::from_text(
        current_user_content.clone(),
    )));
    trace!(history_len = genai_history.len(), %session_id, "Prepared final message list for AI (service history + current payload message)");

    let accept_header = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    let request_thinking = query_params.request_thinking;
    debug!(%session_id, %request_thinking, "request_thinking value from query parameters");

    // RAG related logic
    let enable_rag = headers
        .get("X-Scribe-Enable-RAG")
        .map(|v| v.to_str().unwrap_or("false") == "true")
        .unwrap_or(true); // Default to true for RAG functionality in test

    let mut rag_context_for_json: Option<String> = None;

    if enable_rag && accept_header.contains(mime::APPLICATION_JSON.as_ref()) {
        // RAG for JSON path
        if !current_user_content.is_empty() {
            info!(%session_id, "RAG enabled for JSON path, attempting to retrieve context for user message.");

            // Perform RAG retrieval for JSON path using embedding pipeline service
            let rag_result = state_arc
                .embedding_pipeline_service
                .retrieve_relevant_chunks(
                    state_arc.clone(),
                    user_id_value,         // New argument: user_id
                    Some(session_id),      // For session_id_for_chat_history - Wrapped in Some()
                    None,                  // For active_lorebook_ids_for_search
                    &current_user_content,
                    5                      // Limit to 5 chunks
                )
                .await;

            match rag_result {
                Ok(chunks) => {
                    if !chunks.is_empty() {
                        info!(%session_id, chunk_count = chunks.len(), "Retrieved RAG chunks for JSON path");
                        let mut context = String::from("<RAG_CONTEXT>\n");
                        for chunk in chunks {
                            context.push_str(&format!("- {}\n", chunk.text.trim()));
                        }
                        context.push_str("</RAG_CONTEXT>");
                        rag_context_for_json = Some(context);
                    } else {
                        info!(%session_id, "No relevant RAG chunks found for JSON path");
                    }
                }
                Err(e) => {
                    error!(%session_id, error = ?e, "Failed to retrieve RAG context for JSON path");
                    // Propagate the error to the client with BAD_GATEWAY status code
                    return Err(AppError::BadGateway(
                        "Failed to process embeddings".to_string(),
                    ));
                }
            }
        }
    }

    match accept_header {
        v if v.contains(mime::TEXT_EVENT_STREAM.as_ref()) => {
            info!(%session_id, "Handling streaming SSE request. request_thinking={}", request_thinking);

            // Explicitly save the user's message before streaming AI response
            let _current_user_content_for_save = user_message_struct_to_save.content.clone(); // Assuming content is Vec<u8>
            let current_user_role_for_save = user_message_struct_to_save.role.clone();
            let current_user_parts_for_save = user_message_struct_to_save.parts.clone();
            let current_user_attachments_for_save = user_message_struct_to_save.attachments.clone();

            // We need the actual text content for save_message's `content: &str` param.
            // user_message_struct_to_save.content is Vec<u8> (potentially encrypted later, but plaintext from user initially).
            // For user messages, this original Vec<u8> should be the direct user_message_content.
            // The `DbInsertableChatMessage::new` call in `get_session_data_for_generation` uses `user_message_content.into_bytes()`.

            match chat_service::save_message(
                state_arc.clone(),
                session_id,
                user_id_value,
                MessageRole::User,                 // message_type_enum
                &current_user_content, // This is the original String content from the payload
                current_user_role_for_save, // role_str from the prepared struct
                current_user_parts_for_save, // parts from the prepared struct
                current_user_attachments_for_save, // attachments from the prepared struct
                Some(session_dek_arc.clone()), // DEK for potential encryption
                &model_to_use,
            )
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
            match chat_service::stream_ai_response_and_save_message(
                state_arc.clone(),
                session_id,
                user_id_value,
                genai_history,              // Use the prepared history
                system_prompt_from_service, // Use system prompt from service
                gen_temperature,            // Use temperature from service
                gen_max_output_tokens,      // Use max_tokens from service
                gen_frequency_penalty,
                gen_presence_penalty,
                gen_top_k,
                gen_top_p, // Use top_p from service
                gen_repetition_penalty,
                gen_min_p,
                gen_top_a,
                gen_seed,
                gen_logit_bias,
                model_to_use.clone(), // Use the resolved model
                gen_gemini_thinking_budget,
                gen_gemini_enable_code_execution,
                request_thinking,
                Some(dek_for_stream_service), // MODIFIED: Pass cloned SecretBox
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
                        if !error_from_service_stream {
                            if content_produced {
                                 debug!(%session_id, "Service stream ended, sending [DONE] event because content was produced.");
                                 yield Ok(Event::default().event("done").data("[DONE]"));
                            } else {
                                debug!(%session_id, "Service stream ended without producing content (and no error), sending [DONE_EMPTY] event.");
                                yield Ok(Event::default().event("done").data("[DONE_EMPTY]"));
                            }
                        } else {
                            debug!(%session_id, "Service stream ended with an error or an error event was already sent. Not sending additional [DONE] event.");
                        }
                    };
                    Ok(Sse::new(Box::pin(final_stream))
                        .keep_alive(KeepAlive::default())
                        .into_response())
                }
                Err(e) => {
                    error!(error = ?e, %session_id, "Error calling chat_service::stream_ai_response_and_save_message");
                    let error_stream = async_stream::stream! {
                        let error_msg = format!("Service error: Failed to initiate AI processing - {}", e);
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
            let _user_saved_message = match chat_service::save_message(
                state_arc.clone(),
                session_id,
                user_id_value,
                MessageRole::User,                             // message_type_enum
                &current_user_content,                         // content
                Some("user".to_string()),                      // role_str
                Some(json!([{"text": current_user_content}])), // parts
                None,                                          // attachments
                Some(dek_for_user_save_json),
                &model_to_use,
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

            // RAG context injection for JSON path (if enabled and context was found)
            // This modifies a copy of genai_history for this specific non-streaming call.
            let mut history_for_json_call = genai_history.clone();
            if let Some(context) = rag_context_for_json {
                // This context needs to be populated by actual RAG logic if used
                if let Some(last_message) = history_for_json_call.last_mut() {
                    if matches!(last_message.role, ChatRole::User) {
                        if let MessageContent::Text(text_content_string) = &mut last_message.content
                        {
                            // MODIFIED: Removed ref mut
                            let original_content = text_content_string.clone();
                            *text_content_string = format!("{}\n\n{}", context, original_content);
                            trace!(session_id = %session_id, "Injected RAG context into user message (non-streaming JSON path)");
                        }
                    }
                }
            }

            let chat_request =
                ChatRequest::new(history_for_json_call) // Use potentially RAG-modified history
                    .with_system(system_prompt_from_service.unwrap_or_default()); // Use system prompt from service

            let mut chat_options = ChatOptions::default();
            if let Some(temp) = gen_temperature {
                chat_options = chat_options.with_temperature(temp.to_f32().unwrap_or(0.7).into());
            } // MODIFIED: .into()
            if let Some(tokens) = gen_max_output_tokens {
                chat_options = chat_options.with_max_tokens(tokens as u32);
            }
            if let Some(p) = gen_top_p {
                chat_options = chat_options.with_top_p(p.to_f32().unwrap_or(0.95).into());
            } // MODIFIED: .into()
            // Add other gen_... parameters to chat_options as needed (top_k, penalties etc.)
            // For Gemini specific options via exec_chat, they might need to be part of a different options struct or handled by client
            if let Some(budget) = gen_gemini_thinking_budget {
                if budget > 0 {
                    chat_options = chat_options.with_gemini_thinking_budget(budget as u32);
                }
            }
            if let Some(enable_exec) = gen_gemini_enable_code_execution {
                chat_options = chat_options.with_gemini_enable_code_execution(enable_exec);
            }
            // Note: genai library's exec_chat might not support all tool/Gemini options directly in ChatOptions vs stream_chat.
            // This might need adjustment based on genai library capabilities for non-streaming.

            trace!(%session_id, chat_request = ?chat_request, chat_options = ?chat_options, "Prepared ChatRequest and Options for AI (non-streaming, JSON path)");

            match state_arc
                .ai_client
                .exec_chat(&model_to_use, chat_request, Some(chat_options))
                .await
            {
                Ok(chat_response) => {
                    debug!(%session_id, "Received successful non-streaming AI response (JSON path)");

                    let response_content = match chat_response.content {
                        Some(genai::chat::MessageContent::Text(text)) => text,
                        _ => String::new(),
                    };

                    trace!(%session_id, ?response_content, "Full non-streaming AI response (JSON path)");

                    if !response_content.is_empty() {
                        let dek_for_ai_save_json = session_dek_arc.clone();
                        let state_for_ai_save = state_arc.clone();
                        let response_content_for_save = response_content.clone();
                        tokio::spawn(async move {
                            match chat_service::save_message(
                                state_for_ai_save,
                                session_id,
                                user_id_value,
                                MessageRole::Assistant, // message_type_enum
                                &response_content_for_save, // content
                                Some("assistant".to_string()), // role_str  (or "model")
                                Some(json!([{"text": response_content_for_save}])), // parts
                                None,                   // attachments
                                Some(dek_for_ai_save_json),
                                &model_to_use,
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
                    } else {
                        warn!(session_id = %session_id, "Skipping save for empty AI content (JSON path)");
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
            match chat_service::stream_ai_response_and_save_message(
                state_arc.clone(),
                session_id,
                user_id_value,
                genai_history, // Use the prepared history
                system_prompt_from_service,
                gen_temperature,
                gen_max_output_tokens,
                gen_frequency_penalty,
                gen_presence_penalty,
                gen_top_k,
                gen_top_p,
                gen_repetition_penalty,
                gen_min_p,
                gen_top_a,
                gen_seed,
                gen_logit_bias,
                model_to_use,
                gen_gemini_thinking_budget,
                gen_gemini_enable_code_execution,
                request_thinking,
                Some(dek_for_fallback_stream_service), // MODIFIED: Pass Arc clone
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
                        if !error_from_service_stream {
                             if content_produced {
                                 debug!(%session_id, "Service stream ended (fallback), sending [DONE] event.");
                                 yield Ok(Event::default().event("done").data("[DONE]"));
                             } else {
                                 debug!(%session_id, "Service stream ended without content (fallback), sending [DONE_EMPTY] event.");
                                 yield Ok(Event::default().event("done").data("[DONE_EMPTY]"));
                             }
                        } else {
                             debug!(%session_id, "Service stream ended with error (fallback). Not sending additional [DONE] event.");
                        }
                    };
                    Ok(Sse::new(Box::pin(final_stream))
                        .keep_alive(KeepAlive::default())
                        .into_response())
                }
                Err(e) => {
                    error!(error = ?e, %session_id, "Error calling chat_service (fallback SSE)");
                    let error_stream = async_stream::stream! {
                        let error_msg = format!("Service error (fallback): Failed to initiate AI processing - {}", e);
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
            "/:chat_id/suggested-actions",
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

#[instrument(skip(state, auth_session, payload), fields(chat_id = %chat_id))]
pub async fn generate_suggested_actions(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(chat_id): Path<String>,
    Json(payload): Json<SuggestedActionsRequest>,
) -> Result<Json<SuggestedActionsResponse>, AppError> {
    info!("Entering generate_suggested_actions");
    tracing::info!(
        "@@@ GENERATE_SUGGESTED_ACTIONS HANDLER ENTERED (chat_id: {}) @@@",
        chat_id
    );

    info!(
        "Received request for suggested actions (chat_id: {})",
        chat_id
    );
    payload.validate()?;

    let user = auth_session.user.ok_or_else(|| {
        error!(
            "User not found in session for suggested actions (chat_id: {})",
            chat_id
        );
        AppError::Unauthorized("User not found in session".to_string())
    })?;
    let user_id = user.id;
    debug!(user_id = %user_id, chat_id = %chat_id, "User and chat_id extracted for suggested actions");

    let chat_id = Uuid::parse_str(&chat_id).map_err(|_| {
        error!("Invalid chat UUID format: {}", chat_id);
        AppError::BadRequest("Invalid chat UUID format".to_string())
    })?;
    debug!(%chat_id, "Parsed chat_id from parameter");

    let chat_session = state
        .pool
        .get()
        .await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(chat_id))
                .select(Chat::as_select())
                .first::<Chat>(conn)
                .map_err(AppError::from)
        })
        .await
        .map_err(|e| {
            AppError::InternalServerErrorGeneric(format!("Interact error fetching chat: {}", e))
        })??;

    if chat_session.user_id != user_id {
        return Err(AppError::Forbidden);
    }
    debug!(%chat_id, "User authorized for chat session");

    let prompt_text = format!(
        "Given the following start of a conversation:\n\nCharacter Introduction: \"{}\"\n\nUser's First Message: \"{}\"\n\nAI's First Response: \"{}\"\n\n\nGenerate 2-4 short, contextually relevant follow-up actions or questions that the user might want to take next.\n\nEach action should be a concise sentence suitable for display in a small button.",
        payload.character_first_message,
        payload.user_first_message.as_deref().unwrap_or(""),
        payload.ai_first_response.as_deref().unwrap_or("")
    );
    trace!(%chat_id, "Constructed prompt for Gemini suggested actions: {}", prompt_text);

    let messages = vec![GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::Text(prompt_text),
        options: None,
    }];

    let chat_request = ChatRequest::new(messages);

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
        .with_temperature(0.7)
        .with_max_tokens(150)
        .with_response_format(ChatResponseFormat::JsonSpec(JsonSpec {
            name: "suggested_actions".to_string(),
            description: Some("A list of suggested follow-up actions or questions.".to_string()),
            schema: suggested_actions_schema_value,
        }));

    trace!(%chat_id, model = "gemini-2.5-flash-preview-04-17", ?chat_request, ?chat_options, "Sending request to Gemini for suggested actions (manual JSON parsing)");

    let gemini_response = state
        .ai_client
        .exec_chat(
            "gemini-2.5-flash-preview-04-17",
            chat_request,
            Some(chat_options),
        )
        .await
        .map_err(|e| {
            error!(%chat_id, "Gemini API error for suggested actions: {:?}", e);
            AppError::AiServiceError(format!("Gemini API error: {}", e))
        })?;

    debug!(%chat_id, "Received response from Gemini for suggested actions");
    trace!(%chat_id, ?gemini_response, "Full Gemini response object for suggested actions");

    let response_text = match gemini_response.content {
        Some(MessageContent::Text(text)) => text,
        _ => {
            error!(%chat_id, "Gemini response for suggested actions did not contain text content or was empty.");
            return Err(AppError::InternalServerErrorGeneric(
                "AI response was empty or not in the expected format".to_string(),
            ));
        }
    };
    trace!(%chat_id, "Gemini response text for suggested actions: {}", response_text);

    let suggestions: Vec<SuggestedActionItem> =
        serde_json::from_str(&response_text).map_err(|e| {
            error!(
                %chat_id,
                "Failed to parse Gemini JSON response into expected structure for suggested actions: {:?}. Response text: {}", 
                e,
                response_text
            );
            AppError::InternalServerErrorGeneric("Failed to parse structured response from AI".to_string())
        })?;

    info!(%chat_id, "Successfully generated {} suggested actions", suggestions.len());

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
        Ok(Json(ChatSessionWithDekResponse {
            id: session_db.id,
            user_id: session_db.user_id,
            character_id: session_db.character_id,
            title: session_db.title,
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
    tracing::Span::current().record("user_id", &tracing::field::display(user_id));

    // 1. Verify ownership of the chat_session and get original_character_id
    let chat_session_details = state.pool.get().await?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select((chat_sessions::user_id, chat_sessions::character_id))
                .first::<(Uuid, Uuid)>(conn)
                .optional()
        })
        .await??
        .ok_or_else(|| AppError::NotFound(format!("Chat session {} not found", session_id)))?;

    if chat_session_details.0 != user_id {
        error!(
            "User {} attempted to modify overrides for chat session {} owned by {}",
            user_id, session_id, chat_session_details.0
        );
        return Err(AppError::Forbidden);
    }
    let original_character_id = chat_session_details.1;

    // 2. Call the ChatOverrideService to handle the logic
    let upserted_override: ChatCharacterOverride = state.chat_override_service // Use the service from AppState
        .create_or_update_chat_override(
            session_id,
            original_character_id,
            user_id, // Pass user_id for logging/future checks in service
            payload.field_name, // field_name is already a String
            payload.value,      // value is already a String
            &session_dek,
        )
        .await?;

    info!(override_id = %upserted_override.id, "Chat character override created/updated successfully via handler calling service");
    
    Ok(Json(upserted_override))
}
