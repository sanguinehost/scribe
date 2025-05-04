use crate::{
    auth::user_store::Backend as AuthBackend,
    errors::AppError,
    models::chats::{Chat, MessageRole, NewChatMessageRequest, UpdateChatSettingsRequest}, // Added Chat
    services::chat_service,
    state::AppState,
};
use axum::debug_handler;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response, sse::Event, sse::Sse},
    routing::{get, post},
};
use axum_login::AuthSession;
use bigdecimal::BigDecimal;
use bigdecimal::ToPrimitive;
use futures::StreamExt;
use genai::chat::{ChatMessage, ChatOptions, ChatRequest, ChatResponse, ChatStreamEvent};
use mime;
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, error, info, instrument, warn};
use uuid::Uuid;
use validator::Validate;

const DEFAULT_MODEL_NAME: &str = "gemini-2.5-pro-exp-03-25";

#[derive(Deserialize)]
pub struct CreateChatRequest {
    character_id: Uuid,
}

#[debug_handler]
#[instrument(skip(state, auth_session, payload), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)), err)]
pub async fn create_chat_session(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Json(payload): Json<CreateChatRequest>,
) -> Result<impl IntoResponse, AppError> {
    info!("Creating new chat session");
    let user = auth_session.user.ok_or_else(|| {
        error!("Authentication required for create_chat_session");
        AppError::Unauthorized("Authentication required".to_string())
    })?;
    let user_id = user.id;
    let character_id = payload.character_id;

    // Call the service function to handle database operations
    let created_session =
        chat_service::create_session_and_maybe_first_message(state.clone().into(), user_id, character_id)
            .await?;

    info!(session_id = %created_session.id, "Chat session creation successful");
    Ok((StatusCode::CREATED, Json(created_session)))
}

#[debug_handler]
#[instrument(skip(state, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id)), err)]
pub async fn list_chat_sessions(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id = user.id;

    // Call the service function
    let sessions = chat_service::list_sessions_for_user(&state.pool, user_id).await?;

    Ok(Json(sessions))
}

#[debug_handler]
#[instrument(skip(state, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), %session_id), err)]
pub async fn get_chat_session_details(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(session_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    info!("Fetching chat session details");
    let user = auth_session.user.ok_or_else(|| {
        error!("Authentication required for get_chat_session_details");
        AppError::Unauthorized("Authentication required".to_string())
    })?;
    let user_id = user.id;

    // Call the service function (assuming it will be created)
    // This function needs to verify ownership (user_id against session_id)
    let session = chat_service::get_chat_session_by_id(&state.pool, user_id, session_id).await?;

    info!(%session_id, "Successfully fetched chat session details");
    Ok(Json(session))
}

#[debug_handler]
#[instrument(skip(state, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), %session_id), err)]
pub async fn get_chat_messages(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(session_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session
        .user
        .ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id = user.id;

    // Call the service function
    let messages = chat_service::get_messages_for_session(&state.pool, user_id, session_id).await?;

    Ok(Json(messages))
}

// Helper to extract content from a response, returning an error if missing
fn extract_content_or_error(response: &ChatResponse) -> Result<String, AppError> {
    response
        .content_text_as_str()
        .ok_or_else(|| {
            error!("Gemini response missing content: {:?}", response);
            AppError::GenerationError(
                "Gemini response was empty or missing text content".to_string(),
            )
        })
        .map(|s| s.to_string()) // Convert &str to String on success
}

/// Generates a chat response, supporting both streaming (SSE) and non-streaming (JSON).
/// Checks the Accept header: uses SSE if text/event-stream is present, otherwise JSON.
#[axum::debug_handler] // Keep debug handler for now
#[instrument(
    skip(app_state, auth_session, req),
    fields(
        user_id = ?auth_session.user.as_ref().map(|u| u.id),
        %session_id
    ),
    err
)]
pub async fn generate_chat_response(
    State(app_state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(session_id): Path<Uuid>,
    headers: axum::http::HeaderMap,
    Json(req): Json<NewChatMessageRequest>,
) -> Result<Response, AppError> {
    info!(%session_id, "Received chat generation request");
    let user = auth_session.user.ok_or_else(|| {
        error!("Authentication required for generate_chat_response");
        AppError::Unauthorized("Authentication required".to_string())
    })?;
    let user_id = user.id;
    let user_message_content = req.content;

// --- INFO LOG ---
    info!(session_id = %session_id, "Attempting to get session data for generation");
    // --- END INFO LOG ---
    // --- 1. Get Settings, History, and Prepare User Message Struct ---
    let (
        prompt_history, // History *before* the current user message
        system_prompt,
        temperature,
        max_tokens_setting,
        frequency_penalty,
        presence_penalty,
        top_k,
        top_p,
        repetition_penalty,
        min_p,
        top_a,
        seed,
        logit_bias,
        model_name,
        user_message_to_save, // Get the unsaved user message struct
        // Destructure history management settings (even if not used directly here)
        _history_management_strategy, // Use underscore prefix as it's not used directly
        _history_management_limit,    // Use underscore prefix as it's not used directly
    ) = chat_service::get_session_data_for_generation(
        &app_state.pool,
        user_id,
        session_id,
        user_message_content.clone(), // Clone here for RAG context later
        DEFAULT_MODEL_NAME.to_string(),
    )
    .await?;
// --- INFO LOG ---
    info!(session_id = %session_id, history_len = prompt_history.len(), "Received history from service");
    // --- END INFO LOG ---
    // --- 1a. Save User Message (and trigger its embedding) ---
    let saved_user_message = chat_service::save_message(
        app_state.clone().into(),
        user_message_to_save.chat_id, // Correct field name: chat_id
        user_id,                      // Pass user_id directly (was Some(user_id))
        user_message_to_save.role,    // Correct field name: role
        user_message_to_save.content.clone(), // Clone content for saving
    )
    .await?;
    let user_message_id = saved_user_message.id; // Get ID for potential logging/use
    info!(%user_message_id, %session_id, "User message saved successfully");

    // --- 1b. Retrieve RAG Context (using original user message content) ---
    let retrieved_chunks = match app_state
        .embedding_pipeline_service
        .retrieve_relevant_chunks(
            app_state.clone().into(),
            session_id,
            &user_message_content,
            3,
        ) // Convert AppState to Arc<AppState>, Added limit=3
        .await
    {
        Ok(chunks) => {
            info!(%session_id, count = chunks.len(), "Retrieved RAG chunks");
            chunks
        }
        Err(e) => {
            warn!(error = ?e, %session_id, "Failed to retrieve RAG chunks, proceeding without context.");
            Vec::new() // Proceed without RAG context on error
        }
    };

    let rag_context_string = if !retrieved_chunks.is_empty() {
        let context_lines: Vec<String> = retrieved_chunks
            .iter()
            .map(|chunk| format!("- {}", chunk.text.trim())) // Format each chunk
            .collect();
        // Ensure there's a newline between the closing tag and the user message
        format!(
            "<RAG_CONTEXT>\n{}\n</RAG_CONTEXT>\n\n",
            context_lines.join("\n")
        )
    } else {
        String::new() // Empty string if no chunks
    };

    // --- 2. Assemble Prompt ---
    // Convert DB history to ChatMessage format
    let mut genai_messages: Vec<ChatMessage> = prompt_history // Make mutable
        .into_iter()
        .map(|(role, content)| match role {
            MessageRole::User => ChatMessage::user(content),
            MessageRole::Assistant => ChatMessage::assistant(content),
            MessageRole::System => ChatMessage::system(content), // Keep system messages from history if any
        })
        .collect();

    // Prepend system prompt if it exists
    if let Some(system) = system_prompt {
        if !system.trim().is_empty() {
             genai_messages.insert(0, ChatMessage::system(system)); // Insert at the beginning
        }
    }

    // Prepend RAG context to the *current* user message content
    let user_message_with_rag = format!("{}{}", rag_context_string, user_message_content);

    // Build the request
    let genai_request = ChatRequest::default()
        .append_messages(genai_messages) // History messages (now potentially including system prompt)
        .append_message(ChatMessage::user(user_message_with_rag)); // User message with RAG prepended

    // Apply defaults if settings are None
    let default_temperature = 1.0;
    let default_max_tokens = 512; // Define a default value
    let default_top_p = 0.95; // Define default for top_p

    // Start with the library's defaults
    let base_options = ChatOptions::default();

    // Explicitly set the fields we manage, overriding defaults only where needed
    let chat_options = ChatOptions {
        temperature: temperature
            .and_then(|t| t.to_f64())
            .or(Some(default_temperature)),
        max_tokens: max_tokens_setting
            .map(|t| t as u32)
            .or(Some(default_max_tokens)),
        top_p: top_p.and_then(|p| p.to_f64()).or(Some(default_top_p)), // Apply default if None
        // Use struct update syntax to fill remaining fields from base_options
        ..base_options
    };

    // Warnings for fields potentially not mapped or used by the underlying API
    if frequency_penalty.is_some() {
        warn!(%session_id, "frequency_penalty specified but potentially not used in ChatOptions struct init");
    }
    if presence_penalty.is_some() {
        warn!(%session_id, "presence_penalty specified but potentially not used in ChatOptions struct init");
    }
    if top_k.is_some() {
        warn!(%session_id, "top_k specified but potentially not used in ChatOptions struct init");
    }
    if repetition_penalty.is_some() {
        warn!(%session_id, "repetition_penalty specified but potentially not used in ChatOptions struct init");
    }
    if min_p.is_some() {
        warn!(%session_id, "min_p specified but potentially not used in ChatOptions struct init");
    }
    if top_a.is_some() {
        warn!(%session_id, "top_a specified but potentially not used in ChatOptions struct init");
    }
    if seed.is_some() {
        warn!(%session_id, "seed specified but potentially not used in ChatOptions struct init");
    }
    if logit_bias.is_some() {
        warn!(%session_id, "logit_bias specified but potentially not used in ChatOptions struct init");
    }

    debug!(?chat_options, ?genai_request, %model_name, "Prepared request for Gemini");

    // --- Determine Response Type (Check Accept Header) ---
    let accept_header = headers.get(axum::http::header::ACCEPT);
    let accept_stream = accept_header
        .and_then(|value| value.to_str().ok())
        .map_or(false, |value_str| {
            value_str.contains(mime::TEXT_EVENT_STREAM.as_ref())
        });

    // --- 3. Generate Response ---
    if accept_stream {
        info!(%session_id, "Client accepts SSE, initiating streaming response.");

        let ai_stream_result = app_state
            .ai_client
            .stream_chat(&model_name, genai_request, Some(chat_options))
            .await;

        match ai_stream_result {
            Ok(mut stream) => {
                let sse_stream = async_stream::stream! {
                    let mut full_response = String::new();
                    let mut stream_error_occurred = false; // Flag to track if Err was yielded
                    while let Some(item_result) = stream.next().await {
                        match item_result {
                            Ok(ChatStreamEvent::Chunk(chunk)) => {
                                // Access the content field directly
                                if !chunk.content.is_empty() {
                                    full_response.push_str(&chunk.content);
                                    yield Ok::<_, AppError>(Event::default().event("content").data(chunk.content));
                                } else {
                                    // Log if a chunk had empty content (optional)
                                    debug!(%session_id, ?chunk, "Received stream chunk with empty content.");
                                }
                            }
                            Ok(ChatStreamEvent::End(_end_event)) => {
                                debug!(%session_id, "AI stream End event received.");
                                break; // Normal exit
                            }
                            Ok(ChatStreamEvent::Start) => {
                                debug!("Stream started event received.");
                            }
                            Ok(ChatStreamEvent::ReasoningChunk(reasoning)) => {
                                debug!(?reasoning.content, %session_id, "Reasoning chunk received.");
                                yield Ok::<_, AppError>(Event::default().event("thinking").data(reasoning.content));
                            }
                            Err(e) => {
                                error!(error = ?e, %session_id, "Error during SSE stream processing");
                                let app_state_clone = app_state.clone();
                                let session_id_clone = session_id;
                                let partial_response = full_response.clone();
                                tokio::spawn(async move {
                                    if !partial_response.is_empty() {
                                        info!(%session_id_clone, content_len=partial_response.len(), "Attempting to save PARTIAL streamed AI response due to error.");
                                        if let Err(save_err) = chat_service::save_message(
                                            app_state_clone.into(),
                                            session_id_clone,
                                            user_id, // Pass the request user_id (was None)
                                            MessageRole::Assistant,
                                            partial_response, // Save the partial content
                                        ).await {
                                            error!(error = ?save_err, %session_id_clone, "Failed to save PARTIAL streamed AI response");
                                        } else {
                                            info!(%session_id_clone, "Successfully saved PARTIAL streamed AI response.");
                                        }
                                    } else {
                                       warn!(%session_id_clone, "Stream errored before any content was generated, not saving AI message.");
                                    }
                                });
                                yield Ok::<_, AppError>(Event::default().event("error").data(e.to_string()));
                                stream_error_occurred = true; // Set flag
                                break; // Error exit
                            }
                        }
                    }

                    // Save logic (moved outside the loop for clarity)
                    if !stream_error_occurred && !full_response.is_empty() {
                         // Spawn task to save full response
                         let app_state_clone = app_state.clone();
                         let session_id_clone = session_id;
                         let full_response_clone = full_response.clone(); // Clone for spawn
                         tokio::spawn(async move {
                             info!(%session_id_clone, content_len=full_response_clone.len(), "Attempting to save completed streamed AI response.");
                             if let Err(save_err) = chat_service::save_message(
                                 app_state_clone.into(),
                                 session_id_clone,
                                 user_id, // Pass the request user_id (was None)
                                 MessageRole::Assistant,
                                 full_response_clone, // Use the cloned value
                             ).await {
                                 error!(error = ?save_err, %session_id_clone, "Failed to save completed streamed AI response");
                             } else {
                                 info!(%session_id_clone, "Successfully saved completed streamed AI response.");
                             }
                         });
                    } else if stream_error_occurred && !full_response.is_empty() {
                        // Partial save logic was already inside the Err(e) block's spawn, no need to repeat.
                        // Just log that we finished with an error.
                        warn!(%session_id, "Stream processing finished with an error. Partial response saved (if any).");
                    } else {
                         warn!(%session_id, "Stream finished or errored with no content generated, not saving AI message.");
                    }

                    // Send "done" only if no error occurred
                    if !stream_error_occurred {
                         debug!(%session_id, "Sending final 'done' event");
                         yield Ok::<_, AppError>(Event::default().event("done"));
                    }
                     info!(%session_id, "SSE stream generation finished.");
                };

                Ok(Sse::new(sse_stream)
                    .keep_alive(axum::response::sse::KeepAlive::default())
                    .into_response())
            }
            Err(e) => {
                error!(error = ?e, %session_id, "Failed to initiate AI stream");
                Err(e)
            }
        }
    } else {
        info!(%session_id, "Client does not accept SSE, generating full response.");

        let ai_response_result = app_state
            .ai_client
            .exec_chat(&model_name, genai_request, Some(chat_options))
            .await;

        match ai_response_result {
            Ok(response) => {
                // Try to extract content. This might fail if response is blocked or empty.
                match extract_content_or_error(&response) {
                    Ok(full_content) => {
                        if full_content.is_empty() {
                            warn!(%session_id, "Non-streaming AI response was empty after extraction");
                            // Still save an empty message, return success with empty content
                            let empty_saved_message = chat_service::save_message(
                                app_state.clone().into(),
                                session_id,
                                user_id,
                                MessageRole::Assistant,
                                "".to_string(),
                            )
                            .await?;
                            Ok(
                                Json(
                                    json!({ "message_id": empty_saved_message.id, "content": "" }),
                                )
                                .into_response(),
                            )
                        } else {
                            // Save the successful response
                            let saved_message = chat_service::save_message(
                                app_state.clone().into(),
                                session_id,
                                user_id,
                                MessageRole::Assistant,
                                full_content.clone(),
                            )
                            .await?;
                            // Return success with content
                            Ok(Json(
                                json!({ "message_id": saved_message.id, "content": full_content }),
                            )
                            .into_response())
                        }
                    }
                    Err(e @ AppError::GenerationError(_)) => {
                        // This specifically handles the case where extract_content_or_error failed (e.g., safety block)
                        error!(error = ?e, %session_id, "Failed to extract content from non-streaming AI response, possibly blocked.");
                        // Return a specific error response to the client
                        let status = StatusCode::BAD_GATEWAY; // 502 might be appropriate
                        let body =
                            Json(json!({ "error": "Generation failed", "detail": e.to_string() }));
                        Ok((status, body).into_response())
                    }
                    Err(e) => {
                        // Handle other potential errors from extract_content_or_error if any exist
                        error!(error = ?e, %session_id, "Unexpected error during content extraction");
                        Err(e) // Propagate other errors for default 500 handling
                    }
                }
            }
            Err(e) => {
                // This handles errors from the initial ai_client.exec_chat call (e.g., network error, API key issue)
                error!(error = ?e, %session_id, "Failed to execute non-streaming AI request");
                // Return a specific error response to the client
                let status = StatusCode::BAD_GATEWAY; // Or potentially another 5xx code
                let body =
                    Json(json!({ "error": "AI service request failed", "detail": e.to_string() }));
                Ok((status, body).into_response())
                // Or propagate if default 500 handling is preferred for these specific errors: Err(e)
            }
        }
    }
}

#[debug_handler]
#[instrument(skip(state, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), %session_id), err)]
pub async fn get_chat_settings(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(session_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    info!("Fetching chat settings");
    let user = auth_session.user.ok_or_else(|| {
        error!("Authentication required for get_chat_settings");
        AppError::Unauthorized("Authentication required".to_string())
    })?;
    let user_id = user.id;

    // Call the service function
    let settings_response =
        chat_service::get_session_settings(&state.pool, user_id, session_id).await?;
    info!(%session_id, "Successfully fetched chat settings");
    Ok(Json(settings_response))
}

/// Updates the settings for a specific chat session.
#[debug_handler]
#[instrument(skip(state, auth_session, payload), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), %session_id), err)]
pub async fn update_chat_settings(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(session_id): Path<Uuid>,
    Json(payload): Json<UpdateChatSettingsRequest>,
) -> Result<impl IntoResponse, AppError> {
    info!("Updating chat settings");
    let user = auth_session.user.ok_or_else(|| {
        error!("Authentication required for update_chat_settings");
        AppError::Unauthorized("Authentication required".to_string())
    })?;
    let user_id = user.id;
payload.validate()?; // Trigger model-level validation

    // --- Input Validation ---
    // BigDecimal helpers for comparisons
    use bigdecimal::FromPrimitive;
    let zero = BigDecimal::from_f32(0.0).unwrap();
    let two = BigDecimal::from_f32(2.0).unwrap();
    let one = BigDecimal::from_f32(1.0).unwrap();
    let neg_two = BigDecimal::from_f32(-2.0).unwrap();

    // Validate temperature (between 0.0 and 2.0)
    if let Some(temp) = &payload.temperature {
        // temp is &BigDecimal
        if temp < &zero || temp > &two {
            error!(%session_id, invalid_temp = %temp, "Invalid temperature value");
            return Err(AppError::BadRequest(
                "Temperature must be between 0.0 and 2.0".into(),
            ));
        }
    }

    // Validate max_output_tokens (positive)
    if let Some(tokens) = payload.max_output_tokens {
        if tokens <= 0 {
            error!(%session_id, invalid_tokens = tokens, "Invalid max_output_tokens value");
            return Err(AppError::BadRequest(
                "Max output tokens must be positive".into(),
            ));
        }
    }

    // Validate frequency_penalty (between -2.0 and 2.0)
    if let Some(fp) = &payload.frequency_penalty {
        if fp < &neg_two || fp > &two {
            error!(%session_id, invalid_fp = %fp, "Invalid frequency_penalty value");
            return Err(AppError::BadRequest(
                "Frequency penalty must be between -2.0 and 2.0".into(),
            ));
        }
    }

    // Validate presence_penalty (between -2.0 and 2.0)
    if let Some(pp) = &payload.presence_penalty {
        if pp < &neg_two || pp > &two {
            error!(%session_id, invalid_pp = %pp, "Invalid presence_penalty value");
            return Err(AppError::BadRequest(
                "Presence penalty must be between -2.0 and 2.0".into(),
            ));
        }
    }

    // Validate top_k (positive)
    if let Some(k) = payload.top_k {
        if k <= 0 {
            error!(%session_id, invalid_k = k, "Invalid top_k value");
            return Err(AppError::BadRequest("Top-k must be positive".into()));
        }
    }

    // Validate top_p (between 0.0 and 1.0)
    if let Some(p) = &payload.top_p {
        if p < &zero || p > &one {
            error!(%session_id, invalid_p = %p, "Invalid top_p value");
            return Err(AppError::BadRequest(
                "Top-p must be between 0.0 and 1.0".into(),
            ));
        }
    }

    // Validate repetition_penalty (positive)
    if let Some(rp) = &payload.repetition_penalty {
        if rp <= &zero {
            error!(%session_id, invalid_rp = %rp, "Invalid repetition_penalty value");
            return Err(AppError::BadRequest(
                "Repetition penalty must be positive".into(),
            ));
        }
    }

    // Validate min_p (between 0.0 and 1.0)
    if let Some(mp) = &payload.min_p {
        if mp < &zero || mp > &one {
            error!(%session_id, invalid_mp = %mp, "Invalid min_p value");
            return Err(AppError::BadRequest(
                "Min-p must be between 0.0 and 1.0".into(),
            ));
        }
    }

    // Validate top_a (between 0.0 and 1.0)
    if let Some(ta) = &payload.top_a {
        if ta < &zero || ta > &one {
            // Check if outside 0.0-1.0 range
            error!(%session_id, invalid_ta = %ta, "Invalid top_a value");
            return Err(AppError::BadRequest(
                "Top-a must be between 0.0 and 1.0".into(),
            ));
        }
    }

    // No special validation needed for seed (any i32 is valid)

    // Validate logit_bias (must be a JSON object if present)
    if let Some(bias) = &payload.logit_bias {
        if !bias.is_object() {
            error!(%session_id, invalid_bias = ?bias, "Invalid logit_bias value (must be a JSON object)");
            return Err(AppError::BadRequest(
                "Logit bias must be a JSON object".into(),
            ));
        }
        // Optional: Further validation on the object's keys/values if needed
    }

    // --- Database Update ---
    // Call the service function to handle the update and return the updated settings
    let updated_settings_response = chat_service::update_session_settings(
        &state.pool,
        user_id,
        session_id,
        payload, // Pass the validated payload
    )
    .await?;

    info!(%session_id, "Successfully updated chat settings");
    Ok(Json(updated_settings_response)) // Explicitly return Ok(Json(...))
}

/// Defines the routes related to chat sessions and messages.
pub fn chat_routes() -> Router<AppState> {
    Router::new()
        .route("/", post(create_chat_session).get(list_chat_sessions))
        .route("/{session_id}", get(get_chat_session_details)) // Corrected path parameter syntax
        .route("/{session_id}/messages", get(get_chat_messages))
        .route("/{session_id}/generate", post(generate_chat_response))
        .route(
            "/{session_id}/settings",
            get(get_chat_settings).put(update_chat_settings),
        ) // Add settings routes
}
