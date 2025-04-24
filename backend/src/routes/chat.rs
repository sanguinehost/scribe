use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{sse::Event, sse::Sse, IntoResponse},
    Json,
    routing::{post, get},
    Router,
};
use axum::debug_handler;
use futures::{stream::Stream, StreamExt};
use std::{sync::Arc, time::Duration}; // Removed Pin, Infallible
use tokio::sync::Mutex;
use serde::{Deserialize}; // Removed Serialize
use uuid::Uuid;
use bigdecimal::BigDecimal;
// use std::str::FromStr; // Unused import
// use diesel::prelude::*; // Unused import
use axum_login::AuthSession;
// use serde_json::{Value, json}; // Unused imports
use genai::chat::ChatStreamEvent;
use crate::{
    auth::user_store::Backend as AuthBackend,
    errors::AppError,
    models::{
        // Removed ChatSession, DbChatMessage, ChatSettingsResponse, DbInsertableChatMessage
        chats::{MessageRole, NewChatMessageRequest, UpdateChatSettingsRequest},
    },
    // llm::ChatStream, // Unused import
    state::AppState,
    services::chat_service, // Import the new service
};
use tracing::{error, info, instrument, warn, debug};
use genai::chat::{
    ChatRequest,
    ChatMessage,
    ChatOptions,
};
// use chrono::Utc; // Unused import
// use diesel::result::DatabaseErrorKind; // Already commented out

const DEFAULT_MODEL_NAME: &str = "gemini-1.5-flash-latest";

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
    let created_session = chat_service::create_session_and_maybe_first_message(
        &state.pool,
        user_id,
        character_id,
    )
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
    let user = auth_session.user.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id = user.id;

    // Call the service function
    let sessions = chat_service::list_sessions_for_user(&state.pool, user_id).await?;

    Ok(Json(sessions))
}

#[debug_handler]
#[instrument(skip(state, auth_session), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), %session_id), err)]
pub async fn get_chat_messages(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(session_id): Path<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let user = auth_session.user.ok_or_else(|| AppError::Unauthorized("Authentication required".to_string()))?;
    let user_id = user.id;

    // Call the service function
    let messages = chat_service::get_messages_for_session(&state.pool, user_id, session_id).await?;

    Ok(Json(messages))
}

// Removed save_chat_message_internal as it's now in chat_service
#[debug_handler]
#[instrument(skip(state, auth_session, payload), fields(user_id = ?auth_session.user.as_ref().map(|u| u.id), %session_id), err)]
pub async fn generate_chat_response(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(session_id): Path<Uuid>,
    Json(payload): Json<NewChatMessageRequest>,
) -> Result<Sse<impl Stream<Item = Result<Event, axum::BoxError>>>, AppError> {
    info!(%session_id, "Generating streaming chat response");
    let user = auth_session.user.ok_or_else(|| {
        error!(%session_id, "Authentication required for generate_chat_response");
        AppError::Unauthorized("Authentication required".to_string())
    })?;
    let user_id = user.id;

    if payload.content.trim().is_empty() {
        error!(%session_id, "Attempted to send empty message");
        return Err(AppError::BadRequest("Message content cannot be empty".into()));
    }

    let user_message_content = payload.content.clone();
    let pool = state.pool.clone();

    info!(%session_id, "Calling chat service to get data for generation");
    // Call service function to get history, settings, and save user message in one transaction
    let (
        prompt_history,
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
        model_name // Get model name from service (currently hardcoded default)
    ) = chat_service::get_session_data_for_generation(
        &pool,
        user_id,
        session_id,
        user_message_content,
        DEFAULT_MODEL_NAME.to_string(), // Pass default model name
    ).await?;

    info!(%session_id, "DB interaction complete, preparing AI stream request");

    let genai_messages: Vec<ChatMessage> = prompt_history
        .into_iter()
        .map(|(role, content)| {
            match role {
                MessageRole::User => ChatMessage::user(content),
                MessageRole::Assistant => ChatMessage::assistant(content),
                MessageRole::System => ChatMessage::system(content),
            }
        })
        .collect();

    let mut chat_options = ChatOptions::default();
    if let Some(temp) = temperature {
        if let Ok(temp_f64) = temp.to_string().parse::<f64>() {
             debug!(%session_id, temperature = temp_f64, "Applying temperature setting");
             chat_options = chat_options.with_temperature(temp_f64);
        } else { warn!(%session_id, temperature = %temp, "Could not convert BigDecimal temperature to f64"); }
    }
    if let Some(max_tok) = max_tokens {
        if max_tok >= 0 {
            debug!(%session_id, max_tokens = max_tok, "Applying max_output_tokens setting");
            chat_options = chat_options.with_max_tokens(max_tok as u32);
        } else { warn!(%session_id, max_tokens = max_tok, "Ignoring negative max_output_tokens"); }
    }
    if let Some(p) = top_p {
        if let Ok(p_f64) = p.to_string().parse::<f64>() {
            debug!(%session_id, top_p = p_f64, "Applying top_p setting");
            chat_options = chat_options.with_top_p(p_f64);
        } else { warn!(%session_id, top_p = %p, "Could not convert BigDecimal top_p to f64"); }
    }
    if frequency_penalty.is_some() { debug!(%session_id, "frequency_penalty not currently supported by genai ChatOptions"); }
    if presence_penalty.is_some() { debug!(%session_id, "presence_penalty not currently supported by genai ChatOptions"); }
    if top_k.is_some() { debug!(%session_id, "top_k not currently supported by genai ChatOptions"); }
    if repetition_penalty.is_some() { debug!(%session_id, "repetition_penalty not currently supported by genai ChatOptions"); }
    if min_p.is_some() { debug!(%session_id, "min_p not currently supported by genai ChatOptions"); }
    if top_a.is_some() { debug!(%session_id, "top_a not currently supported by genai ChatOptions"); }
    if seed.is_some() { debug!(%session_id, "seed not currently supported by genai ChatOptions"); }
    if logit_bias.is_some() { debug!(%session_id, "logit_bias not currently supported by genai ChatOptions"); }

    let genai_request = if let Some(system) = system_prompt {
        ChatRequest::new(genai_messages).with_system(system)
    } else {
        ChatRequest::new(genai_messages)
    };

    debug!(%session_id, ?genai_request, ?chat_options, "Sending stream request to AI client");

    let ai_stream_result = state.ai_client
        .stream_chat(&model_name, genai_request, Some(chat_options))
        .await;

    let ai_stream = match ai_stream_result {
        Ok(stream) => {
            info!(%session_id, "Successfully initiated AI stream");
            stream
        },
        Err(e) => {
            error!(error = ?e, %session_id, "LLM stream initiation failed");
            return Err(AppError::InternalServerError(anyhow::anyhow!("LLM stream initiation failed: {}", e).to_string()));
        }
    };

    let session_id_clone = session_id;
    let pool_clone = state.pool.clone();
    let full_response_buffer = Arc::new(Mutex::new(String::new()));
    let buffer_clone = full_response_buffer.clone();

    let sse_stream = async_stream::stream! {
        let mut pinned_stream = Box::pin(ai_stream);
        let mut stream_error_occurred = false; // Flag to track errors

        while let Some(event_result) = pinned_stream.next().await {
            match event_result {
                Ok(ChatStreamEvent::Chunk(chunk)) => {
                    if !chunk.content.is_empty() {
                        // Lock buffer once for the whole chunk
                        let mut buffer_guard = buffer_clone.lock().await;
                        buffer_guard.push_str(&chunk.content);
                        drop(buffer_guard); // Release lock

                        // Split chunk content by lines and yield each line as a separate event
                        for line in chunk.content.lines() {
                             debug!(%session_id_clone, line_len = line.len(), "Yielding content line");
                            // Send each line as its own SSE data field
                             yield Ok::<_, axum::BoxError>(Event::default().event("content").data(line.to_string()));
                        }
                    }
                }
                Ok(ChatStreamEvent::End(end_event)) => {
                    debug!(%session_id_clone, ?end_event, "AI stream ended");
                    // No need to yield anything here, the 'done' event is sent after the loop
                    break;
                }
                 Ok(ChatStreamEvent::Start) => {
                     debug!(%session_id_clone, "AI stream started event received (ignored)");
                     // Explicitly ignore, no SSE event sent
                 }
                 Ok(ChatStreamEvent::ReasoningChunk(reasoning)) => {
                    debug!(%session_id_clone, ?reasoning.content, "Yielding thinking chunk");
                    // Send thinking event
                    yield Ok::<_, axum::BoxError>(Event::default().event("thinking").data(reasoning.content));
                 }
                Err(e) => {
                    error!(error = ?e, %session_id_clone, "Error processing AI stream");
                    // Send only the underlying error message
                    yield Ok::<_, axum::BoxError>(Event::default().event("error").data(e.to_string()));

                    // Save whatever response we got before the error
                    let final_content = full_response_buffer.lock().await.clone();
                    if !final_content.is_empty() {
                        warn!(%session_id_clone, content_len = final_content.len(), "Saving partial response due to stream error");
                        let save_result = chat_service::save_message(
                            &pool_clone,
                            session_id_clone,
                            None, // Assistant messages have no user_id
                            MessageRole::Assistant,
                            final_content,
                        ).await;
                        if let Err(save_err) = save_result {
                            error!(error = ?save_err, %session_id_clone, "Failed to save partial assistant message after stream error");
                        }
                    } else {
                        info!(%session_id_clone, "No partial content to save after stream error.");
                    }
                    stream_error_occurred = true; // Set the flag
                    break; // Stop processing the stream after an error
                }
            }
        }

        // Only save the full response if the stream finished WITHOUT errors
        if !stream_error_occurred {
            let final_content = full_response_buffer.lock().await.clone();
            if !final_content.is_empty() {
                info!(%session_id_clone, bytes = final_content.len(), "Spawning background task to save full AI response via chat service.");
                tokio::spawn(async move {
                    match chat_service::save_message(
                        &pool_clone,
                        session_id_clone,
                        None, // Assistant message has no user_id directly associated
                        MessageRole::Assistant,
                        final_content,
                    ).await {
                        Ok(saved_msg) => info!(%session_id_clone, msg_id=%saved_msg.id, "Successfully saved full AI response in background."),
                        Err(save_err) => error!(%session_id_clone, error=?save_err, "Failed to save full AI response in background."),
                    }
                });
            } else {
               warn!(%session_id_clone, "AI stream finished but produced no content to save.");
            }

            // Send the final "done" event only if no error occurred during the stream
            debug!(%session_id_clone, "Sending final 'done' event");
            yield Ok::<_, axum::BoxError>(Event::default().event("done"));
        }
        // If an error occurred, the 'error' event was already sent, and we don't send 'done'

        info!(%session_id_clone, "SSE stream processing finished.");

    };

    info!(%session_id, "Returning SSE stream to client");
    Ok(Sse::new(sse_stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive-text"),
    ))
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
    let settings_response = chat_service::get_session_settings(&state.pool, user_id, session_id).await?;
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

    // --- Input Validation ---
    // BigDecimal helpers for comparisons
    use bigdecimal::FromPrimitive;
    let zero = BigDecimal::from_f32(0.0).unwrap();
    let two = BigDecimal::from_f32(2.0).unwrap();
    let one = BigDecimal::from_f32(1.0).unwrap();
    let neg_two = BigDecimal::from_f32(-2.0).unwrap();

    // Validate temperature (between 0.0 and 2.0)
    if let Some(temp) = &payload.temperature { // temp is &BigDecimal
        if temp < &zero || temp > &two {
            error!(%session_id, invalid_temp = %temp, "Invalid temperature value");
            return Err(AppError::BadRequest("Temperature must be between 0.0 and 2.0".into()));
        }
    }

    // Validate max_output_tokens (positive)
    if let Some(tokens) = payload.max_output_tokens {
        if tokens <= 0 {
            error!(%session_id, invalid_tokens = tokens, "Invalid max_output_tokens value");
            return Err(AppError::BadRequest("Max output tokens must be positive".into()));
        }
    }

    // Validate frequency_penalty (between -2.0 and 2.0)
    if let Some(fp) = &payload.frequency_penalty {
        if fp < &neg_two || fp > &two {
            error!(%session_id, invalid_fp = %fp, "Invalid frequency_penalty value");
            return Err(AppError::BadRequest("Frequency penalty must be between -2.0 and 2.0".into()));
        }
    }

    // Validate presence_penalty (between -2.0 and 2.0)
    if let Some(pp) = &payload.presence_penalty {
        if pp < &neg_two || pp > &two {
            error!(%session_id, invalid_pp = %pp, "Invalid presence_penalty value");
            return Err(AppError::BadRequest("Presence penalty must be between -2.0 and 2.0".into()));
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
            return Err(AppError::BadRequest("Top-p must be between 0.0 and 1.0".into()));
        }
    }

    // Validate repetition_penalty (positive)
    if let Some(rp) = &payload.repetition_penalty {
        if rp <= &zero {
            error!(%session_id, invalid_rp = %rp, "Invalid repetition_penalty value");
            return Err(AppError::BadRequest("Repetition penalty must be positive".into()));
        }
    }

    // Validate min_p (between 0.0 and 1.0)
    if let Some(mp) = &payload.min_p {
        if mp < &zero || mp > &one {
            error!(%session_id, invalid_mp = %mp, "Invalid min_p value");
            return Err(AppError::BadRequest("Min-p must be between 0.0 and 1.0".into()));
        }
    }

    // Validate top_a (positive)
    if let Some(ta) = &payload.top_a {
        if ta <= &zero {
            error!(%session_id, invalid_ta = %ta, "Invalid top_a value");
            return Err(AppError::BadRequest("Top-a must be positive".into()));
        }
    }

    // No special validation needed for seed (any i32 is valid)
    // No direct validation for logit_bias, treat as generic JSON

    // --- Database Update ---
    // Call the service function to handle the update and return the updated settings
    let updated_settings_response = chat_service::update_session_settings(
        &state.pool,
        user_id,
        session_id,
        payload, // Pass the validated payload
    ).await?;

    info!(%session_id, "Successfully updated chat settings");
    Ok(Json(updated_settings_response)) // Explicitly return Ok(Json(...))
}

/// Defines the routes related to chat sessions and messages.
pub fn chat_routes() -> Router<AppState> {
    Router::new()
        .route("/", post(create_chat_session).get(list_chat_sessions))
        .route("/{session_id}/messages", get(get_chat_messages))
        .route("/{session_id}/generate", post(generate_chat_response))
        .route("/{session_id}/settings", get(get_chat_settings).put(update_chat_settings)) // Add settings routes
}
