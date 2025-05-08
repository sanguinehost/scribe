// backend/src/routes/chat.rs

use axum::{
    extract::{Path, State},
    http::{HeaderMap},
    response::{sse::Event, sse::KeepAlive, Sse, IntoResponse},
    Json,
    routing::{get, post},
    Router,
};
use axum_login::AuthSession;
use diesel::{QueryDsl, ExpressionMethods, RunQueryDsl, SelectableHelper};
use crate::models::chats::{
    MessageRole, GenerateChatRequest, Chat, SuggestedActionsRequest,
    SuggestedActionItem, SuggestedActionsResponse,
};
use crate::errors::AppError;
use crate::services::chat_service;
use crate::state::AppState;
use crate::schema::chat_sessions;
use validator::Validate;
use std::sync::Arc;
use futures::StreamExt;
use tracing::{debug, error, info, instrument, trace};
use uuid::Uuid;
use bigdecimal::ToPrimitive;
use serde_json::json;
use crate::auth::user_store::Backend as AuthBackend;
use genai::chat::{
    ChatRequest, ChatOptions, ChatMessage as GenAiChatMessage, ChatRole, MessageContent,
    ChatResponseFormat, JsonSpec, ChatStreamEvent
};
use crate::routes::chats_api::{
    create_chat_handler,
    get_chats_handler,
    get_chat_by_id_handler,
    get_messages_by_chat_id_handler,
    get_chat_settings_handler,
    update_chat_settings_handler,
};

#[instrument(skip(state, auth_session, payload), fields(session_id = %session_id_str))]
pub async fn generate_chat_response(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(session_id_str): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<GenerateChatRequest>,
) -> Result<impl IntoResponse, AppError> {
    info!("Received request to generate chat response with history");
    payload.validate()?;
    trace!(payload = ?payload, "Received validated payload");

    let state = Arc::new(state);

    let user = auth_session.user
        .ok_or_else(|| AppError::Unauthorized("User not found in session".to_string()))?;
    let user_id_value = user.id;
    debug!(%user_id_value, "Extracted user from session");

    let session_id = Uuid::parse_str(&session_id_str)
        .map_err(|_| AppError::BadRequest("Invalid session UUID format".to_string()))?;
    debug!(%session_id, "Parsed session ID");

    let chat_session = state.pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select(Chat::as_select())
                .first::<Chat>(conn)
                .map_err(AppError::from)
        })
        .await
        .map_err(|e| AppError::InternalServerError(format!("Interact error fetching chat: {}", e)))?
        ?;

    if chat_session.user_id != user_id_value {
        return Err(AppError::Forbidden);
    }
    debug!(%session_id, "User authorized for chat session");

    let system_prompt = chat_session.system_prompt;
    let temperature = chat_session.temperature;
    let max_output_tokens = chat_session.max_output_tokens;
    let top_p = chat_session.top_p;
    let model_name_from_settings = chat_session.model_name;

    let model_to_use = payload.model.clone().unwrap_or(model_name_from_settings);
    debug!(%model_to_use, "Determined model to use");

    let current_user_api_message = payload.history.last().cloned().ok_or_else(|| {
        error!(%session_id, "Payload history is empty, cannot extract current user message.");
        AppError::BadRequest("Request payload must contain at least one message.".to_string())
    })?;

    if current_user_api_message.role.to_lowercase() != "user" {
        error!(%session_id, "Last message in payload history is not from user.");
        return Err(AppError::BadRequest("The last message in the payload's history must be from the 'user'.".to_string()));
    }
    let current_user_content = current_user_api_message.content.clone();

    let (
        managed_history_tuples,
        _db_system_prompt,
        _db_temperature,
        _db_max_tokens,
        _db_freq_penalty,
        _db_pres_penalty,
        _db_top_k,
        _db_top_p,
        _db_rep_penalty,
        _db_min_p,
        _db_top_a,
        _db_seed,
        _db_logit_bias,
        _db_model_name,
        gemini_thinking_budget,
        gemini_enable_code_execution,
        _user_db_message_to_save,
        _hist_strategy,
        _hist_limit,
    ) = chat_service::get_session_data_for_generation(
        &state.pool,
        user_id_value,
        session_id,
        current_user_content.clone(),
    )
    .await?;

    let mut messages_for_ai: Vec<GenAiChatMessage> = managed_history_tuples
        .into_iter()
        .map(|(role, content)| GenAiChatMessage {
            role: match role {
                MessageRole::User => ChatRole::User,
                MessageRole::Assistant => ChatRole::Assistant,
                MessageRole::System => ChatRole::System,
            },
            content: MessageContent::Text(content),
            options: None,
        })
        .collect();

    messages_for_ai.push(GenAiChatMessage {
        role: ChatRole::User,
        content: MessageContent::Text(current_user_content.clone()),
        options: None,
    });
    
    trace!(history_len = messages_for_ai.len(), %session_id, "Prepared final message list for AI (DB history + current payload message)");

    let accept_header = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    let request_thinking = headers
        .get("X-Request-Thinking")
        .map(|v| v.to_str().unwrap_or("false") == "true")
        .unwrap_or(false);

    let enable_rag = headers
        .get("X-Scribe-Enable-RAG")
        .map(|v| v.to_str().unwrap_or("false") == "true")
        .unwrap_or(false);

    let _rag_context: Option<String> = None;

    if enable_rag {
        if !current_user_content.is_empty() {
            info!(%session_id, "RAG enabled, attempting to retrieve context for user message.");

            let user_message_id = Uuid::new_v4();
            
            let user_message_for_embedding = crate::models::chats::ChatMessage { 
                id: user_message_id,
                session_id,
                message_type: MessageRole::User,
                content: current_user_content.clone(), 
                created_at: chrono::Utc::now(),
                user_id: user_id_value,
            };

            match state.embedding_pipeline_service.process_and_embed_message(state.clone(), user_message_for_embedding).await {
                Ok(()) => {
                    info!(%session_id, "RAG pre-processing (process_and_embed_message) completed for current user message.");
                }
                Err(e) => {
                    error!(error = ?e, session_id = %session_id, "Failed to process and embed user message for RAG context preparation");
                }
            }
        }
    }

    match accept_header {
        v if v.contains(mime::TEXT_EVENT_STREAM.as_ref()) => {
            info!(%session_id, "Handling streaming SSE request. request_thinking={}", request_thinking);

            let chat_request = genai::chat::ChatRequest::new(messages_for_ai.clone())
                .with_system(system_prompt.clone().unwrap_or_default());
            
            let mut genai_chat_options = genai::chat::ChatOptions::default();
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

            trace!(%session_id, chat_request = ?chat_request, genai_options = ?genai_chat_options, "Prepared ChatRequest and Options for AI (SSE)");

            let genai_stream: crate::llm::ChatStream = match state.ai_client.stream_chat(model_to_use.as_str(), chat_request, Some(genai_chat_options)).await {
                 Ok(s) => {
                     debug!(%session_id, "Successfully initiated AI stream");

                     let db_pool_sse = state.pool.clone();
                     let embedding_tracker = state.embedding_call_tracker.clone();
                     let session_id_sse = session_id;
                     let user_id_sse = user_id_value;
                     let last_message_content_sse = payload.history.last().map(|m| m.content.clone()).unwrap_or_default();

                     tokio::spawn(async move {
                         if last_message_content_sse.is_empty() {
                             error!(session_id = %session_id_sse, "Cannot save empty user message (SSE)");
                             return;
                         }
                         let conn = match db_pool_sse.get().await {
                             Ok(conn) => conn,
                             Err(e) => {
                                 error!(error = ?e, session_id = %session_id_sse, "Failed to get DB connection to save user message (SSE)");
                                 return;
                             }
                         };

                         let result = conn
                             .interact(move |conn| {
                                 let message = crate::models::chats::DbInsertableChatMessage::new(
                                     session_id_sse,
                                     user_id_sse,
                                     MessageRole::User,
                                     last_message_content_sse,
                                 );
                                 diesel::insert_into(crate::schema::chat_messages::table)
                                     .values(&message)
                                     .returning(crate::schema::chat_messages::id)
                                     .get_result::<Uuid>(conn)
                             })
                             .await;

                         match result {
                             Ok(Ok(message_id)) => {
                                 debug!(session_id = %session_id_sse, message_id = %message_id, "Successfully saved user message in background (SSE)");
                                 
                                 match embedding_tracker.lock().await {
                                     mut tracker => {
                                         tracker.push(message_id);
                                         debug!(session_id = %session_id_sse, message_id = %message_id, "Added user message to embedding call tracker (SSE)");
                                     }
                                 }
                             }
                             Ok(Err(e)) => {
                                 error!(error = ?e, session_id = %session_id_sse, "Database error saving user message (SSE)");
                             }
                             Err(e) => {
                                 error!(error = ?e, session_id = %session_id_sse, "Interact error saving user message (SSE)");
                             }
                         }
                     });

                     s
                 },
                 Err(e) => {
                     error!(error = ?e, %session_id, "Failed to initiate AI stream");
                     let error_stream = async_stream::stream! {
                         let error_msg = format!("LLM API error: Failed to initiate stream - {}", e);
                         trace!(%session_id, error_message = %error_msg, "Sending SSE 'error' event (initiation failed)");
                         yield Ok::<_, AppError>(Event::default().event("error").data(error_msg));
                     };
                     return Ok(Sse::new(Box::pin(error_stream)).keep_alive(KeepAlive::default()).into_response());
                 }
             };

            debug!(%session_id, "Starting SSE generation loop");

            let stream = async_stream::stream! {
                let mut accumulated_content = String::new();
                let mut stream_error_occurred = false;

                futures::pin_mut!(genai_stream);
                trace!(%session_id, "Entering SSE async_stream! processing loop");

                while let Some(event_result) = genai_stream.next().await {
                    trace!(%session_id, "Received event from genai_stream: {:?}", event_result);
                    match event_result {
                        Ok(ChatStreamEvent::Start) => {
                            debug!(%session_id, "Received Start event from AI stream");
                            continue;
                        }
                        Ok(ChatStreamEvent::Chunk(chunk)) => {
                            debug!(%session_id, content_chunk_len = chunk.content.len(), "Received Content chunk from AI stream");
                            if !chunk.content.is_empty() {
                                accumulated_content.push_str(&chunk.content);
                                yield Ok::<_, AppError>(Event::default().event("content").data(chunk.content));
                            } else {
                                 trace!(%session_id, "Skipping empty content chunk from AI");
                             }
                        }
                        Ok(ChatStreamEvent::ReasoningChunk(chunk)) => {
                            debug!(%session_id, reasoning_chunk_len = chunk.content.len(), "Received ReasoningChunk from AI stream");
                            if !chunk.content.is_empty() {
                                yield Ok::<_, AppError>(Event::default().event("reasoning_chunk").data(chunk.content));
                            }
                        }
                        Ok(ChatStreamEvent::End(_)) => {
                            debug!(%session_id, "Received End event from AI stream");
                        }
                        Err(e) => {
                            error!(error = ?e, %session_id, "Error during AI stream processing (inside loop)");
                            stream_error_occurred = true;

                            let partial_content_clone = accumulated_content.clone();
                            let db_pool_clone = state.pool.clone();
                            let error_session_id = session_id;
                            let error_user_id = user_id_value;

                            tokio::spawn(async move {
                                if !partial_content_clone.is_empty() {
                                    trace!(session_id = %error_session_id, "Attempting to save partial AI response after stream error");
                                    let conn = match db_pool_clone.get().await {
                                        Ok(conn) => conn,
                                        Err(e) => {
                                            error!(error = ?e, session_id = %error_session_id, "Failed to get DB connection to save partial response");
                                            return;
                                        }
                                    };

                                    let result = conn
                                        .interact(move |conn| {
                                            let message = crate::models::chats::DbInsertableChatMessage::new(
                                                error_session_id,
                                                error_user_id,
                                                MessageRole::Assistant,
                                                partial_content_clone,
                                            );
                                            diesel::insert_into(crate::schema::chat_messages::table)
                                                .values(&message)
                                                .execute(conn)
                                        })
                                        .await;

                                    match result {
                                        Ok(Ok(_)) => {
                                            debug!(session_id = %error_session_id, "Successfully saved partial AI response after stream error");
                                        }
                                        Ok(Err(save_err)) => {
                                            error!(error = ?save_err, session_id = %error_session_id, "Database error saving partial AI response");
                                        }
                                        Err(save_err) => {
                                            error!(error = ?save_err, session_id = %error_session_id, "Interact error saving partial AI response");
                                        }
                                    }
                                } else {
                                     trace!(session_id = %error_session_id, "No partial content to save after stream error");
                                 }
                            });

                            let detailed_error = e.to_string();
                            error!(error = %detailed_error, %session_id, "Detailed error during SSE stream processing");

                            let client_error_message = if detailed_error.contains("LLM API error:") {
                                detailed_error
                            } else {
                                format!("LLM API error: {}", detailed_error)
                            };
                            trace!(%session_id, error_message = %client_error_message, "Sending SSE 'error' event");
                            yield Ok::<_, AppError>(Event::default().event("error").data(client_error_message));
                            break;
                        }
                    }
                }

                trace!(%session_id, "Exited SSE processing loop. stream_error_occurred={}", stream_error_occurred);

                if !stream_error_occurred && !accumulated_content.is_empty() {
                    debug!(%session_id, "Attempting to save full successful AI response");

                    let state_clone = state.clone();
                    let session_id_clone = session_id;
                    let user_id_clone = user_id_value;
                    let accumulated_content_clone = accumulated_content.clone();

                    tokio::spawn(async move {
                        let conn = match state_clone.pool.get().await {
                            Ok(conn) => conn,
                            Err(e) => {
                                error!(error = ?e, session_id = %session_id_clone, "Failed to get DB connection to save AI message");
                                return;
                            }
                        };

                        let result = conn
                            .interact(move |conn| {
                                let message = crate::models::chats::DbInsertableChatMessage::new(
                                    session_id_clone,
                                    user_id_clone,
                                    MessageRole::Assistant,
                                    accumulated_content_clone,
                                );
                                diesel::insert_into(crate::schema::chat_messages::table)
                                    .values(&message)
                                    .returning(crate::schema::chat_messages::id)
                                    .get_result::<Uuid>(conn)
                            })
                            .await;

                        match result {
                            Ok(Ok(message_id)) => {
                                debug!(session_id = %session_id_clone, message_id = %message_id, "Successfully saved AI message");
                                
                                match state_clone.embedding_call_tracker.lock().await {
                                    mut tracker => {
                                        tracker.push(message_id);
                                        debug!(session_id = %session_id_clone, message_id = %message_id, "Added AI message to embedding call tracker (SSE)");
                                    }
                                }
                            }
                            Ok(Err(e)) => {
                                error!(error = ?e, session_id = %session_id_clone, "Database error saving AI message");
                            }
                            Err(e) => {
                                error!(error = ?e, session_id = %session_id_clone, "Interact error saving AI message");
                            }
                        }
                    });
                    trace!(%session_id, "Sending SSE event: done, data: [DONE]");
                    yield Ok::<_, AppError>(Event::default().event("done").data("[DONE]"));
                } else if stream_error_occurred {
                    trace!(%session_id, "[DONE] not sent due to stream_error_occurred=true");
                } else if accumulated_content.is_empty() && !stream_error_occurred {
                    trace!(%session_id, "Sending SSE event: done, data: [DONE] (empty successful response)");
                    yield Ok::<_, AppError>(Event::default().event("done").data("[DONE]"));
                }
            };

            Ok(Sse::new(Box::pin(stream)).keep_alive(KeepAlive::default()).into_response())
        }
        v if v.contains(mime::APPLICATION_JSON.as_ref()) => {
            info!(%session_id, "Handling non-streaming JSON request. request_thinking={}", request_thinking);
            
            let last_user_message_in_payload = payload.history.last()
                .filter(|m| m.role.to_lowercase() == "user")
                .ok_or_else(|| AppError::BadRequest("Last message in history must be from the user (JSON).".to_string()))?;
            
            let user_message_content_for_json_path = last_user_message_in_payload.content.clone();
            if user_message_content_for_json_path.is_empty() {
                 return Err(AppError::BadRequest("User message content cannot be empty (JSON).".to_string()));
            }

            let user_message_to_save_json = crate::models::chats::DbInsertableChatMessage::new(
                session_id,
                user_id_value,
                MessageRole::User,
                user_message_content_for_json_path.clone(),
            );
            
            let user_message_id_json = state.pool.get().await?.interact(move |conn| {
                diesel::insert_into(crate::schema::chat_messages::table)
                    .values(&user_message_to_save_json)
                    .returning(crate::schema::chat_messages::id)
                    .get_result::<Uuid>(conn)
            }).await??;
            debug!(message_id = %user_message_id_json, session_id = %session_id, "Successfully saved user message (JSON)");
            state.embedding_call_tracker.lock().await.push(user_message_id_json);

            if enable_rag {
                if !user_message_content_for_json_path.is_empty() {
                    let user_message_for_embedding_json = crate::models::chats::ChatMessage {
                        id: user_message_id_json,
                        session_id,
                        message_type: MessageRole::User,
                        content: user_message_content_for_json_path.clone(),
                        created_at: chrono::Utc::now(),
                        user_id: user_id_value,
                    };

                    match state.embedding_pipeline_service.process_and_embed_message(state.clone(), user_message_for_embedding_json).await {
                        Ok(()) => {
                            info!(%session_id, "RAG pre-processing (JSON branch) completed for current user message.");
                        }
                        Err(e) => {
                            error!(error = ?e, session_id = %session_id, "Failed to process and embed user message for RAG (JSON branch)");
                        }
                    }
                }
            }

            let rag_context_json: Option<String> = None;

            if let Some(context) = rag_context_json {
                if let Some(last_message) = messages_for_ai.last_mut() {
                    if matches!(last_message.role, ChatRole::User) {
                        if let MessageContent::Text(text) = &mut last_message.content {
                            let original_content = text.clone();
                            *text = format!("{}\n\n{}", context, original_content);
                            trace!(session_id = %session_id, "Injected RAG context into user message (non-streaming)");
                        }
                    }
                } 
            }

            let chat_request = genai::chat::ChatRequest::new(messages_for_ai)
                .with_system(system_prompt.unwrap_or_default());
            let chat_options = genai::chat::ChatOptions::default()
                .with_temperature(temperature.map(|t| t.to_f32().unwrap_or(0.7) as f64).unwrap_or(0.7))
                .with_max_tokens(max_output_tokens.map(|t| t as u32).unwrap_or(1024))
                .with_top_p(top_p.map(|p| p.to_f32().unwrap_or(0.95) as f64).unwrap_or(0.95));

            trace!(%session_id, chat_request = ?chat_request, "Prepared ChatRequest for AI (non-streaming, post-RAG)");
            match state.ai_client.exec_chat(model_to_use.as_str(), chat_request, Some(chat_options))
                .await
            {
                Ok(chat_response) => {
                    debug!(%session_id, "Received successful non-streaming AI response");
                    
                    let response_content = match chat_response.content {
                        Some(genai::chat::MessageContent::Text(text)) => text,
                        Some(_) => String::new(),
                        None => String::new(),
                    };

                    trace!(%session_id, ?response_content, "Full non-streaming AI response");
                    
                    let db_pool_ai_save = state.pool.clone();
                    let ai_save_session_id = session_id;
                    let ai_save_user_id = user_id_value;
                    let ai_content_to_save = response_content.clone();

                    tokio::spawn(async move {
                        let ai_message = crate::models::chats::DbInsertableChatMessage::new(
                            ai_save_session_id,
                            ai_save_user_id,
                            MessageRole::Assistant,
                            ai_content_to_save,
                        );

                        let conn_result = db_pool_ai_save.get().await;
                        let conn = match conn_result {
                            Ok(c) => c,
                            Err(e) => {
                                error!(error = ?e, session_id = %ai_save_session_id, "Failed to get DB connection to save AI message (JSON)");
                                return;
                            }
                        };

                        let ai_save_result = conn
                            .interact(move |conn_tx| {
                                diesel::insert_into(crate::schema::chat_messages::table)
                                    .values(&ai_message)
                                    .returning(crate::schema::chat_messages::id)
                                    .get_result::<Uuid>(conn_tx)
                            })
                            .await;

                        match ai_save_result {
                            Ok(Ok(ai_message_id)) => {
                                debug!(session_id = %ai_save_session_id, message_id = %ai_message_id, "Successfully saved AI message (JSON)");
                                
                                match state.embedding_call_tracker.lock().await {
                                    mut tracker => {
                                        tracker.push(ai_message_id);
                                        debug!(session_id = %ai_save_session_id, message_id = %ai_message_id, "Added AI message to embedding call tracker (JSON)");
                                    }
                                }
                            }
                            Ok(Err(e)) => {
                                error!(error = ?e, session_id = %ai_save_session_id, "Database error saving AI message (JSON)");
                            }
                            Err(e) => {
                                error!(error = ?e, session_id = %ai_save_session_id, "Interact error saving AI message (JSON)");
                            }
                        }
                    });
                    
                    let response_payload = json!({
                        "message_id": Uuid::new_v4(),
                        "content": response_content
                    });
                    trace!(%session_id, response_payload = ?response_payload, "Sending non-streaming JSON response");

                    Ok(Json(response_payload).into_response())
                }
                Err(e) => {
                    error!(error = ?e, %session_id, "AI generation failed for non-streaming request");
                    Err(e)
                }
            }
        }
        _ => { 
            if !accept_header.is_empty() && !accept_header.contains(mime::APPLICATION_JSON.as_ref()) {
                info!(%session_id, "Accept header '{}' not recognized as JSON, defaulting to SSE.", accept_header);
                
                let chat_request = genai::chat::ChatRequest::new(messages_for_ai.clone())
                    .with_system(system_prompt.clone().unwrap_or_default());
                
                let mut genai_chat_options_fallback = genai::chat::ChatOptions::default();
                if let Some(temp_val) = temperature {
                    if let Some(f_val) = temp_val.to_f32() {
                        genai_chat_options_fallback = genai_chat_options_fallback.with_temperature(f_val.into());
                    }
                }
                if let Some(tokens) = max_output_tokens {
                    genai_chat_options_fallback = genai_chat_options_fallback.with_max_tokens(tokens as u32);
                }
                if let Some(p_val) = top_p {
                    if let Some(f_val) = p_val.to_f32() {
                        genai_chat_options_fallback = genai_chat_options_fallback.with_top_p(f_val.into());
                    }
                }
                if let Some(budget) = gemini_thinking_budget {
                    if budget > 0 {
                        genai_chat_options_fallback = genai_chat_options_fallback.with_gemini_thinking_budget(budget as u32);
                    }
                }
                if let Some(enable_exec) = gemini_enable_code_execution {
                    genai_chat_options_fallback = genai_chat_options_fallback.with_gemini_enable_code_execution(enable_exec);
                }

                trace!(%session_id, chat_request = ?chat_request, genai_options = ?genai_chat_options_fallback, "Prepared ChatRequest and Options for AI (fallback SSE)");

                let genai_stream: crate::llm::ChatStream = match state.ai_client.stream_chat(model_to_use.as_str(), chat_request, Some(genai_chat_options_fallback)).await {
                     Ok(s) => {
                         debug!(%session_id, "Successfully initiated AI stream (fallback SSE)");

                         let db_pool_sse = state.pool.clone();
                         let embedding_tracker = state.embedding_call_tracker.clone();
                         let session_id_sse = session_id;
                         let user_id_sse = user_id_value;
                         let last_message_content_sse_fallback = payload.history.last().map(|m| m.content.clone()).unwrap_or_default();

                         tokio::spawn(async move {
                             if last_message_content_sse_fallback.is_empty() {
                                 error!(session_id = %session_id_sse, "Cannot save empty user message (fallback SSE)");
                                 return;
                             }
                             let conn = match db_pool_sse.get().await {
                                 Ok(conn) => conn,
                                 Err(e) => {
                                     error!(error = ?e, session_id = %session_id_sse, "Failed to get DB connection to save user message (fallback SSE)");
                                     return;
                                 }
                             };

                             let result = conn
                                 .interact(move |conn| {
                                     let message = crate::models::chats::DbInsertableChatMessage::new(
                                         session_id_sse,
                                         user_id_sse,
                                         MessageRole::User,
                                         last_message_content_sse_fallback,
                                     );
                                     diesel::insert_into(crate::schema::chat_messages::table)
                                         .values(&message)
                                         .returning(crate::schema::chat_messages::id)
                                         .get_result::<Uuid>(conn)
                                 })
                                 .await;

                             match result {
                                 Ok(Ok(message_id)) => {
                                     debug!(session_id = %session_id_sse, message_id = %message_id, "Successfully saved user message in background (fallback SSE)");
                                     
                                     match embedding_tracker.lock().await {
                                         mut tracker => {
                                             tracker.push(message_id);
                                             debug!(session_id = %session_id_sse, message_id = %message_id, "Added user message to embedding call tracker (fallback SSE)");
                                         }
                                     }
                                 }
                                 Ok(Err(e)) => {
                                     error!(error = ?e, session_id = %session_id_sse, "Database error saving user message (fallback SSE)");
                                 }
                                 Err(e) => {
                                     error!(error = ?e, session_id = %session_id_sse, "Interact error saving user message (fallback SSE)");
                                 }
                             }
                         });

                         s
                     },
                     Err(e) => {
                         error!(error = ?e, %session_id, "Failed to initiate AI stream (fallback SSE)");
                         let error_stream = async_stream::stream! {
                             let error_msg = format!("LLM API error: Failed to initiate stream - {}", e);
                             trace!(%session_id, error_message = %error_msg, "Sending fallback SSE 'error' event (initiation failed)");
                             yield Ok::<_, AppError>(Event::default().event("error").data(error_msg));
                         };
                         return Ok(Sse::new(Box::pin(error_stream)).keep_alive(KeepAlive::default()).into_response());
                     }
                 };

                debug!(%session_id, "Starting fallback SSE generation loop");

                let stream = async_stream::stream! {
                    let mut accumulated_content = String::new();
                    let mut stream_error_occurred = false;

                    futures::pin_mut!(genai_stream);
                    trace!(%session_id, "Entering fallback SSE async_stream! processing loop");

                    while let Some(event_result) = genai_stream.next().await {
                        trace!(%session_id, "Received event from genai_stream (fallback): {:?}", event_result);
                        match event_result {
                            Ok(ChatStreamEvent::Start) => {
                                debug!(%session_id, "Received Start event from AI stream (fallback)");
                                continue;
                            }
                            Ok(ChatStreamEvent::Chunk(chunk)) => {
                                debug!(%session_id, content_chunk_len = chunk.content.len(), "Received Content chunk from AI stream (fallback)");
                                if !chunk.content.is_empty() {
                                    accumulated_content.push_str(&chunk.content);
                                    yield Ok::<_, AppError>(Event::default().event("content").data(chunk.content));
                                } else {
                                     trace!(%session_id, "Skipping empty content chunk from AI (fallback)");
                                 }
                            }
                            Ok(ChatStreamEvent::ReasoningChunk(chunk)) => {
                                debug!(%session_id, reasoning_chunk_len = chunk.content.len(), "Received ReasoningChunk from AI stream (fallback)");
                                if !chunk.content.is_empty() {
                                    yield Ok::<_, AppError>(Event::default().event("reasoning_chunk").data(chunk.content));
                                }
                            }
                            Ok(ChatStreamEvent::End(_)) => {
                                debug!(%session_id, "Received End event from AI stream (fallback)");
                            }
                            Err(e) => {
                                error!(error = ?e, %session_id, "Error during AI stream processing (fallback loop)");
                                stream_error_occurred = true;

                                let partial_content_clone = accumulated_content.clone();
                                let db_pool_clone = state.pool.clone();
                                let error_session_id = session_id;
                                let error_user_id = user_id_value;

                                tokio::spawn(async move {
                                    if !partial_content_clone.is_empty() {
                                        trace!(session_id = %error_session_id, "Attempting to save partial AI response after stream error (fallback)");
                                        let conn = match db_pool_clone.get().await {
                                            Ok(conn) => conn,
                                            Err(e) => {
                                                error!(error = ?e, session_id = %error_session_id, "Failed to get DB connection to save partial response (fallback)");
                                                return;
                                            }
                                        };

                                        let result = conn
                                            .interact(move |conn| {
                                                let message = crate::models::chats::DbInsertableChatMessage::new(
                                                    error_session_id,
                                                    error_user_id,
                                                    MessageRole::Assistant,
                                                    partial_content_clone,
                                                );
                                                diesel::insert_into(crate::schema::chat_messages::table)
                                                    .values(&message)
                                                    .execute(conn)
                                            })
                                            .await;

                                        match result {
                                            Ok(Ok(_)) => {
                                                debug!(session_id = %error_session_id, "Successfully saved partial AI response after stream error (fallback)");
                                            }
                                            Ok(Err(save_err)) => {
                                                error!(error = ?save_err, session_id = %error_session_id, "Database error saving partial AI response (fallback)");
                                            }
                                            Err(save_err) => {
                                                error!(error = ?save_err, session_id = %error_session_id, "Interact error saving partial AI response (fallback)");
                                            }
                                        }
                                    } else {
                                         trace!(session_id = %error_session_id, "No partial content to save after stream error (fallback)");
                                     }
                                });

                                let detailed_error = e.to_string();
                                error!(error = %detailed_error, %session_id, "Detailed error during fallback SSE stream processing");

                                let client_error_message = if detailed_error.contains("LLM API error:") {
                                    detailed_error
                                } else {
                                    format!("LLM API error: {}", detailed_error)
                                };
                                trace!(%session_id, error_message = %client_error_message, "Sending fallback SSE 'error' event");
                                yield Ok::<_, AppError>(Event::default().event("error").data(client_error_message));
                                break;
                            }
                        }
                    }

                    trace!(%session_id, "Exited fallback SSE processing loop. stream_error_occurred={}", stream_error_occurred);

                    if !stream_error_occurred && !accumulated_content.is_empty() {
                        debug!(%session_id, "Attempting to save full successful AI response (fallback)");

                        let state_clone = state.clone();
                        let session_id_clone = session_id;
                        let user_id_clone = user_id_value;
                        let accumulated_content_clone = accumulated_content.clone();

                        tokio::spawn(async move {
                            let conn = match state_clone.pool.get().await {
                                Ok(conn) => conn,
                                Err(e) => {
                                    error!(error = ?e, session_id = %session_id_clone, "Failed to get DB connection to save AI message (fallback)");
                                    return;
                                }
                            };

                            let result = conn
                                .interact(move |conn| {
                                    let message = crate::models::chats::DbInsertableChatMessage::new(
                                        session_id_clone,
                                        user_id_clone,
                                        MessageRole::Assistant,
                                        accumulated_content_clone,
                                    );
                                    diesel::insert_into(crate::schema::chat_messages::table)
                                        .values(&message)
                                        .returning(crate::schema::chat_messages::id)
                                        .get_result::<Uuid>(conn)
                                })
                                .await;

                            match result {
                                Ok(Ok(message_id)) => {
                                    debug!(session_id = %session_id_clone, message_id = %message_id, "Successfully saved AI message (fallback)");
                                    
                                    match state_clone.embedding_call_tracker.lock().await {
                                        mut tracker => {
                                            tracker.push(message_id);
                                            debug!(session_id = %session_id_clone, message_id = %message_id, "Added AI message to embedding call tracker (fallback)");
                                        }
                                    }
                                }
                                Ok(Err(e)) => {
                                    error!(error = ?e, session_id = %session_id_clone, "Database error saving AI message (fallback)");
                                }
                                Err(e) => {
                                    error!(error = ?e, session_id = %session_id_clone, "Interact error saving AI message (fallback)");
                                }
                            }
                        });
                        trace!(%session_id, "Sending fallback SSE data: [DONE]");
                        yield Ok::<_, AppError>(Event::default().data("[DONE]"));
                    } else if !stream_error_occurred && accumulated_content.is_empty() {
                         debug!(%session_id, "AI stream finished successfully but produced no content in fallback. Sending '[DONE]'.");
                        trace!(%session_id, "Sending fallback SSE data: [DONE] (empty content)");
                        yield Ok::<_, AppError>(Event::default().data("[DONE]"));
                     } else {
                        debug!(%session_id, "Fallback stream finished after an error. No 'done' event sent.");
                     }
                     trace!(%session_id, "Finished fallback SSE async_stream! block");
                };

                Ok(Sse::new(Box::pin(stream)).keep_alive(KeepAlive::default()).into_response())
            } else {
                info!(%session_id, "Accept header is empty, defaulting to SSE.");

                let chat_request = genai::chat::ChatRequest::new(messages_for_ai.clone())
                    .with_system(system_prompt.clone().unwrap_or_default());
                
                let mut genai_chat_options_empty_fallback = genai::chat::ChatOptions::default();
                if let Some(temp_val) = temperature {
                    if let Some(f_val) = temp_val.to_f32() {
                        genai_chat_options_empty_fallback = genai_chat_options_empty_fallback.with_temperature(f_val.into());
                    }
                }
                if let Some(tokens) = max_output_tokens {
                    genai_chat_options_empty_fallback = genai_chat_options_empty_fallback.with_max_tokens(tokens as u32);
                }
                if let Some(p_val) = top_p {
                    if let Some(f_val) = p_val.to_f32() {
                        genai_chat_options_empty_fallback = genai_chat_options_empty_fallback.with_top_p(f_val.into());
                    }
                }
                if let Some(budget) = gemini_thinking_budget {
                    if budget > 0 {
                        genai_chat_options_empty_fallback = genai_chat_options_empty_fallback.with_gemini_thinking_budget(budget as u32);
                    }
                }
                if let Some(enable_exec) = gemini_enable_code_execution {
                    genai_chat_options_empty_fallback = genai_chat_options_empty_fallback.with_gemini_enable_code_execution(enable_exec);
                }

                trace!(%session_id, chat_request = ?chat_request, genai_options = ?genai_chat_options_empty_fallback, "Prepared ChatRequest and Options for AI (empty header fallback SSE)");

                let genai_stream: crate::llm::ChatStream = match state.ai_client.stream_chat(model_to_use.as_str(), chat_request, Some(genai_chat_options_empty_fallback)).await {
                    Ok(s) => {
                        debug!(%session_id, "Successfully initiated AI stream (empty header fallback SSE)");

                        let db_pool_sse = state.pool.clone();
                        let embedding_tracker = state.embedding_call_tracker.clone();
                        let session_id_sse = session_id;
                        let user_id_sse = user_id_value;
                        let last_message_content_empty_fallback = payload.history.last().map(|m| m.content.clone()).unwrap_or_default();

                        tokio::spawn(async move {
                            if last_message_content_empty_fallback.is_empty() {
                                error!(session_id = %session_id_sse, "Cannot save empty user message (empty header fallback SSE)");
                                return;
                            }
                            let conn = match db_pool_sse.get().await {
                                Ok(conn) => conn,
                                Err(e) => {
                                    error!(error = ?e, session_id = %session_id_sse, "Failed to get DB connection to save user message (empty header fallback SSE)");
                                    return;
                                }
                            };

                            let result = conn
                                .interact(move |conn| {
                                    let message = crate::models::chats::DbInsertableChatMessage::new(
                                        session_id_sse,
                                        user_id_sse,
                                        MessageRole::User,
                                        last_message_content_empty_fallback,
                                    );
                                    diesel::insert_into(crate::schema::chat_messages::table)
                                        .values(&message)
                                        .returning(crate::schema::chat_messages::id)
                                        .get_result::<Uuid>(conn)
                                })
                                .await;

                            match result {
                                Ok(Ok(message_id)) => {
                                    debug!(session_id = %session_id_sse, message_id = %message_id, "Successfully saved user message in background (empty header fallback SSE)");

                                    match embedding_tracker.lock().await {
                                        mut tracker => {
                                            tracker.push(message_id);
                                            debug!(session_id = %session_id_sse, message_id = %message_id, "Added user message to embedding call tracker (empty header fallback SSE)");
                                        }
                                    }
                                }
                                Ok(Err(e)) => {
                                    error!(error = ?e, session_id = %session_id_sse, "Database error saving user message (empty header fallback SSE)");
                                }
                                Err(e) => {
                                    error!(error = ?e, session_id = %session_id_sse, "Interact error saving user message (empty header fallback SSE)");
                                }
                            }
                        });
                        s
                    },
                    Err(e) => {
                        error!(error = ?e, %session_id, "Failed to initiate AI stream (empty header fallback SSE)");
                        let error_stream = async_stream::stream! {
                            let error_msg = format!("LLM API error: Failed to initiate stream - {}", e);
                            trace!(%session_id, error_message = %error_msg, "Sending empty header fallback SSE 'error' event (initiation failed)");
                            yield Ok::<_, AppError>(Event::default().event("error").data(error_msg));
                        };
                        return Ok(Sse::new(Box::pin(error_stream)).keep_alive(KeepAlive::default()).into_response());
                    }
                };

                debug!(%session_id, "Starting empty header fallback SSE generation loop");

                let stream = async_stream::stream! {
                    let mut accumulated_content = String::new();
                    let mut stream_error_occurred = false;
                    futures::pin_mut!(genai_stream);
                    trace!(%session_id, "Entering empty header fallback SSE async_stream! processing loop");

                    while let Some(event_result) = genai_stream.next().await {
                        trace!(%session_id, "Received event from genai_stream (empty header fallback): {:?}", event_result);
                        match event_result {
                            Ok(ChatStreamEvent::Start) => {
                                debug!(%session_id, "Received Start event from AI stream (empty header fallback)");
                                continue;
                            }
                            Ok(ChatStreamEvent::Chunk(chunk)) => {
                                debug!(%session_id, content_chunk_len = chunk.content.len(), "Received Content chunk from AI stream (empty header fallback)");
                                if !chunk.content.is_empty() {
                                    accumulated_content.push_str(&chunk.content);
                                    yield Ok::<_, AppError>(Event::default().event("content").data(chunk.content));
                                } else {
                                    trace!(%session_id, "Skipping empty content chunk from AI (empty header fallback)");
                                }
                            }
                            Ok(ChatStreamEvent::ReasoningChunk(chunk)) => {
                                debug!(%session_id, reasoning_chunk_len = chunk.content.len(), "Received ReasoningChunk from AI stream (empty header fallback)");
                                if !chunk.content.is_empty() {
                                    yield Ok::<_, AppError>(Event::default().event("reasoning_chunk").data(chunk.content));
                                }
                            }
                            Ok(ChatStreamEvent::End(_)) => {
                                debug!(%session_id, "Received End event from AI stream (empty header fallback)");
                            }
                            Err(e) => {
                                error!(error = ?e, %session_id, "Error during AI stream processing (empty header fallback loop)");
                                stream_error_occurred = true;

                                let partial_content_clone = accumulated_content.clone();
                                let db_pool_clone = state.pool.clone();
                                let error_session_id = session_id;
                                let error_user_id = user_id_value;

                                tokio::spawn(async move {
                                    if !partial_content_clone.is_empty() {
                                        trace!(session_id = %error_session_id, "Attempting to save partial AI response after stream error (empty header fallback)");
                                        let conn = match db_pool_clone.get().await {
                                            Ok(conn) => conn,
                                            Err(e) => {
                                                error!(error = ?e, session_id = %error_session_id, "Failed to get DB connection to save partial response (empty header fallback)");
                                                return;
                                            }
                                        };
                                        let result = conn
                                            .interact(move |conn| {
                                                let message = crate::models::chats::DbInsertableChatMessage::new(
                                                    error_session_id,
                                                    error_user_id,
                                                    MessageRole::Assistant,
                                                    partial_content_clone,
                                                );
                                                diesel::insert_into(crate::schema::chat_messages::table)
                                                    .values(&message)
                                                    .execute(conn)
                                            })
                                            .await;
                                        match result {
                                            Ok(Ok(_)) => {
                                                debug!(session_id = %error_session_id, "Successfully saved partial AI response after stream error (empty header fallback)");
                                            }
                                            Ok(Err(save_err)) => {
                                                error!(error = ?save_err, session_id = %error_session_id, "Database error saving partial AI response (empty header fallback)");
                                            }
                                            Err(save_err) => {
                                                error!(error = ?save_err, session_id = %error_session_id, "Interact error saving partial AI response (empty header fallback)");
                                            }
                                        }
                                    } else {
                                        trace!(session_id = %error_session_id, "No partial content to save after stream error (empty header fallback)");
                                    }
                                });

                                let detailed_error = e.to_string();
                                error!(error = %detailed_error, %session_id, "Detailed error during empty header fallback SSE stream processing");
                                let client_error_message = if detailed_error.contains("LLM API error:") {
                                    detailed_error
                                } else {
                                    format!("LLM API error: {}", detailed_error)
                                };
                                trace!(%session_id, error_message = %client_error_message, "Sending empty header fallback SSE 'error' event");
                                yield Ok::<_, AppError>(Event::default().event("error").data(client_error_message));
                                break;
                            }
                        }
                    }

                    trace!(%session_id, "Exited empty header fallback SSE processing loop. stream_error_occurred={}", stream_error_occurred);

                    if !stream_error_occurred && !accumulated_content.is_empty() {
                        debug!(%session_id, "Attempting to save full successful AI response (empty header fallback)");
                        let state_clone = state.clone();
                        let session_id_clone = session_id;
                        let user_id_clone = user_id_value;
                        let accumulated_content_clone = accumulated_content.clone();

                        tokio::spawn(async move {
                            let conn = match state_clone.pool.get().await {
                                Ok(conn) => conn,
                                Err(e) => {
                                    error!(error = ?e, session_id = %session_id_clone, "Failed to get DB connection to save AI message (empty header fallback)");
                                    return;
                                }
                            };
                            let result = conn
                                .interact(move |conn| {
                                    let message = crate::models::chats::DbInsertableChatMessage::new(
                                        session_id_clone,
                                        user_id_clone,
                                        MessageRole::Assistant,
                                        accumulated_content_clone,
                                    );
                                    diesel::insert_into(crate::schema::chat_messages::table)
                                        .values(&message)
                                        .returning(crate::schema::chat_messages::id)
                                        .get_result::<Uuid>(conn)
                                })
                                .await;
                            match result {
                                Ok(Ok(message_id)) => {
                                    debug!(session_id = %session_id_clone, message_id = %message_id, "Successfully saved AI message (empty header fallback)");
                                    match state_clone.embedding_call_tracker.lock().await {
                                        mut tracker => {
                                            tracker.push(message_id);
                                            debug!(session_id = %session_id_clone, message_id = %message_id, "Added AI message to embedding call tracker (empty header fallback)");
                                        }
                                    }
                                }
                                Ok(Err(e)) => {
                                    error!(error = ?e, session_id = %session_id_clone, "Database error saving AI message (empty header fallback)");
                                }
                                Err(e) => {
                                    error!(error = ?e, session_id = %session_id_clone, "Interact error saving AI message (empty header fallback)");
                                }
                            }
                        });
                        trace!(%session_id, "Sending empty header fallback SSE data: [DONE]");
                        yield Ok::<_, AppError>(Event::default().data("[DONE]"));
                    } else if !stream_error_occurred && accumulated_content.is_empty() {
                        debug!(%session_id, "AI stream finished successfully but produced no content in empty header fallback. Sending '[DONE]'.");
                        trace!(%session_id, "Sending empty header fallback SSE data: [DONE] (empty content)");
                        yield Ok::<_, AppError>(Event::default().data("[DONE]"));
                    } else {
                        debug!(%session_id, "Empty header fallback stream finished after an error. No '[DONE]' event sent.");
                    }
                    trace!(%session_id, "Finished empty header fallback SSE async_stream! block");
                };

                Ok(Sse::new(Box::pin(stream)).keep_alive(KeepAlive::default()).into_response())
            }
        }
    }
}

#[instrument(skip(state, auth_session, payload), fields(chat_id = %chat_id_str))]
async fn generate_suggested_actions(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(chat_id_str): Path<String>,
    Json(payload): Json<SuggestedActionsRequest>,
) -> Result<Json<SuggestedActionsResponse>, AppError> {
    let chat_id = Uuid::parse_str(&chat_id_str)
        .map_err(|_| AppError::BadRequest("Invalid chat UUID format".to_string()))?;
    debug!(%chat_id, "Received request to generate suggested actions");

    let user = auth_session.user.ok_or_else(|| {
        error!(%chat_id, "User not found in session for suggested actions");
        AppError::Unauthorized("User not found in session".to_string())
    })?;
    let user_id_value = user.id;
    debug!(%chat_id, %user_id_value, "Extracted user for suggested actions");

    let chat_session = state.pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(chat_id))
                .select(Chat::as_select())
                .first::<Chat>(conn)
                .map_err(AppError::from)
        })
        .await
        .map_err(|e| AppError::InternalServerError(format!("Interact error fetching chat: {}", e)))?
        ?;

    if chat_session.user_id != user_id_value {
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
            "gemini-1.5-flash-latest", // Use stable model for suggested actions
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
            return Err(AppError::InternalServerError(
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
            AppError::InternalServerError("Failed to parse structured response from AI".to_string())
        })?;
    
    info!(%chat_id, "Successfully generated {} suggested actions", suggestions.len());

    Ok(Json(SuggestedActionsResponse { suggestions }))
}

pub fn chat_routes() -> Router<AppState> {
    Router::new()
        .route("/", post(create_chat_handler).get(get_chats_handler))
        .route("/{session_id}", get(get_chat_by_id_handler))
        .route("/{session_id}/messages", get(get_messages_by_chat_id_handler))
        .route(
            "/{session_id}/generate",
            post(generate_chat_response),
        )
        .route(
            "/{session_id}/suggested-actions",
            post(generate_suggested_actions),
        )
        .route(
            "/{session_id}/settings",
            get(get_chat_settings_handler).put(update_chat_settings_handler),
        )
}

