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
use diesel::{QueryDsl, ExpressionMethods, RunQueryDsl, BoolExpressionMethods, SelectableHelper}; // Added SelectableHelper
use crate::models::chats::{MessageRole, GenerateChatRequest, ChatMessage, Chat}; // Use GenerateChatRequest, add Chat, ApiChatMessage
use crate::errors::AppError;
use crate::services::chat_service; // Added chat_service
use crate::state::AppState;
use crate::schema::chat_sessions; // Added chat_sessions schema
use validator::Validate; // Added Validate
use std::sync::Arc;
use futures::StreamExt;
use tracing::{debug, error, info, instrument, trace};
use uuid::Uuid;
use genai::chat::ChatStreamEvent;
use bigdecimal::ToPrimitive;
use serde_json::json;
use crate::auth::user_store::Backend as AuthBackend;
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
    Json(payload): Json<GenerateChatRequest>, // <-- Use new payload struct
) -> Result<impl IntoResponse, AppError> {
    info!("Received request to generate chat response with history");
    // Validate the incoming payload
    payload.validate()?;
    trace!(payload = ?payload, "Received validated payload");

    // We'll need to convert state to Arc<AppState> for consistent API
    let state = Arc::new(state);

    // 1. Extract User and Validate Session ID
    let user = auth_session.user
        .ok_or_else(|| AppError::Unauthorized("User not found in session".to_string()))?;
    let user_id_value = user.id;
    debug!(%user_id_value, "Extracted user from session");

    let session_id = Uuid::parse_str(&session_id_str)
        .map_err(|_| AppError::BadRequest("Invalid session UUID format".to_string()))?;
    debug!(%session_id, "Parsed session ID");

    // 2. Authorization & Fetch Session Settings
    // Fetch the chat session to check ownership and get settings
    let chat_session = state.pool.get().await
        .map_err(|e| AppError::DbPoolError(e.to_string()))?
        .interact(move |conn| {
            chat_sessions::table
                .filter(chat_sessions::id.eq(session_id))
                .select(Chat::as_select())
                .first::<Chat>(conn)
                .map_err(AppError::from) // Handles NotFound
        })
        .await
        .map_err(|e| AppError::InternalServerError(format!("Interact error fetching chat: {}", e)))? // Handle interact error
        ?; // Propagate NotFound error

    // Check ownership
    if chat_session.user_id != user_id_value {
        return Err(AppError::Forbidden);
    }
    debug!(%session_id, "User authorized for chat session");

    // Extract settings from the fetched chat session
    let system_prompt = chat_session.system_prompt;
    let temperature = chat_session.temperature;
    let max_output_tokens = chat_session.max_output_tokens;
    let top_p = chat_session.top_p;
    let model_name_from_settings = chat_session.model_name;
    // Note: Other settings like penalties, top_k etc. are not currently used by gemini_client but are available in chat_session

    // Use model from payload if provided, otherwise use the one from settings
    let model_to_use = payload.model.clone().unwrap_or(model_name_from_settings); // Clone payload model name
    debug!(%model_to_use, "Determined model to use");

    // 3. Fetch and Manage History, then prepare AI Request
    let ai_client = state.ai_client.clone();

    // Extract the current user message from the payload.
    // We assume the payload.history contains the current turn, typically one user message.
    let current_user_api_message = payload.history.last().cloned().ok_or_else(|| {
        error!(%session_id, "Payload history is empty, cannot extract current user message.");
        AppError::BadRequest("Request payload must contain at least one message.".to_string())
    })?;

    if current_user_api_message.role.to_lowercase() != "user" {
        error!(%session_id, "Last message in payload history is not from user.");
        return Err(AppError::BadRequest("The last message in the payload's history must be from the 'user'.".to_string()));
    }
    let current_user_content = current_user_api_message.content.clone();

    // Fetch existing session data, including managed history from the database
    let (
        managed_history_tuples, // This is Vec<(MessageRole, String)>
        _db_system_prompt, // System prompt is already handled from chat_session
        _db_temperature,   // Temperature is already handled from chat_session
        _db_max_tokens,    // Max tokens is already handled from chat_session
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
        // -- Gemini Specific Options --
        gemini_thinking_budget,
        gemini_enable_code_execution,
        _user_db_message_to_save,
        _hist_strategy,
        _hist_limit,
    ) = chat_service::get_session_data_for_generation(
        &state.pool,
        user_id_value,
        session_id,
        current_user_content.clone(), // Pass current user message content for get_session_data_for_generation
    )
    .await?;

    // Convert managed_history_tuples to Vec<genai::chat::ChatMessage>
    let mut messages_for_ai: Vec<genai::chat::ChatMessage> = managed_history_tuples
        .into_iter()
        .map(|(role, content)| genai::chat::ChatMessage {
            role: match role {
                MessageRole::User => genai::chat::ChatRole::User,
                MessageRole::Assistant => genai::chat::ChatRole::Assistant,
                MessageRole::System => genai::chat::ChatRole::System,
            },
            content: genai::chat::MessageContent::Text(content),
            options: None,
        })
        .collect();

    // Append the current user message (already extracted as current_user_api_message)
    messages_for_ai.push(genai::chat::ChatMessage {
        role: genai::chat::ChatRole::User, // We've validated it's a user message
        content: genai::chat::MessageContent::Text(current_user_content),
        options: None,
    });
    
    trace!(history_len = messages_for_ai.len(), %session_id, "Prepared final message list for AI (DB history + current payload message)");

    // 4. Determine Response Type (SSE vs JSON) and Generate
    let accept_header = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or(""); // Default to empty string if header missing or invalid

    let request_thinking = headers
        .get("X-Request-Thinking")
        .map(|v| v.to_str().unwrap_or("false") == "true")
        .unwrap_or(false); // Default to false if header is missing


    match accept_header {
        v if v.contains(mime::TEXT_EVENT_STREAM.as_ref()) => {
            // --- Streaming SSE response ---
            info!(%session_id, "Handling streaming SSE request. request_thinking={}", request_thinking);

            // +++ Create ChatRequest and ChatOptions INSIDE the SSE branch +++
            let chat_request = genai::chat::ChatRequest::new(messages_for_ai.clone()) // Clone messages for this branch
                .with_system(system_prompt.clone().unwrap_or_default()); // Clone system prompt
            
            let mut genai_chat_options = genai::chat::ChatOptions::default();
            if let Some(temp_val) = temperature {
                if let Some(f_val) = temp_val.to_f32() { // genai takes f32 for temperature
                    genai_chat_options = genai_chat_options.with_temperature(f_val.into());
                }
            }
            if let Some(tokens) = max_output_tokens {
                genai_chat_options = genai_chat_options.with_max_tokens(tokens as u32);
            }
            if let Some(p_val) = top_p {
                if let Some(f_val) = p_val.to_f32() { // genai takes f32 for top_p
                    genai_chat_options = genai_chat_options.with_top_p(f_val.into());
                }
            }

            // Add new Gemini options
            if let Some(budget) = gemini_thinking_budget {
                if budget > 0 { // gemini_thinking_budget in rust-genai takes u32
                    genai_chat_options = genai_chat_options.with_gemini_thinking_budget(budget as u32);
                }
            }
            if let Some(enable_exec) = gemini_enable_code_execution {
                genai_chat_options = genai_chat_options.with_gemini_enable_code_execution(enable_exec);
            }
            // +++ End Creation +++

            // ++ Logging: Log the prepared chat request ++
            trace!(%session_id, chat_request = ?chat_request, genai_options = ?genai_chat_options, "Prepared ChatRequest and Options for AI (SSE)");
            // ++ End Logging ++

            let genai_stream: crate::llm::ChatStream = match ai_client.stream_chat(model_to_use.as_str(), chat_request, Some(genai_chat_options)).await {
                 Ok(s) => {
                     debug!(%session_id, "Successfully initiated AI stream");

                     // --- Save User Message (SSE Branch - AFTER Successful AI Stream Initiation) ---
                     // Clone necessary data for the background task
                     let db_pool_sse = state.pool.clone();
                     let embedding_tracker = state.embedding_call_tracker.clone();
                     let session_id_sse = session_id;
                     let user_id_sse = user_id_value;
                     // Get the last message from the history payload for saving
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
                                     last_message_content_sse, // Save last message content
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
                                 
                                 // Add user message to embedding call tracker
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
                     // --- End Save User Message (SSE Branch) ---

                     s
                 },
                 Err(e) => {
                     error!(error = ?e, %session_id, "Failed to initiate AI stream");
                     // Immediately return an error stream if initiation fails
                     let error_stream = async_stream::stream! {
                         // ++ Logging: Log sending initiation error ++
                         let error_msg = format!("LLM API error: Failed to initiate stream - {}", e);
                         trace!(%session_id, error_message = %error_msg, "Sending SSE 'error' event (initiation failed)");
                         // ++ End Logging ++
                         yield Ok::<_, AppError>(Event::default().event("error").data(error_msg));
                     };
                     return Ok(Sse::new(Box::pin(error_stream)).keep_alive(KeepAlive::default()).into_response());
                 }
             };

            debug!(%session_id, "Starting SSE generation loop");

            // Use async_stream! to build the SSE stream
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
                            // No need to send anything to the client for this event
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
                            // Don't break here yet, wait for the stream to naturally end (None)
                            // or handle final cleanup after the loop
                        }
                        Err(e) => {
                            // ++ Logging: Log the raw error from the stream ++
                            error!(error = ?e, %session_id, "Error during AI stream processing (inside loop)");
                            // ++ End Logging ++
                            stream_error_occurred = true; // Set flag

                            // --- Save Partial Response on Error ---
                            let partial_content_clone = accumulated_content.clone(); // Clone for background task
                            let db_pool_clone = state.pool.clone(); // Clone DB pool
                            let error_session_id = session_id;
                            let error_user_id = user_id_value;

                            tokio::spawn(async move {
                                if !partial_content_clone.is_empty() {
                                    // ++ Logging: Log saving partial response ++
                                    trace!(session_id = %error_session_id, "Attempting to save partial AI response after stream error");
                                    // ++ End Logging ++
                                    
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
                                     // ++ Logging: Log no partial content ++
                                     trace!(session_id = %error_session_id, "No partial content to save after stream error");
                                     // ++ End Logging ++
                                 }
                            });
                            // --- End Save Partial Response ---


                            // Log the detailed error server-side
                            let detailed_error = e.to_string();
                            error!(error = %detailed_error, %session_id, "Detailed error during SSE stream processing");

                            // Send the detailed error message to the client via SSE
                            // Check if the error already contains "LLM API error:" to avoid double prefixing
                            let client_error_message = if detailed_error.contains("LLM API error:") {
                                detailed_error
                            } else {
                                format!("LLM API error: {}", detailed_error)
                            };
                            // ++ Logging: Log sending error event ++
                            trace!(%session_id, error_message = %client_error_message, "Sending SSE 'error' event");
                            // ++ End Logging ++
                            yield Ok::<_, AppError>(Event::default().event("error").data(client_error_message));
                            break; // Error exit from loop
                        }
                    }
                }

                // ++ Logging: Log exiting the loop ++
                trace!(%session_id, "Exited SSE processing loop. stream_error_occurred={}", stream_error_occurred);
                // ++ End Logging ++

                // --- Final processing after loop ---
                if !stream_error_occurred && !accumulated_content.is_empty() {
                    // Save the full successful response
                    // ++ Logging: Log saving full response ++
                    debug!(%session_id, "Attempting to save full successful AI response");
                    // ++ End Logging ++

                    // Clone everything needed for the background task
                    let state_clone = state.clone();
                    let session_id_clone = session_id;
                    let user_id_clone = user_id_value;
                    let accumulated_content_clone = accumulated_content.clone();

                    // Spawn a task to save the message to the database
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
                                
                                // Add AI message to embedding call tracker
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
                    // Send the final "[DONE]" data event ONLY if no error occurred
                    // ++ Logging: Log sending [DONE] event ++
                    trace!(%session_id, "Sending SSE event: done, data: [DONE]");
                    // ++ End Logging ++
                    yield Ok::<_, AppError>(Event::default().event("done").data("[DONE]"));
                } else if stream_error_occurred {
                    // If an error occurred, we might have already sent an error event.
                    // Consider if a different termination is needed or if the error event is sufficient.
                    // For now, we don't send [DONE] if an error was already sent.
                    // ++ Logging: Log [DONE] not sent due to error ++
                    trace!(%session_id, "[DONE] not sent due to stream_error_occurred=true");
                    // ++ End Logging ++
                } else if accumulated_content.is_empty() && !stream_error_occurred {
                    // Case: Stream finished, no errors, but also no content was accumulated (e.g., LLM returned empty)
                    // Still send [DONE] to signify graceful completion.
                    // ++ Logging: Log sending [DONE] for empty successful response ++
                    trace!(%session_id, "Sending SSE event: done, data: [DONE] (empty successful response)");
                    // ++ End Logging ++
                    yield Ok::<_, AppError>(Event::default().event("done").data("[DONE]"));
                }
            };

            // Return the SSE response
            Ok(Sse::new(Box::pin(stream)).keep_alive(KeepAlive::default()).into_response())
        }
        // --- Non-streaming JSON response ---
        v if v.contains(mime::APPLICATION_JSON.as_ref()) => {
            // --- JSON response ---
            info!(%session_id, "Handling non-streaming JSON request");
            
            // --- Create and Save User Message (JSON path) ---
            // Get the last message from the history payload
            let last_user_message = payload.history.last()
                .filter(|m| m.role.to_lowercase() == "user") // Ensure it's a user message
                .ok_or_else(|| {
                    error!(%session_id, "Last message in history is not from user or history is empty (JSON)");
                    AppError::BadRequest("Last message in history must be from the user.".to_string())
                })?;

            let user_message_content = last_user_message.content.clone();
            if user_message_content.is_empty() {
                 error!(%session_id, "Cannot save empty user message (JSON)");
                 return Err(AppError::BadRequest("User message content cannot be empty.".to_string()));
            }

            let user_message_to_save = crate::models::chats::DbInsertableChatMessage::new(
                session_id,
                user_id_value,
                MessageRole::User,
                user_message_content.clone(), // Use content from the last history message
            );

            // Save user message and get its ID
            let user_message_id = match state.pool.get().await {
                Ok(conn) => {
                    match conn
                        .interact(move |conn| {
                            diesel::insert_into(crate::schema::chat_messages::table)
                                .values(&user_message_to_save) // Use the correct variable
                                .returning(crate::schema::chat_messages::id)
                                .get_result::<Uuid>(conn)
                        })
                        .await
                    {
                        Ok(Ok(id)) => {
                            debug!(message_id = %id, session_id = %session_id, "Successfully saved user message (JSON)");
                            id
                        },
                        Ok(Err(e)) => {
                            error!(error = ?e, session_id = %session_id, "Database error saving user message (JSON)");
                            return Err(AppError::InternalServerError(format!("Failed to save user message: {}", e)));
                        },
                        Err(e) => {
                            error!(error = ?e, session_id = %session_id, "Interact error saving user message (JSON)");
                            return Err(AppError::InternalServerError(format!("Failed to save user message: {}", e)));
                        }
                    }
                },
                Err(e) => {
                    error!(error = ?e, session_id = %session_id, "Failed to get DB connection to save user message (JSON)");
                    return Err(AppError::InternalServerError(format!("Connection error: {}", e)));
                }
            };
            
            // Add user message to embedding call tracker
            match state.embedding_call_tracker.lock().await {
                mut tracker => {
                    tracker.push(user_message_id);
                    debug!(session_id = %session_id, message_id = %user_message_id, "Added user message to embedding call tracker (JSON)");
                }
            }

            // Process and embed the user message
            let user_message_for_embedding = ChatMessage {
                id: user_message_id,
                session_id,
                message_type: MessageRole::User,
                content: user_message_content.clone(), // Use content from the last history message
                created_at: chrono::Utc::now(), // Approximate time, DB has actual timestamp
                user_id: user_id_value,
            };

            let embedding_pipeline_service = state.embedding_pipeline_service.clone();
            match embedding_pipeline_service.process_and_embed_message(state.clone(), user_message_for_embedding).await {
                Ok(_) => {
                    debug!(session_id = %session_id, message_id = %user_message_id, "Successfully started processing and embedding user message");
                }
                Err(e) => {
                    error!(error = ?e, session_id = %session_id, message_id = %user_message_id, "Failed to process and embed user message");
                    // Continue execution even if embedding fails - don't return error to user
                }
            }
            // --- End Save User Message ---

            // --- RAG Logic (Added for non-streaming) ---
            // Use the EmbeddingPipelineService from the state
            let default_rag_limit = 3;

            let rag_context = match embedding_pipeline_service
                .retrieve_relevant_chunks(state.clone(), session_id, &user_message_content, default_rag_limit) // Use last user message content for RAG
                .await
            {
                Ok(chunks) => {
                    debug!(session_id = %session_id, chunk_count = chunks.len(), "Retrieved RAG chunks for non-streaming");
                    if chunks.is_empty() {
                        None
                    } else {
                        let context_string = chunks
                            .into_iter()
                            .map(|c| format!("- {}", c.text))
                            .collect::<Vec<_>>()
                            .join("\n");
                        Some(format!("<RAG_CONTEXT>\n{}\n</RAG_CONTEXT>", context_string))
                    }
                }
                Err(e) => {
                    error!(error = ?e, session_id = %session_id, "Failed to retrieve RAG chunks for non-streaming");
                    
                    // Delete the saved user message if RAG retrieval fails
                    let delete_result = state.pool.get().await.map(|conn| {
                        let message_id_to_delete = user_message_id;
                        let session_id_for_delete = session_id;
                        async move {
                            conn.interact(move |conn| {
                                use crate::schema::chat_messages::dsl::*;
                                diesel::delete(
                                    chat_messages.filter(
                                        id.eq(message_id_to_delete)
                                        .and(session_id.eq(session_id_for_delete))
                                    )
                                ).execute(conn)
                            }).await
                        }
                    });
                    
                    match delete_result {
                        Ok(future) => {
                            match future.await {
                                Ok(Ok(rows_deleted)) => {
                                    info!(message_id = %user_message_id, session_id = %session_id, rows = %rows_deleted,
                                          "Successfully deleted user message after RAG retrieval error");
                                    
                                    // Also remove the message from the embedding call tracker
                                    if let Ok(mut tracker) = state.embedding_call_tracker.try_lock() {
                                        if let Some(pos) = tracker.iter().position(|&id| id == user_message_id) {
                                            tracker.remove(pos);
                                            debug!(session_id = %session_id, message_id = %user_message_id, 
                                                   "Removed user message from embedding call tracker after RAG error");
                                        }
                                    }
                                }
                                Ok(Err(db_err)) => {
                                    error!(error = ?db_err, message_id = %user_message_id, session_id = %session_id, 
                                           "Database error when deleting user message after RAG retrieval error");
                                }
                                Err(interact_err) => {
                                    error!(error = ?interact_err, message_id = %user_message_id, session_id = %session_id, 
                                           "Interaction error when deleting user message after RAG retrieval error");
                                }
                            }
                        }
                        Err(pool_err) => {
                            error!(error = ?pool_err, message_id = %user_message_id, session_id = %session_id, 
                                   "Pool error when deleting user message after RAG retrieval error");
                        }
                    }
                    
                    // Propagate the embedding error (will be mapped to 502 by IntoResponse)
                    return Err(e);
                }
            };

            // Inject RAG context into the message list if available
            if let Some(context) = rag_context {
                // Prepend context to the *last* user message
                if let Some(last_message) = messages_for_ai.last_mut() {
                    if matches!(last_message.role, genai::chat::ChatRole::User) {
                        if let genai::chat::MessageContent::Text(text) = &mut last_message.content {
                            let original_content = text.clone();
                            *text = format!("{}\n\n{}", context, original_content);
                            trace!(session_id = %session_id, "Injected RAG context into user message (non-streaming)");
                        }
                    }
                } 
            }
            // --- End RAG Logic ---

            // Create ChatRequest and ChatOptions
            let chat_request = genai::chat::ChatRequest::new(messages_for_ai)
                .with_system(system_prompt.unwrap_or_default());
            let chat_options = genai::chat::ChatOptions::default()
                .with_temperature(temperature.map(|t| t.to_f32().unwrap_or(0.7) as f64).unwrap_or(0.7))
                .with_max_tokens(max_output_tokens.map(|t| t as u32).unwrap_or(1024))
                .with_top_p(top_p.map(|p| p.to_f32().unwrap_or(0.95) as f64).unwrap_or(0.95));

            // +++ Logging: Log the prepared chat request +++
            trace!(%session_id, chat_request = ?chat_request, "Prepared ChatRequest for AI (non-streaming, post-RAG)");
            // +++ End Logging ++
            match ai_client
                .exec_chat(model_to_use.as_str(), chat_request, Some(chat_options))
                .await
            {
                Ok(chat_response) => {
                    debug!(%session_id, "Received successful non-streaming AI response");
                    
                    // Extract the text content from ChatResponse
                    let response_content = match chat_response.content {
                        Some(genai::chat::MessageContent::Text(text)) => text,
                        // Keep treating non-text/None as empty string for response payload,
                        // but don't error out if the actual text *is* an empty string.
                        Some(_) => String::new(),
                        None => String::new(),
                    };

                    trace!(%session_id, ?response_content, "Full non-streaming AI response");
                    
                    // --- Save AI Message (JSON Branch - After Successful AI Call) ---
                    let db_pool_ai_save = state.pool.clone();
                    let ai_save_session_id = session_id;
                    let ai_save_user_id = user_id_value;
                    let ai_content_to_save = response_content.clone(); // AI response

                    // Save the AI response message and get its ID
                    tokio::spawn(async move {
                        // Prepare AI message outside interact
                        let ai_message = crate::models::chats::DbInsertableChatMessage::new(
                            ai_save_session_id,
                            ai_save_user_id, // AI message is associated with the user who prompted it
                            MessageRole::Assistant,
                            ai_content_to_save, // This might be empty, which is fine
                        );

                        // Get connection
                        let conn_result = db_pool_ai_save.get().await;
                        let conn = match conn_result {
                            Ok(c) => c,
                            Err(e) => {
                                error!(error = ?e, session_id = %ai_save_session_id, "Failed to get DB connection to save AI message (JSON)");
                                return;
                            }
                        };

                        // Execute insert and get the ID
                        let ai_save_result = conn
                            .interact(move |conn_tx| {
                                diesel::insert_into(crate::schema::chat_messages::table)
                                    .values(&ai_message) // Use reference
                                    .returning(crate::schema::chat_messages::id)
                                    .get_result::<Uuid>(conn_tx)
                            })
                            .await;

                        match ai_save_result {
                            Ok(Ok(ai_message_id)) => {
                                debug!(session_id = %ai_save_session_id, message_id = %ai_message_id, "Successfully saved AI message (JSON)");
                                
                                // Add AI message to embedding call tracker
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
                    // --- End Save AI Message ---
                    
                    // Construct the non-streaming response payload
                    let response_payload = json!({
                        "message_id": Uuid::new_v4(), // Generate a placeholder ID for the response message
                        "content": response_content
                    });
                    // ++ Logging: Log sending JSON response ++
                    trace!(%session_id, response_payload = ?response_payload, "Sending non-streaming JSON response");
                    // ++ End Logging ++

                    Ok(Json(response_payload).into_response())
                }
                Err(e) => {
                    // ++ Logging: Log non-streaming AI error ++
                    error!(error = ?e, %session_id, "AI generation failed for non-streaming request");
                    // ++ End Logging ++
                    Err(e) // Propagate the AppError
                }
            }
        }
        // --- Fallback to SSE ---
        _ => { 
            // Check if this is actually a deliberate JSON request that had an error,
            // or a request without a proper Accept header that should fall back to SSE
            if !accept_header.is_empty() && !accept_header.contains(mime::APPLICATION_JSON.as_ref()) {
                // This is a true SSE fallback case - use the streaming approach
                info!(%session_id, "Accept header '{}' not recognized as JSON, defaulting to SSE.", accept_header);
                
                // +++ Create ChatRequest and ChatOptions INSIDE the fallback SSE branch +++
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
                // Add new Gemini options for fallback SSE
                if let Some(budget) = gemini_thinking_budget {
                    if budget > 0 {
                        genai_chat_options_fallback = genai_chat_options_fallback.with_gemini_thinking_budget(budget as u32);
                    }
                }
                if let Some(enable_exec) = gemini_enable_code_execution {
                    genai_chat_options_fallback = genai_chat_options_fallback.with_gemini_enable_code_execution(enable_exec);
                }
                // +++ End Creation +++

                // ++ Logging: Log the prepared chat request ++
                trace!(%session_id, chat_request = ?chat_request, genai_options = ?genai_chat_options_fallback, "Prepared ChatRequest and Options for AI (fallback SSE)");
                // ++ End Logging ++

                let genai_stream: crate::llm::ChatStream = match ai_client.stream_chat(model_to_use.as_str(), chat_request, Some(genai_chat_options_fallback)).await {
                     Ok(s) => {
                         debug!(%session_id, "Successfully initiated AI stream (fallback SSE)");

                         // --- Save User Message (fallback SSE Branch - AFTER Successful AI Stream Initiation) ---
                         // Clone necessary data for the background task
                         let db_pool_sse = state.pool.clone();
                         let embedding_tracker = state.embedding_call_tracker.clone();
                         let session_id_sse = session_id;
                         let user_id_sse = user_id_value;
                         // Get the last message from the history payload for saving
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
                                         last_message_content_sse_fallback, // Save last message content
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
                                     
                                     // Add user message to embedding call tracker
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
                         // --- End Save User Message (fallback SSE Branch) ---

                         s
                     },
                     Err(e) => {
                         error!(error = ?e, %session_id, "Failed to initiate AI stream (fallback SSE)");
                         // Immediately return an error stream if initiation fails
                         let error_stream = async_stream::stream! {
                             // ++ Logging: Log sending initiation error ++
                             let error_msg = format!("LLM API error: Failed to initiate stream - {}", e);
                             trace!(%session_id, error_message = %error_msg, "Sending fallback SSE 'error' event (initiation failed)");
                             // ++ End Logging ++
                             yield Ok::<_, AppError>(Event::default().event("error").data(error_msg));
                         };
                         return Ok(Sse::new(Box::pin(error_stream)).keep_alive(KeepAlive::default()).into_response());
                     }
                 };

                debug!(%session_id, "Starting fallback SSE generation loop");

                // Use async_stream! to build the SSE stream
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
                                // No need to send anything to the client for this event
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
                                // Don't break here yet, wait for the stream to naturally end (None)
                            }
                            Err(e) => {
                                // ++ Logging: Log the raw error from the stream ++
                                error!(error = ?e, %session_id, "Error during AI stream processing (fallback loop)");
                                // ++ End Logging ++
                                stream_error_occurred = true; // Set flag

                                // --- Save Partial Response on Error ---
                                let partial_content_clone = accumulated_content.clone(); // Clone for background task
                                let db_pool_clone = state.pool.clone(); // Clone DB pool
                                let error_session_id = session_id;
                                let error_user_id = user_id_value;

                                tokio::spawn(async move {
                                    if !partial_content_clone.is_empty() {
                                        // ++ Logging: Log saving partial response ++
                                        trace!(session_id = %error_session_id, "Attempting to save partial AI response after stream error (fallback)");
                                        // ++ End Logging ++
                                        
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
                                         // ++ Logging: Log no partial content ++
                                         trace!(session_id = %error_session_id, "No partial content to save after stream error (fallback)");
                                         // ++ End Logging ++
                                     }
                                });
                                // --- End Save Partial Response ---

                                // Log the detailed error server-side
                                let detailed_error = e.to_string();
                                error!(error = %detailed_error, %session_id, "Detailed error during fallback SSE stream processing");

                                // Send the detailed error message to the client via SSE
                                // Check if the error already contains "LLM API error:" to avoid double prefixing
                                let client_error_message = if detailed_error.contains("LLM API error:") {
                                    detailed_error
                                } else {
                                    format!("LLM API error: {}", detailed_error)
                                };
                                // ++ Logging: Log sending error event ++
                                trace!(%session_id, error_message = %client_error_message, "Sending fallback SSE 'error' event");
                                // ++ End Logging ++
                                yield Ok::<_, AppError>(Event::default().event("error").data(client_error_message));
                                break; // Error exit from loop
                            }
                        }
                    }

                    // ++ Logging: Log exiting the loop ++
                    trace!(%session_id, "Exited fallback SSE processing loop. stream_error_occurred={}", stream_error_occurred);
                    // ++ End Logging ++

                    // --- Final processing after loop ---
                    if !stream_error_occurred && !accumulated_content.is_empty() {
                        // Save the full successful response
                        // ++ Logging: Log saving full response ++
                        debug!(%session_id, "Attempting to save full successful AI response (fallback)");
                        // ++ End Logging ++

                        // Clone everything needed for the background task
                        let state_clone = state.clone();
                        let session_id_clone = session_id;
                        let user_id_clone = user_id_value;
                        let accumulated_content_clone = accumulated_content.clone();

                        // Spawn a task to save the message to the database
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
                                    
                                    // Add AI message to embedding call tracker
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
                        // Send the final "[DONE]" data event ONLY if no error occurred
                        // ++ Logging: Log sending [DONE] event ++
                        trace!(%session_id, "Sending fallback SSE data: [DONE]");
                        // ++ End Logging ++
                        yield Ok::<_, AppError>(Event::default().data("[DONE]"));
                    } else if !stream_error_occurred && accumulated_content.is_empty() {
                         // Handle case where stream ended successfully but produced no content
                         debug!(%session_id, "AI stream finished successfully but produced no content in fallback. Sending '[DONE]'.");
                        // Still send [DONE], but don't save anything.
                        // ++ Logging: Log sending [DONE] (empty) ++
                        trace!(%session_id, "Sending fallback SSE data: [DONE] (empty content)");
                        // ++ End Logging ++
                        yield Ok::<_, AppError>(Event::default().data("[DONE]"));
                     } else {
                        // Error occurred, 'error' event was already sent in the loop. Do nothing more.
                        // ++ Logging: Log stream finished after error ++
                        debug!(%session_id, "Fallback stream finished after an error. No 'done' event sent.");
                        // ++ End Logging ++
                     }
                     // ++ Logging: Log finishing the stream block ++
                     trace!(%session_id, "Finished fallback SSE async_stream! block");
                     // ++ End Logging ++
                };

                // Return the SSE response
                Ok(Sse::new(Box::pin(stream)).keep_alive(KeepAlive::default()).into_response())
            } else {
                // This case handles when the accept_header is empty. Default to SSE.
                info!(%session_id, "Accept header is empty, defaulting to SSE.");

                // +++ Create ChatRequest and ChatOptions INSIDE the final fallback SSE branch +++
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
                // Add new Gemini options for empty header fallback SSE
                if let Some(budget) = gemini_thinking_budget {
                    if budget > 0 {
                        genai_chat_options_empty_fallback = genai_chat_options_empty_fallback.with_gemini_thinking_budget(budget as u32);
                    }
                }
                if let Some(enable_exec) = gemini_enable_code_execution {
                    genai_chat_options_empty_fallback = genai_chat_options_empty_fallback.with_gemini_enable_code_execution(enable_exec);
                }
                // +++ End Creation +++

                // ++ Logging: Log the prepared chat request ++
                trace!(%session_id, chat_request = ?chat_request, genai_options = ?genai_chat_options_empty_fallback, "Prepared ChatRequest and Options for AI (empty header fallback SSE)");
                // ++ End Logging ++

                let genai_stream: crate::llm::ChatStream = match ai_client.stream_chat(model_to_use.as_str(), chat_request, Some(genai_chat_options_empty_fallback)).await {
                    Ok(s) => {
                        debug!(%session_id, "Successfully initiated AI stream (empty header fallback SSE)");

                        // --- Save User Message (empty header fallback SSE Branch) ---
                        let db_pool_sse = state.pool.clone();
                        let embedding_tracker = state.embedding_call_tracker.clone();
                        let session_id_sse = session_id;
                        let user_id_sse = user_id_value;
                        // Get the last message from the history payload for saving
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
                                        last_message_content_empty_fallback, // Save last message content
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
                        // --- End Save User Message ---
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

                // Use async_stream! to build the SSE stream
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
                                // No need to send anything to the client for this event
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

                                // --- Save Partial Response on Error ---
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
                                // --- End Save Partial Response ---

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


/// Creates a router with the chat endpoints.
pub fn chat_routes() -> Router<AppState> {
    Router::new()
        // Use handler names from chats_api.rs
        .route("/", post(create_chat_handler).get(get_chats_handler))
        .route("/{session_id}", get(get_chat_by_id_handler))
        .route("/{session_id}/messages", get(get_messages_by_chat_id_handler))
        .route(
            "/{session_id}/generate", // Use {} syntax
            post(generate_chat_response), // This one is defined in this file
        )
        .route(
            "/{session_id}/settings", // Use {} syntax
            // Assuming get_chat_settings and update_chat_settings will be defined below
            get(get_chat_settings_handler).put(update_chat_settings_handler),
        )
        // Login required middleware is applied globally in spawn_app
}

