// backend/src/routes/chat.rs

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{sse::Event, sse::KeepAlive, Sse, IntoResponse},
    Json, 
    routing::{get, post},
    Router,
    body::Body,
};
use axum::http::header;
use axum_login::AuthSession;
use diesel::{QueryDsl, ExpressionMethods, RunQueryDsl, delete, BoolExpressionMethods};
use crate::models::chats::{MessageRole, GenerateResponsePayload, ChatMessage};
use crate::errors::AppError;
use crate::services::chat_service;
use crate::state::AppState;
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
use crate::llm::AiClient;

#[instrument(skip(state, auth_session, payload), fields(session_id = %session_id_str))]
pub async fn generate_chat_response(
    State(state): State<AppState>,
    auth_session: AuthSession<AuthBackend>,
    Path(session_id_str): Path<String>,
    headers: HeaderMap,
    Json(payload): Json<GenerateResponsePayload>,
) -> Result<impl IntoResponse, AppError> {
    info!("Received request to generate chat response");
    trace!(payload = ?payload, "Received payload");

    // We'll need to convert state to Arc<AppState> for consistent API
    let state = Arc::new(state);
    
    // 1. Extract User and Validate Session ID
    let user = auth_session.user
        .ok_or_else(|| AppError::Unauthorized("User not found in session".to_string()))?;
    let user_id_value = user.id; // Use the user ID from the session
    debug!(%user_id_value, "Extracted user from session");

    let session_id = Uuid::parse_str(&session_id_str)
        .map_err(|_| AppError::BadRequest("Invalid session UUID format".to_string()))?;
    debug!(%session_id, "Parsed session ID");

    // 2. Authorization & Data Fetching
    let generation_data = 
        chat_service::get_session_data_for_generation(
            &state.pool,
            user_id_value,
            session_id,
            payload.content.clone(),
        )
        .await?; // Propagates NotFound, Forbidden, etc.
    
    // Unpack the data from the tuple
    let (
        history_for_generation,
        system_prompt,
        temperature,
        max_output_tokens,
        _frequency_penalty,
        _presence_penalty,
        _top_k,
        top_p,
        _repetition_penalty,
        _min_p,
        _top_a,
        _seed,
        _logit_bias,
        model_name_from_settings,
        _user_db_message_to_save,
        _history_strategy,
        _history_limit
    ) = generation_data;

    // Use model from payload if provided, otherwise use the one from settings
    let model_to_use = payload.model.unwrap_or(model_name_from_settings);

    // 3. Prepare AI Request
    let ai_client = state.ai_client.clone(); // Clone Arc<dyn AiServiceClient>

    // Map history to AI client's ChatMessage format
    let mut messages_for_ai: Vec<genai::chat::ChatMessage> = history_for_generation
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
    
    // Add the current user message
    messages_for_ai.push(genai::chat::ChatMessage {
        role: genai::chat::ChatRole::User,
        content: genai::chat::MessageContent::Text(payload.content.clone()),
        options: None,
    });

    trace!(history_len = messages_for_ai.len(), %session_id, "Converted message history for AI");

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
            let chat_options = genai::chat::ChatOptions::default()
                .with_temperature(temperature.map(|t| t.to_f32().unwrap_or(0.7) as f64).unwrap_or(0.7))
                .with_max_tokens(max_output_tokens.map(|t| t as u32).unwrap_or(1024))
                .with_top_p(top_p.map(|p| p.to_f32().unwrap_or(0.95) as f64).unwrap_or(0.95));
            // +++ End Creation +++

            // ++ Logging: Log the prepared chat request ++
            trace!(%session_id, chat_request = ?chat_request, "Prepared ChatRequest for AI (SSE)");
            // ++ End Logging ++

            let genai_stream: crate::llm::ChatStream = match ai_client.stream_chat(model_to_use.as_str(), chat_request, Some(chat_options)).await {
                 Ok(s) => {
                     debug!(%session_id, "Successfully initiated AI stream");

                     // --- Save User Message (SSE Branch - AFTER Successful AI Stream Initiation) ---
                     // Clone necessary data for the background task
                     let db_pool_sse = state.pool.clone();
                     let embedding_tracker = state.embedding_call_tracker.clone();
                     let session_id_sse = session_id;
                     let user_id_sse = user_id_value;
                     let content_sse = payload.content.clone(); // Use original payload content

                     tokio::spawn(async move {
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
                                     content_sse,
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

                // Pin the stream for use in the loop
                futures::pin_mut!(genai_stream);

                // ++ Logging: Log entering the main loop ++
                trace!(%session_id, "Entering SSE async_stream! processing loop");
                // ++ End Logging ++

                // Send a 'start' event if requested (or by default if not specified)
                // Note: We'll reconsider if 'start' event is truly needed. For now, keep logic simple.
                // if request_thinking { // Simplification: Removed explicit 'start' event for now
                //     debug!(%session_id, "Sending SSE 'start' event");
                //     yield Ok::<_, AppError>(Event::default().event("start").data("Processing request..."));
                // }

                while let Some(event_result) = genai_stream.next().await {
                    // ++ Logging: Log every event received from genai ++
                    trace!(%session_id, "Received event from genai_stream: {:?}", event_result);
                    // ++ End Logging ++
                    match event_result {
                        Ok(ChatStreamEvent::Start) => {
                            debug!(%session_id, "Received Start event from AI stream (no SSE sent)");
                            // Optional: Send a 'thinking' or 'start' event if useful
                            // For now, we don't send anything specific for genai's Start event
                            if request_thinking {
                                 // ++ Logging: Log sending thinking event ++
                                 debug!(%session_id, "Sending SSE 'thinking' event (triggered by AI Start)");
                                 // ++ End Logging ++
                                 yield Ok::<_, AppError>(Event::default().event("thinking").data("AI Processing Started"));
                             }
                        }
                        Ok(ChatStreamEvent::Chunk(chunk)) => {
                            debug!(%session_id, content_chunk_len = chunk.content.len(), "Received Content chunk from AI stream"); // Log length instead of full content
                            trace!(%session_id, content_chunk = %chunk.content, "Full content chunk data"); // Trace full content
                            if !chunk.content.is_empty() {
                                accumulated_content.push_str(&chunk.content);
                                // ++ Logging: Log sending content event ++
                                trace!(%session_id, "Sending SSE 'content' event");
                                // ++ End Logging ++
                                yield Ok::<_, AppError>(Event::default().event("content").data(chunk.content));
                            } else {
                                 // ++ Logging: Log skipping empty chunk ++
                                 trace!(%session_id, "Skipping empty content chunk from AI");
                                 // ++ End Logging ++
                             }
                        }
                        Ok(ChatStreamEvent::ReasoningChunk(chunk)) => {
                            debug!(%session_id, content_chunk_len = chunk.content.len(), "Received Reasoning chunk from AI stream");
                            trace!(%session_id, content = %chunk.content, "Full reasoning chunk data");
                            if request_thinking {
                                // Since we don't have label separately anymore, just send the content directly
                                // ++ Logging: Log sending thinking event (reasoning) ++
                                trace!(%session_id, "Sending SSE 'thinking' event (Reasoning)");
                                // ++ End Logging ++
                                yield Ok::<_, AppError>(Event::default().event("thinking").data(chunk.content));
                            } else {
                                // ++ Logging: Log skipping reasoning chunk ++
                                trace!(%session_id, "Skipping Reasoning chunk (request_thinking=false)");
                                // ++ End Logging ++
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
                    // Send the final "done" event ONLY if no error occurred AND content was generated
                    // ++ Logging: Log sending done event ++
                    trace!(%session_id, "Sending SSE 'done' event");
                    // ++ End Logging ++
                    yield Ok::<_, AppError>(Event::default().event("done"));
                } else if !stream_error_occurred && accumulated_content.is_empty() {
                     // Handle case where stream ended successfully but produced no content (rare?)
                     debug!(%session_id, "AI stream finished successfully but produced no content. Sending 'done'.");
                    // Still send done, but don't save anything.
                    // ++ Logging: Log sending done (empty) ++
                    trace!(%session_id, "Sending SSE 'done' event (empty content)");
                    // ++ End Logging ++
                    yield Ok::<_, AppError>(Event::default().event("done"));
                 } else {
                    // Error occurred, 'error' event was already sent in the loop. Do nothing more.
                    // ++ Logging: Log stream finished after error ++
                    debug!(%session_id, "Stream finished after an error. No 'done' event sent.");
                    // ++ End Logging ++
                 }
                 // ++ Logging: Log finishing the stream block ++
                 trace!(%session_id, "Finished SSE async_stream! block");
                 // ++ End Logging ++
            };

            // Return the SSE response
            Ok(Sse::new(Box::pin(stream)).keep_alive(KeepAlive::default()).into_response())
        }
        // --- Non-streaming JSON response ---
        v if v.contains(mime::APPLICATION_JSON.as_ref()) => {
            // --- JSON response ---
            info!(%session_id, "Handling non-streaming JSON request");
            
            // --- Create and Save User Message (JSON path) ---
            let user_message = crate::models::chats::DbInsertableChatMessage::new(
                session_id,
                user_id_value,
                MessageRole::User,
                payload.content.clone(),
            );

            // Save user message and get its ID
            let user_message_id = match state.pool.get().await {
                Ok(conn) => {
                    match conn
                        .interact(move |conn| {
                            diesel::insert_into(crate::schema::chat_messages::table)
                                .values(&user_message)
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
                content: payload.content.clone(),
                created_at: chrono::Utc::now(),
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
                .retrieve_relevant_chunks(state.clone(), session_id, &payload.content, default_rag_limit)
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
                let chat_options = genai::chat::ChatOptions::default()
                    .with_temperature(temperature.map(|t| t.to_f32().unwrap_or(0.7) as f64).unwrap_or(0.7))
                    .with_max_tokens(max_output_tokens.map(|t| t as u32).unwrap_or(1024))
                    .with_top_p(top_p.map(|p| p.to_f32().unwrap_or(0.95) as f64).unwrap_or(0.95));
                // +++ End Creation +++

                // ++ Logging: Log the prepared chat request ++
                trace!(%session_id, chat_request = ?chat_request, "Prepared ChatRequest for AI (fallback SSE)");
                // ++ End Logging ++

                let genai_stream: crate::llm::ChatStream = match ai_client.stream_chat(model_to_use.as_str(), chat_request, Some(chat_options)).await {
                     Ok(s) => {
                         debug!(%session_id, "Successfully initiated AI stream (fallback SSE)");

                         // --- Save User Message (fallback SSE Branch - AFTER Successful AI Stream Initiation) ---
                         // Clone necessary data for the background task
                         let db_pool_sse = state.pool.clone();
                         let embedding_tracker = state.embedding_call_tracker.clone();
                         let session_id_sse = session_id;
                         let user_id_sse = user_id_value;
                         let content_sse = payload.content.clone(); // Use original payload content

                         tokio::spawn(async move {
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
                                         content_sse,
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

                    // Pin the stream for use in the loop
                    futures::pin_mut!(genai_stream);

                    // ++ Logging: Log entering the main loop ++
                    trace!(%session_id, "Entering fallback SSE async_stream! processing loop");
                    // ++ End Logging ++

                    while let Some(event_result) = genai_stream.next().await {
                        // ++ Logging: Log every event received from genai ++
                        trace!(%session_id, "Received event from genai_stream (fallback): {:?}", event_result);
                        // ++ End Logging ++
                        match event_result {
                            Ok(ChatStreamEvent::Start) => {
                                debug!(%session_id, "Received Start event from AI stream (fallback, no SSE sent)");
                                // Optional: Send a 'thinking' or 'start' event if useful
                                // For now, we don't send anything specific for genai's Start event
                                if request_thinking {
                                     // ++ Logging: Log sending thinking event ++
                                     debug!(%session_id, "Sending fallback SSE 'thinking' event (triggered by AI Start)");
                                     // ++ End Logging ++
                                     yield Ok::<_, AppError>(Event::default().event("thinking").data("AI Processing Started"));
                                 }
                            }
                            Ok(ChatStreamEvent::Chunk(chunk)) => {
                                debug!(%session_id, content_chunk_len = chunk.content.len(), "Received Content chunk from AI stream (fallback)");
                                trace!(%session_id, content_chunk = %chunk.content, "Full content chunk data (fallback)");
                                if !chunk.content.is_empty() {
                                    accumulated_content.push_str(&chunk.content);
                                    // ++ Logging: Log sending content event ++
                                    trace!(%session_id, "Sending fallback SSE 'content' event");
                                    // ++ End Logging ++
                                    yield Ok::<_, AppError>(Event::default().event("content").data(chunk.content));
                                } else {
                                     // ++ Logging: Log skipping empty chunk ++
                                     trace!(%session_id, "Skipping empty content chunk from AI (fallback)");
                                     // ++ End Logging ++
                                 }
                            }
                            Ok(ChatStreamEvent::ReasoningChunk(chunk)) => {
                                debug!(%session_id, content_chunk_len = chunk.content.len(), "Received Reasoning chunk from AI stream (fallback)");
                                trace!(%session_id, content = %chunk.content, "Full reasoning chunk data (fallback)");
                                if request_thinking {
                                    // ++ Logging: Log sending thinking event (reasoning) ++
                                    trace!(%session_id, "Sending fallback SSE 'thinking' event (Reasoning)");
                                    // ++ End Logging ++
                                    yield Ok::<_, AppError>(Event::default().event("thinking").data(chunk.content));
                                } else {
                                    // ++ Logging: Log skipping reasoning chunk ++
                                    trace!(%session_id, "Skipping Reasoning chunk in fallback (request_thinking=false)");
                                    // ++ End Logging ++
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
                        // Send the final "done" event ONLY if no error occurred AND content was generated
                        // ++ Logging: Log sending done event ++
                        trace!(%session_id, "Sending fallback SSE 'done' event");
                        // ++ End Logging ++
                        yield Ok::<_, AppError>(Event::default().event("done"));
                    } else if !stream_error_occurred && accumulated_content.is_empty() {
                         // Handle case where stream ended successfully but produced no content (rare?)
                         debug!(%session_id, "AI stream finished successfully but produced no content in fallback. Sending 'done'.");
                        // Still send done, but don't save anything.
                        // ++ Logging: Log sending done (empty) ++
                        trace!(%session_id, "Sending fallback SSE 'done' event (empty content)");
                        // ++ End Logging ++
                        yield Ok::<_, AppError>(Event::default().event("done"));
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
                let chat_options = genai::chat::ChatOptions::default()
                    .with_temperature(temperature.map(|t| t.to_f32().unwrap_or(0.7) as f64).unwrap_or(0.7))
                    .with_max_tokens(max_output_tokens.map(|t| t as u32).unwrap_or(1024))
                    .with_top_p(top_p.map(|p| p.to_f32().unwrap_or(0.95) as f64).unwrap_or(0.95));
                // +++ End Creation +++

                // ++ Logging: Log the prepared chat request ++
                trace!(%session_id, chat_request = ?chat_request, "Prepared ChatRequest for AI (empty header fallback SSE)");
                // ++ End Logging ++

                let genai_stream: crate::llm::ChatStream = match ai_client.stream_chat(model_to_use.as_str(), chat_request, Some(chat_options)).await {
                    Ok(s) => {
                        debug!(%session_id, "Successfully initiated AI stream (empty header fallback SSE)");

                        // --- Save User Message (empty header fallback SSE Branch) ---
                        let db_pool_sse = state.pool.clone();
                        let embedding_tracker = state.embedding_call_tracker.clone();
                        let session_id_sse = session_id;
                        let user_id_sse = user_id_value;
                        let content_sse = payload.content.clone();

                        tokio::spawn(async move {
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
                                        content_sse,
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
                                debug!(%session_id, "Received Start event from AI stream (empty header fallback, no SSE sent)");
                                if request_thinking {
                                    debug!(%session_id, "Sending empty header fallback SSE 'thinking' event (triggered by AI Start)");
                                    yield Ok::<_, AppError>(Event::default().event("thinking").data("AI Processing Started"));
                                }
                            }
                            Ok(ChatStreamEvent::Chunk(chunk)) => {
                                debug!(%session_id, content_chunk_len = chunk.content.len(), "Received Content chunk from AI stream (empty header fallback)");
                                trace!(%session_id, content_chunk = %chunk.content, "Full content chunk data (empty header fallback)");
                                if !chunk.content.is_empty() {
                                    accumulated_content.push_str(&chunk.content);
                                    trace!(%session_id, "Sending empty header fallback SSE 'content' event");
                                    yield Ok::<_, AppError>(Event::default().event("content").data(chunk.content));
                                } else {
                                    trace!(%session_id, "Skipping empty content chunk from AI (empty header fallback)");
                                }
                            }
                            Ok(ChatStreamEvent::ReasoningChunk(chunk)) => {
                                debug!(%session_id, content_chunk_len = chunk.content.len(), "Received Reasoning chunk from AI stream (empty header fallback)");
                                trace!(%session_id, content = %chunk.content, "Full reasoning chunk data (empty header fallback)");
                                if request_thinking {
                                    trace!(%session_id, "Sending empty header fallback SSE 'thinking' event (Reasoning)");
                                    yield Ok::<_, AppError>(Event::default().event("thinking").data(chunk.content));
                                } else {
                                    trace!(%session_id, "Skipping Reasoning chunk in empty header fallback (request_thinking=false)");
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
                        trace!(%session_id, "Sending empty header fallback SSE 'done' event");
                        yield Ok::<_, AppError>(Event::default().event("done"));
                    } else if !stream_error_occurred && accumulated_content.is_empty() {
                        debug!(%session_id, "AI stream finished successfully but produced no content in empty header fallback. Sending 'done'.");
                        trace!(%session_id, "Sending empty header fallback SSE 'done' event (empty content)");
                        yield Ok::<_, AppError>(Event::default().event("done"));
                    } else {
                        debug!(%session_id, "Empty header fallback stream finished after an error. No 'done' event sent.");
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

// Helper function to generate the chat response
async fn generate_ai_response(
    ai_client: Arc<dyn AiClient>,
    system_prompt: &Option<String>,
    messages_for_ai: &[genai::chat::ChatMessage],
    model: &str,
    temperature: Option<bigdecimal::BigDecimal>,
    max_output_tokens: Option<i32>,
    top_p: Option<bigdecimal::BigDecimal>,
) -> Result<String, AppError> {
    // Build ChatRequest
    let chat_request = genai::chat::ChatRequest::new(messages_for_ai.to_vec())
        .with_system(system_prompt.clone().unwrap_or_default());

    // Configure options
    let chat_options = genai::chat::ChatOptions::default()
        .with_temperature(temperature.map(|t| t.to_f32().unwrap_or(0.7) as f64).unwrap_or(0.7))
        .with_max_tokens(max_output_tokens.map(|t| t as u32).unwrap_or(1024))
        .with_top_p(top_p.map(|p| p.to_f32().unwrap_or(0.95) as f64).unwrap_or(0.95));

    // Call AI
    let response = ai_client.exec_chat(model, chat_request, Some(chat_options)).await?;

    // Extract content
    match response.content {
        Some(genai::chat::MessageContent::Text(text)) => {
            Ok(text)
        }
        Some(other) => {
            Err(AppError::InternalServerError(format!("Unexpected message content type: {:?}", other)))
        }
        None => {
            Err(AppError::InternalServerError("AI returned no content".to_string()))
        }
    }
}
