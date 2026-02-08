//! Desktop-specific chat streaming using Tauri Channels
//!
//! This module provides SSE (Server-Sent Events) streaming for chat responses
//! using Tauri's Channel API, which is designed for efficient streaming operations.
//!
//! Key differences from web SSE:
//! - Backend SSE stream → Tauri Channel events → Frontend handlers
//! - Proper streaming (no buffering) via async/await
//! - Type-safe event handling with serde serialization
//!
//! Architecture:
//! 1. Frontend calls `invoke('stream_chat_response', { ..., channel })`
//! 2. This command creates HTTP client, fetches backend SSE endpoint
//! 3. Parses SSE events using `eventsource-stream` crate
//! 4. Converts SSE events → ChatStreamEvent and sends through channel
//! 5. Frontend receives events via `channel.onmessage`

use futures_util::StreamExt;
use serde::Serialize;
use tauri::{ipc::Channel, AppHandle};

/// Channel event types for chat streaming
///
/// Matches backend SSE event structure for compatibility:
/// - ScribeSseEvent::Content → ChatStreamEvent::Content
/// - ScribeSseEvent::Thinking → ChatStreamEvent::Thinking
/// - ScribeSseEvent::Error → ChatStreamEvent::Error
/// - ScribeSseEvent::TokenUsage → ChatStreamEvent::TokenUsage
/// - ScribeSseEvent::MessageSaved → ChatStreamEvent::MessageSaved
/// - "done" event → ChatStreamEvent::Done
///
/// CRITICAL: Each variant's struct fields are serialized as camelCase for frontend compatibility
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase", tag = "event", content = "data")]
pub enum ChatStreamEvent {
    /// Content chunk from AI response
    /// Payload is JSON-serialized StreamedChunk: { index, content, checksum }
    Content { payload: String },
    /// Reasoning/thinking text (for models with thinking mode)
    Thinking { text: String },
    /// Error message
    Error { message: String },
    /// Token usage statistics
    /// Fields serialized as camelCase: promptTokens, completionTokens, modelName
    TokenUsage {
        #[serde(rename = "promptTokens")]
        prompt_tokens: i32,
        #[serde(rename = "completionTokens")]
        completion_tokens: i32,
        #[serde(rename = "modelName")]
        model_name: String,
    },
    /// Message saved to database confirmation
    /// Fields serialized as camelCase: messageId, variantCount, currentVariantIndex
    MessageSaved {
        #[serde(rename = "messageId")]
        message_id: String,
        #[serde(rename = "variantCount")]
        variant_count: i32,
        #[serde(rename = "currentVariantIndex")]
        current_variant_index: i32,
    },
    /// Game state update from Game Master mode
    GameStateUpdate {
        #[serde(rename = "gameState")]
        game_state: serde_json::Value,
    },
    /// Streaming complete marker
    Done,
}

/// Stream chat response using Tauri Channel
///
/// This command:
/// 1. Retrieves JWT token + DEK from secure storage
/// 2. Makes authenticated HTTPS request to backend SSE endpoint
/// 3. Parses SSE events and converts to Channel events
/// 4. Streams events to frontend in real-time
///
/// # Arguments
///
/// * `app` - Tauri AppHandle for accessing secure storage
/// * `session_id` - Chat session UUID
/// * `user_message` - User's message text
/// * `history` - Chat history as JSON array
/// * `model` - Optional model override
/// * `agent_mode` - Optional agent mode (standard, instructed, advanced)
/// * `analysis_mode` - Optional analysis mode (existing, refresh, skip)
/// * `guidance` - Optional guidance text for instructed mode
/// * `variant_of` - Optional message ID for variant generation
/// * `is_regeneration` - Whether this is regenerating previous response
/// * `channel` - Tauri Channel for streaming events
///
/// # Errors
///
/// Returns error string if:
/// - No access token found in secure storage
/// - HTTP request fails
/// - SSE parsing fails
#[tauri::command]
pub async fn stream_chat_response(
    app: AppHandle,
    session_id: String,
    user_message: String,
    history: Vec<serde_json::Value>,
    model: Option<String>,
    agent_mode: Option<String>,
    analysis_mode: Option<String>,
    guidance: Option<String>,
    variant_of: Option<String>,
    thinking_level: Option<String>,
    _is_regeneration: bool,
    channel: Channel<ChatStreamEvent>,
) -> Result<(), String> {
    log::info!(
        "🔥 [stream_chat_response] ===== ENTRY POINT ===== Starting for session {}",
        session_id
    );
    log::info!(
        "🔥 [stream_chat_response] Parameters: user_message_len={}, history_len={}, model={:?}, thinking_level={:?}",
        user_message.len(),
        history.len(),
        model,
        thinking_level
    );

    // Get tokens from secure storage
    let access_token = match load_access_token(&app).await {
        Some(token) => token,
        None => {
            let error_msg = "No access token found - user not authenticated".to_string();
            log::error!("[stream_chat_response] {}", error_msg);
            let _ = channel.send(ChatStreamEvent::Error {
                message: error_msg.clone(),
            });
            return Err(error_msg);
        }
    };

    // Get optional DEK (only present in Quick Start mode)
    let dek = load_dek(&app).await;
    if dek.is_some() {
        log::debug!("[stream_chat_response] DEK loaded from secure storage (Quick Start mode)");
    }

    // Create HTTP client with TLS validation disabled for localhost
    // SAFETY: This is safe because we only connect to localhost:38080 (our own embedded backend)
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // Accept self-signed cert for https://localhost:38080
        .timeout(std::time::Duration::from_secs(300)) // 5 minutes for long responses
        .build()
        .map_err(|e| {
            let error_msg = format!("Failed to create HTTP client: {}", e);
            log::error!("[stream_chat_response] {}", error_msg);
            error_msg
        })?;

    // Prepare request body (matches backend GenerateRequest structure)
    // CRITICAL: Backend expects the new user message as the LAST element in history array
    let mut full_history = history;
    full_history.push(serde_json::json!({
        "role": "user",
        "content": user_message
    }));

    let request_body = serde_json::json!({
        "history": full_history,
        "model": model,
        "agent_mode": agent_mode,
        "analysis_mode": analysis_mode,
        "guidance": guidance,
        "variant_of": variant_of,
        "thinking_level": thinking_level,
        // NOTE: Don't send is_regeneration - backend infers from history/variant_of
    });

    log::debug!(
        "[stream_chat_response] Request body with {} history messages",
        full_history.len()
    );

    // Build request to backend SSE endpoint
    let url = format!("https://localhost:38080/api/chat/{}/generate", session_id);
    let mut request = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .header("Accept", "text/event-stream")
        .json(&request_body);

    // Add DEK header if available (Quick Start mode)
    if let Some(dek_value) = dek {
        log::debug!("[stream_chat_response] Adding X-Scribe-Dek header");
        request = request.header("X-Scribe-Dek", dek_value);
    }

    // Send request and get response
    log::info!("[stream_chat_response] Sending request to {}", url);
    let response = request.send().await.map_err(|e| {
        let error_msg = format!("Failed to send request: {}", e);
        log::error!("[stream_chat_response] {}", error_msg);
        let _ = channel.send(ChatStreamEvent::Error {
            message: error_msg.clone(),
        });
        error_msg
    })?;

    // Check response status
    let status = response.status();
    log::info!("[stream_chat_response] Response status: {}", status);

    if !status.is_success() {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        let error_msg = format!("Request failed: {} - {}", status, error_text);
        log::error!("[stream_chat_response] {}", error_msg);
        let _ = channel.send(ChatStreamEvent::Error {
            message: error_msg.clone(),
        });
        return Err(error_msg);
    }

    // CRITICAL: Stream the response using eventsource-stream crate
    // This properly parses SSE events from the HTTP body stream
    use eventsource_stream::Eventsource;

    let mut stream = response.bytes_stream().eventsource();
    log::info!("[stream_chat_response] Starting SSE stream processing");

    let mut event_count = 0;
    while let Some(event_result) = stream.next().await {
        match event_result {
            Ok(sse_event) => {
                event_count += 1;
                log::debug!(
                    "[stream_chat_response] Received SSE event #{}: type={:?}",
                    event_count,
                    sse_event.event
                );

                // Convert SSE event to ChatStreamEvent and send through channel
                let channel_event = match sse_event.event.as_str() {
                    "content" => ChatStreamEvent::Content {
                        payload: sse_event.data,
                    },
                    "thinking" => {
                        log::info!(
                            "🔥 [stream_chat_response] RECEIVED 'thinking' SSE event - len: {}",
                            sse_event.data.len()
                        );
                        ChatStreamEvent::Thinking {
                            text: sse_event.data,
                        }
                    }
                    "error" => ChatStreamEvent::Error {
                        message: sse_event.data,
                    },
                    "token_usage" => {
                        // Parse JSON: { "prompt_tokens": 123, "completion_tokens": 456, "model_name": "..." }
                        match serde_json::from_str::<serde_json::Value>(&sse_event.data) {
                            Ok(token_data) => ChatStreamEvent::TokenUsage {
                                prompt_tokens: token_data["prompt_tokens"].as_i64().unwrap_or(0)
                                    as i32,
                                completion_tokens: token_data["completion_tokens"]
                                    .as_i64()
                                    .unwrap_or(0)
                                    as i32,
                                model_name: token_data["model_name"]
                                    .as_str()
                                    .unwrap_or("")
                                    .to_string(),
                            },
                            Err(e) => {
                                log::error!(
                                    "[stream_chat_response] Failed to parse token_usage: {}",
                                    e
                                );
                                continue; // Skip this event
                            }
                        }
                    }
                    "message_saved" => {
                        // Parse JSON: { "message_id": "...", "variant_count": 1, "current_variant_index": 0 }
                        log::debug!(
                            "[stream_chat_response] Received message_saved SSE data: {}",
                            &sse_event.data
                        );

                        match serde_json::from_str::<serde_json::Value>(&sse_event.data) {
                            Ok(msg_data) => {
                                log::debug!(
                                    "[stream_chat_response] Parsed message_saved JSON: {:?}",
                                    msg_data
                                );

                                // Extract and validate fields
                                let message_id = match msg_data
                                    .get("message_id")
                                    .and_then(|v| v.as_str())
                                {
                                    Some(id) if !id.is_empty() => id.to_string(),
                                    _ => {
                                        log::error!(
                                            "[stream_chat_response] message_saved missing or invalid 'message_id'. Full JSON: {}",
                                            &sse_event.data
                                        );
                                        continue; // Skip this event
                                    }
                                };

                                let variant_count = match msg_data
                                    .get("variant_count")
                                    .and_then(|v| v.as_i64())
                                {
                                    Some(count) => count as i32,
                                    None => {
                                        log::error!(
                                            "[stream_chat_response] message_saved missing or invalid 'variant_count'. Full JSON: {}",
                                            &sse_event.data
                                        );
                                        continue; // Skip this event
                                    }
                                };

                                let current_variant_index = match msg_data
                                    .get("current_variant_index")
                                    .and_then(|v| v.as_i64())
                                {
                                    Some(index) => index as i32,
                                    None => {
                                        log::error!(
                                            "[stream_chat_response] message_saved missing or invalid 'current_variant_index'. Full JSON: {}",
                                            &sse_event.data
                                        );
                                        continue; // Skip this event
                                    }
                                };

                                log::info!(
                                    "[stream_chat_response] Successfully parsed message_saved: id={}, variant_count={}, current_variant_index={}",
                                    message_id, variant_count, current_variant_index
                                );

                                ChatStreamEvent::MessageSaved {
                                    message_id,
                                    variant_count,
                                    current_variant_index,
                                }
                            }
                            Err(e) => {
                                log::error!(
                                    "[stream_chat_response] Failed to parse message_saved JSON: {}. Raw data: {}",
                                    e,
                                    &sse_event.data
                                );
                                continue; // Skip this event
                            }
                        }
                    }
                    "done" => {
                        log::info!("[stream_chat_response] Received 'done' event, ending stream");
                        ChatStreamEvent::Done
                    }
                    "game_state" => {
                        // Parse JSON game state
                        match serde_json::from_str::<serde_json::Value>(&sse_event.data) {
                            Ok(game_state) => {
                                log::info!("[stream_chat_response] Received game_state event");
                                ChatStreamEvent::GameStateUpdate { game_state }
                            }
                            Err(e) => {
                                log::error!(
                                    "[stream_chat_response] Failed to parse game_state: {}",
                                    e
                                );
                                continue; // Skip this event
                            }
                        }
                    }
                    _ => {
                        // Ignore unknown events
                        log::debug!(
                            "[stream_chat_response] Ignoring unknown SSE event type: {}",
                            sse_event.event
                        );
                        continue;
                    }
                };

                // 🔥 CRITICAL: About to send event through Tauri Channel
                tracing::debug!(
                    "🔥 [stream_chat_response] About to send event #{} through channel",
                    event_count
                );

                // Send event through channel
                if let Err(e) = channel.send(channel_event.clone()) {
                    log::error!(
                        "🔥 [stream_chat_response] FAILED to send event #{} through channel: {}",
                        event_count,
                        e
                    );
                    return Err(format!("Channel send failed: {}", e));
                }

                log::info!(
                    "🔥 [stream_chat_response] Event #{} sent successfully through channel",
                    event_count
                );

                // Check for done event to exit loop
                if sse_event.event == "done" {
                    break;
                }
            }
            Err(e) => {
                // Stream error occurred
                let error_msg = format!("SSE stream error: {}", e);
                log::error!("[stream_chat_response] {}", error_msg);
                let _ = channel.send(ChatStreamEvent::Error {
                    message: error_msg.clone(),
                });
                return Err(error_msg);
            }
        }
    }

    log::info!(
        "[stream_chat_response] Stream completed successfully ({} events processed)",
        event_count
    );
    Ok(())
}

/// Load access token from secure storage
/// Calls the existing load_tokens command and extracts access_token
async fn load_access_token(app: &AppHandle) -> Option<String> {
    // Call the existing load_tokens Tauri command
    // Note: We can't call Tauri commands directly from Rust, so we use the Store API directly
    use tauri_plugin_store::StoreExt;

    const TOKEN_STORE_FILE: &str = ".tokens.dat";
    const ACCESS_TOKEN_KEY: &str = "access_token";

    match app.store(TOKEN_STORE_FILE) {
        Ok(store) => store
            .get(ACCESS_TOKEN_KEY)
            .and_then(|v| v.as_str().map(String::from)),
        Err(e) => {
            log::error!("[load_access_token] Failed to access token store: {}", e);
            None
        }
    }
}

/// Load DEK (Data Encryption Key) from secure storage
/// Returns None if not in Quick Start mode
async fn load_dek(app: &AppHandle) -> Option<String> {
    use tauri_plugin_store::StoreExt;

    const TOKEN_STORE_FILE: &str = ".tokens.dat";
    const DEK_KEY: &str = "dek";

    match app.store(TOKEN_STORE_FILE) {
        Ok(store) => store
            .get(DEK_KEY)
            .and_then(|v| v.as_str().map(String::from)),
        Err(e) => {
            log::debug!("[load_dek] DEK not available: {}", e);
            None
        }
    }
}
