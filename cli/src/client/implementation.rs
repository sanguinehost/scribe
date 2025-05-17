// cli/src/client/implementation.rs

use async_trait::async_trait;
use futures_util::{Stream, StreamExt};
use reqwest::{multipart, Client as ReqwestClient, StatusCode, Url}; // Removed Response
use reqwest_eventsource::{Event, EventSource};
use scribe_backend::models::{
    auth::LoginPayload,
    users::User,
    // No need to import CharacterDataForClient from backend here, as we use ClientCharacterDataForClient
    chats::{Chat, ChatMessage, ApiChatMessage, ChatSettingsResponse, UpdateChatSettingsRequest, GenerateChatRequest},
};
use serde_json::{json, Value};
use std::{fs, path::Path, pin::Pin};
use tracing;
use uuid::Uuid;

use crate::error::CliError;

// Imports from sibling modules
use super::interface::HttpClient;
use super::types::{
    AuthUserResponse, // Used in login/register/me
    ClientCharacterDataForClient,
    HealthStatus,
    RegisterPayload, // Used in register method signature
    SerializableLoginPayload, // Internal helper for login
    SerializableRegisterPayload, // Internal helper for register
    StreamEvent,
    AdminUserListResponse,
    AdminUserDetailResponse,
    UpdateUserRoleRequest,
};
use super::util::{build_url, handle_response, handle_non_streaming_chat_response};


/// Wrapper around ReqwestClient implementing the HttpClient trait.
pub struct ReqwestClientWrapper {
    client: ReqwestClient,
    base_url: Url,
    last_recovery_key: std::sync::Mutex<Option<String>>,
}

impl ReqwestClientWrapper {
    pub fn new(client: ReqwestClient, base_url: Url) -> Self {
        Self { 
            client, 
            base_url,
            last_recovery_key: std::sync::Mutex::new(None),
        }
    }
}

#[async_trait]
impl HttpClient for ReqwestClientWrapper {
    async fn login(&self, credentials: &LoginPayload) -> Result<User, CliError> {
        let url = build_url(&self.base_url, "/api/auth/login")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, identifier = %credentials.identifier, "Attempting login via HttpClient");
        let response = self
            .client
            .post(url)
            .json(&SerializableLoginPayload::from(credentials))
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        
        // Get auth response and convert to User
        let auth_response = handle_response::<AuthUserResponse>(response)
            .await
            .map_err(|e| CliError::AuthFailed(format!("{}", e)))?;
        
        // Check if account is locked
        let user = User::from(auth_response);
        if user.account_status == Some("locked".to_string()) {
            return Err(CliError::AuthFailed("Your account is locked. Please contact an administrator.".to_string()));
        }
        
        // Return the user
        Ok(user)
    }

    async fn register(&self, credentials: &RegisterPayload) -> Result<User, CliError> {
        let url = build_url(&self.base_url, "/api/auth/register")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, username = %credentials.username, email = %credentials.email, "Attempting registration via HttpClient");
        let response = self
            .client
            .post(url)
            .json(&SerializableRegisterPayload::from(credentials))
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        
        // Get auth response and convert to User, just like in the login method
        let auth_response = handle_response::<AuthUserResponse>(response)
            .await
            .map_err(|e| CliError::RegistrationFailed(format!("{}", e)))?;
        
        // Store the recovery key in the client for later retrieval
        if let Some(recovery_key) = &auth_response.recovery_key {
            let mut guard = self.last_recovery_key.lock().unwrap();
            *guard = Some(recovery_key.clone());
        }
        
        // Convert to User for backwards compatibility
        Ok(User::from(auth_response))
    }
    
    fn get_last_recovery_key(&self) -> Option<String> {
        let guard = self.last_recovery_key.lock().unwrap();
        guard.clone()
    }
 
    async fn list_characters(&self) -> Result<Vec<ClientCharacterDataForClient>, CliError> {
        let url = build_url(&self.base_url, "/api/characters")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, "Listing characters via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn create_chat_session(&self, character_id: Uuid) -> Result<Chat, CliError> {
        let url = build_url(&self.base_url, "/api/chats")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %character_id, "Creating chat session via HttpClient");
        let payload = json!({ "character_id": character_id });
        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn upload_character(
        &self,
        name: &str,
        file_path: &str,
    ) -> Result<ClientCharacterDataForClient, CliError> {
        tracing::info!(target: "scribe_cli::client::implementation", %file_path, "Attempting to upload character via HttpClient from file");
 
        let file_bytes = fs::read(file_path).map_err(|e| {
            tracing::error!(target: "scribe_cli::client::implementation", error = ?e, %file_path, "Failed to read character card file");
            CliError::Io(e)
        })?;

        let file_name = Path::new(file_path)
            .file_name()
            .and_then(|os_str| os_str.to_str())
            .ok_or_else(|| CliError::InputError(format!("Invalid file path: {}", file_path)))?;

        let mime_type = if file_name.to_lowercase().ends_with(".png") {
            "image/png"
        } else {
            tracing::warn!(target: "scribe_cli::client::implementation", %file_name, "Uploading non-PNG file, assuming image/png MIME type");
            "image/png"
        };

        let file_part = multipart::Part::bytes(file_bytes)
            .file_name(file_name.to_string())
            .mime_str(mime_type)
            .map_err(|e| {
                CliError::Internal(format!("Failed to create multipart file part: {}", e))
            })?;

        let form = multipart::Form::new()
            .text("name", name.to_string())
            .part("character_card", file_part);

        let url = build_url(&self.base_url, "/api/characters/upload")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, "Sending character upload request via HttpClient");

        let response = self
            .client
            .post(url)
            .multipart(form)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn health_check(&self) -> Result<HealthStatus, CliError> {
        let url = build_url(&self.base_url, "/api/health")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, "Performing health check via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn logout(&self) -> Result<(), CliError> {
        let url = build_url(&self.base_url, "/api/auth/logout")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, "Attempting logout via HttpClient");
        let response = self
            .client
            .post(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            tracing::error!(target: "scribe_cli::client::implementation", %status, error_body = %error_text, "Logout API request failed");
            Err(CliError::ApiError {
                status,
                message: error_text,
            })
        }
    }

    async fn me(&self) -> Result<User, CliError> {
        let url = build_url(&self.base_url, "/api/auth/me")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, "Fetching current user info via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        
        // Get auth response and convert to User
        let auth_response = handle_response::<AuthUserResponse>(response).await?;
        
        // Convert to User for backwards compatibility
        Ok(User::from(auth_response))
    }
 
    async fn get_character(&self, character_id: Uuid) -> Result<ClientCharacterDataForClient, CliError> {
        let url = build_url(&self.base_url, &format!("/api/characters/fetch/{}", character_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %character_id, "Fetching character details via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn list_chat_sessions(&self) -> Result<Vec<Chat>, CliError> {
        let url = build_url(&self.base_url, "/api/chats")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, "Listing chat sessions via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn get_chat_messages(&self, session_id: Uuid) -> Result<Vec<ChatMessage>, CliError> {
        let url = build_url(
            &self.base_url,
            &format!("/api/chats/{}/messages", session_id),
        )?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %session_id, "Fetching chat messages via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    // This is the non-streaming version
    async fn send_message(
        &self,
        chat_id: Uuid,
        content: &str,
        model_name: Option<&str>,
    ) -> Result<ChatMessage, CliError> {
        // Build URL with query parameter for non-streaming
        let mut url = build_url(&self.base_url, &format!("/api/chats/{}/generate", chat_id))?;
        url.query_pairs_mut()
            .append_pair("request_thinking", "false");

        // Create a history with just the current user message in the format the backend expects
        let message_history = vec![ApiChatMessage {
            role: "user".to_string(),
            content: content.to_string(),
        }];

        // Use the updated GenerateChatRequest that includes the history field
        let request_body = GenerateChatRequest {
            history: message_history,
            model: model_name.map(|s| s.to_string()),
        };

        tracing::info!(target: "scribe_cli::client::implementation", %url, chat_id = %chat_id, model = ?model_name, "Sending non-streaming message via HttpClient");

        // Handle network errors or HTTP 429 errors directly
        let response = match self
            .client
            .post(url.clone()) // Clone URL here
            .header(reqwest::header::ACCEPT, "application/json") // Set Accept header to get JSON response
            .json(&request_body)
            .send()
            .await {
                Ok(resp) => {
                    // Check for HTTP 429 status code directly before processing response
                    if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                        tracing::warn!(target: "scribe_cli::client::implementation", "Received 429 Too Many Requests from backend API");
                        return Err(CliError::RateLimitExceeded);
                    }
                    resp
                },
                Err(e) => {
                    tracing::error!(target: "scribe_cli::client::implementation", error = ?e, "Network error sending message");
                    return Err(CliError::Network(e.to_string()));
                }
            };

        // Use the NEW handler function specifically for this response type
        handle_non_streaming_chat_response(response).await
    }

    // NEW: Implement stream_chat_response
    async fn stream_chat_response(
        &self,
        chat_id: Uuid,
        history: Vec<ApiChatMessage>, 
        request_thinking: bool,
        model_name: Option<&str>,  // Add model_name parameter
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent, CliError>> + Send>>, CliError> {
        // Build URL with query parameter for streaming
        let mut url = build_url(&self.base_url, &format!("/api/chats/{}/generate", chat_id))?;
        url.query_pairs_mut()
            .append_pair("request_thinking", &request_thinking.to_string());

        tracing::info!(target: "scribe_cli::client::implementation", %url, %chat_id, %request_thinking, "Initiating streaming chat response via HttpClient");

        // Payload now includes history using the backend's struct directly
        let payload = GenerateChatRequest { 
            history,
            model: model_name.map(|s| s.to_string())  // Use the model name provided or None
        };

        // Build the request manually to use with EventSource
        let request_builder = self.client.post(url.clone())
            .header(reqwest::header::ACCEPT, "text/event-stream") // Explicitly request SSE format
            .json(&payload); // Clone URL, create builder

        // Create the EventSource from the RequestBuilder
        let mut es = EventSource::new(request_builder)
            .map_err(|e| CliError::Internal(format!("Failed to create EventSource: {}", e)))?;

        // Use async_stream to create a Stream
        let stream = async_stream::stream! {
            while let Some(event) = es.next().await {
                match event {
                    Ok(Event::Open) => {
                        tracing::debug!(target: "scribe_cli::client::implementation", "SSE connection opened.");
                        // No need to yield anything for the Open event
                    }
                    Ok(Event::Message(message)) => {
                        tracing::trace!(target: "scribe_cli::client::implementation", event_type = %message.event, data = %message.data, "Received SSE message");

                        // Directly match the event type and construct the StreamEvent enum
                        let stream_event_result = match message.event.as_str() {
                            "thinking" => Ok(StreamEvent::Thinking(message.data)),
                            "content" => Ok(StreamEvent::Content(message.data)),
                            "reasoning_chunk" => Ok(StreamEvent::ReasoningChunk(message.data)), // NEWLY ADDED
                            "message" => {
                                #[derive(serde::Deserialize)] // Use serde directly
                                struct PartialText { text: String }
                                match serde_json::from_str::<PartialText>(&message.data) {
                                    Ok(partial) => {
                                        tracing::debug!(target: "scribe_cli::client::implementation", event_type = %message.event, data = %message.data, "Parsed partial message event");
                                        Ok(StreamEvent::PartialMessage(partial.text))
                                    }
                                    Err(e) => {
                                        tracing::warn!(target: "scribe_cli::client::implementation", event_type = %message.event, data = %message.data, error = %e, "Failed to parse data for 'message' SSE event, skipping");
                                        continue; // Skip this event, go to next es.next().await
                                    }
                                }
                            },
                            "done" => Ok(StreamEvent::Done),
                            "error" => {
                                // Handle potential errors sent via SSE 'error' event
                                tracing::error!(target: "scribe_cli::client::implementation", sse_error_data = %message.data, "Received error event from backend stream");
                                
                                // Check for rate limit errors in the error data
                                if message.data.contains("429") || 
                                   message.data.contains("Too Many Requests") || 
                                   message.data.contains("rate limit") {
                                    tracing::warn!(target: "scribe_cli::client::implementation", "SSE error event contains rate limit indication: {}", message.data);
                                    yield Err(CliError::RateLimitExceeded);
                                    es.close(); // Close the source on error
                                    break;
                                } else {
                                    // Propagate as a general backend error for other types of errors
                                    yield Err(CliError::Backend(format!("Stream error from server: {}", message.data)));
                                    es.close(); // Close the source on error
                                    break;
                                }
                            }
                            unknown_event => {
                                tracing::warn!(target: "scribe_cli::client::implementation", %unknown_event, data = %message.data, "Received unknown SSE event type");
                                // Decide how to handle unknown events: ignore or error?
                                // Let's ignore for now, but log a warning.
                                continue; // Skip to the next event
                            }
                        };

                        match stream_event_result {
                            Ok(StreamEvent::Done) => {
                                yield Ok(StreamEvent::Done);
                                es.close(); // Close the event source
                                break; // Stop processing
                            }
                            Ok(event) => {
                                yield Ok(event);
                            }
                            Err(cli_error) => { // This case is for when stream_event_result itself is an Err
                                yield Err(cli_error);
                                es.close();
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        // Handle different EventSource errors
                        match e {
                            reqwest_eventsource::Error::StreamEnded => {
                                tracing::debug!(target: "scribe_cli::client::implementation", "SSE stream ended by the server.");
                                // Don't yield an error, just break. The caller expects Done or an error.
                                // If Done wasn't received, it implies an unexpected closure.
                                // We could potentially yield a custom error here if needed.
                                break; // Exit the loop cleanly
                            }
                            reqwest_eventsource::Error::InvalidStatusCode(status, resp) => {
                                // Check for rate limit status code first
                                if status == StatusCode::TOO_MANY_REQUESTS {
                                    tracing::warn!(target: "scribe_cli::client::implementation", "SSE request failed with 429 Too Many Requests");
                                    yield Err(CliError::RateLimitExceeded);
                                    es.close();
                                    break;
                                }
                                
                                let body = resp.text().await.unwrap_or_else(|_| "Failed to read error body".to_string());
                                tracing::error!(target: "scribe_cli::client::implementation", %status, error_body = %body, "SSE request failed with status code");
                                yield Err(CliError::ApiError { status, message: body });
                                es.close();
                                break;
                            }
                            _ => {
                                tracing::error!(target: "scribe_cli::client::implementation", error = ?e, "SSE stream error");
                                // Check if the error message contains any indication of rate limiting
                                let error_str = format!("{}", e);
                                if error_str.contains("429") || error_str.contains("Too Many Requests") || error_str.contains("rate limit") {
                                    tracing::warn!(target: "scribe_cli::client::implementation", "SSE error appears to be a rate limit: {}", error_str);
                                    yield Err(CliError::RateLimitExceeded);
                                    es.close();
                                    break;
                                }
                                yield Err(CliError::Network(format!("SSE stream error: {}", e)));
                                es.close();
                                break;
                            }
                        };
                    }
                }
            }
            tracing::debug!(target: "scribe_cli::client::implementation", "SSE stream processing finished.");
        };

        Ok(Box::pin(stream))
    }

    // NEW: Implement update_chat_settings
    async fn update_chat_settings(&self, session_id: Uuid, payload: &UpdateChatSettingsRequest) -> Result<ChatSettingsResponse, CliError> {
        let url = build_url(&self.base_url, &format!("/api/chats/{}/settings", session_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %session_id, payload = ?payload, "Updating chat settings via HttpClient");

        let response = self.client.put(url).json(payload).send().await.map_err(CliError::Reqwest)?;
        handle_response(response).await
    }
    
    // ADMIN APIs
    async fn admin_list_users(&self) -> Result<Vec<AdminUserListResponse>, CliError> {
        let url = build_url(&self.base_url, "/api/admin/users")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, "Admin: Listing users via HttpClient");
        let response = self.client.get(url).send().await.map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn admin_get_user(&self, user_id: Uuid) -> Result<AdminUserDetailResponse, CliError> {
        let url = build_url(&self.base_url, &format!("/api/admin/users/{}", user_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %user_id, "Admin: Getting user details via HttpClient");
        let response = self.client.get(url).send().await.map_err(CliError::Reqwest)?;
        handle_response(response).await
    }
    
    async fn admin_get_user_by_username(&self, username: &str) -> Result<AdminUserDetailResponse, CliError> {
        // Try to get user by ID first if the input looks like a UUID
        if let Ok(user_id) = Uuid::parse_str(username) {
            return self.admin_get_user(user_id).await;
        }

        // Otherwise, let's find the user in the list and then use their ID
        let users = self.admin_list_users().await?;
        for user in users {
            if user.username == username {
                return self.admin_get_user(user.id).await;
            }
        }
        
        Err(CliError::InputError(format!("User with username '{}' not found", username)))
    }

    async fn admin_update_user_role(&self, user_id: Uuid, role: &str) -> Result<AdminUserDetailResponse, CliError> {
        let url = build_url(&self.base_url, &format!("/api/admin/users/{}/role", user_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %user_id, %role, "Admin: Updating user role via HttpClient");
        let payload = UpdateUserRoleRequest { role: role.to_string() };
        let response = self.client.put(url).json(&payload).send().await.map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn admin_lock_user(&self, user_id: Uuid) -> Result<(), CliError> {
        let url = build_url(&self.base_url, &format!("/api/admin/users/{}/lock", user_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %user_id, "Admin: Locking user via HttpClient");
        let response = self.client.put(url).send().await.map_err(CliError::Reqwest)?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            handle_response::<Value>(response).await?; // Attempt to parse error body
            Err(CliError::ApiError{status, message: "Failed to lock user".to_string()}) // Fallback
        }
    }

    async fn admin_unlock_user(&self, user_id: Uuid) -> Result<(), CliError> {
        let url = build_url(&self.base_url, &format!("/api/admin/users/{}/unlock", user_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %user_id, "Admin: Unlocking user via HttpClient");
        let response = self.client.put(url).send().await.map_err(CliError::Reqwest)?;
         if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            handle_response::<Value>(response).await?; // Attempt to parse error body
            Err(CliError::ApiError{status, message: "Failed to unlock user".to_string()}) // Fallback
        }
    }

    // Keep generate_response for mock compatibility if needed
    #[allow(dead_code)]
    async fn generate_response(
        &self,
        chat_id: Uuid,
        message_content: &str,
        model_name: Option<String>,
    ) -> Result<ChatMessage, CliError> {
        // This implementation might need adjustment if used, but for now, it mirrors send_message
        self.send_message(chat_id, message_content, model_name.as_deref())
            .await
    }
}