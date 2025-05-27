// cli/src/client/implementation.rs

use async_trait::async_trait;
use futures_util::{Stream, StreamExt};
use reqwest::{Client as ReqwestClient, StatusCode, Url, multipart}; // Removed Response
use reqwest_eventsource::{Event, EventSource};
use scribe_backend::models::{
    auth::LoginPayload,
    // No need to import CharacterDataForClient from backend here, as we use ClientCharacterDataForClient
    chats::{
        ApiChatMessage, Chat, ChatForClient, ChatMessage, ChatSettingsResponse, GenerateChatRequest,
        UpdateChatSettingsRequest,
    },
    lorebook_dtos::{
        AssociateLorebookToChatPayload, ChatSessionBasicInfo,
        ChatSessionLorebookAssociationResponse, CreateLorebookEntryPayload,
        CreateLorebookPayload, LorebookEntryResponse, LorebookEntrySummaryResponse,
        LorebookResponse, UpdateLorebookEntryPayload, UpdateLorebookPayload,
    },
    users::User,
};
use serde_json::Value;
use std::{fs, path::Path, pin::Pin};
use tracing;
use uuid::Uuid;

use crate::error::CliError;

// Imports from sibling modules
use super::interface::HttpClient;
use super::types::{
    // User persona types are now directly available under super::types
    CreateUserPersonaDto, UpdateUserPersonaDto, UserPersonaDataForClient,
    AdminUserDetailResponse,
    AdminUserListResponse,
    AuthUserResponse, // Used in login/register/me
    ClientCharacterDataForClient,
    ClientChatMessageResponse,
    HealthStatus,
    RegisterPayload,             // Used in register method signature
    SerializableLoginPayload,    // Internal helper for login
    SerializableRegisterPayload, // Internal helper for register
    StreamEvent,
    UpdateUserRoleRequest,
    // New DTOs
    CharacterCreateDto,
    CharacterUpdateDto,
    ChatSessionDetails,
    CharacterOverrideRequest, // For the payload of set_chat_character_override
    OverrideSuccessResponse,
};
use super::util::{build_url, handle_non_streaming_chat_response, handle_response};

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
            return Err(CliError::AuthFailed(
                "Your account is locked. Please contact an administrator.".to_string(),
            ));
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

    async fn create_chat_session(&self, character_id: Uuid, active_custom_persona_id: Option<Uuid>) -> Result<Chat, CliError> {
        let url = build_url(&self.base_url, "/api/chat/create_session")?; // Corrected path to match backend routes/chat.rs
        tracing::info!(target: "scribe_cli::client::implementation", %url, %character_id, ?active_custom_persona_id, "Creating chat session via HttpClient");
        // Use the backend's CreateChatSessionPayload struct
        let payload = scribe_backend::models::chats::CreateChatSessionPayload {
            character_id,
            active_custom_persona_id,
        };
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

    async fn get_character(
        &self,
        character_id: Uuid,
    ) -> Result<ClientCharacterDataForClient, CliError> {
        let url = build_url(
            &self.base_url,
            &format!("/api/characters/fetch/{}", character_id),
        )?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %character_id, "Fetching character details via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn list_chat_sessions(&self) -> Result<Vec<ChatForClient>, CliError> {
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

    async fn get_chat_messages(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<ClientChatMessageResponse>, CliError> {
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

    async fn delete_chat(&self, chat_id: Uuid) -> Result<(), CliError> {
        // Following the same pattern as characters for GET and DELETE:
        //   /characters/fetch/:id and /characters/remove/:id
        // Note: The route in the backend uses :id notation, but we need to use actual values here
        let url = build_url(&self.base_url, &format!("/api/chats/remove/{}", chat_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %chat_id, "Deleting chat session via HttpClient");
        let response = self
            .client
            .delete(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            tracing::error!(target: "scribe_cli::client::implementation", %status, error_body = %error_text, "Delete chat operation failed");
            Err(CliError::ApiError {
                status,
                message: error_text,
            })
        }
    }

    // This is the non-streaming version
    async fn send_message(
        &self,
        chat_id: Uuid,
        content: &str,
        model_name: Option<&str>,
    ) -> Result<ChatMessage, CliError> {
        // Build URL with query parameter for non-streaming
        let mut url = build_url(&self.base_url, &format!("/api/chat/{}/generate", chat_id))?;
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
            query_text_for_rag: None,
        };

        tracing::info!(target: "scribe_cli::client::implementation", %url, chat_id = %chat_id, model = ?model_name, "Sending non-streaming message via HttpClient");

        // Handle network errors or HTTP 429 errors directly
        let response = match self
            .client
            .post(url.clone()) // Clone URL here
            .header(reqwest::header::ACCEPT, "application/json") // Set Accept header to get JSON response
            .json(&request_body)
            .send()
            .await
        {
            Ok(resp) => {
                // Check for HTTP 429 status code directly before processing response
                if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                    tracing::warn!(target: "scribe_cli::client::implementation", "Received 429 Too Many Requests from backend API");
                    return Err(CliError::RateLimitExceeded);
                }
                resp
            }
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
        model_name: Option<&str>, // Add model_name parameter
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent, CliError>> + Send>>, CliError> {
        // Build URL with query parameter for streaming
        let mut url = build_url(&self.base_url, &format!("/api/chat/{}/generate", chat_id))?;
        url.query_pairs_mut()
            .append_pair("request_thinking", &request_thinking.to_string());

        tracing::info!(target: "scribe_cli::client::implementation", %url, %chat_id, %request_thinking, "Initiating streaming chat response via HttpClient");

        // Payload now includes history using the backend's struct directly
        let payload = GenerateChatRequest {
            history,
            model: model_name.map(|s| s.to_string()), // Use the model name provided or None
            query_text_for_rag: None,
        };

        // Build the request manually to use with EventSource
        let request_builder = self
            .client
            .post(url.clone())
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
    async fn update_chat_settings(
        &self,
        session_id: Uuid,
        payload: &UpdateChatSettingsRequest,
    ) -> Result<ChatSettingsResponse, CliError> {
        let url = build_url(
            &self.base_url,
            &format!("/api/chat/{}/settings", session_id),
        )?;
        tracing::info!(
            target: "scribe_cli::client::implementation",
            %url,
            %session_id,
            model_name = %payload.model_name.as_deref().unwrap_or("Not Set"),
            "Updating chat settings via HttpClient"
        );
        let response = self
            .client
            .put(url)
            .json(payload)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    // ADMIN APIs
    async fn admin_list_users(&self) -> Result<Vec<AdminUserListResponse>, CliError> {
        let url = build_url(&self.base_url, "/api/admin/users")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, "Admin: Listing users via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn admin_get_user(&self, user_id: Uuid) -> Result<AdminUserDetailResponse, CliError> {
        let url = build_url(&self.base_url, &format!("/api/admin/users/{}", user_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %user_id, "Admin: Getting user details via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn admin_get_user_by_username(
        &self,
        username: &str,
    ) -> Result<AdminUserDetailResponse, CliError> {
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

        Err(CliError::InputError(format!(
            "User with username '{}' not found",
            username
        )))
    }

    async fn admin_update_user_role(
        &self,
        user_id: Uuid,
        role: &str,
    ) -> Result<AdminUserDetailResponse, CliError> {
        let url = build_url(
            &self.base_url,
            &format!("/api/admin/users/{}/role", user_id),
        )?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %user_id, %role, "Admin: Updating user role via HttpClient");
        let payload = UpdateUserRoleRequest {
            role: role.to_string(),
        };
        let response = self
            .client
            .put(url)
            .json(&payload)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn admin_lock_user(&self, user_id: Uuid) -> Result<(), CliError> {
        let url = build_url(
            &self.base_url,
            &format!("/api/admin/users/{}/lock", user_id),
        )?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %user_id, "Admin: Locking user via HttpClient");
        let response = self
            .client
            .put(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            handle_response::<Value>(response).await?; // Attempt to parse error body
            Err(CliError::ApiError {
                status,
                message: "Failed to lock user".to_string(),
            }) // Fallback
        }
    }

    async fn admin_unlock_user(&self, user_id: Uuid) -> Result<(), CliError> {
        let url = build_url(
            &self.base_url,
            &format!("/api/admin/users/{}/unlock", user_id),
        )?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %user_id, "Admin: Unlocking user via HttpClient");
        let response = self
            .client
            .put(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            handle_response::<Value>(response).await?; // Attempt to parse error body
            Err(CliError::ApiError {
                status,
                message: "Failed to unlock user".to_string(),
            }) // Fallback
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

    async fn create_character(
        &self,
        character_data: CharacterCreateDto,
    ) -> Result<ClientCharacterDataForClient, CliError> {
        let url = build_url(&self.base_url, "/api/characters")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, "Creating character via HttpClient");
        let response = self
            .client
            .post(url)
            .json(&character_data)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn update_character(
        &self,
        id: Uuid,
        character_update_data: CharacterUpdateDto,
    ) -> Result<ClientCharacterDataForClient, CliError> {
        let url = build_url(&self.base_url, &format!("/api/characters/{}", id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %id, "Updating character via HttpClient");
        let response = self
            .client
            .put(url) // Assuming PUT for full update, or PATCH for partial
            .json(&character_update_data)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn get_chat_session(&self, session_id: Uuid) -> Result<ChatSessionDetails, CliError> {
        let url = build_url(&self.base_url, &format!("/api/chats/fetch/{}", session_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %session_id, "Fetching chat session details via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn set_chat_character_override(
        &self,
        session_id: Uuid,
        field_name: String,
        value: String,
    ) -> Result<OverrideSuccessResponse, CliError> {
        let url = build_url(
            &self.base_url,
            &format!("/api/chats/{}/character/overrides", session_id),
        )?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %session_id, %field_name, "Setting chat character override via HttpClient");
        let payload = CharacterOverrideRequest { field_name, value };
        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn get_effective_character_for_chat(
        &self,
        character_id: Uuid,
        session_id: Uuid,
    ) -> Result<ClientCharacterDataForClient, CliError> {
        // The plan suggests: GET /api/characters/fetch/:original_character_id?session_id=<session_id>
        // This implies the character_id passed here is the original_character_id.
        let mut url = build_url(
            &self.base_url,
            &format!("/api/characters/fetch/{}", character_id),
        )?;
        url.query_pairs_mut()
            .append_pair("session_id", &session_id.to_string());

        tracing::info!(target: "scribe_cli::client::implementation", %url, %character_id, %session_id, "Fetching effective character for chat via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    // User Persona Methods
    async fn create_user_persona(
        &self,
        persona_data: CreateUserPersonaDto,
    ) -> Result<UserPersonaDataForClient, CliError> {
        let url = build_url(&self.base_url, "/api/personas")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, "Creating user persona via HttpClient");
        let response = self
            .client
            .post(url)
            .json(&persona_data)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn list_user_personas(&self) -> Result<Vec<UserPersonaDataForClient>, CliError> {
        let url = build_url(&self.base_url, "/api/personas")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, "Listing user personas via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn get_user_persona(&self, persona_id: Uuid) -> Result<UserPersonaDataForClient, CliError> {
        let url = build_url(&self.base_url, &format!("/api/personas/{}", persona_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %persona_id, "Fetching user persona via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn update_user_persona(
        &self,
        persona_id: Uuid,
        persona_data: UpdateUserPersonaDto,
    ) -> Result<UserPersonaDataForClient, CliError> {
        let url = build_url(&self.base_url, &format!("/api/personas/{}", persona_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %persona_id, "Updating user persona via HttpClient");
        let response = self
            .client
            .put(url)
            .json(&persona_data)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn delete_user_persona(&self, persona_id: Uuid) -> Result<(), CliError> {
        let url = build_url(&self.base_url, &format!("/api/personas/{}", persona_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %persona_id, "Deleting user persona via HttpClient");
        let response = self
            .client
            .delete(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            tracing::error!(target: "scribe_cli::client::implementation", %status, error_body = %error_text, "Delete user persona operation failed");
            Err(CliError::ApiError {
                status,
                message: error_text,
            })
        }
    }

    async fn set_default_persona(&self, persona_id: Uuid) -> Result<User, CliError> {
        let url = build_url(&self.base_url, &format!("/api/user-settings/set_default_persona/{}", persona_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %persona_id, "Setting default persona via HttpClient");
        let response = self
            .client
            .put(url)
            // No JSON body is sent for this PUT request as persona_id is in the path
            .send()
            .await
            .map_err(CliError::Reqwest)?;

        // The backend returns DefaultPersonaResponse, which is similar to AuthUserResponse.
        // We can reuse AuthUserResponse for parsing if the fields align, or create a new one.
        // For now, assuming AuthUserResponse can be used or adapted.
        let auth_response = handle_response::<AuthUserResponse>(response)
            .await
            .map_err(|e| CliError::OperationFailed(format!("Set default persona failed: {}", e)))?;
        
        Ok(User::from(auth_response))
    }

    async fn clear_default_persona(&self) -> Result<(), CliError> {
        let url = build_url(&self.base_url, "/api/user-settings/clear_default_persona")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, "Clearing default persona via HttpClient");
        let response = self
            .client
            .delete(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Failed to read error body".to_string());
            tracing::error!(target: "scribe_cli::client::implementation", %status, error_body = %error_text, "Clear default persona operation failed");
            Err(CliError::ApiError {
                status,
                message: error_text,
            })
        }
    }

    // Lorebooks
    async fn create_lorebook(&self, payload: &CreateLorebookPayload) -> Result<LorebookResponse, CliError> {
        let url = build_url(&self.base_url, "/api/lorebooks")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, "Creating lorebook via HttpClient");
        let response = self
            .client
            .post(url)
            .json(payload)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn list_lorebooks(&self) -> Result<Vec<LorebookResponse>, CliError> {
        let url = build_url(&self.base_url, "/api/lorebooks")?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, "Listing lorebooks via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn get_lorebook(&self, lorebook_id: Uuid) -> Result<LorebookResponse, CliError> {
        let url = build_url(&self.base_url, &format!("/api/lorebooks/{}", lorebook_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %lorebook_id, "Fetching lorebook via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn update_lorebook(&self, lorebook_id: Uuid, payload: &UpdateLorebookPayload) -> Result<LorebookResponse, CliError> {
        let url = build_url(&self.base_url, &format!("/api/lorebooks/{}", lorebook_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %lorebook_id, "Updating lorebook via HttpClient");
        let response = self
            .client
            .put(url)
            .json(payload)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn delete_lorebook(&self, lorebook_id: Uuid) -> Result<(), CliError> {
        let url = build_url(&self.base_url, &format!("/api/lorebooks/{}", lorebook_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %lorebook_id, "Deleting lorebook via HttpClient");
        let response = self
            .client
            .delete(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Failed to read error body".to_string());
            Err(CliError::ApiError { status, message: error_text })
        }
    }

    // Lorebook Entries
    async fn create_lorebook_entry(&self, lorebook_id: Uuid, payload: &CreateLorebookEntryPayload) -> Result<LorebookEntryResponse, CliError> {
        let url = build_url(&self.base_url, &format!("/api/lorebooks/{}/entries", lorebook_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %lorebook_id, "Creating lorebook entry via HttpClient");
        let response = self
            .client
            .post(url)
            .json(payload)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn list_lorebook_entries(&self, lorebook_id: Uuid) -> Result<Vec<LorebookEntrySummaryResponse>, CliError> {
        let url = build_url(&self.base_url, &format!("/api/lorebooks/{}/entries", lorebook_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %lorebook_id, "Listing lorebook entries via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn get_lorebook_entry(&self, lorebook_id: Uuid, entry_id: Uuid) -> Result<LorebookEntryResponse, CliError> {
        let url = build_url(&self.base_url, &format!("/api/lorebooks/{}/entries/{}", lorebook_id, entry_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %lorebook_id, %entry_id, "Fetching lorebook entry via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn update_lorebook_entry(&self, lorebook_id: Uuid, entry_id: Uuid, payload: &UpdateLorebookEntryPayload) -> Result<LorebookEntryResponse, CliError> {
        let url = build_url(&self.base_url, &format!("/api/lorebooks/{}/entries/{}", lorebook_id, entry_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %lorebook_id, %entry_id, "Updating lorebook entry via HttpClient");
        let response = self
            .client
            .put(url)
            .json(payload)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn delete_lorebook_entry(&self, lorebook_id: Uuid, entry_id: Uuid) -> Result<(), CliError> {
        let url = build_url(&self.base_url, &format!("/api/lorebooks/{}/entries/{}", lorebook_id, entry_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %lorebook_id, %entry_id, "Deleting lorebook entry via HttpClient");
        let response = self
            .client
            .delete(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Failed to read error body".to_string());
            Err(CliError::ApiError { status, message: error_text })
        }
    }

    // Chat Session Lorebook Associations
    async fn associate_lorebook_to_chat(&self, chat_session_id: Uuid, payload: &AssociateLorebookToChatPayload) -> Result<ChatSessionLorebookAssociationResponse, CliError> {
        let url = build_url(&self.base_url, &format!("/api/chats/{}/lorebooks", chat_session_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %chat_session_id, lorebook_id = %payload.lorebook_id, "Associating lorebook to chat session via HttpClient");
        let response = self
            .client
            .post(url)
            .json(payload)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn list_chat_lorebook_associations(&self, chat_session_id: Uuid) -> Result<Vec<ChatSessionLorebookAssociationResponse>, CliError> {
        let url = build_url(&self.base_url, &format!("/api/chats/{}/lorebooks", chat_session_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %chat_session_id, "Listing chat lorebook associations via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn disassociate_lorebook_from_chat(&self, chat_session_id: Uuid, lorebook_id: Uuid) -> Result<(), CliError> {
        let url = build_url(&self.base_url, &format!("/api/chats/{}/lorebooks/{}", chat_session_id, lorebook_id))?;
        tracing::info!(target: "scribe_cli::client::implementation", %url, %chat_session_id, %lorebook_id, "Disassociating lorebook from chat session via HttpClient");
        let response = self
            .client
            .delete(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Failed to read error body".to_string());
            Err(CliError::ApiError { status, message: error_text })
        }
    }

    async fn list_associated_chat_sessions_for_lorebook(
        &self,
        lorebook_id: Uuid,
    ) -> Result<Vec<ChatSessionBasicInfo>, CliError> {
        let url = build_url(&self.base_url, &format!("/api/lorebooks/{}/fetch/associated_chats", lorebook_id))?; // Updated path
        tracing::info!(target: "scribe_cli::client::implementation", %url, %lorebook_id, "Listing associated chat sessions for lorebook via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }
}
