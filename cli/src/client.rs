// cli/src/client.rs

use crate::error::CliError;
use async_trait::async_trait;
use reqwest::multipart;
use reqwest::{Client as ReqwestClient, Response, Url, StatusCode};
use scribe_backend::models::auth::Credentials;
use scribe_backend::models::characters::CharacterMetadata;
// Updated imports for chats models
use scribe_backend::models::chats::{ChatMessage, ChatSession, GenerateResponsePayload};
use scribe_backend::models::users::User;
use serde::de::DeserializeOwned;
use serde::Deserialize; // Added Deserialize
use serde_json::json;
use std::fs;
use std::path::Path;
use uuid::Uuid;
use futures_util::{Stream, StreamExt}; // Removed StreamExt, TryStreamExt // Add StreamExt back
use reqwest_eventsource::{Event, EventSource}; // Added Event, EventSource
use std::pin::Pin; // Added Pin

// Define the expected response structure from the /health endpoint (matching backend)
#[derive(serde::Deserialize, Debug, Clone)]
pub struct HealthStatus {
    pub status: String,
}

// Helper to join path to base URL
pub fn build_url(base: &Url, path: &str) -> Result<Url, CliError> {
    base.join(path).map_err(CliError::UrlParse)
}

// Helper to handle API responses
pub async fn handle_response<T: DeserializeOwned>(response: Response) -> Result<T, CliError> {
    let status = response.status();
    if status.is_success() {
        response.json::<T>().await.map_err(CliError::Reqwest)
    } else {
        if status == StatusCode::TOO_MANY_REQUESTS {
             tracing::warn!("Received 429 Too Many Requests from backend");
             return Err(CliError::RateLimitExceeded);
        }
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Failed to read error body".to_string());
        tracing::error!(%status, error_body = %error_text, "API request failed");
        Err(CliError::ApiError {
            status,
            message: error_text,
        })
    }
}

// NEW: Define the StreamEvent enum for SSE events
#[derive(Debug, Deserialize, Clone)] // Added Deserialize and Clone
#[serde(tag = "event", content = "data")] // Specify how to deserialize based on SSE event name
#[serde(rename_all = "snake_case")] // Match backend event names (e.g., event: thinking)
pub enum StreamEvent {
    Thinking(String), // Corresponds to event: thinking, data: "step description"
    Content(String),  // Corresponds to event: content, data: "text chunk"
    Done,             // Corresponds to event: done (no data expected)
}


/// Trait for abstracting HTTP client interactions to allow mocking in tests.
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn login(&self, credentials: &Credentials) -> Result<User, CliError>;
    async fn register(&self, credentials: &Credentials) -> Result<User, CliError>;
    async fn list_characters(&self) -> Result<Vec<CharacterMetadata>, CliError>;
    async fn create_chat_session(&self, character_id: Uuid) -> Result<ChatSession, CliError>;
    async fn upload_character(&self, name: &str, file_path: &str) -> Result<CharacterMetadata, CliError>;
    async fn health_check(&self) -> Result<HealthStatus, CliError>;
    async fn logout(&self) -> Result<(), CliError>;
    async fn me(&self) -> Result<User, CliError>;
    async fn get_character(&self, character_id: Uuid) -> Result<CharacterMetadata, CliError>;
    async fn list_chat_sessions(&self) -> Result<Vec<ChatSession>, CliError>;
    async fn get_chat_messages(&self, session_id: Uuid) -> Result<Vec<ChatMessage>, CliError>;
    async fn send_message(
        &self,
        chat_id: Uuid,
        content: &str,
        model_name: Option<&str>,
    ) -> Result<ChatMessage, CliError>;

    // NEW: Add stream_chat_response signature
    async fn stream_chat_response(
        &self,
        chat_id: Uuid,
        message_content: &str,
        request_thinking: bool,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent, CliError>> + Send>>, CliError>;

    // Keep generate_response for mock compatibility if needed, but mark unused
    #[allow(dead_code)]
    async fn generate_response(&self, chat_id: Uuid, message_content: &str, model_name: Option<String>) -> Result<ChatMessage, CliError>;
}

/// Wrapper around ReqwestClient implementing the HttpClient trait.
pub struct ReqwestClientWrapper {
    client: ReqwestClient,
    base_url: Url,
}

impl ReqwestClientWrapper {
    pub fn new(client: ReqwestClient, base_url: Url) -> Self {
        Self { client, base_url }
    }
}

#[async_trait]
impl HttpClient for ReqwestClientWrapper {
    async fn login(&self, credentials: &Credentials) -> Result<User, CliError> {
        let url = build_url(&self.base_url, "/api/auth/login")?;
        tracing::info!(%url, username = %credentials.username, "Attempting login via HttpClient");
        let response = self.client
            .post(url)
            .json(credentials)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response::<User>(response).await
             .map_err(|e| CliError::AuthFailed(format!("{}", e)))
    }

    async fn register(&self, credentials: &Credentials) -> Result<User, CliError> {
        let url = build_url(&self.base_url, "/api/auth/register")?;
        tracing::info!(%url, username = %credentials.username, "Attempting registration via HttpClient");
        let response = self.client
            .post(url)
            .json(credentials)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response::<User>(response).await
             .map_err(|e| CliError::RegistrationFailed(format!("{}", e)))
    }

    async fn list_characters(&self) -> Result<Vec<CharacterMetadata>, CliError> {
        let url = build_url(&self.base_url, "/api/characters")?;
        tracing::info!(%url, "Listing characters via HttpClient");
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn create_chat_session(&self, character_id: Uuid) -> Result<ChatSession, CliError> {
        let url = build_url(&self.base_url, "/api/chats")?;
        tracing::info!(%url, %character_id, "Creating chat session via HttpClient");
        let payload = json!({ "character_id": character_id });
        let response = self.client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }


    async fn upload_character(&self, name: &str, file_path: &str) -> Result<CharacterMetadata, CliError> {
        tracing::info!(character_name = name, %file_path, "Attempting to upload character via HttpClient");

        let file_bytes = fs::read(file_path)
            .map_err(|e| {
                tracing::error!(error = ?e, %file_path, "Failed to read character card file");
                CliError::Io(e)
            })?;

        let file_name = Path::new(file_path)
            .file_name()
            .and_then(|os_str| os_str.to_str())
            .ok_or_else(|| CliError::InputError(format!("Invalid file path: {}", file_path)))?;

        let mime_type = if file_name.to_lowercase().ends_with(".png") {
            "image/png"
        } else {
             tracing::warn!(%file_name, "Uploading non-PNG file, assuming image/png MIME type");
            "image/png"
        };

        let file_part = multipart::Part::bytes(file_bytes)
            .file_name(file_name.to_string())
            .mime_str(mime_type)
            .map_err(|e| CliError::Internal(format!("Failed to create multipart file part: {}", e)))?;

        let form = multipart::Form::new()
            .text("name", name.to_string())
            .part("character_card", file_part);

        let url = build_url(&self.base_url, "/api/characters/upload")?;
        tracing::info!(%url, "Sending character upload request via HttpClient");

        let response = self.client
            .post(url)
            .multipart(form)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn health_check(&self) -> Result<HealthStatus, CliError> {
        let url = build_url(&self.base_url, "/api/health")?;
        tracing::info!(%url, "Performing health check via HttpClient");
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn logout(&self) -> Result<(), CliError> {
        let url = build_url(&self.base_url, "/api/auth/logout")?;
        tracing::info!(%url, "Attempting logout via HttpClient");
        let response = self.client
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
            tracing::error!(%status, error_body = %error_text, "Logout API request failed");
            Err(CliError::ApiError {
                status,
                message: error_text,
            })
        }
    }

    async fn me(&self) -> Result<User, CliError> {
        let url = build_url(&self.base_url, "/api/auth/me")?;
        tracing::info!(%url, "Fetching current user info via HttpClient");
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn get_character(&self, character_id: Uuid) -> Result<CharacterMetadata, CliError> {
        let url = build_url(&self.base_url, &format!("/api/characters/{}", character_id))?;
        tracing::info!(%url, %character_id, "Fetching character details via HttpClient");
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn list_chat_sessions(&self) -> Result<Vec<ChatSession>, CliError> {
        let url = build_url(&self.base_url, "/api/chats")?;
        tracing::info!(%url, "Listing chat sessions via HttpClient");
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn get_chat_messages(&self, session_id: Uuid) -> Result<Vec<ChatMessage>, CliError> {
        let url = build_url(&self.base_url, &format!("/api/chats/{}/messages", session_id))?;
        tracing::info!(%url, %session_id, "Fetching chat messages via HttpClient");
        let response = self.client
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
        url.query_pairs_mut().append_pair("request_thinking", "false");

        // Use the backend model struct directly (without request_thinking)
        let request_body = GenerateResponsePayload {
            content: content.to_string(),
            model: model_name.map(|s| s.to_string()),
        };

        tracing::info!(%url, chat_id = %chat_id, model = ?model_name, "Sending non-streaming message via HttpClient");

        let response = self.client.post(url.clone()) // Clone URL here
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                 tracing::error!(error = ?e, "Network error sending message");
                 CliError::Network(e.to_string())
            })?;

        match response.status() {
            StatusCode::OK => {
                #[derive(serde::Deserialize)]
                struct GenerateResponseBody { ai_message: ChatMessage }
                let response_body: GenerateResponseBody = handle_response(response).await?;
                 tracing::info!(chat_id = %chat_id, message_id = %response_body.ai_message.id, "Message sent successfully (non-streaming)");
                Ok(response_body.ai_message)
            },
            StatusCode::TOO_MANY_REQUESTS => {
                tracing::warn!("Received 429 Too Many Requests from backend");
                Err(CliError::RateLimitExceeded)
            },
            status => {
                let error_text = response.text().await.unwrap_or_else(|_| "Failed to read error body".to_string());
                tracing::error!(%status, error = %error_text, "Failed to send message");
                Err(CliError::Backend(format!("{} - {}", status, error_text)))
            }
        }
    }

    // NEW: Implement stream_chat_response
    async fn stream_chat_response(
        &self,
        chat_id: Uuid,
        message_content: &str,
        request_thinking: bool,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent, CliError>> + Send>>, CliError> {
        // Build URL with query parameter for streaming
        let mut url = build_url(&self.base_url, &format!("/api/chats/{}/generate", chat_id))?;
        url.query_pairs_mut().append_pair("request_thinking", &request_thinking.to_string());

        tracing::info!(%url, %chat_id, %request_thinking, "Initiating streaming chat response via HttpClient");

        // Payload without request_thinking
        let payload = GenerateResponsePayload {
            content: message_content.to_string(),
            model: None, // Model selection isn't part of this specific test endpoint for now
        };

        // Build the request manually to use with EventSource
        let request_builder = self.client.post(url.clone()).json(&payload); // Clone URL, create builder

        // Create the EventSource from the RequestBuilder
        let mut es = EventSource::new(request_builder).map_err(|e| CliError::Internal(format!("Failed to create EventSource: {}", e)))?;

        // Use async_stream to create a Stream
        let stream = async_stream::stream! {
            while let Some(event) = es.next().await {
                match event {
                    Ok(Event::Open) => {
                        tracing::debug!("SSE connection opened.");
                        // No need to yield anything for the Open event
                    }
                    Ok(Event::Message(message)) => {
                        tracing::trace!(event_type = %message.event, data = %message.data, "Received SSE message");

                        // Directly match the event type and construct the StreamEvent enum
                        let stream_event_result = match message.event.as_str() {
                            "thinking" => Ok(StreamEvent::Thinking(message.data)),
                            "content" => Ok(StreamEvent::Content(message.data)),
                            "done" => Ok(StreamEvent::Done),
                            "error" => {
                                // Handle potential errors sent via SSE 'error' event
                                tracing::error!(sse_error_data = %message.data, "Received error event from backend stream");
                                // Propagate as a general backend error, or create a specific variant if needed
                                Err(CliError::Backend(format!("Stream error from server: {}", message.data)))
                            }
                            unknown_event => {
                                tracing::warn!(%unknown_event, data = %message.data, "Received unknown SSE event type");
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
                            Err(cli_error) => {
                                yield Err(cli_error);
                                es.close();
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        // Handle different EventSource errors
                        let cli_error = match e {
                            reqwest_eventsource::Error::StreamEnded => {
                                tracing::debug!("SSE stream ended by the server.");
                                // Don't yield an error, just break. The caller expects Done or an error.
                                // If Done wasn't received, it implies an unexpected closure.
                                // We could potentially yield a custom error here if needed.
                                break; // Exit the loop cleanly
                            }
                            reqwest_eventsource::Error::InvalidStatusCode(status, resp) => {
                                let body = resp.text().await.unwrap_or_else(|_| "Failed to read error body".to_string());
                                tracing::error!(%status, error_body = %body, "SSE request failed with status code");
                                CliError::ApiError { status, message: body }
                            }
                            _ => {
                                tracing::error!(error = ?e, "SSE stream error");
                                CliError::Network(format!("SSE stream error: {}", e))
                            }
                        };
                        yield Err(cli_error);
                        es.close(); // Close the source on error
                        break; // Stop processing on error
                    }
                }
            }
            tracing::debug!("SSE stream processing finished.");
        };

        Ok(Box::pin(stream))
    }

    // Keep generate_response for mock compatibility if needed
    #[allow(dead_code)]
    async fn generate_response(&self, chat_id: Uuid, message_content: &str, model_name: Option<String>) -> Result<ChatMessage, CliError> {
        // This implementation might need adjustment if used, but for now, it mirrors send_message
        self.send_message(chat_id, message_content, model_name.as_deref()).await
    }
}


// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[test]
    fn test_build_url_success() {
        let base = Url::parse("http://localhost:3000").unwrap();
        let expected = Url::parse("http://localhost:3000/api/users").unwrap();
        assert_eq!(build_url(&base, "/api/users").unwrap(), expected);

        let base_with_path = Url::parse("http://example.com/base/").unwrap();
        let expected_with_path = Url::parse("http://example.com/base/path").unwrap();
        assert_eq!(build_url(&base_with_path, "path").unwrap(), expected_with_path);

        let base_no_slash = Url::parse("http://example.com").unwrap();
        let expected_no_slash = Url::parse("http://example.com/path").unwrap();
        assert_eq!(build_url(&base_no_slash, "/path").unwrap(), expected_no_slash);
    }

    #[test]
    fn test_build_url_invalid_path() {
        let base = Url::parse("http://localhost:3000").unwrap();
        let result = build_url(&base, "ftp:"); // Example invalid path component
        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::UrlParse(_) => {} // Expected error variant
            e => panic!("Expected UrlParse error, but got {:?}", e),
        }
    }

    // TODO: Add tests for handle_response if possible (requires mocking reqwest::Response)
    // TODO: Add tests for stream_chat_response using a mock server (e.g., wiremock)
}