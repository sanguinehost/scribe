// cli/src/client.rs

use crate::error::CliError;
use async_trait::async_trait;
use reqwest::multipart;
use reqwest::{Client as ReqwestClient, Response, StatusCode, Url};
use scribe_backend::models::auth::Credentials;
use scribe_backend::models::characters::CharacterMetadata;
// Updated imports for chats models
use futures_util::{Stream, StreamExt}; // Removed StreamExt, TryStreamExt // Add StreamExt back
use reqwest_eventsource::{Event, EventSource}; // Added Event, EventSource
use scribe_backend::models::chats::{ChatMessage, ChatSession, GenerateResponsePayload};
use scribe_backend::models::users::User;
use serde::Deserialize; // Added Deserialize
use serde::de::DeserializeOwned;
use serde_json::json;
use std::fs;
use std::path::Path;
use std::pin::Pin;
use uuid::Uuid; // Added Pin
use httptest::{matchers::*, responders::*, Expectation, ServerPool, ServerHandle};
use tokio;
use chrono::Utc; // Added Utc
use tempfile::NamedTempFile;
use std::io::Write;

// Define the expected response structure from the /health endpoint (matching backend)
#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
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

// NEW: Intermediate struct for the non-streaming response body
#[derive(Deserialize)]
struct NonStreamingResponse {
    message_id: Uuid,
    content: String,
}

// NEW: Helper function specifically for handling the non-streaming chat response
async fn handle_non_streaming_chat_response(response: Response) -> Result<ChatMessage, CliError> {
    let status = response.status();
    if status.is_success() {
        match response.json::<NonStreamingResponse>().await {
            Ok(body) => {
                // Construct a partial ChatMessage. The chat loop primarily needs the content.
                // Other fields like created_at, session_id are not strictly needed by the loop
                // but we can add them with default/dummy values if necessary elsewhere.
                Ok(ChatMessage {
                    id: body.message_id,
                    session_id: Uuid::nil(), // Not provided by this endpoint, set to nil
                    message_type: scribe_backend::models::chats::MessageRole::Assistant,
                    content: body.content,
                    created_at: chrono::Utc::now(), // Use current time
                })
            }
            Err(e) => {
                tracing::error!(error = ?e, "Failed to decode non-streaming chat response");
                Err(CliError::Reqwest(e))
            }
        }
    } else {
        // Reuse the existing error handling logic from handle_response
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

/// Trait for abstracting HTTP client interactions to allow mocking in tests.
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn login(&self, credentials: &Credentials) -> Result<User, CliError>;
    async fn register(&self, credentials: &Credentials) -> Result<User, CliError>;
    async fn list_characters(&self) -> Result<Vec<CharacterMetadata>, CliError>;
    async fn create_chat_session(&self, character_id: Uuid) -> Result<ChatSession, CliError>;
    async fn upload_character(
        &self,
        name: &str,
        file_path: &str,
    ) -> Result<CharacterMetadata, CliError>;
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
    async fn generate_response(
        &self,
        chat_id: Uuid,
        message_content: &str,
        model_name: Option<String>,
    ) -> Result<ChatMessage, CliError>;
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
        let response = self
            .client
            .post(url)
            .json(credentials)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response::<User>(response)
            .await
            .map_err(|e| CliError::AuthFailed(format!("{}", e)))
    }

    async fn register(&self, credentials: &Credentials) -> Result<User, CliError> {
        let url = build_url(&self.base_url, "/api/auth/register")?;
        tracing::info!(%url, username = %credentials.username, "Attempting registration via HttpClient");
        let response = self
            .client
            .post(url)
            .json(credentials)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response::<User>(response)
            .await
            .map_err(|e| CliError::RegistrationFailed(format!("{}", e)))
    }

    async fn list_characters(&self) -> Result<Vec<CharacterMetadata>, CliError> {
        let url = build_url(&self.base_url, "/api/characters")?;
        tracing::info!(%url, "Listing characters via HttpClient");
        let response = self
            .client
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
    ) -> Result<CharacterMetadata, CliError> {
        tracing::info!(character_name = name, %file_path, "Attempting to upload character via HttpClient");

        let file_bytes = fs::read(file_path).map_err(|e| {
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
            .map_err(|e| {
                CliError::Internal(format!("Failed to create multipart file part: {}", e))
            })?;

        let form = multipart::Form::new()
            .text("name", name.to_string())
            .part("character_card", file_part);

        let url = build_url(&self.base_url, "/api/characters/upload")?;
        tracing::info!(%url, "Sending character upload request via HttpClient");

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
        tracing::info!(%url, "Performing health check via HttpClient");
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
        tracing::info!(%url, "Attempting logout via HttpClient");
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
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn get_character(&self, character_id: Uuid) -> Result<CharacterMetadata, CliError> {
        let url = build_url(&self.base_url, &format!("/api/characters/{}", character_id))?;
        tracing::info!(%url, %character_id, "Fetching character details via HttpClient");
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        handle_response(response).await
    }

    async fn list_chat_sessions(&self) -> Result<Vec<ChatSession>, CliError> {
        let url = build_url(&self.base_url, "/api/chats")?;
        tracing::info!(%url, "Listing chat sessions via HttpClient");
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
        tracing::info!(%url, %session_id, "Fetching chat messages via HttpClient");
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

        // Use the backend model struct directly (without request_thinking)
        let request_body = GenerateResponsePayload {
            content: content.to_string(),
            model: model_name.map(|s| s.to_string()),
        };

        tracing::info!(%url, chat_id = %chat_id, model = ?model_name, "Sending non-streaming message via HttpClient");

        let response = self
            .client
            .post(url.clone()) // Clone URL here
            .json(&request_body)
            .send()
            .await
            .map_err(|e| {
                tracing::error!(error = ?e, "Network error sending message");
                CliError::Network(e.to_string())
            })?;

        // Use the NEW handler function specifically for this response type
        handle_non_streaming_chat_response(response).await
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
        url.query_pairs_mut()
            .append_pair("request_thinking", &request_thinking.to_string());

        tracing::info!(%url, %chat_id, %request_thinking, "Initiating streaming chat response via HttpClient");

        // Payload without request_thinking
        let payload = GenerateResponsePayload {
            content: message_content.to_string(),
            model: None, // Model selection isn't part of this specific test endpoint for now
        };

        // Build the request manually to use with EventSource
        let request_builder = self.client.post(url.clone()).json(&payload); // Clone URL, create builder

        // Create the EventSource from the RequestBuilder
        let mut es = EventSource::new(request_builder)
            .map_err(|e| CliError::Internal(format!("Failed to create EventSource: {}", e)))?;

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

// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*;
    use httptest::{
        matchers::{self, json_decoded, all_of, request, contains, key, any}, // Add any
        responders::*,
        Expectation, ServerPool, ServerHandle,
    };
    use scribe_backend::models::auth::Credentials;
    use scribe_backend::models::users::User;
    use serde_json::json;
    use url::Url;
    use uuid::Uuid;
    use chrono::Utc;

    // Shared setup for tests needing a mock server
    fn setup_test_server() -> (ServerHandle<'static>, ReqwestClientWrapper) {
        let server_pool = Box::leak(Box::new(ServerPool::new(1)));
        let server = server_pool.get_server();
        let base_url = Url::parse(&server.url_str("")).unwrap();
        let reqwest_client = ReqwestClient::builder().cookie_store(true).build().unwrap();
        let client_wrapper = ReqwestClientWrapper::new(reqwest_client, base_url);
        (server, client_wrapper)
    }

    #[test]
    fn test_build_url_success() {
        let base = Url::parse("http://localhost:3000").unwrap();
        let expected = Url::parse("http://localhost:3000/api/users").unwrap();
        assert_eq!(build_url(&base, "/api/users").unwrap(), expected);

        let base_with_path = Url::parse("http://example.com/base/").unwrap();
        let expected_with_path = Url::parse("http://example.com/base/path").unwrap();
        assert_eq!(
            build_url(&base_with_path, "path").unwrap(),
            expected_with_path
        );

        let base_no_slash = Url::parse("http://example.com").unwrap();
        let expected_no_slash = Url::parse("http://example.com/path").unwrap();
        assert_eq!(
            build_url(&base_no_slash, "/path").unwrap(),
            expected_no_slash
        );
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

    #[tokio::test]
    async fn test_login_success() {
        let (mut server, client) = setup_test_server();

        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let mock_user = User {
            id: user_id,
            username: "testuser".to_string(),
            password_hash: "hashed_password".to_string(),
            created_at: now,
            updated_at: now,
        };
        let credentials = Credentials {
            username: "testuser".to_string(),
            password: "password".to_string(),
        };
        let credentials_json = serde_json::to_string(&credentials).unwrap();

        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/api/auth/login"),
                request::body(credentials_json),
            ])
            .respond_with(json_encoded(mock_user.clone())),
        );

        let result = client.login(&credentials).await;

        assert!(result.is_ok());
        let logged_in_user = result.unwrap();
        assert_eq!(logged_in_user.id, mock_user.id);
        assert_eq!(logged_in_user.username, mock_user.username);

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_login_failure_unauthorized() {
        let (mut server, client) = setup_test_server();

        let credentials = Credentials {
            username: "testuser".to_string(),
            password: "wrongpassword".to_string(),
        };
        let error_body = "Invalid credentials";

        server.expect(
            Expectation::matching(request::method_path("POST", "/api/auth/login"))
                .respond_with(status_code(401).body(error_body)),
        );

        let result = client.login(&credentials).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::AuthFailed(msg) => {
                assert!(msg.contains(error_body), "Error message was: {}", msg);
                assert!(msg.contains("401"), "Error message was: {}", msg);
            }
            e => panic!("Expected CliError::AuthFailed, got {:?}", e),
        }

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_login_failure_rate_limit() {
        let (mut server, client) = setup_test_server();

        let credentials = Credentials {
            username: "testuser".to_string(),
            password: "password".to_string(),
        };

        server.expect(
            Expectation::matching(request::method_path("POST", "/api/auth/login"))
                .respond_with(status_code(429)),
        );

        let result = client.login(&credentials).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::AuthFailed(msg) => {
                let expected_substring = "API rate limit exceeded";
                assert!(
                    msg.contains(expected_substring),
                    "Error message \"{}\" did not contain \"{}\"",
                    msg,
                    expected_substring
                );
            }
            e => panic!("Expected CliError::AuthFailed indicating rate limit, got {:?}", e),
        }

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_register_success() {
        let (mut server, client) = setup_test_server();

        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let mock_user = User {
            id: user_id,
            username: "newuser".to_string(),
            password_hash: "hashed_password".to_string(), // Backend handles hashing
            created_at: now,
            updated_at: now,
        };
        let credentials = Credentials {
            username: "newuser".to_string(),
            password: "password123".to_string(),
        };
        let credentials_json = serde_json::to_string(&credentials).unwrap();

        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/api/auth/register"),
                request::body(credentials_json),
            ])
            .respond_with(json_encoded(mock_user.clone())),
        );

        let result = client.register(&credentials).await;

        assert!(result.is_ok());
        let registered_user = result.unwrap();
        assert_eq!(registered_user.id, mock_user.id);
        assert_eq!(registered_user.username, mock_user.username);

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_register_failure_conflict() {
        let (mut server, client) = setup_test_server();

        let credentials = Credentials {
            username: "existinguser".to_string(),
            password: "password123".to_string(),
        };
        let error_body = "Username already taken";

        server.expect(
            Expectation::matching(request::method_path("POST", "/api/auth/register"))
                .respond_with(status_code(409).body(error_body)), // Simulate 409 Conflict
        );

        let result = client.register(&credentials).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::RegistrationFailed(msg) => {
                // Check that the underlying ApiError message is included
                assert!(msg.contains(error_body), "Error message was: {}", msg);
                assert!(msg.contains("409"), "Error message was: {}", msg);
            }
            e => panic!("Expected CliError::RegistrationFailed, got {:?}", e),
        }

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_list_characters_success() {
        let (mut server, client) = setup_test_server();

        let char1_id = Uuid::new_v4();
        let char2_id = Uuid::new_v4();
        let user_id_mock = Uuid::new_v4(); // Mock user ID
        let now = Utc::now();

        let mock_characters = vec![
            CharacterMetadata {
                id: char1_id,
                user_id: user_id_mock,
                name: "Character One".to_string(),
                description: Some("Description One".to_string()),
                first_mes: Some("Hello from Character One!".to_string()), // Added first_mes
                created_at: now,
                updated_at: now,
            },
            CharacterMetadata {
                id: char2_id,
                user_id: user_id_mock,
                name: "Character Two".to_string(),
                description: None,
                first_mes: None, // Added first_mes (None case)
                created_at: now,
                updated_at: now,
            },
        ];

        server.expect(
            Expectation::matching(request::method_path("GET", "/api/characters"))
                .respond_with(json_encoded(mock_characters.clone())),
        );

        let result = client.list_characters().await;

        assert!(result.is_ok());
        let characters = result.unwrap();
        assert_eq!(characters.len(), 2);
        assert_eq!(characters[0].id, mock_characters[0].id);
        assert_eq!(characters[1].name, mock_characters[1].name);
        assert_eq!(characters[0].first_mes, mock_characters[0].first_mes); // Verify new field

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_list_characters_success_empty() {
        let (mut server, client) = setup_test_server();

        let mock_characters: Vec<CharacterMetadata> = vec![];

        server.expect(
            Expectation::matching(request::method_path("GET", "/api/characters"))
                .respond_with(json_encoded(mock_characters)), // Respond with empty JSON array
        );

        let result = client.list_characters().await;

        assert!(result.is_ok());
        let characters = result.unwrap();
        assert!(characters.is_empty());

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_list_characters_api_error() {
        let (mut server, client) = setup_test_server();
        let error_body = "Database connection failed";

        server.expect(
            Expectation::matching(request::method_path("GET", "/api/characters"))
                .respond_with(status_code(500).body(error_body)), // Simulate 500 error
        );

        let result = client.list_characters().await;

        assert!(result.is_err());
        match result.err().unwrap() {
            // list_characters doesn't wrap errors like login/register, it returns ApiError directly
            CliError::ApiError { status, message } => {
                assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
                assert_eq!(message, error_body);
            }
            e => panic!("Expected CliError::ApiError, got {:?}", e),
        }

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_upload_character_success() {
        let (mut server, client) = setup_test_server();

        let character_name = "Test Character Upload";
        let file_content = "PNG image data or character card content";
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(file_content.as_bytes()).unwrap();
        let temp_file_path = temp_file.path().to_str().unwrap().to_string();

        let mock_response_id = Uuid::new_v4();
        let mock_response_user_id = Uuid::new_v4();
        let now = Utc::now();
        let mock_response = CharacterMetadata {
            id: mock_response_id,
            user_id: mock_response_user_id,
            name: character_name.to_string(),
            description: Some("Uploaded via test".to_string()),
            first_mes: Some("Hello from upload!".to_string()),
            created_at: now,
            updated_at: now,
        };

        // Define the expected multipart body parts
        // Note: Exact boundary and formatting is tricky to match perfectly,
        // httptest matchers might need adjusting or focus on essential parts.
        // We will focus on method, path and presence of expected field names/filenames.

        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/api/characters/upload"),
                // Simplified: Check only for the presence of the Content-Type header key
                request::headers(contains(key("content-type"))),
                // More robust checks commented out
                // request::body(contains(format!("name=\"{}\"", character_name))),
                // request::body(contains(format!("filename=\"{}\"", temp_file_name))),
            ])
            .respond_with(json_encoded(mock_response.clone())),
        );

        let result = client
            .upload_character(character_name, &temp_file_path)
            .await;

        assert!(result.is_ok());
        let uploaded_char = result.unwrap();
        assert_eq!(uploaded_char.id, mock_response_id);
        assert_eq!(uploaded_char.name, character_name);

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_upload_character_file_not_found() {
        let (_server, client) = setup_test_server(); // Server not needed, as error is local

        let character_name = "Test Character Fail";
        let non_existent_path = "/path/to/non/existent/file.png";

        // No server expectation needed, as the fs::read should fail first

        let result = client
            .upload_character(character_name, non_existent_path)
            .await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::Io(io_error) => {
                // Check that it's a file not found error
                assert_eq!(io_error.kind(), std::io::ErrorKind::NotFound);
            }
            e => panic!("Expected CliError::Io(NotFound), got {:?}", e),
        }

        // No server verification needed
    }

    #[tokio::test]
    async fn test_health_check_success() {
        let (mut server, client) = setup_test_server();

        let mock_status = HealthStatus { status: "OK".to_string() };

        server.expect(
            Expectation::matching(request::method_path("GET", "/api/health"))
                .respond_with(json_encoded(mock_status.clone())),
        );

        let result = client.health_check().await;

        assert!(result.is_ok());
        let health = result.unwrap();
        assert_eq!(health.status, mock_status.status);

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_health_check_api_error() {
        let (mut server, client) = setup_test_server();
        let error_body = "Service Unavailable";

        server.expect(
            Expectation::matching(request::method_path("GET", "/api/health"))
                .respond_with(status_code(503).body(error_body)), // Simulate 503 error
        );

        let result = client.health_check().await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::ApiError { status, message } => {
                assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(message, error_body);
            }
            e => panic!("Expected CliError::ApiError, got {:?}", e),
        }

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_logout_success() {
        let (mut server, client) = setup_test_server();

        server.expect(
            Expectation::matching(request::method_path("POST", "/api/auth/logout"))
                .respond_with(status_code(200)), // Expect 200 OK, no body needed
        );

        let result = client.logout().await;

        assert!(result.is_ok());

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_logout_api_error() {
        let (mut server, client) = setup_test_server();
        let error_body = "Logout failed internally";

        server.expect(
            Expectation::matching(request::method_path("POST", "/api/auth/logout"))
                .respond_with(status_code(500).body(error_body)), // Simulate 500 error
        );

        let result = client.logout().await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::ApiError { status, message } => {
                assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
                assert_eq!(message, error_body);
            }
            e => panic!("Expected CliError::ApiError, got {:?}", e),
        }

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_me_success() {
        let (mut server, client) = setup_test_server();

        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let mock_user = User {
            id: user_id,
            username: "currentuser".to_string(),
            password_hash: "some_hash".to_string(), // The endpoint returns the full user
            created_at: now,
            updated_at: now,
        };

        server.expect(
            Expectation::matching(request::method_path("GET", "/api/auth/me"))
                .respond_with(json_encoded(mock_user.clone())),
        );

        let result = client.me().await;

        assert!(result.is_ok());
        let fetched_user = result.unwrap();
        assert_eq!(fetched_user.id, mock_user.id);
        assert_eq!(fetched_user.username, mock_user.username);
        // Should we assert password_hash? Probably not critical for the client.
        assert_eq!(fetched_user.created_at, mock_user.created_at);

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_me_unauthorized() {
        let (mut server, client) = setup_test_server();
        let error_body = "Authentication token missing or invalid";

        server.expect(
            Expectation::matching(request::method_path("GET", "/api/auth/me"))
                .respond_with(status_code(401).body(error_body)), // Simulate 401 Unauthorized
        );

        let result = client.me().await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::ApiError { status, message } => {
                assert_eq!(status, StatusCode::UNAUTHORIZED);
                assert_eq!(message, error_body);
            }
            e => panic!("Expected CliError::ApiError, got {:?}", e),
        }

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_get_character_success() {
        let (mut server, client) = setup_test_server();

        let character_id = Uuid::new_v4();
        let user_id_mock = Uuid::new_v4();
        let now = Utc::now();
        let mock_character = CharacterMetadata {
            id: character_id,
            user_id: user_id_mock,
            name: "Specific Character".to_string(),
            description: Some("Details here".to_string()),
            first_mes: Some("Specific greeting".to_string()),
            created_at: now,
            updated_at: now,
        };

        let path_string = format!("/api/characters/{}", character_id);
        let static_path_str: &'static str = Box::leak(path_string.into_boxed_str());
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                static_path_str, // Pass &'static str
            ))
            .respond_with(json_encoded(mock_character.clone())),
        );

        let result = client.get_character(character_id).await;

        assert!(result.is_ok());
        let character = result.unwrap();
        assert_eq!(character.id, mock_character.id);
        assert_eq!(character.name, mock_character.name);

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_get_character_not_found() {
        let (mut server, client) = setup_test_server();
        let character_id = Uuid::new_v4();
        let error_body = format!("Character {} not found", character_id);

        let path_string = format!("/api/characters/{}", character_id);
        let static_path_str: &'static str = Box::leak(path_string.into_boxed_str());
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                static_path_str, // Pass &'static str
            ))
            .respond_with(status_code(404).body(error_body.clone())), // Simulate 404
        );

        let result = client.get_character(character_id).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::ApiError { status, message } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert!(message.contains(&error_body)); // Check if the specific error message is present
            }
            e => panic!("Expected CliError::ApiError with 404, got {:?}", e),
        }

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_list_chat_sessions_success() {
        let (mut server, client) = setup_test_server();

        let session1_id = Uuid::new_v4();
        let session2_id = Uuid::new_v4();
        let user_id_mock = Uuid::new_v4();
        let char_id_mock = Uuid::new_v4();
        let now = Utc::now();
        use bigdecimal::BigDecimal;
        use std::str::FromStr;
        use serde_json::json;

        let mock_sessions = vec![
            ChatSession {
                id: session1_id,
                user_id: user_id_mock,
                character_id: char_id_mock,
                title: Some("Session One".to_string()),
                system_prompt: None,
                temperature: Some(BigDecimal::from_str("0.8").unwrap()),
                max_output_tokens: Some(512),
                created_at: now,
                updated_at: now,
                frequency_penalty: None,
                presence_penalty: None,
                top_k: None,
                top_p: None,
                repetition_penalty: None,
                min_p: None,
                top_a: None,
                seed: None,
                logit_bias: None,
            },
            ChatSession {
                id: session2_id,
                user_id: user_id_mock,
                character_id: Uuid::new_v4(), // Different character
                title: None,
                system_prompt: Some("You are helpful.".to_string()),
                temperature: None,
                max_output_tokens: None,
                created_at: now,
                updated_at: now,
                frequency_penalty: Some(BigDecimal::from_str("0.1").unwrap()),
                presence_penalty: Some(BigDecimal::from_str("0.2").unwrap()),
                top_k: Some(40),
                top_p: Some(BigDecimal::from_str("0.95").unwrap()),
                repetition_penalty: Some(BigDecimal::from_str("1.1").unwrap()),
                min_p: None,
                top_a: None,
                seed: Some(123),
                logit_bias: Some(json!({ "token_id": -1.0 })),
            },
        ];

        server.expect(
            Expectation::matching(request::method_path("GET", "/api/chats"))
                .respond_with(json_encoded(mock_sessions.clone())),
        );

        let result = client.list_chat_sessions().await;

        assert!(result.is_ok());
        let sessions = result.unwrap();
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].id, mock_sessions[0].id);
        assert_eq!(sessions[1].title, mock_sessions[1].title);
        assert_eq!(sessions[0].temperature, mock_sessions[0].temperature);
        assert_eq!(sessions[1].seed, mock_sessions[1].seed);

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_list_chat_sessions_success_empty() {
        let (mut server, client) = setup_test_server();

        let mock_sessions: Vec<ChatSession> = vec![];

        server.expect(
            Expectation::matching(request::method_path("GET", "/api/chats"))
                .respond_with(json_encoded(mock_sessions)), // Respond with empty JSON array
        );

        let result = client.list_chat_sessions().await;

        assert!(result.is_ok());
        let sessions = result.unwrap();
        assert!(sessions.is_empty());

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_list_chat_sessions_api_error() {
        let (mut server, client) = setup_test_server();
        let error_body = "Internal Server Error listing chats";

        server.expect(
            Expectation::matching(request::method_path("GET", "/api/chats"))
                .respond_with(status_code(500).body(error_body)), // Simulate 500 error
        );

        let result = client.list_chat_sessions().await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::ApiError { status, message } => {
                assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
                assert_eq!(message, error_body);
            }
            e => panic!("Expected CliError::ApiError, got {:?}", e),
        }

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_get_chat_messages_success() {
        let (mut server, client) = setup_test_server();
        let session_id = Uuid::new_v4();
        let now = Utc::now();
        use scribe_backend::models::chats::{ChatMessage, MessageRole}; // Ensure imports

        let mock_messages = vec![
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                message_type: MessageRole::User,
                content: "Hello there".to_string(),
                created_at: now,
            },
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                message_type: MessageRole::Assistant,
                content: "General Kenobi!".to_string(),
                created_at: now + chrono::Duration::seconds(1),
            },
        ];

        let path_string = format!("/api/chats/{}/messages", session_id);
        let static_path_str: &'static str = Box::leak(path_string.into_boxed_str());

        server.expect(
            Expectation::matching(request::method_path("GET", static_path_str))
                .respond_with(json_encoded(mock_messages.clone())),
        );

        let result = client.get_chat_messages(session_id).await;

        assert!(result.is_ok());
        let messages = result.unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].content, mock_messages[0].content);
        assert_eq!(messages[1].message_type, MessageRole::Assistant);

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_get_chat_messages_success_empty() {
        let (mut server, client) = setup_test_server();
        let session_id = Uuid::new_v4();
        use scribe_backend::models::chats::ChatMessage; // Ensure import

        let mock_messages: Vec<ChatMessage> = vec![];

        let path_string = format!("/api/chats/{}/messages", session_id);
        let static_path_str: &'static str = Box::leak(path_string.into_boxed_str());

        server.expect(
            Expectation::matching(request::method_path("GET", static_path_str))
                .respond_with(json_encoded(mock_messages)), // Respond with empty JSON array
        );

        let result = client.get_chat_messages(session_id).await;

        assert!(result.is_ok());
        let messages = result.unwrap();
        assert!(messages.is_empty());

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_get_chat_messages_not_found() {
        let (mut server, client) = setup_test_server();
        let session_id = Uuid::new_v4();
        let error_body = format!("Chat session {} not found", session_id);

        let path_string = format!("/api/chats/{}/messages", session_id);
        let static_path_str: &'static str = Box::leak(path_string.into_boxed_str());

        server.expect(
            Expectation::matching(request::method_path("GET", static_path_str))
                .respond_with(status_code(404).body(error_body.clone())), // Simulate 404
        );

        let result = client.get_chat_messages(session_id).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::ApiError { status, message } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert!(message.contains(&error_body));
            }
            e => panic!("Expected CliError::ApiError with 404, got {:?}", e),
        }

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_create_chat_session_success() {
        let (mut server, client) = setup_test_server();
        let character_id = Uuid::new_v4();
        let user_id_mock = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let now = Utc::now();
        use bigdecimal::BigDecimal;
        use std::str::FromStr;
        use scribe_backend::models::chats::ChatSession; // Import ChatSession
        use serde_json::json; // Import json!

        let mock_session = ChatSession {
            id: session_id,
            user_id: user_id_mock, // Assuming backend returns this
            character_id,
            title: None, // Usually starts untitled
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            created_at: now,
            updated_at: now,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
        };

        let request_payload = json!({ "character_id": character_id });

        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/api/chats"),
                request::body(request_payload.to_string()), // Match JSON body
            ])
            .respond_with(json_encoded(mock_session.clone())),
        );

        let result = client.create_chat_session(character_id).await;

        assert!(result.is_ok());
        let created_session = result.unwrap();
        assert_eq!(created_session.id, mock_session.id);
        assert_eq!(created_session.character_id, character_id);

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_create_chat_session_char_not_found() {
        let (mut server, client) = setup_test_server();
        let character_id = Uuid::new_v4();
        let error_body = format!("Character {} not found", character_id);
        use serde_json::json; // Import json!

        let request_payload = json!({ "character_id": character_id });

        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/api/chats"),
                request::body(request_payload.to_string()),
            ])
            .respond_with(status_code(404).body(error_body.clone())), // Simulate 404 from backend
        );

        let result = client.create_chat_session(character_id).await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::ApiError { status, message } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert!(message.contains(&error_body));
            }
            e => panic!("Expected CliError::ApiError with 404, got {:?}", e),
        }

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_send_message_success() {
        let (mut server, client) = setup_test_server();
        let session_id = Uuid::new_v4();
        let message_content = "Hello, assistant!";
        let response_message_id = Uuid::new_v4();
        let response_content = "Hello, user!";
        use scribe_backend::models::chats::{MessageRole}; // Only import what's needed
        use serde_json::json;
        use httptest::matchers::{request, all_of, matches};

        // Mock response structure
        let mock_api_response = json!({ "message_id": response_message_id, "content": response_content });

        // Create a matcher that checks the method and uses regex for the path
        server.expect(
            Expectation::matching(all_of![
                request::method("POST"),
                request::path(matches(format!("/api/chats/{}/generate.*", session_id)))
            ])
            .respond_with(json_encoded(mock_api_response))
        );

        let result = client
            .send_message(session_id, message_content, None)
            .await;

        assert!(result.is_ok(), "send_message failed: {:?}", result.err());
        let response_message = result.unwrap();
        assert_eq!(response_message.id, response_message_id);
        assert_eq!(response_message.content, response_content);
        assert_eq!(response_message.message_type, MessageRole::Assistant);
        assert_eq!(response_message.session_id, Uuid::nil());

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_send_message_session_not_found() {
        let (mut server, client) = setup_test_server();
        let session_id = Uuid::new_v4();
        let message_content = "Does this exist?";
        let error_body = format!("Session {} not found", session_id);
        use httptest::matchers::{request, all_of, matches};

        // Create a matcher that checks the method and uses regex for the path
        server.expect(
            Expectation::matching(all_of![
                request::method("POST"),
                request::path(matches(format!("/api/chats/{}/generate.*", session_id)))
            ])
            .respond_with(status_code(404).body(error_body.clone()))
        );

        let result = client
            .send_message(session_id, message_content, None)
            .await;

        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::ApiError { status, message } => {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert!(message.contains(&error_body), 
                    "Expected message to contain '{}', but got: '{}'", error_body, message);
            }
            e => panic!("Expected CliError::ApiError, got {:?}", e),
        }

        server.verify_and_clear();
    }

    // TODO: Add tests for handle_response if possible (requires mocking reqwest::Response)
    // TODO: Add tests for stream_chat_response using a mock server (e.g., httptest or wiremock)
}
