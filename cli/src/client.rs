// cli/src/client.rs

use crate::error::CliError;
use async_trait::async_trait;
use reqwest::multipart;
use reqwest::{Client as ReqwestClient, Response, Url, StatusCode}; // Added Response, Url, and StatusCode
use scribe_backend::models::auth::Credentials;
use scribe_backend::models::characters::CharacterMetadata;
use scribe_backend::models::chats::{ChatMessage, ChatSession};
use scribe_backend::models::users::User;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::fs;
use std::path::Path;
use uuid::Uuid;

// Define the expected response structure from the /health endpoint (matching backend)
// Moved here as it's returned by the client trait method
#[derive(serde::Deserialize, Debug, Clone)]
pub struct HealthStatus { // Made pub
    pub status: String, // Made pub
}

// Helper to join path to base URL - moved here from main
pub fn build_url(base: &Url, path: &str) -> Result<Url, CliError> { // Made pub
    base.join(path).map_err(CliError::UrlParse)
}

// Helper to handle API responses - moved here from main
pub async fn handle_response<T: DeserializeOwned>(response: Response) -> Result<T, CliError> { // Made pub
    let status = response.status();
    if status.is_success() {
        // Use map_err for concise error conversion
        response.json::<T>().await.map_err(CliError::Reqwest)
    } else {
        // Check for specific status codes before generic ApiError
        if status == StatusCode::TOO_MANY_REQUESTS { // Check for 429
             tracing::warn!("Received 429 Too Many Requests from backend");
             return Err(CliError::RateLimited);
        }

        // Existing generic error handling
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
pub trait HttpClient { // Made pub
    async fn login(&self, credentials: &Credentials) -> Result<User, CliError>;
    async fn register(&self, credentials: &Credentials) -> Result<User, CliError>;
    async fn list_characters(&self) -> Result<Vec<CharacterMetadata>, CliError>;
    async fn create_chat_session(&self, character_id: Uuid) -> Result<ChatSession, CliError>;
    async fn generate_response(&self, chat_id: Uuid, message_content: &str) -> Result<ChatMessage, CliError>;
    async fn upload_character(&self, name: &str, file_path: &str) -> Result<CharacterMetadata, CliError>;
    async fn health_check(&self) -> Result<HealthStatus, CliError>;
    async fn logout(&self) -> Result<(), CliError>;
    async fn me(&self) -> Result<User, CliError>;
    async fn get_character(&self, character_id: Uuid) -> Result<CharacterMetadata, CliError>;
    async fn list_chat_sessions(&self) -> Result<Vec<ChatSession>, CliError>;
    async fn get_chat_messages(&self, session_id: Uuid) -> Result<Vec<ChatMessage>, CliError>;
}

/// Wrapper around ReqwestClient implementing the HttpClient trait.
pub struct ReqwestClientWrapper { // Made pub
    client: ReqwestClient,
    base_url: Url,
}

impl ReqwestClientWrapper {
    // Kept pub as it's used in main
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
        // Use map_err for concise error formatting
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
        // Use map_err for concise error formatting
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

     async fn generate_response(&self, chat_id: Uuid, message_content: &str) -> Result<ChatMessage, CliError> {
        // Define the expected structure locally as it's an implementation detail for this client
        #[derive(serde::Deserialize)] struct ResponseBody { ai_message: ChatMessage }

        let url = build_url(&self.base_url, &format!("/api/chats/{}/generate", chat_id))?;
        tracing::debug!(%url, %chat_id, "Sending message and generating response via HttpClient");
        let payload = json!({ "content": message_content });
        let response = self.client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(CliError::Reqwest)?;
        // Handle response and extract ai_message
        let response_body: ResponseBody = handle_response(response).await?;
        Ok(response_body.ai_message)
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
            "image/png" // Or default to application/octet-stream? Backend expects image.
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
}


// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*; // Import items from parent module (client.rs)
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
    // Consider testing specific client methods using a mock server (e.g., wiremock)
    // or by further abstracting the reqwest::Client interaction within ReqwestClientWrapper.
} 