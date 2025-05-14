// cli/src/client.rs

use crate::error::CliError;
use async_trait::async_trait;
use reqwest::multipart;
use reqwest::{Client as ReqwestClient, Response, StatusCode, Url};
use scribe_backend::models::auth::LoginPayload;
use scribe_backend::models::characters::{CharacterDataForClient}; // Import CharacterDataForClient
// Updated imports for chats models
use futures_util::{Stream, StreamExt}; // Removed StreamExt, TryStreamExt // Add StreamExt back
use reqwest_eventsource::{Event, EventSource}; // Added Event, EventSource
use scribe_backend::models::chats::{ChatMessage, Chat, GenerateResponsePayload, ApiChatMessage, ChatSettingsResponse, UpdateChatSettingsRequest}; // <-- Added ChatSettingsResponse, UpdateChatSettingsRequest
use scribe_backend::models::users::User;
use serde::{Deserialize, Deserializer}; // Added Deserialize, Deserializer
use serde::Serialize; // Added for SerializableLoginPayload
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::pin::Pin;
 // Added Write trait
 // Added FromStr trait
use uuid::Uuid; // Added Pin
use secrecy::{ExposeSecret, SecretString}; // Added SecretString
use anyhow::Result;
use chrono::{DateTime, Utc};
use bigdecimal::BigDecimal;
// Custom Json type to mirror backend's diesel_json::Json
#[derive(Debug, Clone, Deserialize)]
pub struct Json<T>(pub T);

// Import the backend Json type directly for conversion
use diesel_json::Json as DieselJson;

// Define the expected response structure from the /health endpoint (matching backend)
#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct HealthStatus {
    pub status: String,
}

// Create a struct to match the backend's auth response
#[derive(Deserialize, Debug, Clone)]
pub struct AuthUserResponse {
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
}

// Map AuthUserResponse to User for compatibility
impl From<AuthUserResponse> for User {
    fn from(auth: AuthUserResponse) -> Self {
        User {
            id: auth.user_id,
            username: auth.username,
            email: auth.email,
            password_hash: String::new(), // Default empty string
            kek_salt: String::new(),      // Default empty string
            encrypted_dek: Vec::new(),    // Default empty Vec
            dek_nonce: Vec::new(),        // Default empty Vec
            encrypted_dek_by_recovery: None,
            recovery_kek_salt: None,
            recovery_dek_nonce: None,
            dek: None,                    // Option<SerializableSecretDek>
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }
}

// Helper to join path to base URL
pub fn build_url(base: &Url, path: &str) -> Result<Url, CliError> {
    base.join(path).map_err(CliError::UrlParse)
}

// Helper to handle API responses
// Add std::fmt::Debug to T for logging
pub async fn handle_response<T: DeserializeOwned + std::fmt::Debug>(response: Response) -> Result<T, CliError> {
    let status = response.status();
    let type_name = std::any::type_name::<T>(); // Get type name for logs

    // Try to get response text
    let response_body = match response.text().await {
        Ok(text) => {
            // Use eprintln for debug logging as requested
            // Attempt to parse the response body for safe logging.
            // If T is CharacterDataForClient or Vec<CharacterDataForClient>,
            // its Debug impl (now custom) will be used.
            match serde_json::from_str::<T>(&text) {
                Ok(parsed_data_for_log) => {
                    eprintln!(
                        "[Scribe-CLI Debug] Response for T={}: Status={}, ParsedBody={:?}",
                        type_name, status, parsed_data_for_log
                    );
                }
                Err(parse_err) => {
                    // If parsing fails, log a redacted version of the body or a placeholder.
                    // Also log the parsing error for debugging why it failed, but not the raw body.
                    eprintln!(
                        "[Scribe-CLI Debug] Response for T={}: Status={}, Body='[RAW_BODY_REDACTED_DUE_TO_PARSE_ERROR_FOR_LOGGING]' (Parse Error for logging: {})",
                        type_name, status, parse_err
                    );
                    // Optionally, log a very short, non-sensitive prefix of the text if deemed necessary for some debugging,
                    // but full redaction on parse error is safest for sensitive data.
                    // e.g., eprintln!("Raw body prefix (first 30 chars): '{}...'", text.chars().take(30).collect::<String>());
                }
            }
            text
        }
        Err(e) => {
            eprintln!("[Scribe-CLI Debug] Failed to get response text for T={}: {}", type_name, e);
            // Existing tracing log, kept for consistency with other parts of the codebase if desired
            tracing::error!("Failed to get response text for T={}: {}", type_name, e);
            return Err(CliError::Reqwest(e));
        }
    };

    if status.is_success() {
        match serde_json::from_str::<T>(&response_body) {
            Ok(data) => {
                eprintln!("[Scribe-CLI Debug] Successfully deserialized T={} into: {:?}", type_name, data);
                Ok(data)
            }
            Err(e) => {
                eprintln!("[Scribe-CLI Debug] Failed to deserialize T={} from body '{}': {}", type_name, response_body, e);
                // Existing tracing logs
                tracing::error!("Failed to deserialize successful response for T={}: {}", type_name, e);
                tracing::error!("Response text for T={} was: {}", type_name, response_body);
                // Map to CliError::Json or CliError::Internal as appropriate
                // Using CliError::Json as it's more specific for deserialization issues
                Err(CliError::Json(e))
            }
        }
    } else {
        eprintln!("[Scribe-CLI Debug] Non-success status for T={}: {}. Body: '{}'", type_name, status, response_body);

        // IMPORTANT: Check for 429 Too Many Requests *before* trying to parse body
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            eprintln!("[Scribe-CLI Debug] Status is 429 Too Many Requests for T={}, returning CliError::RateLimitExceeded.", type_name);
            tracing::warn!("Received 429 Too Many Requests from backend for T={}", type_name);
            return Err(CliError::RateLimitExceeded);
        }

        // Define local structs for attempting to parse a structured error response
        // These are based on the user's previous diff's implied structure.
        #[derive(Deserialize, Debug)]
        struct ApiErrorDetail {
            message: String,
            details: Option<serde_json::Value>, // Using serde_json::Value for flexibility
        }
        #[derive(Deserialize, Debug)]
        struct StructuredApiErrorResponse {
            error: ApiErrorDetail,
        }

        let structured_error_result: Result<StructuredApiErrorResponse, _> = serde_json::from_str(&response_body);

        if let Ok(parsed_error) = structured_error_result {
            eprintln!("[Scribe-CLI Debug] Successfully parsed structured API error for T={}: {:?}", type_name, parsed_error);
            // Existing tracing log
            tracing::error!(
                target: "scribe_cli::client",
                %status,
                parsed_error_message = %parsed_error.error.message,
                parsed_error_details = ?parsed_error.error.details,
                raw_body = %response_body,
                "API request failed for T={}: (parsed structured error)", type_name
            );
            Err(CliError::ApiError {
                status,
                // Use the message from the parsed error if available, otherwise fall back to the whole body
                message: parsed_error.error.message,
            })
        } else {
            eprintln!("[Scribe-CLI Debug] Failed to parse response body as StructuredApiErrorResponse for T={}. Error: {:?}. Body: '{}'", type_name, structured_error_result.err(), response_body);
            // Existing tracing log
            tracing::error!(
                target: "scribe_cli::client",
                %status,
                error_body = %response_body,
                "API request failed for T={}: (raw error body)", type_name
            );
            // Fallback if error response itself can't be deserialized into the structure
            Err(CliError::ApiError {
                status,
                message: response_body, // Use the full response_body as the message
            })
        }
    }
}

// NEW: Define the StreamEvent enum for SSE events
#[derive(Debug, Deserialize, Clone)] // Added Deserialize and Clone
#[serde(tag = "event", content = "data")] // Specify how to deserialize based on SSE event name
#[serde(rename_all = "snake_case")] // Match backend event names (e.g., event: thinking)
pub enum StreamEvent {
    Thinking(String), // Corresponds to event: thinking, data: "step description"
    Content(String),  // Corresponds to event: content, data: "text chunk"
    ReasoningChunk(String), // NEW: Corresponds to event: reasoning_chunk, data: "reasoning text chunk"
    PartialMessage(String), // NEW: For event: message, data: {"text": "..."}
    Done,             // Corresponds to event: done (no data expected)
}

// NEW: Intermediate struct for the non-streaming response body
#[derive(Deserialize)]
struct NonStreamingResponse {
    message_id: Uuid,
    content: String,
}

/// Client-side wrapper for CharacterDataForClient that can deserialize from the backend's encrypted format
/// This handles the fact that some string fields are now returned as Vec<u8> from the backend
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ClientCharacterDataForClient {
    pub id: Uuid,
    pub user_id: Uuid,
    #[serde(default)]
    pub spec: String,
    #[serde(default)]
    pub spec_version: String,
    pub name: String,
    #[serde(default, deserialize_with = "deserialize_option_bytes_to_string")]
    pub description: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_bytes_to_string")]
    pub personality: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_bytes_to_string")]
    pub scenario: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_bytes_to_string")]
    pub first_mes: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_bytes_to_string")]
    pub mes_example: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_bytes_to_string")]
    pub creator_notes: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_bytes_to_string")]
    pub system_prompt: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_bytes_to_string")]
    pub post_history_instructions: Option<String>,
    #[serde(default)]
    pub tags: Option<Vec<Option<String>>>,
    #[serde(default)]
    pub creator: Option<String>,
    #[serde(default)]
    pub character_version: Option<String>,
    #[serde(default)]
    pub alternate_greetings: Option<Vec<Option<String>>>,
    #[serde(default)]
    pub nickname: Option<String>,
    #[serde(default)]
    pub creator_notes_multilingual: Option<Json<Value>>,
    #[serde(default)]
    pub source: Option<Vec<Option<String>>>,
    #[serde(default)]
    pub group_only_greetings: Option<Vec<Option<String>>>,
    #[serde(default)]
    pub creation_date: Option<DateTime<Utc>>,
    #[serde(default)]
    pub modification_date: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default, deserialize_with = "deserialize_option_bytes_to_string")]
    pub persona: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_bytes_to_string")]
    pub world_scenario: Option<String>,
    #[serde(default)]
    pub avatar: Option<String>,
    #[serde(default)]
    pub chat: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_bytes_to_string")]
    pub greeting: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_bytes_to_string")]
    pub definition: Option<String>,
    #[serde(default)]
    pub default_voice: Option<String>,
    #[serde(default)]
    pub extensions: Option<Json<Value>>,
    #[serde(default)]
    pub data_id: Option<i32>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub definition_visibility: Option<String>,
    #[serde(default)]
    pub depth: Option<i32>,
    #[serde(default, deserialize_with = "deserialize_option_bytes_to_string")]
    pub example_dialogue: Option<String>,
    #[serde(default)]
    pub favorite: Option<bool>,
    #[serde(default)]
    pub first_message_visibility: Option<String>,
    #[serde(default)]
    pub height: Option<BigDecimal>,
    #[serde(default)]
    pub last_activity: Option<DateTime<Utc>>,
    #[serde(default)]
    pub migrated_from: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_bytes_to_string")]
    pub model_prompt: Option<String>,
    #[serde(default)]
    pub model_prompt_visibility: Option<String>,
    #[serde(default)]
    pub model_temperature: Option<BigDecimal>,
    #[serde(default)]
    pub num_interactions: Option<i64>,
    #[serde(default)]
    pub permanence: Option<BigDecimal>,
    #[serde(default)]
    pub persona_visibility: Option<String>,
    #[serde(default)]
    pub revision: Option<i32>,
    #[serde(default)]
    pub sharing_visibility: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub system_prompt_visibility: Option<String>,
    #[serde(default)]
    pub system_tags: Option<Vec<Option<String>>>,
    #[serde(default)]
    pub token_budget: Option<i32>,
    #[serde(default)]
    pub usage_hints: Option<Json<Value>>,
    #[serde(default, deserialize_with = "deserialize_option_bytes_to_string")]
    pub user_persona: Option<String>,
    #[serde(default)]
    pub user_persona_visibility: Option<String>,
    #[serde(default)]
    pub visibility: Option<String>,
    #[serde(default)]
    pub weight: Option<BigDecimal>,
    #[serde(default)]
    pub world_scenario_visibility: Option<String>,
}

// Custom deserializer function that can handle both string and byte array formats
fn deserialize_option_bytes_to_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    // First try deserializing as any value
    let value = serde_json::Value::deserialize(deserializer)?;
    
    // Handle different value types
    match value {
        // Null - return None
        serde_json::Value::Null => {
            Ok(None)
        }
        // String - return the string wrapped in Some
        serde_json::Value::String(s) => {
            if s.is_empty() {
                Ok(None)
            } else {
                Ok(Some(s))
            }
        }
        // Array of integers (byte array) - convert to UTF-8 string
        serde_json::Value::Array(arr) => {
            // Convert the array of numbers to bytes
            let bytes: Result<Vec<u8>, _> = arr.into_iter()
                .map(|v| {
                    if let serde_json::Value::Number(n) = v {
                        if let Some(i) = n.as_u64() {
                            if i <= 255 {
                                return Ok(i as u8);
                            }
                        }
                    }
                    Err(serde::de::Error::custom(format!("Expected byte value 0-255")))
                })
                .collect();
                
            match bytes {
                Ok(b) if b.is_empty() => Ok(None),
                Ok(b) => {
                    String::from_utf8(b)
                        .map(Some)
                        .map_err(|e| serde::de::Error::custom(format!("Invalid UTF-8: {}", e)))
                }
                Err(e) => Err(e)
            }
        }
        // Any other value type - error
        v => Err(serde::de::Error::custom(format!("Expected string, byte array, or null, got {:?}", v))),
    }
}

// Implement From trait to convert ClientCharacterDataForClient to CharacterDataForClient
impl From<ClientCharacterDataForClient> for CharacterDataForClient {
    fn from(client: ClientCharacterDataForClient) -> Self {
        CharacterDataForClient {
            id: client.id,
            user_id: client.user_id,
            spec: client.spec,
            spec_version: client.spec_version,
            name: client.name,
            description: client.description,
            personality: client.personality,
            scenario: client.scenario,
            first_mes: client.first_mes,
            mes_example: client.mes_example,
            creator_notes: client.creator_notes,
            system_prompt: client.system_prompt,
            post_history_instructions: client.post_history_instructions,
            tags: client.tags,
            creator: client.creator,
            character_version: client.character_version,
            alternate_greetings: client.alternate_greetings,
            nickname: client.nickname,
            creator_notes_multilingual: client.creator_notes_multilingual.map(|json| DieselJson(json.0)),
            source: client.source,
            group_only_greetings: client.group_only_greetings,
            creation_date: client.creation_date,
            modification_date: client.modification_date,
            created_at: client.created_at,
            updated_at: client.updated_at,
            persona: client.persona,
            world_scenario: client.world_scenario,
            avatar: client.avatar,
            chat: client.chat,
            greeting: client.greeting,
            definition: client.definition,
            default_voice: client.default_voice,
            extensions: client.extensions.map(|json| DieselJson(json.0)),
            data_id: client.data_id,
            category: client.category,
            definition_visibility: client.definition_visibility,
            depth: client.depth,
            example_dialogue: client.example_dialogue,
            favorite: client.favorite,
            first_message_visibility: client.first_message_visibility,
            height: client.height,
            last_activity: client.last_activity,
            migrated_from: client.migrated_from,
            model_prompt: client.model_prompt,
            model_prompt_visibility: client.model_prompt_visibility,
            model_temperature: client.model_temperature,
            num_interactions: client.num_interactions,
            permanence: client.permanence,
            persona_visibility: client.persona_visibility,
            revision: client.revision,
            sharing_visibility: client.sharing_visibility,
            status: client.status,
            system_prompt_visibility: client.system_prompt_visibility,
            system_tags: client.system_tags,
            token_budget: client.token_budget,
            usage_hints: client.usage_hints.map(|json| DieselJson(json.0)),
            user_persona: client.user_persona,
            user_persona_visibility: client.user_persona_visibility,
            visibility: client.visibility,
            weight: client.weight,
            world_scenario_visibility: client.world_scenario_visibility,
        }
    }
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
                    user_id: Uuid::nil(), // Use Uuid::nil() for CLI context
                    message_type: scribe_backend::models::chats::MessageRole::Assistant,
                    content: body.content.into_bytes(), // Convert String to Vec<u8>
                    content_nonce: None, // Add missing field
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

// NEW: Struct for the streaming request payload, mirroring backend's GenerateChatRequest
#[derive(Serialize)]
struct CliGenerateChatRequest {
    history: Vec<ApiChatMessage>,
    // Add other fields like 'model' if the CLI needs to specify them
    // model: Option<String>,
}

/// Trait for abstracting HTTP client interactions to allow mocking in tests.
#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn login(&self, credentials: &LoginPayload) -> Result<User, CliError>;
    async fn register(&self, credentials: &RegisterPayload) -> Result<User, CliError>;
    async fn list_characters(&self) -> Result<Vec<ClientCharacterDataForClient>, CliError>;
    async fn create_chat_session(&self, character_id: Uuid) -> Result<Chat, CliError>;
    async fn upload_character(
        &self,
        name: &str,
        file_path: &str,
    ) -> Result<ClientCharacterDataForClient, CliError>;
    async fn health_check(&self) -> Result<HealthStatus, CliError>;
    async fn logout(&self) -> Result<(), CliError>;
    async fn me(&self) -> Result<User, CliError>;
    async fn get_character(&self, character_id: Uuid) -> Result<ClientCharacterDataForClient, CliError>;
    async fn list_chat_sessions(&self) -> Result<Vec<Chat>, CliError>;
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
        history: Vec<ApiChatMessage>, // <-- Change parameter type and name
        request_thinking: bool,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent, CliError>> + Send>>, CliError>;

    // NEW: Chat Settings methods
    async fn update_chat_settings(&self, session_id: Uuid, payload: &UpdateChatSettingsRequest) -> Result<ChatSettingsResponse, CliError>;
 
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

// Create a local wrapper for LoginPayload that implements Serialize
#[derive(Serialize)]
struct SerializableLoginPayload<'a> {
    identifier: &'a str,
    password: &'a str,
}

impl<'a> From<&'a LoginPayload> for SerializableLoginPayload<'a> {
    fn from(payload: &'a LoginPayload) -> Self {
        // Use the expose_secret method to get the password value
        SerializableLoginPayload {
            identifier: &payload.identifier,
            password: payload.password.expose_secret(),
        }
    }
}

// Add a new struct for RegisterPayload used by the client
#[derive(Debug, Clone)]
pub struct RegisterPayload {
    pub username: String,
    pub email: String,
    pub password: SecretString,
}

// Add a serializable version of RegisterPayload for requests
#[derive(Serialize)]
struct SerializableRegisterPayload<'a> {
    username: &'a str,
    email: &'a str,
    password: &'a str,
}

impl<'a> From<&'a RegisterPayload> for SerializableRegisterPayload<'a> {
    fn from(payload: &'a RegisterPayload) -> Self {
        SerializableRegisterPayload {
            username: &payload.username,
            email: &payload.email,
            password: payload.password.expose_secret(),
        }
    }
}

#[async_trait]
impl HttpClient for ReqwestClientWrapper {
    async fn login(&self, credentials: &LoginPayload) -> Result<User, CliError> {
        let url = build_url(&self.base_url, "/api/auth/login")?;
        tracing::info!(%url, identifier = %credentials.identifier, "Attempting login via HttpClient");
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
        
        // Convert to User for backwards compatibility
        Ok(User::from(auth_response))
    }

    async fn register(&self, credentials: &RegisterPayload) -> Result<User, CliError> {
        let url = build_url(&self.base_url, "/api/auth/register")?;
        tracing::info!(%url, username = %credentials.username, email = %credentials.email, "Attempting registration via HttpClient");
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
        
        // Convert to User for backwards compatibility
        Ok(User::from(auth_response))
    }
 
    async fn list_characters(&self) -> Result<Vec<ClientCharacterDataForClient>, CliError> {
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

    async fn create_chat_session(&self, character_id: Uuid) -> Result<Chat, CliError> {
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
    ) -> Result<ClientCharacterDataForClient, CliError> {
        tracing::info!(%file_path, "Attempting to upload character via HttpClient from file");
 
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
        
        // Get auth response and convert to User
        let auth_response = handle_response::<AuthUserResponse>(response).await?;
        
        // Convert to User for backwards compatibility
        Ok(User::from(auth_response))
    }
 
    async fn get_character(&self, character_id: Uuid) -> Result<ClientCharacterDataForClient, CliError> {
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

    async fn list_chat_sessions(&self) -> Result<Vec<Chat>, CliError> {
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
        history: Vec<ApiChatMessage>, // <-- Change parameter type and name
        request_thinking: bool,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<StreamEvent, CliError>> + Send>>, CliError> {
        // Build URL with query parameter for streaming
        let mut url = build_url(&self.base_url, &format!("/api/chats/{}/generate", chat_id))?;
        url.query_pairs_mut()
            .append_pair("request_thinking", &request_thinking.to_string());

        tracing::info!(%url, %chat_id, %request_thinking, "Initiating streaming chat response via HttpClient");

        // Payload now includes history
        let payload = CliGenerateChatRequest { history }; // <-- Use new payload struct

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
                            "reasoning_chunk" => Ok(StreamEvent::ReasoningChunk(message.data)), // NEWLY ADDED
                            "message" => {
                                #[derive(Deserialize)]
                                struct PartialText { text: String }
                                match serde_json::from_str::<PartialText>(&message.data) {
                                    Ok(partial) => {
                                        tracing::debug!(event_type = %message.event, data = %message.data, "Parsed partial message event");
                                        Ok(StreamEvent::PartialMessage(partial.text))
                                    }
                                    Err(e) => {
                                        tracing::warn!(event_type = %message.event, data = %message.data, error = %e, "Failed to parse data for 'message' SSE event, skipping");
                                        continue; // Skip this event, go to next es.next().await
                                    }
                                }
                            },
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

    // NEW: Implement update_chat_settings
    async fn update_chat_settings(&self, session_id: Uuid, payload: &UpdateChatSettingsRequest) -> Result<ChatSettingsResponse, CliError> {
        let url = build_url(&self.base_url, &format!("/api/chats/{}/settings", session_id))?;
        tracing::info!(%url, %session_id, payload = ?payload, "Updating chat settings via HttpClient");

        let response = self.client.put(url).json(payload).send().await.map_err(CliError::Reqwest)?;
        handle_response(response).await
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
        matchers::{all_of, request, contains, key}, // Add any
        responders::{json_encoded, status_code}, // Added json_encoded and status_code
        Expectation, ServerPool, ServerHandle,
    };
    use scribe_backend::models::auth::LoginPayload;
    use scribe_backend::models::characters::CharacterMetadata; // Added import for tests
    use serde_json::json;
    use url::Url;
    use uuid::Uuid;
    use chrono::Utc;
    use tempfile::NamedTempFile; // Added NamedTempFile
    use bigdecimal::BigDecimal; // Added BigDecimal
    use std::io::Write; // Added Write for temp_file
    use std::str::FromStr; // Added FromStr for BigDecimal

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
        let (server, client_wrapper) = setup_test_server();
        let user_id = Uuid::new_v4();
        let mock_user = json!({
            "user_id": user_id,
            "username": "testuser",
            "email": "test@example.com",
            "created_at": Utc::now().to_rfc3339(),
            "updated_at": Utc::now().to_rfc3339()
        });

        server.expect(
            Expectation::matching(request::method_path("POST", "/api/auth/login"))
                .respond_with(json_encoded(mock_user)),
        );

        let credentials = LoginPayload {
            identifier: "testuser".to_string(),
            password: SecretString::new("password123".to_string().into()),
        };
        let result = client_wrapper.login(&credentials).await;

        eprintln!("Login test result: {:?}", result);
        assert!(result.is_ok(), "Login failed: {:?}", result.err());
        let user = result.unwrap();
        assert_eq!(user.id, user_id);
        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");
    }

    #[tokio::test]
    async fn test_login_failure_unauthorized() {
        let (mut server, client) = setup_test_server();

        let credentials = LoginPayload {
            identifier: "testuser".to_string(),
            password: SecretString::new("wrongpassword".to_string().into()),
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

        let credentials = LoginPayload {
            identifier: "testuser".to_string(),
            password: SecretString::new("password".to_string().into()),
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
        let (server, client_wrapper) = setup_test_server();
        let user_id = Uuid::new_v4();
        let mock_user_response = json!({
            "user_id": user_id,
            "username": "newuser",
            "email": "new@example.com",
            "created_at": Utc::now().to_rfc3339(),
            "updated_at": Utc::now().to_rfc3339()
        });

        server.expect(
            Expectation::matching(request::method_path("POST", "/api/auth/register"))
                .respond_with(json_encoded(mock_user_response))
        );

        let credentials = RegisterPayload {
            username: "newuser".to_string(),
            email: "new@example.com".to_string(),
            password: SecretString::new("password123".to_string().into()),
        };
        let result = client_wrapper.register(&credentials).await;

        eprintln!("Register test result: {:?}", result);
        assert!(result.is_ok(), "Registration failed: {:?}", result.err());
        let user = result.unwrap();
        assert_eq!(user.id, user_id);
        assert_eq!(user.username, "newuser");
        assert_eq!(user.email, "new@example.com");
    }

    #[tokio::test]
    async fn test_register_failure_conflict() {
        let (mut server, client) = setup_test_server();
        
        let register_payload = RegisterPayload {
            username: "existinguser".to_string(),
            email: "existing@example.com".to_string(),
            password: SecretString::new("password123".to_string().into()),
        };
        
        let error_body = "Username already taken";
        
        server.expect(
            Expectation::matching(request::method_path("POST", "/api/auth/register"))
                .respond_with(status_code(409).body(error_body))
        );
        
        let result = client.register(&register_payload).await;
        
        assert!(result.is_err());
        match result.err().unwrap() {
            CliError::RegistrationFailed(msg) => {
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

        // Create mock responses that match the backend format (with Vec<u8> for encrypted fields)
        let char1_response = json!({
            "id": char1_id,
            "user_id": user_id_mock,
            "name": "Character One",
            "spec": "chara_card_v3",
            "spec_version": "1.0",
            "description": "Description One".to_string().into_bytes(),
            "description_nonce": null,
            "first_mes": "Hello from Character One!".to_string().into_bytes(),
            "first_mes_nonce": null,
            "created_at": now,
            "updated_at": now
        });

        let char2_response = json!({
            "id": char2_id,
            "user_id": user_id_mock,
            "name": "Character Two",
            "spec": "chara_card_v3",
            "spec_version": "1.0",
            "description": null,
            "description_nonce": null,
            "first_mes": null,
            "first_mes_nonce": null,
            "created_at": now,
            "updated_at": now
        });

        let mock_response = json!([char1_response, char2_response]);

        server.expect(
            Expectation::matching(request::method_path("GET", "/api/characters"))
                .respond_with(json_encoded(mock_response)),
        );

        let result = client.list_characters().await;

        assert!(result.is_ok());
        let characters = result.unwrap();
        assert_eq!(characters.len(), 2);
        assert_eq!(characters[0].id, char1_id);
        assert_eq!(characters[1].name, "Character Two");
        // Now we can directly check the strings since our deserializer converts bytes to strings
        assert_eq!(characters[0].description, Some("Description One".to_string()));
        assert_eq!(characters[0].first_mes, Some("Hello from Character One!".to_string()));
        assert_eq!(characters[1].description, None);
        assert_eq!(characters[1].first_mes, None);

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_list_characters_success_empty() {
        let (mut server, client) = setup_test_server();

        // Empty JSON array response
        let mock_characters: Vec<Value> = vec![];

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

        // Create a response that matches the backend format with byte arrays
        let mock_response = json!({
            "id": mock_response_id,
            "user_id": mock_response_user_id,
            "name": character_name,
            "spec": "chara_card_v3",
            "spec_version": "1.0",
            "description": "Uploaded via test".to_string().into_bytes(),
            "description_nonce": null,
            "first_mes": "Hello from upload!".to_string().into_bytes(),
            "first_mes_nonce": null,
            "created_at": now,
            "updated_at": now
        });

        // Define the expected multipart body parts
        server.expect(
            Expectation::matching(all_of![
                request::method_path("POST", "/api/characters/upload"),
                // Simplified: Check only for the presence of the Content-Type header key
                request::headers(contains(key("content-type"))),
            ])
            .respond_with(json_encoded(mock_response)),
        );

        let result = client
            .upload_character(character_name, &temp_file_path)
            .await;

        assert!(result.is_ok());
        let uploaded_char = result.unwrap();
        assert_eq!(uploaded_char.id, mock_response_id);
        assert_eq!(uploaded_char.name, character_name);
        assert_eq!(uploaded_char.description, Some("Uploaded via test".to_string()));
        assert_eq!(uploaded_char.first_mes, Some("Hello from upload!".to_string()));

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
        let (server, client_wrapper) = setup_test_server();
        let user_id = Uuid::new_v4();
        let mock_user = json!({
            "user_id": user_id,
            "username": "currentuser",
            "email": "user@example.com",
            "created_at": Utc::now().to_rfc3339(),
            "updated_at": Utc::now().to_rfc3339()
        });

        server.expect(
            Expectation::matching(request::method_path("GET", "/api/auth/me"))
                .respond_with(json_encoded(mock_user)),
        );

        let result = client_wrapper.me().await;
        eprintln!("Me test result: {:?}", result);
        assert!(result.is_ok(), "Fetching /me failed: {:?}", result.err());
        let user = result.unwrap();
        assert_eq!(user.id, user_id);
        assert_eq!(user.username, "currentuser");
        assert_eq!(user.email, "user@example.com");
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
        
        // Create a response that matches the backend format with byte arrays
        let mock_character = json!({
            "id": character_id,
            "user_id": user_id_mock,
            "name": "Specific Character",
            "spec": "chara_card_v3",
            "spec_version": "1.0",
            "description": "Details here".to_string().into_bytes(),
            "description_nonce": null,
            "first_mes": "Specific greeting".to_string().into_bytes(),
            "first_mes_nonce": null,
            "created_at": now,
            "updated_at": now
        });

        let path_string = format!("/api/characters/{}", character_id);
        let static_path_str: &'static str = Box::leak(path_string.into_boxed_str());
        server.expect(
            Expectation::matching(request::method_path(
                "GET",
                static_path_str, // Pass &'static str
            ))
            .respond_with(json_encoded(mock_character)),
        );

        let result = client.get_character(character_id).await;

        assert!(result.is_ok());
        let character = result.unwrap();
        assert_eq!(character.id, character_id);
        assert_eq!(character.name, "Specific Character");
        assert_eq!(character.description, Some("Details here".to_string()));
        assert_eq!(character.first_mes, Some("Specific greeting".to_string()));

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
        use serde_json::json;

        let mock_sessions = vec![
            Chat {
                id: session1_id,
                user_id: user_id_mock,
                character_id: char_id_mock,
                title: Some("First Chat".to_string()),
                created_at: now,
                updated_at: now,
                system_prompt: None,
                temperature: Some(BigDecimal::from_str("0.8").unwrap()),
                max_output_tokens: Some(512),
                frequency_penalty: None,
                presence_penalty: None,
                top_k: None,
                top_p: None,
                repetition_penalty: None,
                min_p: None,
                top_a: None,
                seed: None,
                logit_bias: None,
                history_management_strategy: "window".to_string(),
                history_management_limit: 20,
                visibility: Some("private".to_string()),
                model_name: "default-model".to_string(), // Added missing field
                gemini_thinking_budget: None,
                gemini_enable_code_execution: None,
            },
            Chat {
                id: session2_id,
                user_id: user_id_mock,
                character_id: Uuid::new_v4(), // Different character
                title: Some("Second Chat".to_string()),
                created_at: now,
                updated_at: now,
                system_prompt: Some("You are helpful.".to_string()),
                temperature: None,
                max_output_tokens: None,
                frequency_penalty: Some(BigDecimal::from_str("0.1").unwrap()), // Assuming FromStr is now in scope
                presence_penalty: Some(BigDecimal::from_str("0.2").unwrap()), // Assuming FromStr is now in scope
                top_k: Some(40),
                top_p: Some(BigDecimal::from_str("0.95").unwrap()), // Assuming FromStr is now in scope
                repetition_penalty: Some(BigDecimal::from_str("1.1").unwrap()), // Assuming FromStr is now in scope
                min_p: None,
                top_a: None,
                seed: Some(123),
                logit_bias: Some(json!({ "token_id": -1.0 })),
                history_management_strategy: "window".to_string(),
                history_management_limit: 20,
                visibility: Some("private".to_string()),
                model_name: "default-model".to_string(), // Added missing field (already present, ensuring consistency)
                gemini_thinking_budget: None,
                gemini_enable_code_execution: None,
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
        assert_eq!(sessions[1].system_prompt, mock_sessions[1].system_prompt);
        assert_eq!(sessions[0].temperature, mock_sessions[0].temperature);
        assert_eq!(sessions[1].seed, mock_sessions[1].seed);

        server.verify_and_clear();
    }

    #[tokio::test]
    async fn test_list_chat_sessions_success_empty() {
        let (mut server, client) = setup_test_server();

        let mock_sessions: Vec<Chat> = vec![]; // Changed from ChatSession to Chat

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
                user_id: Uuid::nil(), // Use Uuid::nil() for test context
                message_type: MessageRole::User,
                content: "Hello there".to_string().into_bytes(),
                content_nonce: None,
                created_at: now,
            },
            ChatMessage {
                id: Uuid::new_v4(),
                session_id,
                user_id: Uuid::nil(), // Use Uuid::nil() for test context
                message_type: MessageRole::Assistant,
                content: "General Kenobi!".to_string().into_bytes(),
                content_nonce: None,
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
        assert_eq!(messages[0].content, mock_messages[0].content); // content is Vec<u8>
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
        use serde_json::json; // Import json!

        let mock_session = Chat {
            id: session_id,
            user_id: user_id_mock, // Assuming backend returns this
            character_id,
            title: Some("New Chat".to_string()),
            created_at: now,
            updated_at: now,
            system_prompt: None,
            temperature: None,
            max_output_tokens: None,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            history_management_strategy: "window".to_string(),
            history_management_limit: 20,
            visibility: Some("private".to_string()),
            model_name: "default-model".to_string(), // Added missing field (already present, ensuring consistency)
            gemini_thinking_budget: None,
            gemini_enable_code_execution: None,
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
        assert_eq!(response_message.content, response_content.as_bytes());
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
