//! This module aggregates all DTOs used for client-server communication.

pub mod user_personas;
// Add other type modules here as needed, e.g.:
// pub mod characters;
// pub mod chat_sessions;

// Potentially re-export common types if desired for easier access
pub use self::user_personas::{CreateUserPersonaDto, UserPersonaDataForClient, UpdateUserPersonaDto};

// --- Content from old cli/src/client/types.rs below ---

use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use scribe_backend::models::characters::CharacterDataForClient;
use scribe_backend::models::users::{User, UserRole};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use uuid::Uuid;
// Import the backend Json type directly for conversion
use diesel_json::Json as DieselJson;

// Custom Json type to mirror backend's diesel_json::Json
#[derive(Debug, Clone, Deserialize, Serialize)] // Added Serialize
pub struct Json<T>(pub T);

// Define the expected response structure from the /health endpoint (matching backend)
#[derive(serde::Deserialize, serde::Serialize, Debug, Clone)]
pub struct HealthStatus {
    pub status: String,
}

// Update AuthUserResponse to include role and recovery key
#[derive(Deserialize, Debug, Clone)]
pub struct AuthUserResponse {
    pub user_id: Uuid,
    pub username: String,
    pub email: String,
    pub role: String, // Changed from Option<String> to String since backend now always returns role
    pub recovery_key: Option<String>, // Add recovery key field
}

// Map AuthUserResponse to User for compatibility
impl From<AuthUserResponse> for User {
    fn from(auth: AuthUserResponse) -> Self {
        // Map role string to UserRole enum
        let role = match auth.role.as_str() {
            "Administrator" => UserRole::Administrator,
            "Moderator" => UserRole::Moderator,
            _ => UserRole::User, // Default to User role
        };

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
            dek: None, // Option<SerializableSecretDek>
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            role,                                       // Add the role field
            recovery_phrase: None,                      // Add the recovery_phrase field
            account_status: Some("active".to_string()), // Default to active, may be overridden by login response
        }
    }
}

// NEW: Define the StreamEvent enum for SSE events
#[derive(Debug, Deserialize, Clone)] // Added Deserialize and Clone
#[serde(tag = "event", content = "data")] // Specify how to deserialize based on SSE event name
#[serde(rename_all = "snake_case")] // Match backend event names (e.g., event: thinking)
pub enum StreamEvent {
    Thinking(String),       // Corresponds to event: thinking, data: "step description"
    Content(String),        // Corresponds to event: content, data: "text chunk"
    ReasoningChunk(String), // NEW: Corresponds to event: reasoning_chunk, data: "reasoning text chunk"
    PartialMessage(String), // NEW: For event: message, data: {"text": "..."}
    Done,                   // Corresponds to event: done (no data expected)
}

// NEW: Intermediate struct for the non-streaming response body
// This is internal to the response handling logic, so not pub
#[derive(Deserialize)]
pub(crate) struct NonStreamingResponse {
    pub(crate) message_id: Uuid,
    pub(crate) content: String,
}

/// Client-side wrapper for CharacterDataForClient that can deserialize from the backend's encrypted format
/// This handles the fact that some string fields are now returned as Vec<u8> from the backend
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
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

// NEW: Struct for deserializing chat message responses from the backend
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ClientChatMessageResponse {
    pub id: Uuid,
    pub session_id: Uuid,
    pub message_type: String, // Or a specific enum if defined, like MessageRole
    pub role: String,         // Or a specific enum
    pub parts: Value,         // serde_json::Value for flexible structure like `[{"text": "..."}]`
    pub attachments: Value,   // serde_json::Value for flexible structure
    pub created_at: DateTime<Utc>,
    // Add other fields if the backend MessageResponse includes them and they are needed by CLI
    // pub user_id: Option<Uuid>, // Example: if backend sends user_id for messages
}

// Custom deserializer function that can handle both string and byte array formats
// This function is module-private as it's only used by ClientCharacterDataForClient's serde attributes
fn deserialize_option_bytes_to_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    // First try deserializing as any value
    let value = serde_json::Value::deserialize(deserializer)?;

    // Handle different value types
    match value {
        // Null - return None
        serde_json::Value::Null => Ok(None),
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
            let bytes: Result<Vec<u8>, _> = arr
                .into_iter()
                .map(|v| {
                    if let serde_json::Value::Number(n) = v {
                        if let Some(i) = n.as_u64() {
                            if i <= 255 {
                                return Ok(i as u8);
                            }
                        }
                    }
                    Err(serde::de::Error::custom(format!(
                        "Expected byte value 0-255"
                    )))
                })
                .collect();

            match bytes {
                Ok(b) if b.is_empty() => Ok(None),
                Ok(b) => String::from_utf8(b)
                    .map(Some)
                    .map_err(|e| serde::de::Error::custom(format!("Invalid UTF-8: {}", e))),
                Err(e) => Err(e),
            }
        }
        // Any other value type - error
        v => Err(serde::de::Error::custom(format!(
            "Expected string, byte array, or null, got {:?}",
            v
        ))),
    }
}
// Helper for deserializing Vec<u8> to String, typically for non-optional encrypted fields
fn deserialize_bytes_to_string_for_override<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    match value {
        serde_json::Value::Array(arr) => {
            let bytes: Result<Vec<u8>, _> = arr
                .into_iter()
                .map(|v| {
                    if let serde_json::Value::Number(n) = v {
                        if let Some(i) = n.as_u64() {
                            if i <= 255 {
                                return Ok(i as u8);
                            }
                        }
                    }
                    Err(serde::de::Error::custom(format!(
                        "Expected byte value 0-255"
                    )))
                })
                .collect();

            match bytes {
                Ok(b) => String::from_utf8(b)
                    .map_err(|e| serde::de::Error::custom(format!("Invalid UTF-8: {}", e))),
                Err(e) => Err(e),
            }
        }
        serde_json::Value::String(s) => Ok(s), // Allow if it's already a string
        v => Err(serde::de::Error::custom(format!(
            "Expected byte array or string, got {:?}",
            v
        ))),
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
            creator_notes_multilingual: client
                .creator_notes_multilingual
                .map(|json| DieselJson(json.0)),
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

// Admin User List Response DTO
#[derive(Debug, Deserialize, Clone)]
pub struct AdminUserListResponse {
    pub id: Uuid,
    pub username: String,
    pub role: String,
    pub account_status: String,
}

// Admin User Detail Response DTO
#[derive(Debug, Deserialize, Clone)]
pub struct AdminUserDetailResponse {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub role: String,
    pub account_status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// Update User Role Request DTO
#[derive(Debug, Serialize)]
pub struct UpdateUserRoleRequest {
    pub role: String,
}

// Create a local wrapper for LoginPayload that implements Serialize
// This is internal to the implementation module, so not pub
#[derive(Serialize)]
pub(crate) struct SerializableLoginPayload<'a> {
    pub(crate) identifier: &'a str,
    pub(crate) password: &'a str,
}

impl<'a> From<&'a scribe_backend::models::auth::LoginPayload> for SerializableLoginPayload<'a> {
    fn from(payload: &'a scribe_backend::models::auth::LoginPayload) -> Self {
        // Use the expose_secret method to get the password value
        SerializableLoginPayload {
            identifier: &payload.identifier,
            password: payload.password.expose_secret(),
        }
    }
}

// Add a new struct for RegisterPayload used by the client
#[derive(Debug, Clone)] // Removed Serialize since SecretString is not directly serializable
pub struct RegisterPayload {
    pub username: String,
    pub email: String,
    pub password: SecretString,
}

// Add a serializable version of RegisterPayload for requests
// This is internal to the implementation module, so not pub
#[derive(Serialize)]
pub(crate) struct SerializableRegisterPayload<'a> {
    pub(crate) username: &'a str,
    pub(crate) email: &'a str,
    pub(crate) password: &'a str,
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

// DTO for character creation requests (mirrors backend/src/models/character_dto.rs)
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CharacterCreateDto {
    // Required fields
    pub name: Option<String>,
    pub description: Option<String>,
    pub first_mes: Option<String>,

    // Optional fields
    #[serde(default)]
    pub personality: String,
    #[serde(default)]
    pub scenario: String,
    #[serde(default)]
    pub mes_example: String,
    #[serde(default)]
    pub creator_notes: String,
    #[serde(default)]
    pub system_prompt: String,
    #[serde(default)]
    pub post_history_instructions: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub creator: String,
    #[serde(default)]
    pub character_version: String,
    #[serde(default)]
    pub alternate_greetings: Vec<String>,
    #[serde(default)]
    pub creator_notes_multilingual: Option<Json<Value>>,
    #[serde(default)]
    pub nickname: Option<String>,
    #[serde(default)]
    pub source: Option<Vec<String>>,
    #[serde(default)]
    pub group_only_greetings: Vec<String>,
    #[serde(default)]
    pub creation_date: Option<i64>,
    #[serde(default)]
    pub modification_date: Option<i64>,
    #[serde(default)]
    pub extensions: Option<Json<Value>>,
    // Fields from CharacterCardDataV2 (ensure these are covered if needed by CLI)
    #[serde(default)]
    pub persona: String, // Note: In backend DTO, this is not Option. For CLI create, it's optional.
    #[serde(default)]
    pub world_scenario: String, // Note: In backend DTO, this is not Option.
    #[serde(default)]
    pub avatar: String, // e.g. "char_image.png" or "none"
    #[serde(default)]
    pub chat: String, // Example: "character_chat_history.jsonl"
    #[serde(default)]
    pub greeting: String,
    #[serde(default)]
    pub definition: String, // TavernAI card definition
    #[serde(default)]
    pub default_voice: String,
    #[serde(default)]
    pub data_id: Option<i32>,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub definition_visibility: String,
    #[serde(default)]
    pub depth: Option<i32>,
    #[serde(default)]
    pub example_dialogue: String,
    #[serde(default)]
    pub favorite: Option<bool>,
    #[serde(default)]
    pub first_message_visibility: String,
    #[serde(default)]
    pub height: Option<BigDecimal>,
    #[serde(default)]
    pub last_activity: Option<DateTime<Utc>>,
    #[serde(default)]
    pub migrated_from: String,
    #[serde(default)]
    pub model_prompt: String,
    #[serde(default)]
    pub model_prompt_visibility: String,
    #[serde(default)]
    pub model_temperature: Option<BigDecimal>,
    #[serde(default)]
    pub num_interactions: Option<i64>,
    #[serde(default)]
    pub permanence: Option<BigDecimal>,
    #[serde(default)]
    pub persona_visibility: String,
    #[serde(default)]
    pub revision: Option<i32>,
    #[serde(default)]
    pub sharing_visibility: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub system_prompt_visibility: String,
    #[serde(default)]
    pub system_tags: Vec<String>,
    #[serde(default)]
    pub token_budget: Option<i32>,
    #[serde(default)]
    pub usage_hints: Option<Json<Value>>,
    #[serde(default)]
    pub user_persona: String,
    #[serde(default)]
    pub user_persona_visibility: String,
    #[serde(default)]
    pub visibility: String,
    #[serde(default)]
    pub weight: Option<BigDecimal>,
    #[serde(default)]
    pub world_scenario_visibility: String,
}

// DTO for character update requests (mirrors backend/src/models/character_dto.rs)
// All fields are optional to allow partial updates
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CharacterUpdateDto {
    pub name: Option<String>,
    pub description: Option<String>,
    pub personality: Option<String>,
    pub scenario: Option<String>,
    pub first_mes: Option<String>,
    pub mes_example: Option<String>,
    pub creator_notes: Option<String>,
    pub system_prompt: Option<String>,
    pub post_history_instructions: Option<String>,
    pub tags: Option<Vec<String>>,
    pub creator: Option<String>,
    pub character_version: Option<String>,
    pub alternate_greetings: Option<Vec<String>>,
    pub creator_notes_multilingual: Option<Json<Value>>,
    pub nickname: Option<String>,
    pub source: Option<Vec<String>>,
    pub group_only_greetings: Option<Vec<String>>,
    pub creation_date: Option<i64>,
    pub modification_date: Option<i64>,
    pub extensions: Option<Json<Value>>,
    // Fields from CharacterCardDataV2
    pub persona: Option<String>,
    pub world_scenario: Option<String>,
    pub avatar: Option<String>,
    pub chat: Option<String>,
    pub greeting: Option<String>,
    pub definition: Option<String>,
    pub default_voice: Option<String>,
    pub data_id: Option<i32>,
    pub category: Option<String>,
    pub definition_visibility: Option<String>,
    pub depth: Option<i32>,
    pub example_dialogue: Option<String>,
    pub favorite: Option<bool>,
    pub first_message_visibility: Option<String>,
    pub height: Option<BigDecimal>,
    pub last_activity: Option<DateTime<Utc>>,
    pub migrated_from: Option<String>,
    pub model_prompt: Option<String>,
    pub model_prompt_visibility: Option<String>,
    pub model_temperature: Option<BigDecimal>,
    pub num_interactions: Option<i64>,
    pub permanence: Option<BigDecimal>,
    pub persona_visibility: Option<String>,
    pub revision: Option<i32>,
    pub sharing_visibility: Option<String>,
    pub status: Option<String>,
    pub system_prompt_visibility: Option<String>,
    pub system_tags: Option<Vec<String>>,
    pub token_budget: Option<i32>,
    pub usage_hints: Option<Json<Value>>,
    pub user_persona: Option<String>,
    pub user_persona_visibility: Option<String>,
    pub visibility: Option<String>,
    pub weight: Option<BigDecimal>,
    pub world_scenario_visibility: Option<String>,
}

/// DTO for chat session details, used when fetching a session to get its original character ID.
#[derive(Debug, Deserialize, Clone)]
pub struct ChatSessionDetails {
    pub id: Uuid,
    pub user_id: Uuid,
    pub character_id: Uuid, // This is the original_character_id
    pub title: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    // Add other fields from backend ChatSession if needed by CLI
    // e.g., settings, model_name, etc.
}

/// DTO for the request to set a character override for a chat session.
#[derive(Debug, Serialize, Clone)]
pub struct CharacterOverrideRequest {
    pub field_name: String,
    pub value: String,
}

/// DTO for the successful response of a character override operation.
/// This should match the actual response from the backend.
#[derive(Debug, Deserialize, Clone)]
pub struct OverrideSuccessResponse {
    pub message: String, // e.g., "Override applied successfully."
    pub session_id: Uuid,
    pub field_name: String,
    pub new_value: String, // The backend might return the applied value
}

/// DTO for representing a character override as returned by the backend.
/// This is used when fetching effective character details for a chat.
/// It needs to handle potentially encrypted fields.
#[derive(Debug, Deserialize, Clone)]
pub struct CliChatCharacterOverride {
    pub id: Uuid,
    pub session_id: Uuid,
    pub character_id: Uuid,
    pub field_name: String,
    #[serde(deserialize_with = "deserialize_bytes_to_string_for_override")]
    pub overriden_value: String, // Stored as Vec<u8> in DB, needs deserialization
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}