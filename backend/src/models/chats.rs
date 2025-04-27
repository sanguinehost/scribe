use crate::models::characters::CharacterMetadata;
use crate::models::users::User;
use crate::schema::{chat_messages, chat_sessions};
use bigdecimal::BigDecimal; // Add import
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::error;
use uuid::Uuid; // Add import for JSON value

// Import necessary Diesel traits for manual enum mapping
use diesel::deserialize::{self, FromSql};
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, IsNull, Output, ToSql};
use diesel::{AsExpression, FromSqlRow};
use std::io::Write;

// Represents a chat session in the database
#[derive(
    Queryable, Selectable, Identifiable, Associations, Debug, Clone, Serialize, Deserialize,
)]
#[diesel(belongs_to(User, foreign_key = user_id))]
#[diesel(belongs_to(CharacterMetadata, foreign_key = character_id))]
#[diesel(table_name = chat_sessions)]
pub struct ChatSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub character_id: Uuid,
    pub title: Option<String>,
    pub system_prompt: Option<String>,
    pub temperature: Option<BigDecimal>, // Changed f32 to BigDecimal to match NUMERIC
    pub max_output_tokens: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    // New generation settings fields
    pub frequency_penalty: Option<BigDecimal>,
    pub presence_penalty: Option<BigDecimal>,
    pub top_k: Option<i32>,
    pub top_p: Option<BigDecimal>,
    pub repetition_penalty: Option<BigDecimal>,
    pub min_p: Option<BigDecimal>,
    pub top_a: Option<BigDecimal>,
    pub seed: Option<i32>,
    pub logit_bias: Option<Value>, // JSONB maps to serde_json::Value
}

// Type alias for the tuple returned when querying chat session settings
pub type SettingsTuple = (
    Option<String>,     // system_prompt
    Option<BigDecimal>, // temperature
    Option<i32>,        // max_output_tokens
    Option<BigDecimal>, // frequency_penalty
    Option<BigDecimal>, // presence_penalty
    Option<i32>,        // top_k
    Option<BigDecimal>, // top_p
    Option<BigDecimal>, // repetition_penalty
    Option<BigDecimal>, // min_p
    Option<BigDecimal>, // top_a
    Option<i32>,        // seed
    Option<Value>,      // logit_bias
);

// For creating a new chat session
#[derive(Insertable)]
#[diesel(table_name = chat_sessions)]
pub struct NewChatSession {
    pub user_id: Uuid,
    pub character_id: Uuid,
    // Add initial settings if needed
}

// Enum to represent the role of the sender
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, AsExpression, FromSqlRow,
)]
#[diesel(sql_type = crate::schema::sql_types::MessageType)]
pub enum MessageRole {
    #[default]
    User,
    Assistant,
    System,
}

// Manual ToSql implementation
impl ToSql<crate::schema::sql_types::MessageType, Pg> for MessageRole {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        match *self {
            MessageRole::User => out.write_all(b"User")?,
            MessageRole::Assistant => out.write_all(b"Assistant")?,
            MessageRole::System => out.write_all(b"System")?,
        }
        Ok(IsNull::No)
    }
}

// Manual FromSql implementation
impl FromSql<crate::schema::sql_types::MessageType, Pg> for MessageRole {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        match bytes.as_bytes() {
            b"User" => Ok(MessageRole::User),
            b"Assistant" => Ok(MessageRole::Assistant),
            b"System" => Ok(MessageRole::System),
            unrecognized => {
                error!(
                    "Unrecognized message_type enum variant from DB: {:?}",
                    String::from_utf8_lossy(unrecognized)
                );
                Err("Unrecognized enum variant from database".into())
            }
        }
    }
}

// Implement Display for MessageRole
impl std::fmt::Display for MessageRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageRole::User => write!(f, "User"),
            MessageRole::Assistant => write!(f, "Assistant"),
            MessageRole::System => write!(f, "System"),
        }
    }
}

// Represents a chat message in the database
#[derive(
    Queryable, Selectable, Identifiable, Associations, Debug, Clone, Serialize, Deserialize,
)]
#[diesel(belongs_to(ChatSession, foreign_key = session_id))]
#[diesel(table_name = chat_messages)]
pub struct ChatMessage {
    pub id: Uuid,
    #[diesel(column_name = session_id)]
    pub session_id: Uuid,
    #[diesel(column_name = message_type)]
    pub message_type: MessageRole,
    pub content: String,
    pub created_at: DateTime<Utc>,
    // pub embedding: Option<Vec<f32>>, // Maybe store embeddings here later? Or Qdrant?
    // pub token_count: Option<i32>,
}

// For inserting a new chat message
#[derive(Insertable, Default, Debug, Clone)] // Added Debug and Clone
#[diesel(table_name = chat_messages)]
pub struct NewChatMessage {
    pub session_id: Uuid,
    pub message_type: MessageRole,
    pub content: String,
}

// For inserting a new chat message with better naming clarity
#[derive(Insertable, Debug)]
#[diesel(table_name = chat_messages)]
pub struct DbInsertableChatMessage {
    #[diesel(column_name = session_id)]
    pub chat_id: Uuid, // Maps to session_id in the database
    #[diesel(column_name = message_type)]
    pub role: MessageRole, // Maps to message_type in the database
    pub content: String,
    pub user_id: Uuid, // Add the user_id field
}

impl DbInsertableChatMessage {
    pub fn new(
        chat_id: Uuid,
        user_id: Uuid, // Change parameter to non-optional Uuid
        role: MessageRole,
        text: String,
    ) -> Self {
        Self {
            chat_id,
            user_id, // Assign the user_id
            role,
            content: text,
        }
    }
}

// Request body for sending a new message (used by generate endpoint)
// Added Serialize for cases where it might be returned or logged
#[derive(Deserialize, Serialize, Debug)]
pub struct NewChatMessageRequest {
    pub content: String,
    // Add optional model field
    pub model: Option<String>,
    // Role is often implicit based on the sender/endpoint being called
}

// API Request/Response Structures

#[derive(Deserialize, Debug)]
pub struct CreateChatSessionPayload {
    pub character_id: Uuid,
}

#[derive(Deserialize, Serialize, Debug)] // Added Serialize
pub struct GenerateResponsePayload {
    pub content: String,
    pub model: Option<String>, // Added optional model field
}

#[derive(Serialize, Debug)]
pub struct GenerateResponse {
    pub ai_message: ChatMessage,
}

// --- Chat Settings API Structures ---

/// Response body for GET /api/chats/{id}/settings
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ChatSettingsResponse {
    pub system_prompt: Option<String>,
    pub temperature: Option<BigDecimal>, // Changed f32 to BigDecimal
    pub max_output_tokens: Option<i32>,
    // New generation settings fields
    pub frequency_penalty: Option<BigDecimal>,
    pub presence_penalty: Option<BigDecimal>,
    pub top_k: Option<i32>,
    pub top_p: Option<BigDecimal>,
    pub repetition_penalty: Option<BigDecimal>,
    pub min_p: Option<BigDecimal>,
    pub top_a: Option<BigDecimal>,
    pub seed: Option<i32>,
    pub logit_bias: Option<Value>,
}

/// Request body for PUT /api/chats/{id}/settings
/// All fields are optional to allow partial updates.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, AsChangeset)] // Added AsChangeset
#[diesel(table_name = crate::schema::chat_sessions)] // Specify target table
pub struct UpdateChatSettingsRequest {
    pub system_prompt: Option<String>,
    pub temperature: Option<BigDecimal>, // Changed f32 to BigDecimal
    pub max_output_tokens: Option<i32>,
    // New generation settings fields
    pub frequency_penalty: Option<BigDecimal>,
    pub presence_penalty: Option<BigDecimal>,
    pub top_k: Option<i32>,
    pub top_p: Option<BigDecimal>,
    pub repetition_penalty: Option<BigDecimal>,
    pub min_p: Option<BigDecimal>,
    pub top_a: Option<BigDecimal>,
    pub seed: Option<i32>,
    pub logit_bias: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bigdecimal::BigDecimal; // Import BigDecimal
    use chrono::Utc;
    use serde_json::json; // Import json macro
    use std::str::FromStr; // For BigDecimal::from_str
    use uuid::Uuid;

    // Helper to create BigDecimal from string, panicking on error
    fn bd(s: &str) -> BigDecimal {
        BigDecimal::from_str(s).expect("Invalid BigDecimal string in test")
    }

    // --- ChatSession Tests (Lines 20-46) ---

    fn create_sample_chat_session() -> ChatSession {
        ChatSession {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            character_id: Uuid::new_v4(),
            title: Some("Test Chat Session".to_string()),
            system_prompt: Some("You are a helpful assistant.".to_string()),
            temperature: Some(bd("0.7")),
            max_output_tokens: Some(256),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            frequency_penalty: Some(bd("0.1")),
            presence_penalty: Some(bd("0.2")),
            top_k: Some(50),
            top_p: Some(bd("0.9")),
            repetition_penalty: Some(bd("1.1")),
            min_p: Some(bd("0.05")),
            top_a: Some(bd("0.8")),
            seed: Some(12345),
            logit_bias: Some(json!({ "token_id": 1.5 })),
        }
    }

    #[test]
    fn test_debug_chat_session() {
        let session = create_sample_chat_session();
        let debug_output = format!("{:?}", session);
        assert!(!debug_output.is_empty());
        assert!(debug_output.contains("Test Chat Session"));
        assert!(debug_output.contains("helpful assistant"));
        println!("ChatSession Debug: {}", debug_output);
        assert!(debug_output.contains("temperature: Some("));
    }

    #[test]
    fn test_clone_chat_session() {
        let session = create_sample_chat_session();
        let cloned_session = session.clone();
        // Basic field comparison (PartialEq not derived, compare key fields)
        assert_eq!(session.id, cloned_session.id);
        assert_eq!(session.user_id, cloned_session.user_id);
        assert_eq!(session.character_id, cloned_session.character_id);
        assert_eq!(session.title, cloned_session.title);
        assert_eq!(session.system_prompt, cloned_session.system_prompt);
        assert_eq!(session.temperature, cloned_session.temperature);
        assert_eq!(session.max_output_tokens, cloned_session.max_output_tokens);
        assert_eq!(session.logit_bias, cloned_session.logit_bias);
    }

    // --- MessageRole Tests (Lines 74-124) ---
    // Testing Debug and Clone for the enum itself

    #[test]
    fn test_debug_message_role() {
        assert_eq!(format!("{:?}", MessageRole::User), "User");
        assert_eq!(format!("{:?}", MessageRole::Assistant), "Assistant");
        assert_eq!(format!("{:?}", MessageRole::System), "System");
    }

    #[test]
    fn test_clone_message_role() {
        let role = MessageRole::Assistant;
        let cloned_role = role.clone();
        assert_eq!(role, cloned_role); // PartialEq is derived
    }

    // --- ChatMessage Tests (Lines 127-142) ---

    fn create_sample_chat_message() -> ChatMessage {
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "Hello!".to_string(),
            created_at: Utc::now(),
        }
    }

    #[test]
    fn test_debug_chat_message() {
        let message = create_sample_chat_message();
        let debug_output = format!("{:?}", message);
        assert!(!debug_output.is_empty());
        assert!(debug_output.contains("message_type: User"));
        assert!(debug_output.contains("Hello!"));
    }

    #[test]
    fn test_clone_chat_message() {
        let message = create_sample_chat_message();
        let cloned_message = message.clone();
        // Basic field comparison (PartialEq not derived)
        assert_eq!(message.id, cloned_message.id);
        assert_eq!(message.session_id, cloned_message.session_id);
        assert_eq!(message.message_type, cloned_message.message_type);
        assert_eq!(message.content, cloned_message.content);
        assert_eq!(message.created_at, cloned_message.created_at);
    }

    // --- NewChatMessage Tests (Lines 145-151) ---

    fn create_sample_new_chat_message() -> NewChatMessage {
        NewChatMessage {
            session_id: Uuid::new_v4(),
            message_type: MessageRole::Assistant,
            content: "Hi there!".to_string(),
        }
    }

    #[test]
    fn test_debug_new_chat_message() {
        let new_message = create_sample_new_chat_message();
        let debug_output = format!("{:?}", new_message); // Requires Debug derive
        assert!(!debug_output.is_empty());
        assert!(debug_output.contains("message_type: Assistant"));
        assert!(debug_output.contains("Hi there!"));
    }

    #[test]
    fn test_clone_new_chat_message() {
        let new_message = create_sample_new_chat_message();
        let cloned_message = new_message.clone(); // Requires Clone derive
        // Basic field comparison (PartialEq not derived)
        assert_eq!(new_message.session_id, cloned_message.session_id);
        assert_eq!(new_message.message_type, cloned_message.message_type);
        assert_eq!(new_message.content, cloned_message.content);
    }

    // --- ChatSettingsResponse Tests (Lines 212-227) ---

    fn create_sample_chat_settings_response() -> ChatSettingsResponse {
        ChatSettingsResponse {
            system_prompt: Some("Response system prompt".to_string()),
            temperature: Some(bd("0.75")),
            max_output_tokens: Some(512),
            frequency_penalty: Some(bd("0.15")),
            presence_penalty: Some(bd("0.25")),
            top_k: Some(40),
            top_p: Some(bd("0.95")),
            repetition_penalty: Some(bd("1.15")),
            min_p: Some(bd("0.06")),
            top_a: Some(bd("0.85")),
            seed: Some(54321),
            logit_bias: Some(json!({ "another_token": -0.5 })),
        }
    }

    #[test]
    fn test_debug_chat_settings_response() {
        let settings = create_sample_chat_settings_response();
        let debug_output = format!("{:?}", settings);
        assert!(!debug_output.is_empty());
        assert!(debug_output.contains("Response system prompt"));
        println!("ChatSettingsResponse Debug: {}", debug_output);
        assert!(debug_output.contains("temperature: Some("));
        assert!(debug_output.contains("logit_bias: Some(Object"));
    }

    #[test]
    fn test_clone_chat_settings_response() {
        let settings = create_sample_chat_settings_response();
        let cloned_settings = settings.clone();
        assert_eq!(settings, cloned_settings); // PartialEq is derived
    }

    // --- UpdateChatSettingsRequest Tests (Lines 231-247) ---

    fn create_sample_update_chat_settings_request() -> UpdateChatSettingsRequest {
        UpdateChatSettingsRequest {
            system_prompt: Some("Updated system prompt".to_string()),
            temperature: Some(bd("0.65")),
            max_output_tokens: Some(1024),
            frequency_penalty: None, // Test None
            presence_penalty: Some(bd("0.3")),
            top_k: Some(60),
            top_p: None, // Test None
            repetition_penalty: Some(bd("1.2")),
            min_p: Some(bd("0.07")),
            top_a: None, // Test None
            seed: Some(98765),
            logit_bias: Some(json!({ "updated_bias": 2.0 })),
        }
    }

    // Note: Default is not derived for UpdateChatSettingsRequest, so no default test needed.

    #[test]
    fn test_debug_update_chat_settings_request() {
        let settings = create_sample_update_chat_settings_request();
        let debug_output = format!("{:?}", settings);
        assert!(!debug_output.is_empty());
        assert!(debug_output.contains("Updated system prompt"));
        println!("UpdateChatSettingsRequest Debug: {}", debug_output);
        assert!(debug_output.contains("temperature: Some("));
        assert!(debug_output.contains("logit_bias: Some(Object"));
    }

    #[test]
    fn test_clone_update_chat_settings_request() {
        let update_settings = create_sample_update_chat_settings_request();
        let cloned_settings = update_settings.clone();
        assert_eq!(update_settings, cloned_settings); // PartialEq is derived
    }
}
