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
use validator::{Validate, ValidationError}; // Import validator

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
    // History Management Fields
    pub history_management_strategy: String,
    pub history_management_limit: i32,
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
    // History Management Fields
    String,             // history_management_strategy
    i32,                // history_management_limit
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
    pub user_id: Uuid,              // Changed to non-optional Uuid to match schema
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
    // History Management Fields
    pub history_management_strategy: String,
    pub history_management_limit: i32,
}

/// Request body for PUT /api/chats/{id}/settings
/// All fields are optional to allow partial updates.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, AsChangeset, Validate, Default)] // Added AsChangeset, Validate & Default
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
    // History Management Fields
    #[validate(custom(function = "validate_optional_history_strategy"))]
    pub history_management_strategy: Option<String>,
    #[validate(range(min = 1))]
    pub history_management_limit: Option<i32>,
}

// Custom validation function for history_management_strategy (called only when Some)
fn validate_optional_history_strategy(strategy: &String) -> Result<(), ValidationError> {
    match strategy.as_str() {
        "sliding_window_tokens" | "sliding_window_messages" | "truncate_tokens" | "none" => Ok(()),
        _ => Err(ValidationError::new("invalid_history_strategy")),
    }
    // No need to handle None case here, validator only calls this for Some(value)
}


#[cfg(test)]
mod tests {
    use validator::Validate; // Import the Validate trait for tests
    use super::*;
    use bigdecimal::BigDecimal; // Import BigDecimal
    use chrono::Utc;
    use serde_json::json; // Import json macro
    use std::str::FromStr; // For BigDecimal::from_str
    use uuid::Uuid;

    // Helper function to create BigDecimal from a string for tests
    fn bd(s: &str) -> BigDecimal {
        BigDecimal::from_str(s).expect("Invalid decimal string")
    }

    // Helper function to create a sample chat session
    fn create_sample_chat_session() -> ChatSession {
        ChatSession {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            character_id: Uuid::new_v4(),
            title: Some("Test Chat".to_string()),
            system_prompt: Some("You are a helpful assistant".to_string()),
            temperature: Some(bd("0.7")),
            max_output_tokens: Some(1024),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            frequency_penalty: Some(bd("0.0")),
            presence_penalty: Some(bd("0.0")),
            top_k: Some(50),
            top_p: Some(bd("0.9")),
            repetition_penalty: Some(bd("1.1")),
            min_p: Some(bd("0.05")),
            top_a: Some(bd("0.0")),
            seed: Some(12345),
            logit_bias: Some(json!({"50256": -100})),
            history_management_strategy: "none".to_string(), // Add default test value
            history_management_limit: 4096,                 // Add default test value
        }
    }

    #[test]
    fn test_debug_chat_session() {
        let session = create_sample_chat_session();
        let debug_str = format!("{:?}", session);
        assert!(debug_str.contains("ChatSession"));
        assert!(debug_str.contains(&session.id.to_string()));
        assert!(debug_str.contains("Test Chat"));
        assert!(debug_str.contains("history_management_strategy: \"none\"")); // Check new field
    }

    #[test]
    fn test_clone_chat_session() {
        let original = create_sample_chat_session();
        let cloned = original.clone();

        assert_eq!(original.id, cloned.id);
        assert_eq!(original.user_id, cloned.user_id);
        assert_eq!(original.character_id, cloned.character_id);
        assert_eq!(original.title, cloned.title);
        assert_eq!(original.system_prompt, cloned.system_prompt);
        assert_eq!(original.temperature, cloned.temperature);
        assert_eq!(original.max_output_tokens, cloned.max_output_tokens);
        // Advanced settings
        assert_eq!(original.frequency_penalty, cloned.frequency_penalty);
        assert_eq!(original.presence_penalty, cloned.presence_penalty);
        assert_eq!(original.top_k, cloned.top_k);
        assert_eq!(original.top_p, cloned.top_p);
        assert_eq!(original.repetition_penalty, cloned.repetition_penalty);
        assert_eq!(original.min_p, cloned.min_p);
        assert_eq!(original.top_a, cloned.top_a);
        assert_eq!(original.seed, cloned.seed);
        assert_eq!(original.logit_bias, cloned.logit_bias);
        // Add assertions for new fields
        assert_eq!(original.history_management_strategy, cloned.history_management_strategy);
        assert_eq!(original.history_management_limit, cloned.history_management_limit);
    }

    #[test]
    fn test_debug_message_role() {
        assert!(format!("{:?}", MessageRole::User).contains("User"));
        assert!(format!("{:?}", MessageRole::Assistant).contains("Assistant"));
        assert!(format!("{:?}", MessageRole::System).contains("System"));
    }

    #[test]
    fn test_clone_message_role() {
        let original = MessageRole::User;
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_message_role_display() {
        assert_eq!(MessageRole::User.to_string(), "User");
        assert_eq!(MessageRole::Assistant.to_string(), "Assistant");
        assert_eq!(MessageRole::System.to_string(), "System");
    }

    // Helper function to create a sample chat message
    fn create_sample_chat_message() -> ChatMessage {
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "Hello, how are you?".to_string(),
            created_at: Utc::now(),
            user_id: Uuid::new_v4(), // Add dummy user_id for test data
        }
    }

    #[test]
    fn test_debug_chat_message() {
        let message = create_sample_chat_message();
        let debug_str = format!("{:?}", message);
        assert!(debug_str.contains("ChatMessage"));
        assert!(debug_str.contains(&message.id.to_string()));
        assert!(debug_str.contains("Hello, how are you?"));
    }

    #[test]
    fn test_clone_chat_message() {
        let original = create_sample_chat_message();
        let cloned = original.clone();

        assert_eq!(original.id, cloned.id);
        assert_eq!(original.session_id, cloned.session_id);
        assert_eq!(original.message_type, cloned.message_type);
        assert_eq!(original.content, cloned.content);
        assert_eq!(original.created_at, cloned.created_at);
        assert_eq!(original.user_id, cloned.user_id); // Assert user_id
    }

    #[test]
    fn test_serde_chat_message() {
        let message = create_sample_chat_message();
        let serialized = serde_json::to_string(&message).expect("Serialization failed");
        let deserialized: ChatMessage = serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(message.id, deserialized.id);
        assert_eq!(message.session_id, deserialized.session_id);
        assert_eq!(message.message_type, deserialized.message_type);
        assert_eq!(message.content, deserialized.content);
        // Note: DateTime<Utc> might have precision differences after serde
        // assert_eq!(message.created_at, deserialized.created_at);
        assert_eq!(message.user_id, deserialized.user_id); // Assert user_id
    }

    // Helper function to create a sample new chat message
    fn create_sample_new_chat_message() -> NewChatMessage {
        NewChatMessage {
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "Hello!".to_string(),
        }
    }

    #[test]
    fn test_debug_new_chat_message() {
        let message = create_sample_new_chat_message();
        let debug_str = format!("{:?}", message);
        assert!(debug_str.contains("NewChatMessage"));
        assert!(debug_str.contains(&message.session_id.to_string()));
        assert!(debug_str.contains("Hello!"));
    }

    #[test]
    fn test_clone_new_chat_message() {
        let original = create_sample_new_chat_message();
        let cloned = original.clone();

        assert_eq!(original.session_id, cloned.session_id);
        assert_eq!(original.message_type, cloned.message_type);
        assert_eq!(original.content, cloned.content);
    }

    #[test]
    fn test_db_insertable_chat_message() {
        let chat_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let role = MessageRole::User;
        let content = "Test message";

        let message = DbInsertableChatMessage::new(chat_id, user_id, role, content.to_string());

        assert_eq!(message.chat_id, chat_id);
        assert_eq!(message.user_id, user_id);
        assert_eq!(message.role, role);
        assert_eq!(message.content, content);
    }

    // Helper function to create a sample chat settings response
    fn create_sample_chat_settings_response() -> ChatSettingsResponse {
        ChatSettingsResponse {
            system_prompt: Some("You are a helpful assistant".to_string()),
            temperature: Some(bd("0.7")),
            max_output_tokens: Some(1024),
            frequency_penalty: Some(bd("0.0")),
            presence_penalty: Some(bd("0.0")),
            top_k: Some(50),
            top_p: Some(bd("0.9")),
            repetition_penalty: Some(bd("1.1")),
            min_p: Some(bd("0.05")),
            top_a: Some(bd("0.0")),
            seed: Some(12345),
            logit_bias: Some(json!({"50256": -100})),
            // Add new fields to response helper
            history_management_strategy: "none".to_string(),
            history_management_limit: 4096,
        }
    }

    #[test]
    fn test_debug_chat_settings_response() {
        let settings = create_sample_chat_settings_response();
        let debug_str = format!("{:?}", settings);
        assert!(debug_str.contains("ChatSettingsResponse"));
        assert!(debug_str.contains("You are a helpful assistant"));
        assert!(debug_str.contains("temperature: Some"));
        assert!(debug_str.contains("history_management_strategy: \"none\"")); // Check new field
    }

    #[test]
    fn test_clone_chat_settings_response() {
        let original = create_sample_chat_settings_response();
        let cloned = original.clone();

        assert_eq!(original.system_prompt, cloned.system_prompt);
        assert_eq!(original.temperature, cloned.temperature);
        assert_eq!(original.max_output_tokens, cloned.max_output_tokens);
        // Add assertions for new fields
        assert_eq!(original.history_management_strategy, cloned.history_management_strategy);
        assert_eq!(original.history_management_limit, cloned.history_management_limit);
    }

    // Helper function to create a sample update chat settings request
    fn create_sample_update_chat_settings_request() -> UpdateChatSettingsRequest {
        UpdateChatSettingsRequest {
            system_prompt: Some("You are a helpful assistant".to_string()),
            temperature: Some(bd("0.8")),
            max_output_tokens: Some(2048),
            frequency_penalty: Some(bd("0.1")),
            presence_penalty: Some(bd("0.1")),
            top_k: Some(40),
            top_p: Some(bd("0.95")),
            repetition_penalty: Some(bd("1.2")),
            min_p: Some(bd("0.1")),
            top_a: Some(bd("0.1")),
            seed: Some(54321),
            logit_bias: Some(json!({"50256": -50})),
            // Add new fields to request helper
            history_management_strategy: Some("sliding_window_tokens".to_string()),
            history_management_limit: Some(2000),
        }
    }

    #[test]
    fn test_debug_update_chat_settings_request() {
        let settings = create_sample_update_chat_settings_request();
        let debug_str = format!("{:?}", settings);
        assert!(debug_str.contains("UpdateChatSettingsRequest"));
        assert!(debug_str.contains("You are a helpful assistant"));
        assert!(debug_str.contains("temperature: Some"));
        assert!(debug_str.contains("history_management_strategy: Some(\"sliding_window_tokens\")")); // Check new field
    }

    #[test]
    fn test_clone_update_chat_settings_request() {
        let original = create_sample_update_chat_settings_request();
        let cloned = original.clone();

        assert_eq!(original.system_prompt, cloned.system_prompt);
        assert_eq!(original.temperature, cloned.temperature);
        assert_eq!(original.max_output_tokens, cloned.max_output_tokens);
        // Add assertions for new fields
        assert_eq!(original.history_management_strategy, cloned.history_management_strategy);
        assert_eq!(original.history_management_limit, cloned.history_management_limit);
    }

    #[test]
    fn test_serde_chat_settings_response() {
        let settings = create_sample_chat_settings_response();
        let serialized = serde_json::to_string(&settings).expect("Serialization failed");
        let deserialized: ChatSettingsResponse = serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(settings.system_prompt, deserialized.system_prompt);
        assert_eq!(settings.temperature, deserialized.temperature);
        assert_eq!(settings.max_output_tokens, deserialized.max_output_tokens);
        // Add assertions for new fields
        assert_eq!(settings.history_management_strategy, deserialized.history_management_strategy);
        assert_eq!(settings.history_management_limit, deserialized.history_management_limit);
    }

    #[test]
    fn test_serde_update_chat_settings_request() {
        let settings = create_sample_update_chat_settings_request();
        let serialized = serde_json::to_string(&settings).expect("Serialization failed");
        let deserialized: UpdateChatSettingsRequest = serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(settings.system_prompt, deserialized.system_prompt);
        assert_eq!(settings.temperature, deserialized.temperature);
        assert_eq!(settings.max_output_tokens, deserialized.max_output_tokens);
        // Add assertions for new fields
        assert_eq!(settings.history_management_strategy, deserialized.history_management_strategy);
        assert_eq!(settings.history_management_limit, deserialized.history_management_limit);
    }

    #[test]
    fn test_new_chat_message_request_serde() {
        let original = NewChatMessageRequest {
            content: "Hello AI".to_string(),
            model: Some("gpt-4".to_string()),
        };

        let serialized = serde_json::to_string(&original).expect("Serialization failed");
        let deserialized: NewChatMessageRequest = serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(original.content, deserialized.content);
        assert_eq!(original.model, deserialized.model);
    }

    #[test]
    fn test_generate_response_payload_serde() {
        let original = GenerateResponsePayload {
            content: "Hello human".to_string(),
            model: Some("gpt-4".to_string()),
        };

        let serialized = serde_json::to_string(&original).expect("Serialization failed");
        let deserialized: GenerateResponsePayload = serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(original.content, deserialized.content);
        assert_eq!(original.model, deserialized.model);
    }

    #[test]
    fn test_partial_eq_chat_settings_response() {
        let settings1 = create_sample_chat_settings_response();
        let mut settings2 = settings1.clone();

        assert_eq!(settings1, settings2);

        settings2.temperature = Some(bd("0.9"));
        assert_ne!(settings1, settings2);

        // Add test for new fields inequality
        settings2 = settings1.clone();
        settings2.history_management_limit = 1000;
        assert_ne!(settings1, settings2);

        settings2 = settings1.clone();
        settings2.history_management_strategy = "sliding_window_messages".to_string();
        assert_ne!(settings1, settings2);
    }

    #[test]
    fn test_partial_eq_update_chat_settings_request() {
        let settings1 = create_sample_update_chat_settings_request();
        let mut settings2 = settings1.clone();

        assert_eq!(settings1, settings2);

        settings2.temperature = Some(bd("0.7"));
        assert_ne!(settings1, settings2);

        // Add test for new fields inequality
        settings2 = settings1.clone();
        settings2.history_management_strategy = Some("none".to_string());
        assert_ne!(settings1, settings2);

        settings2 = settings1.clone();
        settings2.history_management_limit = Some(100);
        assert_ne!(settings1, settings2);
    }

    #[test]
    fn test_update_chat_settings_request_validation() {
        // Valid
        let valid_settings = UpdateChatSettingsRequest {
            history_management_strategy: Some("sliding_window_tokens".to_string()),
            history_management_limit: Some(1000),
            ..Default::default() // Use default for other fields
        };
        assert!(valid_settings.validate().is_ok());

        let valid_settings_none = UpdateChatSettingsRequest {
            history_management_strategy: Some("none".to_string()),
            history_management_limit: Some(1), // Min limit
            ..Default::default()
        };
        assert!(valid_settings_none.validate().is_ok());

        // Invalid strategy
        let invalid_strategy = UpdateChatSettingsRequest {
            history_management_strategy: Some("invalid_strategy".to_string()),
            history_management_limit: Some(1000),
            ..Default::default()
        };
        let err = invalid_strategy.validate().unwrap_err();
        assert!(err.field_errors().contains_key("history_management_strategy"));
        assert_eq!(err.field_errors()["history_management_strategy"][0].code, "invalid_history_strategy");


        // Invalid limit (zero)
        let invalid_limit_zero = UpdateChatSettingsRequest {
            history_management_strategy: Some("none".to_string()),
            history_management_limit: Some(0),
            ..Default::default()
        };
         let err = invalid_limit_zero.validate().unwrap_err();
        assert!(err.field_errors().contains_key("history_management_limit"));
        assert_eq!(err.field_errors()["history_management_limit"][0].code, "range");


        // Invalid limit (negative)
        let invalid_limit_neg = UpdateChatSettingsRequest {
            history_management_strategy: Some("none".to_string()),
            history_management_limit: Some(-100),
            ..Default::default()
        };
        let err = invalid_limit_neg.validate().unwrap_err();
        assert!(err.field_errors().contains_key("history_management_limit"));
        assert_eq!(err.field_errors()["history_management_limit"][0].code, "range");

        // Test optional fields being None (should be valid)
        let none_settings = UpdateChatSettingsRequest {
            history_management_strategy: None,
            history_management_limit: None,
            ..Default::default()
        };
        assert!(none_settings.validate().is_ok());
    }
}
