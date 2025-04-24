use crate::schema::{chat_messages, chat_sessions};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use bigdecimal::BigDecimal; // Add import
use crate::models::users::User;
use crate::models::characters::CharacterMetadata;
use tracing::error;
use serde_json::Value; // Add import for JSON value

// Import necessary Diesel traits for manual enum mapping
use diesel::deserialize::{self, FromSql};
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, IsNull, Output, ToSql};
use std::io::Write;
use diesel::{AsExpression, FromSqlRow};

// Represents a chat session in the database
#[derive(Queryable, Selectable, Identifiable, Associations, Debug, Clone, Serialize, Deserialize)]
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
    Option<String>,      // system_prompt
    Option<BigDecimal>,  // temperature
    Option<i32>,         // max_output_tokens
    Option<BigDecimal>,  // frequency_penalty
    Option<BigDecimal>,  // presence_penalty
    Option<i32>,         // top_k
    Option<BigDecimal>,  // top_p
    Option<BigDecimal>,  // repetition_penalty
    Option<BigDecimal>,  // min_p
    Option<BigDecimal>,  // top_a
    Option<i32>,         // seed
    Option<Value>,       // logit_bias
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, AsExpression, FromSqlRow)]
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
                error!("Unrecognized message_type enum variant from DB: {:?}", String::from_utf8_lossy(unrecognized));
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
#[derive(Queryable, Selectable, Identifiable, Associations, Debug, Clone, Serialize, Deserialize)]
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
#[derive(Insertable, Default)]
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
}

impl DbInsertableChatMessage {
    pub fn new(
        chat_id: Uuid,
        _user_id: Option<Uuid>, // Keep this parameter for backward compatibility
        role: MessageRole,
        text: String,
    ) -> Self {
        Self {
            chat_id,
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
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)] // Added Serialize
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