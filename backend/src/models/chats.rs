use crate::schema::{chat_messages, chat_sessions};
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::models::users::User;
use crate::models::characters::CharacterMetadata;
use tracing::error;

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
    // pub system_prompt: Option<String>, // Added in later migration
    // pub temperature: Option<f64>,
    // pub max_output_tokens: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

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

// Request body for sending a new message (used by generate endpoint)
#[derive(Deserialize, Debug)]
pub struct NewChatMessageRequest {
    pub content: String,
    // Role is often implicit based on the sender/endpoint being called
} 