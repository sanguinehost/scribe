use crate::schema::{chat_messages, chat_sessions};
use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::error; // Added warn
use uuid::Uuid;
use validator::{Validate, ValidationError};

// Import necessary Diesel traits for manual enum mapping
use diesel::deserialize::{self, FromSql};
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, IsNull, Output, ToSql};
use diesel::{AsExpression, FromSqlRow};
use std::io::Write;

use secrecy::SecretBox; // For DEK (SecretBox<Vec<u8>>)
use secrecy::ExposeSecret; // Added for ExposeSecret
use crate::crypto::{decrypt_gcm, encrypt_gcm}; // For encryption/decryption
use crate::errors::AppError; // For error handling
use crate::models::users::SerializableSecretDek; // Import the newtype

// Main Chat model (similar to the frontend Chat type)
// Type alias for the tuple returned when selecting/returning chat settings
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
    String,             // history_management_strategy
    i32,                // history_management_limit
    String,             // model_name
    // -- Gemini Specific Options --
    Option<i32>,        // gemini_thinking_budget
    Option<bool>,       // gemini_enable_code_execution
);
#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Debug, Clone)]
#[diesel(table_name = chat_sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Chat {
    pub id: Uuid,
    pub user_id: Uuid,
    pub character_id: Uuid,
    pub title: Option<String>,
    pub system_prompt: Option<String>,
    pub temperature: Option<bigdecimal::BigDecimal>,
    pub max_output_tokens: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub frequency_penalty: Option<bigdecimal::BigDecimal>,
    pub presence_penalty: Option<bigdecimal::BigDecimal>,
    pub top_k: Option<i32>,
    pub top_p: Option<bigdecimal::BigDecimal>,
    pub repetition_penalty: Option<bigdecimal::BigDecimal>,
    pub min_p: Option<bigdecimal::BigDecimal>,
    pub top_a: Option<bigdecimal::BigDecimal>,
    pub seed: Option<i32>,
    pub logit_bias: Option<serde_json::Value>,
    pub history_management_strategy: String,
    pub history_management_limit: i32,
    pub model_name: String,
    pub visibility: Option<String>, // Added based on migration 2025-05-10-100002
    // -- Gemini Specific Options --
    pub gemini_thinking_budget: Option<i32>,      // Corresponds to u32, but Diesel might prefer i32 for Option<INT4>
    pub gemini_enable_code_execution: Option<bool>,
}

// New Chat for insertion
#[derive(Insertable, Debug, Clone)]
#[diesel(table_name = chat_sessions)]
pub struct NewChat {
    pub id: Uuid,
    pub user_id: Uuid,
    pub character_id: Uuid,
    pub title: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub history_management_strategy: String,
    pub history_management_limit: i32,
    pub model_name: String,
    pub visibility: Option<String>,
}

// Chat Message model
#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Debug, Clone)]
#[diesel(table_name = chat_messages)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Message {
    pub id: Uuid,
    pub session_id: Uuid,
    pub message_type: MessageRole, // Changed String to MessageRole
    pub content: Vec<u8>,
    pub content_nonce: Option<Vec<u8>>, // Added nonce
    pub rag_embedding_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub user_id: Uuid,
    pub role: Option<String>,
    pub parts: Option<serde_json::Value>,
    pub attachments: Option<serde_json::Value>,
}

// New Message for insertion
#[derive(Insertable, Debug)]
#[diesel(table_name = chat_messages)]
pub struct NewMessage {
    pub id: Uuid,
    pub session_id: Uuid,
    pub message_type: MessageRole, // Changed String to MessageRole
    pub content: Vec<u8>,
    pub content_nonce: Option<Vec<u8>>, // Added nonce
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub role: Option<String>,
    pub parts: Option<serde_json::Value>,
    pub attachments: Option<serde_json::Value>,
}

// Request/Response DTOs
#[derive(Deserialize, Debug)]
pub struct CreateChatRequest {
    #[serde(default)]
    pub title: String,
    pub character_id: Uuid,
}

#[derive(Serialize, Debug)]
pub struct ChatResponse {
    pub id: Uuid,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub user_id: Uuid,
    pub visibility: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct CreateMessageRequest {
    pub role: String,
    pub content: String,
    pub parts: Option<serde_json::Value>,
    pub attachments: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MessageResponse {
    pub id: Uuid,
    pub session_id: Uuid, // Renamed from chat_id
    pub message_type: MessageRole, // Added missing field
    pub role: String, // TODO: Consider removing this if message_type covers it? Check usage.
    pub parts: serde_json::Value,
    pub attachments: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

// Vote model
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Vote {
    pub chat_id: Uuid,
    pub message_id: Uuid,
    pub is_upvoted: bool,
}

#[derive(Deserialize, Debug)]
pub struct VoteRequest {
    pub message_id: Uuid,
    pub type_: String, // "up" or "down"
}

// Visibility update
#[derive(Deserialize, Debug)]
pub struct UpdateChatVisibilityRequest {
    pub visibility: String, // "public" or "private"
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
#[diesel(belongs_to(Chat, foreign_key = session_id))] // Renamed ChatSession to Chat
#[diesel(table_name = chat_messages)]
pub struct ChatMessage {
    pub id: Uuid,
    #[diesel(column_name = session_id)]
    pub session_id: Uuid,
    #[diesel(column_name = message_type)]
    pub message_type: MessageRole,
    pub content: Vec<u8>,
    pub content_nonce: Option<Vec<u8>>, // Added nonce
    pub created_at: DateTime<Utc>,
    pub user_id: Uuid,              // Changed to non-optional Uuid to match schema
    // pub embedding: Option<Vec<f32>>, // Maybe store embeddings here later? Or Qdrant?
    // pub token_count: Option<i32>,
}

impl ChatMessage {
    /// Encrypts the content field if plaintext is provided and a DEK is available.
    /// Updates self.content and self.content_nonce.
    pub fn encrypt_content_field(
        &mut self,
        dek: &SecretBox<Vec<u8>>,
        plaintext_content: String, // Assuming plaintext comes as String
    ) -> Result<(), AppError> {
        if !plaintext_content.is_empty() {
            let (ciphertext, nonce) = encrypt_gcm(plaintext_content.as_bytes(), dek)
                .map_err(|e| AppError::CryptoError(e.to_string()))?;
            self.content = ciphertext;
            self.content_nonce = Some(nonce);
        } else {
            self.content = Vec::new();
            self.content_nonce = None; // No nonce if content is empty
        }
        Ok(())
    }

    /// Decrypts the content field if ciphertext and nonce are present and a DEK is available.
    /// Returns String representing the decrypted content.
    pub fn decrypt_content_field(
        &self,
        dek: &SecretBox<Vec<u8>>,
    ) -> Result<String, AppError> { // content_nonce is taken from self.content_nonce
        if self.content.is_empty() {
            return Ok(String::new()); // Return empty string if content is empty
        }
        
        match &self.content_nonce {
            Some(nonce_bytes) => {
                if nonce_bytes.is_empty() {
                    tracing::error!(
                        "ChatMessage ID {} content nonce is present but empty. Cannot decrypt.",
                        self.id
                    );
                    return Err(AppError::DecryptionError("Missing nonce for content decryption".to_string()));
                }
                match decrypt_gcm(&self.content, nonce_bytes, dek) {
                    Ok(plaintext_secret_vec) => {
                        String::from_utf8(plaintext_secret_vec.expose_secret().to_vec())
                            .map_err(|e| {
                                error!("Failed to convert decrypted message content to UTF-8: {}", e);
                                AppError::DecryptionError("Failed to convert message content to UTF-8".to_string())
                            })
                    }
                    Err(e) => {
                        error!("Failed to decrypt chat message content for ID {}: {}", self.id, e);
                        Err(AppError::DecryptionError(format!("Decryption failed for message content: {}", e)))
                    }
                }
            }
            None => {
                tracing::error!(
                    "ChatMessage ID {} content is present but nonce is missing. Cannot decrypt.",
                    self.id
                );
                Err(AppError::DecryptionError("Missing nonce for content decryption".to_string()))
            }
        }
    }

    /// Convert this ChatMessage to a decrypted ClientChatMessage
    pub fn into_decrypted_for_client(self, user_dek_secret_box: Option<&SecretBox<Vec<u8>>>) -> Result<ChatMessageForClient, AppError> {
        let decrypted_content_result: Result<String, AppError> = if let Some(nonce) = &self.content_nonce {
            if let Some(dek_sb) = user_dek_secret_box {
                match crate::crypto::decrypt_gcm(&self.content, nonce, dek_sb) { 
                    Ok(plaintext_secret_vec) => {
                        String::from_utf8(plaintext_secret_vec.expose_secret().to_vec())
                            .map_err(|e| {
                                error!("UTF-8 conversion error for msg {}: {:?}", self.id, e);
                                AppError::DecryptionError(format!("UTF-8 conversion: {}", e))
                            })
                    },
                    Err(e) => {
                        error!("Decryption failed for msg {}: {:?}", self.id, e);
                        Err(AppError::DecryptionError(format!("Decryption failed: {}", e)))
                    }
                }
            } else {
                error!("Msg {} is encrypted but no DEK provided.", self.id);
                // This case should probably be an error too if strict decryption is required.
                // For now, matches previous behavior of returning placeholder.
                Ok("[Content encrypted, DEK not available]".to_string()) 
            }
        } else {
            // No nonce, assume plaintext
            String::from_utf8(self.content.clone())
                .map_err(|e| {
                    error!("Invalid UTF-8 in plaintext for msg {}: {:?}", self.id, e);
                    AppError::InternalServerErrorGeneric(format!("Invalid UTF-8: {}", e))
                })
        };

        let final_decrypted_content = decrypted_content_result?;

        Ok(ChatMessageForClient {
            id: self.id,
            session_id: self.session_id,
            message_type: self.message_type, 
            content: final_decrypted_content,
            created_at: self.created_at,
            user_id: self.user_id, 
        })
    }
}

/// JSON-friendly structure for client responses
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientChatMessage {
    pub id: Uuid,
    pub chat_id: Uuid,
    pub character_id: Uuid,
    pub content: String,
    pub role: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Structure for sending ChatMessage data to the client, with decrypted content.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChatMessageForClient {
    pub id: Uuid,
    pub session_id: Uuid,
    pub message_type: MessageRole,
    pub content: String, // Decrypted content
    pub created_at: DateTime<Utc>,
    pub user_id: Uuid,
    // Include other fields from ChatMessage if they are also sent to client
    // pub role: Option<String>, // from Message struct, if needed
    // pub parts: Option<serde_json::Value>, // from Message struct, if needed
    // pub attachments: Option<serde_json::Value>, // from Message struct, if needed
}

// Moved into_decrypted_for_client from ChatMessage to Message struct
impl Message {
    pub fn into_decrypted_for_client(self, dek: Option<&SecretBox<Vec<u8>>>) -> Result<ChatMessageForClient, AppError> {
        let decrypted_content_string = if !self.content.is_empty() {
            match dek {
                Some(actual_dek) => {
                    let nonce_bytes = self.content_nonce.as_deref()
                        .ok_or_else(|| AppError::DecryptionError("Nonce missing for content decryption".to_string()))?;
                    if nonce_bytes.is_empty() {
                        return Err(AppError::DecryptionError("Nonce is empty for content decryption".to_string()));
                    }
                    match decrypt_gcm(&self.content, nonce_bytes, actual_dek) { 
                        Ok(plaintext_bytes_secret) => {
                            String::from_utf8(plaintext_bytes_secret.expose_secret().to_vec()).map_err(|e| {
                                tracing::error!("Failed to convert decrypted message content to UTF-8: {}", e);
                                AppError::DecryptionError("Failed to convert message content to UTF-8".to_string())
                            })
                        }
                        Err(e) => {
                            error!("Failed to decrypt chat message content for ID {}: {}", self.id, e);
                            Err(AppError::DecryptionError(format!("Decryption failed for message content: {}", e)))
                        }
                    }
                }
                None => {
                    error!("Attempted to decrypt chat message (ID: {}) but no DEK provided in session.", self.id);
                    Err(AppError::DecryptionError("DEK not available for message decryption".to_string()))
                }
            }
        } else {
            Ok(String::new()) // Content was empty to begin with
        }?;

        Ok(ChatMessageForClient {
            id: self.id,
            session_id: self.session_id,
            message_type: self.message_type,
            content: decrypted_content_string,
            created_at: self.created_at,
            user_id: self.user_id,
        })
    }
}


// For inserting a new chat message
#[derive(Insertable, Default, Debug, Clone)]
#[diesel(table_name = chat_messages)]
pub struct NewChatMessage {
    pub session_id: Uuid,
    pub message_type: MessageRole,
    pub content: Vec<u8>, // This will store encrypted content
    // Add user_id if it's part of NewChatMessage and not set by default in DB
    // pub user_id: Uuid, // Example, check schema and insertion logic
}

// For inserting a new chat message with better naming clarity
#[derive(Insertable, Debug)]
#[diesel(table_name = chat_messages)]
pub struct DbInsertableChatMessage {
    #[diesel(column_name = session_id)]
    pub chat_id: Uuid, // Maps to session_id in the database
    #[diesel(column_name = message_type)]
    pub role: MessageRole, // Maps to message_type in the database
    pub content: Vec<u8>,
    pub content_nonce: Option<Vec<u8>>, // Added nonce
    pub user_id: Uuid, // Add the user_id field
}

impl DbInsertableChatMessage {
    pub fn new(
        chat_id: Uuid,
        user_id: Uuid, // Change parameter to non-optional Uuid
        role: MessageRole,
        text: Vec<u8>,
        nonce: Option<Vec<u8>>, // Added nonce parameter
    ) -> Self {
        DbInsertableChatMessage {
            chat_id,
            user_id, // Ensure user_id is assigned
            role,
            content: text,
            content_nonce: nonce, // Assign nonce
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

// --- Generate Endpoint Payload Structures ---

/// Represents a single message within the chat history payload.
#[derive(Deserialize, Serialize, Debug, Clone, Validate)]
pub struct ApiChatMessage {
    #[validate(length(min = 1))] // Role cannot be empty
    pub role: String, // Expecting "user", "assistant", "system"
    #[validate(length(min = 1))] // Content cannot be empty
    pub content: String,
}

/// Request body for POST /api/chats/{session_id}/generate
#[derive(Deserialize, Serialize, Debug, Validate)] // Added Validate
pub struct GenerateChatRequest {
    #[validate(length(min = 1))] // History must contain at least one message
    #[validate(nested)] // Validate each ApiChatMessage within the Vec
    pub history: Vec<ApiChatMessage>,
    pub model: Option<String>, // Keep optional model override
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
    // Model Name
    pub model_name: String,
    // Gemini Specific Options
    pub gemini_thinking_budget: Option<i32>,
    pub gemini_enable_code_execution: Option<bool>,
}
// Implement From<Chat> for ChatSettingsResponse
impl From<Chat> for ChatSettingsResponse {
    fn from(chat: Chat) -> Self {
        ChatSettingsResponse {
            system_prompt: chat.system_prompt,
            temperature: chat.temperature,
            max_output_tokens: chat.max_output_tokens,
            frequency_penalty: chat.frequency_penalty,
            presence_penalty: chat.presence_penalty,
            top_k: chat.top_k,
            top_p: chat.top_p,
            repetition_penalty: chat.repetition_penalty,
            min_p: chat.min_p,
            top_a: chat.top_a,
            seed: chat.seed,
            logit_bias: chat.logit_bias,
            history_management_strategy: chat.history_management_strategy,
            history_management_limit: chat.history_management_limit,
            model_name: chat.model_name,
            gemini_thinking_budget: chat.gemini_thinking_budget,
            gemini_enable_code_execution: chat.gemini_enable_code_execution,
        }
    }
}

/// Request body for PUT /api/chats/{id}/settings
/// All fields are optional to allow partial updates.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, AsChangeset, Validate, Default)] // Added AsChangeset, Validate & Default
#[diesel(table_name = crate::schema::chat_sessions)] // Specify target table
pub struct UpdateChatSettingsRequest {
    pub system_prompt: Option<String>,
    #[validate(custom(function = "validate_optional_temperature"))]
    pub temperature: Option<BigDecimal>, // Changed f32 to BigDecimal
    #[validate(range(min = 1))]
    pub max_output_tokens: Option<i32>,
    // New generation settings fields
    #[validate(custom(function = "validate_optional_frequency_penalty"))]
    pub frequency_penalty: Option<BigDecimal>,
    #[validate(custom(function = "validate_optional_presence_penalty"))]
    pub presence_penalty: Option<BigDecimal>,
    #[validate(range(min = 0))]
    pub top_k: Option<i32>,
    #[validate(custom(function = "validate_optional_top_p"))]
    pub top_p: Option<BigDecimal>,
    #[validate(custom(function = "validate_optional_repetition_penalty"))]
    pub repetition_penalty: Option<BigDecimal>,
    #[validate(custom(function = "validate_optional_min_p"))]
    pub min_p: Option<BigDecimal>,
    #[validate(custom(function = "validate_optional_top_a"))]
    pub top_a: Option<BigDecimal>,
    pub seed: Option<i32>,
    #[validate(custom(function = "validate_optional_logit_bias"))]
    pub logit_bias: Option<Value>,
    // History Management Fields
    #[validate(custom(function = "validate_optional_history_strategy"))]
    pub history_management_strategy: Option<String>,
    #[validate(range(min = 1))]
    pub history_management_limit: Option<i32>,
    // Model Name
    pub model_name: Option<String>,
    // Gemini Specific Options
    pub gemini_thinking_budget: Option<i32>,
    pub gemini_enable_code_execution: Option<bool>,
}

// Custom validation function for history_management_strategy (called only when Some)
fn validate_optional_history_strategy(strategy: &String) -> Result<(), ValidationError> {
    // Check if the strategy is a known value
    match strategy.as_str() {
        "none" | "sliding_window_messages" | "sliding_window_tokens" | "truncate_tokens" | "message_window" | "token_limit" => Ok(()),
        _ => {
            let mut err = ValidationError::new("unknown_strategy");
            err.message = Some(format!("Unknown history management strategy: {}. Allowed values are: none, sliding_window_messages, message_window, sliding_window_tokens, truncate_tokens, token_limit", strategy).into());
            Err(err)
        }
    }
}

// Custom validation function for optional temperature (0.0 to 2.0)
fn validate_optional_temperature(temp: &BigDecimal) -> Result<(), ValidationError> {
    let zero = BigDecimal::from(0);
    let two = BigDecimal::from(2);
    if *temp < zero || *temp > two {
        let mut err = ValidationError::new("range");
        err.add_param("min".into(), &0.0);
        err.add_param("max".into(), &2.0);
        return Err(err);
    }
    Ok(())
}

// Custom validation function for optional frequency penalty (-2.0 to 2.0)
fn validate_optional_frequency_penalty(penalty: &BigDecimal) -> Result<(), ValidationError> {
    let neg_two = BigDecimal::from(-2);
    let two = BigDecimal::from(2);
    if *penalty < neg_two || *penalty > two {
        let mut err = ValidationError::new("range");
        err.add_param("min".into(), &-2.0);
        err.add_param("max".into(), &2.0);
        return Err(err);
    }
    Ok(())
}

// Custom validation function for optional presence penalty (-2.0 to 2.0)
fn validate_optional_presence_penalty(penalty: &BigDecimal) -> Result<(), ValidationError> {
    let neg_two = BigDecimal::from(-2);
    let two = BigDecimal::from(2);
    if *penalty < neg_two || *penalty > two {
        let mut err = ValidationError::new("range");
        err.add_param("min".into(), &-2.0);
        err.add_param("max".into(), &2.0);
        return Err(err);
    }
    Ok(())
}

// Custom validation function for optional top-p (0.0 to 1.0)
fn validate_optional_top_p(value: &BigDecimal) -> Result<(), ValidationError> {
    let zero = BigDecimal::from(0);
    let one = BigDecimal::from(1);
    if *value < zero || *value > one {
        let mut err = ValidationError::new("range");
        err.add_param("min".into(), &0.0);
        err.add_param("max".into(), &1.0);
        return Err(err);
    }
    Ok(())
}

// Custom validation function for optional repetition penalty (> 0)
fn validate_optional_repetition_penalty(value: &BigDecimal) -> Result<(), ValidationError> {
    let zero = BigDecimal::from(0);
    if *value <= zero {
        let mut err = ValidationError::new("range");
        err.add_param("min".into(), &"greater than 0");
        return Err(err);
    }
    Ok(())
}

// Custom validation function for optional min-p (0.0 to 1.0)
fn validate_optional_min_p(value: &BigDecimal) -> Result<(), ValidationError> {
    let zero = BigDecimal::from(0);
    let one = BigDecimal::from(1);
    if *value < zero || *value > one {
        let mut err = ValidationError::new("range");
        err.add_param("min".into(), &0.0);
        err.add_param("max".into(), &1.0);
        return Err(err);
    }
    Ok(())
}

// Custom validation function for optional top-a (0.0 to 1.0)
fn validate_optional_top_a(value: &BigDecimal) -> Result<(), ValidationError> {
    let zero = BigDecimal::from(0);
    let one = BigDecimal::from(1);
    if *value < zero || *value > one {
        let mut err = ValidationError::new("range");
        err.add_param("min".into(), &0.0);
        err.add_param("max".into(), &1.0);
        return Err(err);
    }
    Ok(())
}

// Custom validation function for optional logit_bias (must be an object)
fn validate_optional_logit_bias(value: &Value) -> Result<(), ValidationError> {
    if !value.is_object() {
        let mut err = ValidationError::new("type");
        err.add_param("expected".into(), &"object");
        return Err(err);
    }
    Ok(())
}

// --- Suggested Actions API Structures ---

/// Payload for requesting suggested actions.
#[derive(Debug, Serialize, Deserialize, Validate)] // Added Validate
pub struct SuggestedActionsRequest {
    /// The history of messages in the chat so far.
    /// This provides context for generating relevant suggestions.
    #[validate(length(min = 0))] // Example: allow empty history
    pub message_history: Vec<ApiChatMessage>,
    pub character_first_message: String,
    pub user_first_message: Option<String>,
    pub ai_first_response: Option<String>,
}

/// Structure for a single suggested action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestedActionItem {
    pub action: String,
}

/// Response structure for suggested actions API
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuggestedActionsResponse {
    pub suggestions: Vec<SuggestedActionItem>,
}

#[cfg(test)]
mod tests {
    use validator::Validate; // Import the Validate trait for tests
    use super::*;
    use bigdecimal::BigDecimal; // Import BigDecimal
    use chrono::Utc;
    use serde_json::json;
    use std::str::FromStr;
    use uuid::Uuid;
    use secrecy::SecretBox; // For testing encryption/decryption
    use ring::rand::{SystemRandom, SecureRandom}; // For generating a dummy DEK

    // Helper function to generate a dummy DEK for testing
    fn generate_dummy_dek() -> SecretBox<Vec<u8>> {
        let mut key_bytes = vec![0u8; 32]; // AES-256-GCM needs a 32-byte key
        let rng = SystemRandom::new();
        rng.fill(&mut key_bytes).unwrap();
        SecretBox::new(Box::new(key_bytes))
    }

    // Helper function to create BigDecimal from a string for tests
    fn bd(s: &str) -> BigDecimal {
        BigDecimal::from_str(s).expect("Invalid decimal string")
    }

    // Helper function to create a sample chat session
    fn create_sample_chat_session() -> Chat {
        Chat {
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
            history_management_strategy: "none".to_string(),
            history_management_limit: 4096,
            model_name: "gemini-2.5-flash-preview-04-17".to_string(),
            visibility: Some("private".to_string()),
            gemini_thinking_budget: Some(100),
            gemini_enable_code_execution: Some(true),
        }
    }

    #[test]
    fn test_debug_chat_session() {
        let session = create_sample_chat_session();
        let debug_str = format!("{:?}", session);
        assert!(debug_str.contains("Chat {"));
        assert!(debug_str.contains(&session.id.to_string()));
        assert!(debug_str.contains("Test Chat"));
        assert!(debug_str.contains("history_management_strategy: \"none\""));
    }

    #[test]
    fn test_clone_chat_session() {
        let original = create_sample_chat_session();
        let cloned = original.clone();
        assert_eq!(original.id, cloned.id);
        // ... (rest of assertions for Chat fields)
        assert_eq!(original.gemini_enable_code_execution, cloned.gemini_enable_code_execution);
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
    fn create_sample_chat_message_db() -> ChatMessage { // Renamed to avoid conflict
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "Hello, how are you?".as_bytes().to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn test_debug_chat_message() {
        let message = create_sample_chat_message_db();
        let debug_str = format!("{:?}", message);
        assert!(debug_str.contains("ChatMessage"));
        assert!(debug_str.contains(&message.id.to_string()));
        assert!(debug_str.contains("content: [72, 101, 108, 108, 111, 44, 32, 104, 111, 119, 32, 97, 114, 101, 32, 121, 111, 117, 63]"));
    }

    #[test]
    fn test_clone_chat_message() {
        let original = create_sample_chat_message_db();
        let cloned = original.clone();
        assert_eq!(original.id, cloned.id);
        // ... (rest of assertions for ChatMessage fields)
        assert_eq!(original.user_id, cloned.user_id);
    }

    #[test]
    fn test_serde_chat_message() {
        let message = create_sample_chat_message_db();
        let serialized = serde_json::to_string(&message).expect("Serialization failed");
        let deserialized: ChatMessage = serde_json::from_str(&serialized).expect("Deserialization failed");
        assert_eq!(message.id, deserialized.id);
        // ... (rest of assertions, minding DateTime precision)
        assert_eq!(message.user_id, deserialized.user_id);
    }

    #[test]
    fn test_encrypt_decrypt_chat_message_content() {
        let dek = generate_dummy_dek();
        let mut message = create_sample_chat_message_db(); // Gets a message with plaintext content
        let original_content_str = String::from_utf8(message.content.clone()).unwrap();

        // Encrypt
        message.encrypt_content_field(&dek, original_content_str.clone()).unwrap();
        assert_ne!(message.content, original_content_str.as_bytes(), "Content should be encrypted");

        // Decrypt
        let decrypted_content = message.decrypt_content_field(&dek).unwrap();
        assert_eq!(decrypted_content, original_content_str, "Decrypted content should match original");

        // Test with empty string
        message.encrypt_content_field(&dek, "".to_string()).unwrap();
        assert!(message.content.is_empty(), "Encrypting empty string should result in empty bytes");
        let decrypted_empty = message.decrypt_content_field(&dek).unwrap();
        assert_eq!(decrypted_empty, "", "Decrypting empty bytes should result in empty string");
    }

    #[test]
    fn test_chat_message_into_decrypted_for_client() {
        let dek = generate_dummy_dek();
        let mut message_db = create_sample_chat_message_db();
        let original_content_str = String::from_utf8(message_db.content.clone()).unwrap();

        // Encrypt the content for the DB version
        message_db.encrypt_content_field(&dek, original_content_str.clone()).unwrap();

        // Test with DEK
        let client_message_with_dek = message_db.clone().into_decrypted_for_client(Some(&dek)).unwrap();
        assert_eq!(client_message_with_dek.content, original_content_str);
        assert_eq!(client_message_with_dek.id, message_db.id);

        // Test without DEK (when content is encrypted)
        let client_message_without_dek = message_db.clone().into_decrypted_for_client(None).unwrap();
        assert_eq!(client_message_without_dek.content, "[Encrypted Content]"); // Or policy for this case

        // Test with initially empty content
        let mut empty_content_msg_db = create_sample_chat_message_db();
        empty_content_msg_db.content = Vec::new(); // Set content to empty
        let client_empty_with_dek = empty_content_msg_db.clone().into_decrypted_for_client(Some(&dek)).unwrap();
        assert_eq!(client_empty_with_dek.content, "");
        let client_empty_without_dek = empty_content_msg_db.clone().into_decrypted_for_client(None).unwrap();
        assert_eq!(client_empty_without_dek.content, "");
    }


    // Helper function to create a sample new chat message
    fn create_sample_new_chat_message_db() -> NewChatMessage { // Renamed
        NewChatMessage {
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: "Hello!".as_bytes().to_vec(), // Will be encrypted by handler
        }
    }

    #[test]
    fn test_debug_new_chat_message() {
        let message = create_sample_new_chat_message_db();
        let debug_str = format!("{:?}", message);
        assert!(debug_str.contains("NewChatMessage"));
        assert!(debug_str.contains(&message.session_id.to_string()));
        assert!(debug_str.contains("content: [72, 101, 108, 108, 111, 33]"));
    }

    #[test]
    fn test_clone_new_chat_message() {
        let original = create_sample_new_chat_message_db();
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
        let content_str = "Test message";
        let content_vec = content_str.as_bytes().to_vec(); // Will be encrypted by handler

        let message = DbInsertableChatMessage::new(chat_id, user_id, role, content_vec.clone(), None);
        assert_eq!(message.chat_id, chat_id);
        assert_eq!(message.user_id, user_id);
        assert_eq!(message.role, role);
        assert_eq!(message.content, content_vec);
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
            model_name: "gemini-2.5-flash-preview-04-17".to_string(),
            gemini_thinking_budget: Some(1000),
            gemini_enable_code_execution: Some(true),
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
        assert_eq!(original.model_name, cloned.model_name);
        assert_eq!(original.gemini_thinking_budget, cloned.gemini_thinking_budget);
        assert_eq!(original.gemini_enable_code_execution, cloned.gemini_enable_code_execution);
    }

    // Helper function to create a sample update chat settings request
    fn create_sample_update_chat_settings_request() -> UpdateChatSettingsRequest {
        UpdateChatSettingsRequest {
            system_prompt: Some("Test system prompt".to_string()),
            temperature: Some(bd("0.7")),
            max_output_tokens: Some(150),
            frequency_penalty: Some(bd("0.5")),
            presence_penalty: Some(bd("0.5")),
            top_k: Some(40),
            top_p: Some(bd("0.95")),
            repetition_penalty: Some(bd("1.1")),
            min_p: Some(bd("0.05")),
            top_a: Some(bd("0.1")),
            seed: Some(42),
            logit_bias: Some(json!({"50256": -100})),
            history_management_strategy: Some("sliding_window_tokens".to_string()),
            history_management_limit: Some(2000),
            model_name: Some("gemini-2.5-pro-preview-03-25".to_string()),
            gemini_thinking_budget: Some(512),
            gemini_enable_code_execution: Some(false),
        }
    }

    #[test]
    fn test_debug_update_chat_settings_request() {
        let settings = create_sample_update_chat_settings_request();
        let debug_str = format!("{:?}", settings);
        assert!(debug_str.contains("UpdateChatSettingsRequest"));
        assert!(debug_str.contains("Test system prompt"));
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
        assert_eq!(original.model_name, cloned.model_name);
        assert_eq!(original.gemini_thinking_budget, cloned.gemini_thinking_budget);
        assert_eq!(original.gemini_enable_code_execution, cloned.gemini_enable_code_execution);
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
        assert_eq!(settings.model_name, deserialized.model_name);
        assert_eq!(settings.gemini_thinking_budget, deserialized.gemini_thinking_budget);
        assert_eq!(settings.gemini_enable_code_execution, deserialized.gemini_enable_code_execution);
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
        assert_eq!(settings.model_name, deserialized.model_name);
        assert_eq!(settings.gemini_thinking_budget, deserialized.gemini_thinking_budget);
        assert_eq!(settings.gemini_enable_code_execution, deserialized.gemini_enable_code_execution);
    }

    #[test]
    fn test_new_chat_message_request_serde() {
        let original = NewChatMessageRequest {
            content: "Hello AI".to_string(),
            model: Some("gemini-2.5-flash-preview-04-17".to_string()),
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
            model: Some("gemini-2.5-flash-preview-04-17".to_string()),
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
        
        settings2 = settings1.clone();
        settings2.gemini_thinking_budget = Some(0);
        assert_ne!(settings1, settings2);

        settings2 = settings1.clone();
        settings2.gemini_enable_code_execution = Some(false);
        // If original sample has true, this will be assert_ne. Check sample.
        // create_sample_chat_settings_response has gemini_enable_code_execution: Some(true)
        assert_ne!(settings1, settings2);
    }

    #[test]
    fn test_partial_eq_update_chat_settings_request() {
        let settings1 = create_sample_update_chat_settings_request();
        let mut settings2 = settings1.clone();

        assert_eq!(settings1, settings2);

        settings2.temperature = Some(bd("0.8"));
        assert_ne!(settings1, settings2);

        // Add test for new fields inequality
        settings2 = settings1.clone();
        settings2.history_management_strategy = Some("none".to_string());
        assert_ne!(settings1, settings2);

        settings2 = settings1.clone();
        settings2.history_management_limit = Some(100);
        assert_ne!(settings1, settings2);

        settings2 = settings1.clone();
        settings2.gemini_thinking_budget = Some(1024);
        assert_ne!(settings1, settings2);

        settings2 = settings1.clone();
        settings2.gemini_enable_code_execution = Some(true);
        // create_sample_update_chat_settings_request has gemini_enable_code_execution: Some(false)
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
        assert_eq!(err.field_errors()["history_management_strategy"][0].code, "unknown_strategy");


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
