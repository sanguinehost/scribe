use crate::schema::{chat_messages, chat_sessions, message_variants};
use bigdecimal::BigDecimal;
use chrono::{DateTime, Utc};
use diesel::{Associations, Identifiable, Insertable, Queryable, Selectable};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use uuid::Uuid;
use validator::{Validate, ValidationError};

// Import necessary Diesel traits for manual enum mapping
use diesel::deserialize::{self, FromSql};
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, IsNull, Output, ToSql};
use diesel::{AsExpression, FromSqlRow};
use std::io::Write;

use crate::crypto::{decrypt_gcm, encrypt_gcm};
use crate::errors::AppError;
use secrecy::ExposeSecret;
use secrecy::SecretBox;

// Main Chat model (similar to the frontend Chat type)
// Type alias for the tuple returned when selecting/returning chat settings
pub type SettingsTuple = (
    Option<Vec<u8>>,             // system_prompt_ciphertext
    Option<Vec<u8>>,             // system_prompt_nonce
    Option<BigDecimal>,          // temperature
    Option<i32>,                 // max_output_tokens
    Option<BigDecimal>,          // frequency_penalty
    Option<BigDecimal>,          // presence_penalty
    Option<i32>,                 // top_k
    Option<BigDecimal>,          // top_p
    Option<i32>,                 // seed
    Option<Vec<Option<String>>>, // stop_sequences
    String,                      // history_management_strategy
    i32,                         // history_management_limit
    String,                      // model_name
    // -- Gemini Specific Options --
    Option<i32>,  // gemini_thinking_budget
    Option<bool>, // gemini_enable_code_execution
    // -- Chronicle Support --
    Option<Uuid>, // player_chronicle_id
    // -- Agent Mode --
    Option<String>, // agent_mode
); // Close the tuple definition
#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Clone)]
#[diesel(table_name = chat_sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Chat {
    pub id: Uuid,
    pub user_id: Uuid,
    pub character_id: Option<Uuid>,
    pub temperature: Option<bigdecimal::BigDecimal>,
    pub max_output_tokens: Option<i32>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub frequency_penalty: Option<bigdecimal::BigDecimal>,
    pub presence_penalty: Option<bigdecimal::BigDecimal>,
    pub top_k: Option<i32>,
    pub top_p: Option<bigdecimal::BigDecimal>,
    pub seed: Option<i32>,
    pub history_management_strategy: String,
    pub history_management_limit: i32,
    pub model_name: String,
    pub gemini_thinking_budget: Option<i32>,
    pub gemini_enable_code_execution: Option<bool>,
    pub visibility: Option<String>,
    pub active_custom_persona_id: Option<Uuid>,
    pub active_impersonated_character_id: Option<Uuid>,
    pub system_prompt_ciphertext: Option<Vec<u8>>,
    pub system_prompt_nonce: Option<Vec<u8>>,
    pub title_ciphertext: Option<Vec<u8>>,
    pub title_nonce: Option<Vec<u8>>,
    pub stop_sequences: Option<Vec<Option<String>>>,
    pub chat_mode: ChatMode,
    pub player_chronicle_id: Option<Uuid>,
    pub agent_mode: Option<String>,
}

impl std::fmt::Debug for Chat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chat")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("character_id", &self.character_id)
            .field(
                "title_ciphertext",
                &self.title_ciphertext.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "title_nonce",
                &self.title_nonce.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "system_prompt_ciphertext",
                &self
                    .system_prompt_ciphertext
                    .as_ref()
                    .map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "system_prompt_nonce",
                &self
                    .system_prompt_nonce
                    .as_ref()
                    .map(|_| "[REDACTED_BYTES]"),
            )
            .field("temperature", &self.temperature)
            .field("max_output_tokens", &self.max_output_tokens)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("frequency_penalty", &self.frequency_penalty)
            .field("presence_penalty", &self.presence_penalty)
            .field("top_k", &self.top_k)
            .field("top_p", &self.top_p)
            .field("seed", &self.seed)
            .field("stop_sequences", &self.stop_sequences)
            .field(
                "history_management_strategy",
                &self.history_management_strategy,
            )
            .field("history_management_limit", &self.history_management_limit)
            .field("model_name", &self.model_name)
            .field("gemini_thinking_budget", &self.gemini_thinking_budget)
            .field(
                "gemini_enable_code_execution",
                &self.gemini_enable_code_execution,
            )
            .field("visibility", &self.visibility)
            // Add new fields to Debug output
            .field("active_custom_persona_id", &self.active_custom_persona_id)
            .field(
                "active_impersonated_character_id",
                &self.active_impersonated_character_id,
            )
            .finish()
    }
}

// New Chat for insertion
#[derive(Insertable, Clone)]
#[diesel(table_name = chat_sessions)]
pub struct NewChat {
    pub id: Uuid,
    pub user_id: Uuid,
    pub character_id: Uuid,
    pub title_ciphertext: Option<Vec<u8>>,
    pub title_nonce: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub history_management_strategy: String,
    pub history_management_limit: i32,
    pub model_name: String,
    pub visibility: Option<String>,
    // Added to match schema and Chat struct
    pub active_custom_persona_id: Option<Uuid>,
    pub active_impersonated_character_id: Option<Uuid>,
    // Additional optional fields that can be set during insertion
    pub temperature: Option<BigDecimal>,
    pub max_output_tokens: Option<i32>,
    pub frequency_penalty: Option<BigDecimal>,
    pub presence_penalty: Option<BigDecimal>,
    pub top_k: Option<i32>,
    pub top_p: Option<BigDecimal>,
    pub seed: Option<i32>,
    pub stop_sequences: Option<Vec<Option<String>>>,
    pub gemini_thinking_budget: Option<i32>,
    pub gemini_enable_code_execution: Option<bool>,
    pub system_prompt_ciphertext: Option<Vec<u8>>,
    pub system_prompt_nonce: Option<Vec<u8>>,
    pub player_chronicle_id: Option<Uuid>,
}

impl std::fmt::Debug for NewChat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewChat")
            .field("id", &self.id)
            .field("user_id", &self.user_id)
            .field("character_id", &self.character_id)
            .field("title_ciphertext", &"[REDACTED_BYTES]")
            .field("title_nonce", &"[REDACTED_BYTES]")
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field(
                "history_management_strategy",
                &self.history_management_strategy,
            )
            .field("history_management_limit", &self.history_management_limit)
            .field("model_name", &self.model_name)
            .field("visibility", &self.visibility)
            .field("active_custom_persona_id", &self.active_custom_persona_id)
            .field(
                "active_impersonated_character_id",
                &self.active_impersonated_character_id,
            )
            .field("temperature", &self.temperature)
            .field("max_output_tokens", &self.max_output_tokens)
            .field("frequency_penalty", &self.frequency_penalty)
            .field("presence_penalty", &self.presence_penalty)
            .field("top_k", &self.top_k)
            .field("top_p", &self.top_p)
            .field("seed", &self.seed)
            .field("stop_sequences", &self.stop_sequences)
            .field("gemini_thinking_budget", &self.gemini_thinking_budget)
            .field(
                "gemini_enable_code_execution",
                &self.gemini_enable_code_execution,
            )
            .field(
                "system_prompt_ciphertext",
                &self
                    .system_prompt_ciphertext
                    .as_ref()
                    .map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "system_prompt_nonce",
                &self
                    .system_prompt_nonce
                    .as_ref()
                    .map(|_| "[REDACTED_BYTES]"),
            )
            .finish()
    }
}

// MessageRole enum for database storage
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
            Self::User => out.write_all(b"User")?,
            Self::Assistant => out.write_all(b"Assistant")?,
            Self::System => out.write_all(b"System")?,
        }
        Ok(IsNull::No)
    }
}

// Manual FromSql implementation
impl FromSql<crate::schema::sql_types::MessageType, Pg> for MessageRole {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        match bytes.as_bytes() {
            b"User" => Ok(Self::User),
            b"Assistant" => Ok(Self::Assistant),
            b"System" => Ok(Self::System),
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
            Self::User => write!(f, "User"),
            Self::Assistant => write!(f, "Assistant"),
            Self::System => write!(f, "System"),
        }
    }
}

// ChatMode enum for different types of chat sessions
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, AsExpression, FromSqlRow,
)]
#[diesel(sql_type = diesel::sql_types::Text)]
pub enum ChatMode {
    #[default]
    Character,
    ScribeAssistant,
    Rpg,
}

// Manual ToSql implementation for ChatMode
impl ToSql<diesel::sql_types::Text, Pg> for ChatMode {
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Pg>) -> serialize::Result {
        match *self {
            ChatMode::Character => out.write_all(b"Character")?,
            ChatMode::ScribeAssistant => out.write_all(b"ScribeAssistant")?,
            ChatMode::Rpg => out.write_all(b"Rpg")?,
        }
        Ok(IsNull::No)
    }
}

// Manual FromSql implementation for ChatMode
impl FromSql<diesel::sql_types::Text, Pg> for ChatMode {
    fn from_sql(bytes: PgValue<'_>) -> deserialize::Result<Self> {
        match bytes.as_bytes() {
            b"Character" => Ok(Self::Character),
            b"ScribeAssistant" => Ok(Self::ScribeAssistant),
            b"Rpg" => Ok(Self::Rpg),
            unrecognized => {
                error!(
                    "Unrecognized chat_mode enum variant from DB: {:?}",
                    String::from_utf8_lossy(unrecognized)
                );
                Err("Unrecognized enum variant from database".into())
            }
        }
    }
}

// Implement Display for ChatMode
impl std::fmt::Display for ChatMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Character => write!(f, "Character"),
            Self::ScribeAssistant => write!(f, "ScribeAssistant"),
            Self::Rpg => write!(f, "Rpg"),
        }
    }
}

// Represents a chat message in the database
#[derive(Queryable, Selectable, Identifiable, Associations, Clone, Serialize, Deserialize)]
#[diesel(belongs_to(Chat, foreign_key = session_id))]
#[diesel(table_name = chat_messages)]
pub struct ChatMessage {
    pub id: Uuid,
    #[diesel(column_name = session_id)]
    pub session_id: Uuid,
    #[diesel(column_name = message_type)]
    pub message_type: MessageRole,
    pub content: Vec<u8>,
    pub content_nonce: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
    pub user_id: Uuid,
    pub prompt_tokens: Option<i32>,
    pub completion_tokens: Option<i32>,
    pub raw_prompt_ciphertext: Option<Vec<u8>>,
    pub raw_prompt_nonce: Option<Vec<u8>>,
    pub model_name: String,
}

impl std::fmt::Debug for ChatMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatMessage")
            .field("id", &self.id)
            .field("session_id", &self.session_id)
            .field("message_type", &self.message_type)
            .field("content", &"[REDACTED_BYTES]")
            .field(
                "content_nonce",
                &self.content_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field("created_at", &self.created_at)
            .field("user_id", &self.user_id)
            .field("prompt_tokens", &self.prompt_tokens)
            .field("completion_tokens", &self.completion_tokens)
            .field("model_name", &self.model_name)
            .field("model_name", &self.model_name)
            .field(
                "raw_prompt_ciphertext",
                &self
                    .raw_prompt_ciphertext
                    .as_ref()
                    .map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "raw_prompt_nonce",
                &self.raw_prompt_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .finish()
    }
}

impl ChatMessage {
    /// Encrypts the content field if plaintext is provided and a DEK is available.
    /// Updates `self.content` and `self.content_nonce`.
    ///
    /// # Errors
    /// Returns `AppError` if encryption fails
    pub fn encrypt_content_field(
        &mut self,
        dek: &SecretBox<Vec<u8>>,
        plaintext_content: &str,
    ) -> Result<(), AppError> {
        if plaintext_content.is_empty() {
            self.content = Vec::new();
            self.content_nonce = None;
        } else {
            let (ciphertext, nonce) = encrypt_gcm(plaintext_content.as_bytes(), dek)
                .map_err(|e| AppError::CryptoError(e.to_string()))?;
            self.content = ciphertext;
            self.content_nonce = Some(nonce);
        }
        Ok(())
    }

    /// Decrypts the content field if a DEK is available and content is encrypted.
    /// Returns the decrypted string.
    ///
    /// # Errors
    /// Returns `AppError::DecryptionError` if the nonce is empty, missing, or decryption fails
    pub fn decrypt_content_field(&self, dek: &SecretBox<Vec<u8>>) -> Result<String, AppError> {
        if self.content.is_empty() {
            return Ok(String::new());
        }

        let nonce = self.content_nonce.as_ref().ok_or_else(|| {
            tracing::error!(
                "ENCRYPTION VIOLATION: ChatMessage ID {} has content but missing nonce. This violates encryption-at-rest requirements and indicates data corruption or migration issues.",
                self.id
            );
            AppError::DecryptionError("ENCRYPTION VIOLATION: Missing nonce for content decryption - all data must be encrypted at rest".to_string())
        })?;

        if nonce.is_empty() {
            tracing::error!(
                "ChatMessage ID {} content is present but nonce is empty. Cannot decrypt.",
                self.id
            );
            return Err(AppError::DecryptionError(
                "Nonce is empty for content decryption".to_string(),
            ));
        }

        self.decrypt_with_nonce(nonce, dek)
    }

    /// Helper method to decrypt content with a validated nonce
    fn decrypt_with_nonce(
        &self,
        nonce: &[u8],
        dek: &SecretBox<Vec<u8>>,
    ) -> Result<String, AppError> {
        let plaintext_secret = decrypt_gcm(&self.content, nonce, dek).map_err(|e| {
            error!(
                "Failed to decrypt chat message content for ID {}: {}",
                self.id, e
            );
            AppError::DecryptionError(format!("Decryption failed for message content: {e}"))
        })?;

        String::from_utf8(plaintext_secret.expose_secret().clone()).map_err(|e| {
            tracing::error!(
                "Failed to convert decrypted message content to UTF-8: {}",
                e
            );
            AppError::DecryptionError("Failed to convert message content to UTF-8".to_string())
        })
    }

    /// Encrypts the raw_prompt field if plaintext is provided and a DEK is available.
    /// Updates `self.raw_prompt_ciphertext` and `self.raw_prompt_nonce`.
    ///
    /// # Errors
    /// Returns `AppError` if encryption fails
    pub fn encrypt_raw_prompt_field(
        &mut self,
        dek: &SecretBox<Vec<u8>>,
        plaintext_raw_prompt: &str,
    ) -> Result<(), AppError> {
        if plaintext_raw_prompt.is_empty() {
            self.raw_prompt_ciphertext = None;
            self.raw_prompt_nonce = None;
        } else {
            let (ciphertext, nonce) = encrypt_gcm(plaintext_raw_prompt.as_bytes(), dek)
                .map_err(|e| AppError::CryptoError(e.to_string()))?;
            self.raw_prompt_ciphertext = Some(ciphertext);
            self.raw_prompt_nonce = Some(nonce);
        }
        Ok(())
    }

    /// Decrypts the raw_prompt field if a DEK is available and content is encrypted.
    /// Returns the decrypted string.
    ///
    /// # Errors
    /// Returns `AppError::DecryptionError` if the nonce is empty, missing, or decryption fails
    pub fn decrypt_raw_prompt_field(
        &self,
        dek: &SecretBox<Vec<u8>>,
    ) -> Result<Option<String>, AppError> {
        match (&self.raw_prompt_ciphertext, &self.raw_prompt_nonce) {
            (None, None) => Ok(None), // No raw prompt was stored
            (Some(ciphertext), Some(nonce)) => {
                if ciphertext.is_empty() {
                    return Ok(Some(String::new()));
                }

                if nonce.is_empty() {
                    tracing::error!(
                        "ChatMessage ID {} raw_prompt is present but nonce is empty. Cannot decrypt.",
                        self.id
                    );
                    return Err(AppError::DecryptionError(
                        "Nonce is empty for raw prompt decryption".to_string(),
                    ));
                }

                let plaintext_secret = decrypt_gcm(ciphertext, nonce, dek).map_err(|e| {
                    error!(
                        "Failed to decrypt chat message raw prompt for ID {}: {}",
                        self.id, e
                    );
                    AppError::DecryptionError(format!(
                        "Decryption failed for message raw prompt: {e}"
                    ))
                })?;

                let decrypted_text = String::from_utf8(plaintext_secret.expose_secret().clone())
                    .map_err(|e| {
                        tracing::error!(
                            "Failed to convert decrypted message raw prompt to UTF-8: {}",
                            e
                        );
                        AppError::DecryptionError(
                            "Failed to convert message raw prompt to UTF-8".to_string(),
                        )
                    })?;

                Ok(Some(decrypted_text))
            }
            _ => Err(AppError::DecryptionError(
                "Mismatched raw prompt ciphertext/nonce pair".to_string(),
            )),
        }
    }

    /// Convert this `ChatMessage` to a decrypted `ChatMessageForClient`
    ///
    /// # Errors
    /// Returns `AppError::DecryptionError` if decryption fails or UTF-8 conversion errors occur
    pub fn into_decrypted_for_client(
        self,
        user_dek_secret_box: Option<&SecretBox<Vec<u8>>>,
    ) -> Result<ChatMessageForClient, AppError> {
        let decrypted_content_result: Result<String, AppError> =
            if let Some(nonce) = &self.content_nonce {
                if let Some(dek_sb) = user_dek_secret_box {
                    decrypt_gcm(&self.content, nonce, dek_sb).map_or_else(
                        |e| {
                            error!("Decryption error for msg {}: {:?}", self.id, e);
                            Err(AppError::DecryptionError(format!("Decryption error: {e}")))
                        },
                        |plaintext_secret_vec| {
                            String::from_utf8(plaintext_secret_vec.expose_secret().clone()).map_err(
                                |e| {
                                    error!("UTF-8 conversion error for msg {}: {:?}", self.id, e);
                                    AppError::DecryptionError(format!("UTF-8 conversion: {e}"))
                                },
                            )
                        },
                    )
                } else {
                    // No DEK provided but content appears encrypted
                    Ok("[Content encrypted, DEK not available]".to_string())
                }
            } else {
                // No nonce implies content might not be encrypted or is empty
                String::from_utf8(self.content.clone()).map_err(|e| {
                    error!("UTF-8 conversion error for msg {}: {:?}", self.id, e);
                    AppError::DecryptionError(format!("UTF-8 conversion: {e}"))
                })
            };

        let final_content = decrypted_content_result.unwrap_or_else(|_| {
            error!("Failed to decrypt content for message {}", self.id);
            "[Decryption failed]".to_string()
        });

        // Decrypt raw prompt if available
        let raw_prompt = if let Some(dek) = user_dek_secret_box {
            match self.decrypt_raw_prompt_field(dek) {
                Ok(decrypted_raw_prompt) => {
                    if let Some(ref raw_prompt_text) = decrypted_raw_prompt {
                        info!(
                            "Successfully decrypted raw prompt for message {} (length: {})",
                            self.id,
                            raw_prompt_text.len()
                        );
                    } else {
                        info!("No raw prompt stored for message {}", self.id);
                    }
                    decrypted_raw_prompt
                }
                Err(e) => {
                    error!(
                        "Failed to decrypt raw prompt for message {}: {}",
                        self.id, e
                    );
                    None
                }
            }
        } else {
            // If raw prompt exists but no DEK provided, indicate it's encrypted
            if self.raw_prompt_ciphertext.is_some() {
                warn!(
                    "Raw prompt exists for message {} but no DEK provided",
                    self.id
                );
                Some("[Raw prompt encrypted, DEK not available]".to_string())
            } else {
                None
            }
        };

        Ok(ChatMessageForClient {
            id: self.id,
            session_id: self.session_id,
            message_type: self.message_type,
            content: final_content,
            created_at: self.created_at,
            user_id: self.user_id,
            prompt_tokens: self.prompt_tokens,
            completion_tokens: self.completion_tokens,
            raw_prompt,
            model_name: self.model_name,
        })
    }
}

// Chat Message model
#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Clone)]
#[diesel(table_name = chat_messages)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Message {
    pub id: Uuid,
    pub session_id: Uuid,
    pub message_type: MessageRole,
    pub content: Vec<u8>,
    pub rag_embedding_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub user_id: Uuid,
    pub content_nonce: Option<Vec<u8>>,
    pub role: Option<String>,
    pub parts: Option<serde_json::Value>,
    pub attachments: Option<serde_json::Value>,
    pub prompt_tokens: Option<i32>,
    pub completion_tokens: Option<i32>,
    pub raw_prompt_ciphertext: Option<Vec<u8>>,
    pub raw_prompt_nonce: Option<Vec<u8>>,
    pub model_name: String,
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Message")
            .field("id", &self.id)
            .field("session_id", &self.session_id)
            .field("message_type", &self.message_type)
            .field("content", &"[REDACTED_BYTES]")
            .field("rag_embedding_id", &self.rag_embedding_id)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("user_id", &self.user_id)
            .field(
                "content_nonce",
                &self.content_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field("role", &self.role)
            .field("parts", &self.parts.as_ref().map(|_| "[REDACTED_JSON]"))
            .field(
                "attachments",
                &self.attachments.as_ref().map(|_| "[REDACTED_JSON]"),
            )
            .field("prompt_tokens", &self.prompt_tokens)
            .field("completion_tokens", &self.completion_tokens)
            .field("model_name", &self.model_name)
            .field(
                "raw_prompt_ciphertext",
                &self
                    .raw_prompt_ciphertext
                    .as_ref()
                    .map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "raw_prompt_nonce",
                &self.raw_prompt_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .finish()
    }
}

impl Message {
    /// Encrypts the content field if plaintext is provided and a DEK is available.
    /// Updates `self.content` and `self.content_nonce`.
    ///
    /// # Errors
    /// Returns `AppError::CryptoError` if encryption fails
    pub fn encrypt_content_field(
        &mut self,
        dek: &SecretBox<Vec<u8>>,
        plaintext_content: &str,
    ) -> Result<(), AppError> {
        if plaintext_content.is_empty() {
            self.content = Vec::new();
            self.content_nonce = None;
        } else {
            let (ciphertext, nonce) = encrypt_gcm(plaintext_content.as_bytes(), dek)
                .map_err(|e| AppError::CryptoError(e.to_string()))?;
            self.content = ciphertext;
            self.content_nonce = Some(nonce);
        }
        Ok(())
    }

    /// Decrypts the content field if ciphertext and nonce are present and a DEK is available.
    /// Returns String representing the decrypted content.
    ///
    /// # Errors
    /// Returns `AppError::DecryptionError` if the nonce is empty, missing, or decryption fails
    pub fn decrypt_content_field(&self, dek: &SecretBox<Vec<u8>>) -> Result<String, AppError> {
        if self.content.is_empty() {
            return Ok(String::new());
        }

        let nonce_bytes = self.content_nonce.as_ref().ok_or_else(|| {
            tracing::error!(
                "ChatMessage ID {} content is present but nonce is missing. Cannot decrypt.",
                self.id
            );
            AppError::DecryptionError("Missing nonce for content decryption".to_string())
        })?;

        if nonce_bytes.is_empty() {
            tracing::error!(
                "ChatMessage ID {} content nonce is present but empty. Cannot decrypt.",
                self.id
            );
            return Err(AppError::DecryptionError(
                "Missing nonce for content decryption".to_string(),
            ));
        }

        self.decrypt_content_with_nonce(nonce_bytes, dek)
    }

    /// Helper method to decrypt content with a validated nonce
    fn decrypt_content_with_nonce(
        &self,
        nonce_bytes: &[u8],
        dek: &SecretBox<Vec<u8>>,
    ) -> Result<String, AppError> {
        let plaintext_secret_vec = decrypt_gcm(&self.content, nonce_bytes, dek).map_err(|e| {
            error!(
                "Failed to decrypt chat message content for ID {}: {e}",
                self.id
            );
            AppError::DecryptionError(format!("Decryption failed for message content: {e}"))
        })?;

        String::from_utf8(plaintext_secret_vec.expose_secret().clone()).map_err(|e| {
            error!("Failed to convert decrypted message content to UTF-8: {e}");
            AppError::DecryptionError("Failed to convert message content to UTF-8".to_string())
        })
    }

    /// Encrypts the raw_prompt field if plaintext is provided and a DEK is available.
    /// Updates `self.raw_prompt_ciphertext` and `self.raw_prompt_nonce`.
    ///
    /// # Errors
    /// Returns `AppError` if encryption fails
    pub fn encrypt_raw_prompt_field(
        &mut self,
        dek: &SecretBox<Vec<u8>>,
        plaintext_raw_prompt: &str,
    ) -> Result<(), AppError> {
        if plaintext_raw_prompt.is_empty() {
            self.raw_prompt_ciphertext = None;
            self.raw_prompt_nonce = None;
        } else {
            let (ciphertext, nonce) = encrypt_gcm(plaintext_raw_prompt.as_bytes(), dek)
                .map_err(|e| AppError::CryptoError(e.to_string()))?;
            self.raw_prompt_ciphertext = Some(ciphertext);
            self.raw_prompt_nonce = Some(nonce);
        }
        Ok(())
    }

    /// Decrypts the raw_prompt field if a DEK is available and content is encrypted.
    /// Returns the decrypted string.
    ///
    /// # Errors
    /// Returns `AppError::DecryptionError` if the nonce is empty, missing, or decryption fails
    pub fn decrypt_raw_prompt_field(
        &self,
        dek: &SecretBox<Vec<u8>>,
    ) -> Result<Option<String>, AppError> {
        match (&self.raw_prompt_ciphertext, &self.raw_prompt_nonce) {
            (None, None) => Ok(None), // No raw prompt was stored
            (Some(ciphertext), Some(nonce)) => {
                if ciphertext.is_empty() {
                    return Ok(Some(String::new()));
                }

                if nonce.is_empty() {
                    tracing::error!(
                        "Message ID {} raw_prompt is present but nonce is empty. Cannot decrypt.",
                        self.id
                    );
                    return Err(AppError::DecryptionError(
                        "Nonce is empty for raw prompt decryption".to_string(),
                    ));
                }

                let plaintext_secret = decrypt_gcm(ciphertext, nonce, dek).map_err(|e| {
                    error!(
                        "Failed to decrypt message raw prompt for ID {}: {}",
                        self.id, e
                    );
                    AppError::DecryptionError(format!(
                        "Decryption failed for message raw prompt: {e}"
                    ))
                })?;

                let decrypted_text = String::from_utf8(plaintext_secret.expose_secret().clone())
                    .map_err(|e| {
                        tracing::error!(
                            "Failed to convert decrypted message raw prompt to UTF-8: {}",
                            e
                        );
                        AppError::DecryptionError(
                            "Failed to convert message raw prompt to UTF-8".to_string(),
                        )
                    })?;

                Ok(Some(decrypted_text))
            }
            _ => Err(AppError::DecryptionError(
                "Mismatched raw prompt ciphertext/nonce pair".to_string(),
            )),
        }
    }

    /// Convert this `ChatMessage` to a decrypted `ClientChatMessage`
    ///
    /// # Errors
    /// Returns `AppError::DecryptionError` if decryption fails, or `AppError::InternalServerErrorGeneric` for UTF-8 conversion errors
    pub fn into_decrypted_for_client(
        self,
        user_dek_secret_box: Option<&SecretBox<Vec<u8>>>,
    ) -> Result<ChatMessageForClient, AppError> {
        let decrypted_content_result: Result<String, AppError> =
            if let Some(nonce) = &self.content_nonce {
                if let Some(dek_sb) = user_dek_secret_box {
                    decrypt_gcm(&self.content, nonce, dek_sb).map_or_else(
                        |e| {
                            error!("Decryption failed for msg {}: {:?}", self.id, e);
                            Err(AppError::DecryptionError(format!("Decryption failed: {e}")))
                        },
                        |plaintext_secret_vec| {
                            String::from_utf8(plaintext_secret_vec.expose_secret().clone()).map_err(
                                |e| {
                                    error!("UTF-8 conversion error for msg {}: {:?}", self.id, e);
                                    AppError::DecryptionError(format!("UTF-8 conversion: {e}"))
                                },
                            )
                        },
                    )
                } else {
                    error!("Msg {} is encrypted but no DEK provided.", self.id);
                    Ok("[Content encrypted, DEK not available]".to_string())
                }
            } else {
                String::from_utf8(self.content.clone()).map_err(|e| {
                    error!("Invalid UTF-8 in plaintext for msg {}: {:?}", self.id, e);
                    AppError::InternalServerErrorGeneric(format!("Invalid UTF-8: {e}"))
                })
            };

        let final_decrypted_content = decrypted_content_result?;

        // Decrypt raw prompt if available (Message struct needs the same raw prompt methods as ChatMessage)
        let raw_prompt = if let Some(dek) = user_dek_secret_box {
            self.decrypt_raw_prompt_field(dek).unwrap_or_else(|e| {
                error!(
                    "Failed to decrypt raw prompt for message {}: {}",
                    self.id, e
                );
                None
            })
        } else {
            // If raw prompt exists but no DEK provided, indicate it's encrypted
            if self.raw_prompt_ciphertext.is_some() {
                Some("[Raw prompt encrypted, DEK not available]".to_string())
            } else {
                None
            }
        };

        Ok(ChatMessageForClient {
            id: self.id,
            session_id: self.session_id,
            message_type: self.message_type,
            content: final_decrypted_content,
            created_at: self.created_at,
            user_id: self.user_id,
            prompt_tokens: self.prompt_tokens,
            completion_tokens: self.completion_tokens,
            raw_prompt,
            model_name: self.model_name,
        })
    }
}

/// JSON-friendly structure for client responses
#[derive(Serialize, Deserialize, Clone)]
pub struct ClientChatMessage {
    pub id: Uuid,
    pub chat_id: Uuid,
    pub character_id: Uuid,
    pub content: String,
    pub role: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl std::fmt::Debug for ClientChatMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientChatMessage")
            .field("id", &self.id)
            .field("chat_id", &self.chat_id)
            .field("character_id", &self.character_id)
            .field("content", &"[REDACTED]")
            .field("role", &self.role)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// Structure for sending `ChatMessage` data to the client, with decrypted content.
#[derive(Serialize, Deserialize, Clone)]
pub struct ChatMessageForClient {
    pub id: Uuid,
    pub session_id: Uuid,
    pub message_type: MessageRole,
    pub content: String,
    pub created_at: DateTime<Utc>,
    pub user_id: Uuid,
    pub prompt_tokens: Option<i32>,
    pub completion_tokens: Option<i32>,
    pub raw_prompt: Option<String>,
    pub model_name: String,
}

impl std::fmt::Debug for ChatMessageForClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatMessageForClient")
            .field("id", &self.id)
            .field("session_id", &self.session_id)
            .field("message_type", &self.message_type)
            .field("content", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("user_id", &self.user_id)
            .field("prompt_tokens", &self.prompt_tokens)
            .field("completion_tokens", &self.completion_tokens)
            .field("model_name", &self.model_name)
            .field(
                "raw_prompt",
                &self.raw_prompt.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

// For inserting a new chat message
#[derive(Insertable, Default, Clone)]
#[diesel(table_name = chat_messages)]
pub struct NewChatMessage {
    pub id: Uuid,
    pub session_id: Uuid,
    pub message_type: MessageRole,
    pub content: Vec<u8>,
    pub content_nonce: Option<Vec<u8>>,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub role: Option<String>,
    pub parts: Option<serde_json::Value>,
    pub attachments: Option<serde_json::Value>,
    pub prompt_tokens: Option<i32>,
    pub completion_tokens: Option<i32>,
    pub raw_prompt_ciphertext: Option<Vec<u8>>,
    pub raw_prompt_nonce: Option<Vec<u8>>,
    pub model_name: String, // Added model_name field for consistency
}

impl std::fmt::Debug for NewChatMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewChatMessage")
            .field("id", &self.id)
            .field("session_id", &self.session_id)
            .field("message_type", &self.message_type)
            .field("content", &"[REDACTED_BYTES]")
            .field(
                "content_nonce",
                &self.content_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field("user_id", &self.user_id)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("role", &self.role)
            .field("parts", &self.parts.as_ref().map(|_| "[REDACTED_JSON]"))
            .field(
                "attachments",
                &self.attachments.as_ref().map(|_| "[REDACTED_JSON]"),
            )
            .field("prompt_tokens", &self.prompt_tokens)
            .field("completion_tokens", &self.completion_tokens)
            .field("model_name", &self.model_name)
            .field(
                "raw_prompt_ciphertext",
                &self
                    .raw_prompt_ciphertext
                    .as_ref()
                    .map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "raw_prompt_nonce",
                &self.raw_prompt_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .finish()
    }
}

// For inserting a new chat message with better naming clarity
#[derive(Insertable, Clone)]
#[diesel(table_name = chat_messages)]
pub struct DbInsertableChatMessage {
    #[diesel(column_name = session_id)]
    pub chat_id: Uuid,
    #[diesel(column_name = message_type)]
    pub msg_type: MessageRole,
    pub content: Vec<u8>,
    pub content_nonce: Option<Vec<u8>>,
    pub user_id: Uuid,
    pub role: Option<String>,
    pub parts: Option<serde_json::Value>,
    pub attachments: Option<serde_json::Value>,
    pub prompt_tokens: Option<i32>,
    pub completion_tokens: Option<i32>,
    pub raw_prompt_ciphertext: Option<Vec<u8>>,
    pub raw_prompt_nonce: Option<Vec<u8>>,
    pub model_name: String,
}

impl std::fmt::Debug for DbInsertableChatMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbInsertableChatMessage")
            .field("chat_id", &self.chat_id)
            .field("msg_type", &self.msg_type)
            .field("content", &"[REDACTED_BYTES]")
            .field(
                "content_nonce",
                &self.content_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .field("user_id", &self.user_id)
            .field("role", &self.role)
            .field("parts", &self.parts.as_ref().map(|_| "[REDACTED_JSON]"))
            .field(
                "attachments",
                &self.attachments.as_ref().map(|_| "[REDACTED_JSON]"),
            )
            .field("prompt_tokens", &self.prompt_tokens)
            .field("completion_tokens", &self.completion_tokens)
            .field("model_name", &self.model_name)
            .field(
                "raw_prompt_ciphertext",
                &self
                    .raw_prompt_ciphertext
                    .as_ref()
                    .map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "raw_prompt_nonce",
                &self.raw_prompt_nonce.as_ref().map(|_| "[REDACTED_NONCE]"),
            )
            .finish()
    }
}

impl DbInsertableChatMessage {
    /// Create a new chat message with required fields only
    #[must_use]
    pub fn new(
        chat_id: Uuid,
        user_id: Uuid,
        msg_type: MessageRole,
        content: Vec<u8>,
        content_nonce: Option<Vec<u8>>,
        model_name: String,
    ) -> Self {
        Self {
            chat_id,
            user_id,
            msg_type,
            content,
            content_nonce,
            model_name,
            role: None,
            parts: None,
            attachments: None,
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
        }
    }

    /// Builder methods for optional fields
    #[must_use]
    pub fn with_role(mut self, role: String) -> Self {
        self.role = Some(role);
        self
    }

    #[must_use]
    pub fn with_parts(mut self, parts: serde_json::Value) -> Self {
        self.parts = Some(parts);
        self
    }

    #[must_use]
    pub fn with_attachments(mut self, attachments: serde_json::Value) -> Self {
        self.attachments = Some(attachments);
        self
    }

    #[must_use]
    pub const fn with_token_counts(
        mut self,
        prompt_tokens: Option<i32>,
        completion_tokens: Option<i32>,
    ) -> Self {
        self.prompt_tokens = prompt_tokens;
        self.completion_tokens = completion_tokens;
        self
    }

    #[must_use]
    pub fn with_raw_prompt(
        mut self,
        raw_prompt_ciphertext: Option<Vec<u8>>,
        raw_prompt_nonce: Option<Vec<u8>>,
    ) -> Self {
        self.raw_prompt_ciphertext = raw_prompt_ciphertext;
        self.raw_prompt_nonce = raw_prompt_nonce;
        self
    }
}

// Request body for sending a new message (used by generate endpoint)
#[derive(Deserialize, Serialize)]
pub struct NewChatMessageRequest {
    pub content: String,
    pub model: Option<String>,
}

impl std::fmt::Debug for NewChatMessageRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewChatMessageRequest")
            .field("content", &"[REDACTED]")
            .field("model", &self.model)
            .finish()
    }
}

// API Request/Response Structures

#[derive(Deserialize, Serialize)]
pub struct CreateChatSessionPayload {
    pub character_id: Option<Uuid>,
    pub active_custom_persona_id: Option<Uuid>,
    pub chat_mode: Option<ChatMode>, // Default to Character if not provided
}

impl std::fmt::Debug for CreateChatSessionPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateChatSessionPayload")
            .field("character_id", &self.character_id)
            .field("active_custom_persona_id", &self.active_custom_persona_id)
            .field("chat_mode", &self.chat_mode)
            .finish()
    }
}

#[derive(Deserialize, Serialize)]
pub struct GenerateResponsePayload {
    pub content: String,
    pub model: Option<String>,
}

impl std::fmt::Debug for GenerateResponsePayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerateResponsePayload")
            .field("content", &"[REDACTED]")
            .field("model", &self.model)
            .finish()
    }
}

#[derive(Deserialize, Serialize)]
pub struct CreateMessageVariantPayload {
    pub content: String,
}

impl std::fmt::Debug for CreateMessageVariantPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateMessageVariantPayload")
            .field("content", &"[REDACTED]")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
pub struct GenerateResponse {
    pub ai_message: ChatMessage,
}

impl std::fmt::Debug for GenerateResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerateResponse")
            .field("ai_message", &self.ai_message)
            .finish()
    }
}

// --- Generate Endpoint Payload Structures ---

/// Represents a single message within the chat history payload.
#[derive(Deserialize, Serialize, Clone, Validate)]
pub struct ApiChatMessage {
    #[validate(length(min = 1))]
    pub role: String,
    #[validate(length(min = 1))]
    pub content: String,
}

impl std::fmt::Debug for ApiChatMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiChatMessage")
            .field("role", &self.role)
            .field("content", &"[REDACTED]")
            .finish()
    }
}

/// Request body for POST `/api/chat/{session_id}/generate`
#[derive(Deserialize, Serialize, Validate)]
pub struct GenerateChatRequest {
    #[validate(length(min = 1))]
    #[validate(nested)]
    pub history: Vec<ApiChatMessage>,
    pub model: Option<String>,
    pub query_text_for_rag: Option<String>,
}

impl std::fmt::Debug for GenerateChatRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerateChatRequest")
            .field(
                "history",
                &self
                    .history
                    .iter()
                    .map(|_| "[REDACTED_ApiChatMessage]")
                    .collect::<Vec<_>>(),
            )
            .field("model", &self.model)
            .field(
                "query_text_for_rag",
                &self.query_text_for_rag.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}
// --- Chat Client Response Structures ---

/// Chat struct for client responses with decrypted fields
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatForClient {
    pub id: Uuid,
    pub user_id: Uuid,
    pub character_id: Option<Uuid>,
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
    pub seed: Option<i32>,
    pub stop_sequences: Option<Vec<Option<String>>>,
    pub history_management_strategy: String,
    pub history_management_limit: i32,
    pub model_name: String,
    pub gemini_thinking_budget: Option<i32>,
    pub gemini_enable_code_execution: Option<bool>,
    pub visibility: Option<String>,
    pub active_custom_persona_id: Option<Uuid>,
    pub active_impersonated_character_id: Option<Uuid>,
    pub chat_mode: ChatMode,
    pub chronicle_id: Option<Uuid>, // Chronicle association (maps to player_chronicle_id in database)
}

impl Chat {
    /// Converts a `Chat` database model into a `ChatForClient` DTO,
    /// decrypting sensitive fields like `title` and `system_prompt` if a DEK is provided.
    ///
    /// If no DEK is provided, encrypted fields will be represented by a placeholder string.
    ///
    /// # Errors
    ///
    /// Returns `AppError::DecryptionError` if decryption fails due to invalid ciphertext, nonce,
    /// or key, or if UTF-8 conversion fails.
    pub fn into_decrypted_for_client(
        self,
        dek_opt: Option<&SecretBox<Vec<u8>>>,
    ) -> Result<ChatForClient, AppError> {
        let encryption_service = crate::services::encryption_service::EncryptionService::new();

        let decrypted_title = match (self.title_ciphertext, self.title_nonce) {
            (Some(ciphertext), Some(nonce)) => {
                if let Some(dek) = dek_opt {
                    if ciphertext.is_empty() && nonce.is_empty() {
                        // Convention for empty encrypted field
                        Ok(Some(String::new()))
                    } else if ciphertext.is_empty() || nonce.is_empty() {
                        // Mismatched state
                        Err(AppError::DecryptionError(
                            "Mismatched ciphertext/nonce for chat title: one is empty, the other is not."
                                .to_string(),
                        ))
                    } else {
                        let decrypted_bytes = encryption_service.decrypt(
                            &ciphertext,
                            &nonce,
                            dek.expose_secret().as_slice(),
                        )?;
                        String::from_utf8(decrypted_bytes).map(Some).map_err(|e| {
                            AppError::DecryptionError(format!(
                                "Invalid UTF-8 for decrypted chat title: {e}"
                            ))
                        })
                    }
                } else {
                    // Encrypted but no DEK
                    Ok(Some("[Encrypted]".to_string()))
                }
            }
            (None, None) => Ok(None), // No title was set
            (Some(_), None) => Err(AppError::DecryptionError(
                "Chat title ciphertext present but nonce missing.".to_string(),
            )),
            (None, Some(_)) => Err(AppError::DecryptionError(
                "Chat title nonce present but ciphertext missing.".to_string(),
            )),
        }?;

        let decrypted_system_prompt = match (
            self.system_prompt_ciphertext,
            self.system_prompt_nonce,
        ) {
            (Some(ciphertext), Some(nonce)) => {
                if let Some(dek) = dek_opt {
                    if ciphertext.is_empty() && nonce.is_empty() {
                        // Convention for empty encrypted field
                        Ok(Some(String::new()))
                    } else if ciphertext.is_empty() || nonce.is_empty() {
                        // Mismatched state
                        Err(AppError::DecryptionError(
                            "Mismatched ciphertext/nonce for system prompt: one is empty, the other is not."
                                .to_string(),
                        ))
                    } else {
                        let decrypted_bytes = encryption_service.decrypt(
                            &ciphertext,
                            &nonce,
                            dek.expose_secret().as_slice(),
                        )?;
                        String::from_utf8(decrypted_bytes).map(Some).map_err(|e| {
                            AppError::DecryptionError(format!(
                                "Invalid UTF-8 for decrypted system prompt: {e}"
                            ))
                        })
                    }
                } else {
                    // Encrypted but no DEK
                    Ok(Some("[Encrypted]".to_string()))
                }
            }
            (None, None) => Ok(None), // No system prompt was set
            (Some(_), None) => Err(AppError::DecryptionError(
                "System prompt ciphertext present but nonce missing.".to_string(),
            )),
            (None, Some(_)) => Err(AppError::DecryptionError(
                "System prompt nonce present but ciphertext missing.".to_string(),
            )),
        }?;

        Ok(ChatForClient {
            id: self.id,
            user_id: self.user_id,
            character_id: self.character_id,
            title: decrypted_title,
            system_prompt: decrypted_system_prompt,
            temperature: self.temperature,
            max_output_tokens: self.max_output_tokens,
            created_at: self.created_at,
            updated_at: self.updated_at,
            frequency_penalty: self.frequency_penalty,
            presence_penalty: self.presence_penalty,
            top_k: self.top_k,
            top_p: self.top_p,
            seed: self.seed,
            stop_sequences: self.stop_sequences,
            history_management_strategy: self.history_management_strategy,
            history_management_limit: self.history_management_limit,
            model_name: self.model_name,
            gemini_thinking_budget: self.gemini_thinking_budget,
            gemini_enable_code_execution: self.gemini_enable_code_execution,
            visibility: self.visibility,
            active_custom_persona_id: self.active_custom_persona_id,
            active_impersonated_character_id: self.active_impersonated_character_id,
            chat_mode: self.chat_mode,
            chronicle_id: self.player_chronicle_id, // Map database field to API field
        })
    }
}

// --- Chat Settings API Structures ---

/// Response body for GET /api/chat/{id}/settings
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ChatSettingsResponse {
    pub system_prompt: Option<String>,
    pub temperature: Option<BigDecimal>,
    pub max_output_tokens: Option<i32>,
    pub frequency_penalty: Option<BigDecimal>,
    pub presence_penalty: Option<BigDecimal>,
    pub top_k: Option<i32>,
    pub top_p: Option<BigDecimal>,
    pub seed: Option<i32>,
    pub stop_sequences: Option<Vec<Option<String>>>,
    // History Management Fields
    pub history_management_strategy: String,
    pub history_management_limit: i32,
    // Model Name
    pub model_name: String,
    // Gemini-specific options
    pub gemini_thinking_budget: Option<i32>,
    pub gemini_enable_code_execution: Option<bool>,
    // Chronicle association
    pub chronicle_id: Option<Uuid>,
    // Agent mode for context enrichment
    pub agent_mode: Option<String>,
}

impl std::fmt::Debug for ChatSettingsResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChatSettingsResponse")
            .field(
                "system_prompt",
                &self.system_prompt.as_ref().map(|_| "[REDACTED]"),
            )
            .field("temperature", &self.temperature)
            .field("max_output_tokens", &self.max_output_tokens)
            .field("frequency_penalty", &self.frequency_penalty)
            .field("presence_penalty", &self.presence_penalty)
            .field("top_k", &self.top_k)
            .field("top_p", &self.top_p)
            .field("seed", &self.seed)
            .field("stop_sequences", &self.stop_sequences)
            .field(
                "history_management_strategy",
                &self.history_management_strategy,
            )
            .field("history_management_limit", &self.history_management_limit)
            .field("model_name", &self.model_name)
            .field("gemini_thinking_budget", &self.gemini_thinking_budget)
            .field(
                "gemini_enable_code_execution",
                &self.gemini_enable_code_execution,
            )
            .field("chronicle_id", &self.chronicle_id)
            .finish()
    }
}
// Implement From<Chat> for ChatSettingsResponse
impl From<Chat> for ChatSettingsResponse {
    fn from(chat: Chat) -> Self {
        Self {
            system_prompt: None,
            temperature: chat.temperature,
            max_output_tokens: chat.max_output_tokens,
            frequency_penalty: chat.frequency_penalty,
            presence_penalty: chat.presence_penalty,
            top_k: chat.top_k,
            top_p: chat.top_p,
            seed: chat.seed,
            stop_sequences: chat.stop_sequences,
            history_management_strategy: chat.history_management_strategy,
            history_management_limit: chat.history_management_limit,
            model_name: chat.model_name,
            gemini_thinking_budget: chat.gemini_thinking_budget,
            gemini_enable_code_execution: chat.gemini_enable_code_execution,
            chronicle_id: chat.player_chronicle_id,
            agent_mode: chat.agent_mode,
        }
    }
}

/// Request body for PUT /api/chat/{id}/settings
/// All fields are optional to allow partial updates.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Validate, Default)]
pub struct UpdateChatSettingsRequest {
    pub system_prompt: Option<String>,
    #[validate(custom(function = "validate_optional_temperature"))]
    pub temperature: Option<BigDecimal>,
    #[validate(range(min = 1))]
    pub max_output_tokens: Option<i32>,
    #[validate(custom(function = "validate_optional_frequency_penalty"))]
    pub frequency_penalty: Option<BigDecimal>,
    #[validate(custom(function = "validate_optional_presence_penalty"))]
    pub presence_penalty: Option<BigDecimal>,
    #[validate(range(min = 0))]
    pub top_k: Option<i32>,
    #[validate(custom(function = "validate_optional_top_p"))]
    pub top_p: Option<BigDecimal>,
    pub seed: Option<i32>,
    pub stop_sequences: Option<Vec<Option<String>>>,
    // History Management Fields
    #[validate(custom(function = "validate_optional_history_strategy"))]
    pub history_management_strategy: Option<String>,
    #[validate(range(min = 1))]
    pub history_management_limit: Option<i32>,
    // Model Name
    pub model_name: Option<String>,
    // Gemini-specific options
    pub gemini_thinking_budget: Option<i32>,
    pub gemini_enable_code_execution: Option<bool>,
    // Chronicle association
    pub chronicle_id: Option<Uuid>,
    // Agent mode for context enrichment
    #[validate(custom(function = "validate_optional_agent_mode"))]
    pub agent_mode: Option<String>,
}

impl std::fmt::Debug for UpdateChatSettingsRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateChatSettingsRequest")
            .field(
                "system_prompt",
                &self.system_prompt.as_ref().map(|_| "[REDACTED]"),
            )
            .field("temperature", &self.temperature)
            .field("max_output_tokens", &self.max_output_tokens)
            .field("frequency_penalty", &self.frequency_penalty)
            .field("presence_penalty", &self.presence_penalty)
            .field("top_k", &self.top_k)
            .field("top_p", &self.top_p)
            .field("seed", &self.seed)
            .field("stop_sequences", &self.stop_sequences)
            .field(
                "history_management_strategy",
                &self.history_management_strategy,
            )
            .field("history_management_limit", &self.history_management_limit)
            .field("model_name", &self.model_name)
            .field("gemini_thinking_budget", &self.gemini_thinking_budget)
            .field(
                "gemini_enable_code_execution",
                &self.gemini_enable_code_execution,
            )
            .field("chronicle_id", &self.chronicle_id)
            .finish()
    }
}

/// Custom validation function for `agent_mode` (called only when Some)
///
/// # Errors
/// Returns `ValidationError` if the mode is not one of the allowed values
fn validate_optional_agent_mode(mode: &String) -> Result<(), ValidationError> {
    // Check if the mode is a known value
    match mode.as_str() {
        "disabled" | "pre_processing" | "post_processing" => Ok(()),
        _ => {
            let mut err = ValidationError::new("unknown_agent_mode");
            err.message = Some(format!("Unknown agent mode: {mode}. Allowed values are: disabled, pre_processing, post_processing").into());
            Err(err)
        }
    }
}

/// Custom validation function for `history_management_strategy` (called only when Some)
///
/// # Errors
/// Returns `ValidationError` if the strategy is not one of the allowed values
fn validate_optional_history_strategy(strategy: &String) -> Result<(), ValidationError> {
    // Check if the strategy is a known value
    match strategy.as_str() {
        "none"
        | "sliding_window_messages"
        | "sliding_window_tokens"
        | "truncate_tokens"
        | "message_window"
        | "token_limit" => Ok(()),
        _ => {
            let mut err = ValidationError::new("unknown_strategy");
            err.message = Some(format!("Unknown history management strategy: {strategy}. Allowed values are: none, sliding_window_messages, message_window, sliding_window_tokens, truncate_tokens, token_limit").into());
            Err(err)
        }
    }
}

/// Custom validation function for optional temperature (0.0 to 2.0)
///
/// # Errors
/// Returns `ValidationError` if temperature is not between 0.0 and 2.0
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

/// Custom validation function for optional frequency penalty (-2.0 to 2.0)
///
/// # Errors
/// Returns `ValidationError` if frequency penalty is not between -2.0 and 2.0
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

/// Custom validation function for optional presence penalty (-2.0 to 2.0)
///
/// # Errors
/// Returns `ValidationError` if presence penalty is not between -2.0 and 2.0
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

/// Custom validation function for optional top-p (0.0 to 1.0)
///
/// # Errors
/// Returns `ValidationError` if top-p value is not between 0.0 and 1.0
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

// --- Suggested Actions API Structures ---

/// Payload for requesting suggested actions.
#[derive(Serialize, Deserialize, Debug)]
pub struct SuggestedActionsRequest {
    // This struct is now empty. Context will be derived by the handler.
    // Potential future fields: num_suggestions_hint, etc.
}

/// Structure for a single suggested action
#[derive(Clone, Serialize, Deserialize)]
pub struct SuggestedActionItem {
    pub action: String,
}

impl std::fmt::Debug for SuggestedActionItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuggestedActionItem")
            .field("action", &"[REDACTED]")
            .finish()
    }
}

/// Token usage information for suggested actions
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SuggestedActionsTokenUsage {
    pub input_tokens: usize,
    pub output_tokens: usize,
    pub total_tokens: usize,
}

/// Response structure for suggested actions API
#[derive(Clone, Serialize, Deserialize)]
pub struct SuggestedActionsResponse {
    pub suggestions: Vec<SuggestedActionItem>,
    pub token_usage: Option<SuggestedActionsTokenUsage>,
}

impl std::fmt::Debug for SuggestedActionsResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuggestedActionsResponse")
            .field(
                "suggestions",
                &self
                    .suggestions
                    .iter()
                    .map(|_| "[REDACTED_SuggestedActionItem]")
                    .collect::<Vec<_>>(),
            )
            .field("token_usage", &self.token_usage)
            .finish()
    }
}

// MessageResponse struct for API responses
#[derive(Clone, Serialize, Deserialize)]
pub struct MessageResponse {
    pub id: Uuid,
    pub session_id: Uuid,
    pub message_type: MessageRole,
    pub role: String,
    pub parts: serde_json::Value,
    pub attachments: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub raw_prompt: Option<String>, // Debug field containing the full prompt sent to AI
    pub prompt_tokens: Option<i32>,
    pub completion_tokens: Option<i32>,
    pub model_name: Option<String>, // Optional for backward compatibility with existing messages
}

impl std::fmt::Debug for MessageResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageResponse")
            .field("id", &self.id)
            .field("session_id", &self.session_id)
            .field("message_type", &self.message_type)
            .field("role", &self.role)
            .field("parts", &"[REDACTED_JSON]")
            .field("attachments", &"[REDACTED_JSON]")
            .field("created_at", &self.created_at)
            .field(
                "raw_prompt",
                &self.raw_prompt.as_ref().map(|_| "[REDACTED_RAW_PROMPT]"),
            )
            .finish()
    }
}

// Vote struct for message voting
#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub chat_id: Uuid,
    pub message_id: Uuid,
    pub is_upvoted: bool,
}

impl std::fmt::Debug for Vote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vote")
            .field("chat_id", &self.chat_id)
            .field("message_id", &self.message_id)
            .field("is_upvoted", &self.is_upvoted)
            .finish()
    }
}

// VoteRequest struct for API requests
#[derive(Clone, Serialize, Deserialize)]
pub struct VoteRequest {
    pub message_id: Uuid,
    pub type_: String, // "up" or "down"
}

impl std::fmt::Debug for VoteRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VoteRequest")
            .field("message_id", &self.message_id)
            .field("type_", &self.type_)
            .finish()
    }
}

// UpdateChatVisibilityRequest struct for API requests
#[derive(Clone, Serialize, Deserialize)]
pub struct UpdateChatVisibilityRequest {
    pub visibility: String, // "public" or "private"
}

impl std::fmt::Debug for UpdateChatVisibilityRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateChatVisibilityRequest")
            .field("visibility", &self.visibility)
            .finish()
    }
}

// CreateChatRequest struct for API requests
#[derive(Clone, Serialize, Deserialize)]
pub struct CreateChatRequest {
    pub character_id: Uuid,
    pub title: Option<String>,
    pub active_custom_persona_id: Option<Uuid>,
    pub lorebook_ids: Option<Vec<Uuid>>,
}

impl std::fmt::Debug for CreateChatRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateChatRequest")
            .field("character_id", &self.character_id)
            .field("title", &self.title.as_ref().map(|_| "[REDACTED]"))
            .field("active_custom_persona_id", &self.active_custom_persona_id)
            .field("lorebook_ids", &self.lorebook_ids)
            .finish()
    }
}

// CreateMessageRequest struct for API requests
#[derive(Clone, Serialize, Deserialize)]
pub struct CreateMessageRequest {
    pub content: String,
    pub role: String,
    pub parts: Option<serde_json::Value>,
    pub attachments: Option<serde_json::Value>,
}

impl std::fmt::Debug for CreateMessageRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateMessageRequest")
            .field("content", &"[REDACTED]")
            .field("role", &self.role)
            .field("parts", &self.parts.as_ref().map(|_| "[REDACTED_JSON]"))
            .field(
                "attachments",
                &self.attachments.as_ref().map(|_| "[REDACTED_JSON]"),
            )
            .finish()
    }
}

// Text expansion request and response for AI-powered text impersonation
#[derive(Clone, Serialize, Deserialize, Validate)]
pub struct ExpandTextRequest {
    #[validate(length(min = 1, max = 2000))]
    pub original_text: String,
}

impl std::fmt::Debug for ExpandTextRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExpandTextRequest")
            .field("original_text", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ExpandTextResponse {
    pub expanded_text: String,
}

impl std::fmt::Debug for ExpandTextResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExpandTextResponse")
            .field("expanded_text", &"[REDACTED]")
            .finish()
    }
}

// Impersonate request and response for generating full user response
#[derive(Clone, Serialize, Deserialize, Validate)]
pub struct ImpersonateRequest {
    // Empty for now, uses chat context
}

impl std::fmt::Debug for ImpersonateRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImpersonateRequest").finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ImpersonateResponse {
    pub generated_response: String,
}

impl std::fmt::Debug for ImpersonateResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImpersonateResponse")
            .field("generated_response", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bigdecimal::BigDecimal;
    use chrono::Utc;
    use ring::rand::{SecureRandom, SystemRandom};
    use secrecy::SecretBox;
    use std::str::FromStr;
    use uuid::Uuid;
    use validator::Validate;

    // Helper function to generate a dummy DEK for testing
    fn generate_dummy_dek() -> SecretBox<Vec<u8>> {
        let mut key_bytes = vec![0u8; 32];
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
            character_id: Some(Uuid::new_v4()),
            chat_mode: ChatMode::Character,
            title_ciphertext: None,
            title_nonce: None,
            system_prompt_ciphertext: None,
            system_prompt_nonce: None,
            temperature: Some(bd("0.7")),
            max_output_tokens: Some(1024),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            frequency_penalty: Some(bd("0.0")),
            presence_penalty: Some(bd("0.0")),
            top_k: Some(50),
            top_p: Some(bd("0.9")),
            seed: Some(12345),
            stop_sequences: Some(vec![Some("\n\n".to_string()), Some("##".to_string())]),
            history_management_strategy: "none".to_string(),
            history_management_limit: 4096,
            model_name: "gemini-2.5-flash".to_string(),
            gemini_thinking_budget: None,
            gemini_enable_code_execution: None,
            visibility: Some("private".to_string()),
            active_custom_persona_id: None,
            active_impersonated_character_id: None,
            player_chronicle_id: None,
        }
    }

    #[test]
    fn test_debug_chat_session() {
        let session = create_sample_chat_session();
        let debug_str = format!("{session:?}");
        assert!(debug_str.contains("Chat {"));
        assert!(debug_str.contains(&session.id.to_string()));
        assert!(debug_str.contains("title_ciphertext: None"));
        assert!(debug_str.contains("title_nonce: None"));
        assert!(debug_str.contains("system_prompt_ciphertext: None"));
        assert!(debug_str.contains("system_prompt_nonce: None"));
        assert!(debug_str.contains("history_management_strategy: \"none\""));
    }

    #[test]
    fn test_clone_chat_session() {
        let original = create_sample_chat_session();
        let cloned = &original;
        assert_eq!(original.id, cloned.id);
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
        let cloned = original;
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_message_role_display() {
        assert_eq!(MessageRole::User.to_string(), "User");
        assert_eq!(MessageRole::Assistant.to_string(), "Assistant");
        assert_eq!(MessageRole::System.to_string(), "System");
    }

    // Helper function to create a sample chat message
    fn create_sample_chat_message_db() -> ChatMessage {
        ChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: b"Hello, how are you?".to_vec(),
            content_nonce: None,
            created_at: Utc::now(),
            user_id: Uuid::new_v4(),
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        }
    }

    #[test]
    fn test_debug_chat_message() {
        let message = create_sample_chat_message_db();
        let debug_str = format!("{message:?}");
        assert!(debug_str.contains("ChatMessage"));
        assert!(debug_str.contains(&message.id.to_string()));
        assert!(debug_str.contains("content: \"[REDACTED_BYTES]\""));
    }

    #[test]
    fn test_clone_chat_message() {
        let original = create_sample_chat_message_db();
        let cloned = &original;
        assert_eq!(original.id, cloned.id);
        assert_eq!(original.user_id, cloned.user_id);
    }

    #[test]
    fn test_serde_chat_message() {
        let message = create_sample_chat_message_db();
        let serialized = serde_json::to_string(&message).expect("Serialization failed");
        let deserialized: ChatMessage =
            serde_json::from_str(&serialized).expect("Deserialization failed");
        assert_eq!(message.id, deserialized.id);
        assert_eq!(message.user_id, deserialized.user_id);
    }

    #[test]
    fn test_encrypt_decrypt_chat_message_content() {
        let dek = generate_dummy_dek();
        let mut message = create_sample_chat_message_db();
        let original_content_str = String::from_utf8(message.content.clone()).unwrap();

        // Encrypt
        message
            .encrypt_content_field(&dek, &original_content_str)
            .unwrap();
        assert_ne!(
            message.content,
            original_content_str.as_bytes(),
            "Content should be encrypted"
        );

        // Decrypt
        let decrypted_content = message.decrypt_content_field(&dek).unwrap();
        assert_eq!(
            decrypted_content, original_content_str,
            "Decrypted content should match original"
        );

        // Test with empty string
        message.encrypt_content_field(&dek, "").unwrap();
        assert!(
            message.content.is_empty(),
            "Encrypting empty string should result in empty bytes"
        );
        let decrypted_empty = message.decrypt_content_field(&dek).unwrap();
        assert_eq!(
            decrypted_empty, "",
            "Decrypting empty bytes should result in empty string"
        );
    }

    #[test]
    fn test_chat_message_into_decrypted_for_client() {
        let dek = generate_dummy_dek();
        let mut message_db = create_sample_chat_message_db();
        let original_content_str = String::from_utf8(message_db.content.clone()).unwrap();

        // Encrypt the content for the DB version
        message_db
            .encrypt_content_field(&dek, &original_content_str)
            .unwrap();

        // Test with DEK
        let client_message_with_dek = message_db
            .clone()
            .into_decrypted_for_client(Some(&dek))
            .unwrap();
        assert_eq!(client_message_with_dek.content, original_content_str);
        assert_eq!(client_message_with_dek.id, message_db.id);

        // Test without DEK (when content is encrypted)
        let client_message_without_dek =
            message_db.clone().into_decrypted_for_client(None).unwrap();
        assert_eq!(
            client_message_without_dek.content,
            "[Content encrypted, DEK not available]"
        );
        // Test with initially empty content
        let mut empty_content_msg_db = create_sample_chat_message_db();
        empty_content_msg_db.content = Vec::new();
        let client_empty_with_dek = empty_content_msg_db
            .clone()
            .into_decrypted_for_client(Some(&dek))
            .unwrap();
        assert_eq!(client_empty_with_dek.content, "");
        let client_empty_without_dek = empty_content_msg_db
            .into_decrypted_for_client(None)
            .unwrap();
        assert_eq!(client_empty_without_dek.content, "");
    }

    // Helper function to create a sample new chat message
    fn create_sample_new_chat_message_db() -> NewChatMessage {
        NewChatMessage {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            message_type: MessageRole::User,
            content: b"Hello!".to_vec(),
            content_nonce: None,
            user_id: Uuid::new_v4(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            role: Some("user".to_string()),
            parts: None,
            attachments: None,
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: "test-model".to_string(),
        }
    }

    #[test]
    fn test_debug_new_chat_message() {
        let message = create_sample_new_chat_message_db();
        let debug_str = format!("{message:?}");
        assert!(debug_str.contains("NewChatMessage"));
        assert!(debug_str.contains(&message.session_id.to_string()));
        assert!(debug_str.contains("content: \"[REDACTED_BYTES]\""));
    }

    #[test]
    fn test_clone_new_chat_message() {
        let original = create_sample_new_chat_message_db();
        let cloned = &original;
        // Test specific fields to ensure deep clone works correctly
        assert_eq!(original.session_id, cloned.session_id);
        assert_eq!(original.message_type, cloned.message_type);
        assert_eq!(original.content, cloned.content);
        assert_eq!(original.content_nonce, cloned.content_nonce);
        assert_eq!(original.user_id, cloned.user_id);
    }

    #[test]
    fn test_db_insertable_chat_message() {
        let chat_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let role = MessageRole::User;
        let content_str = "Test message";
        let content_vec = content_str.as_bytes().to_vec();

        let message =
            DbInsertableChatMessage::new(chat_id, user_id, role, content_vec.clone(), None, "test-model".to_string());
        assert_eq!(message.chat_id, chat_id);
        assert_eq!(message.user_id, user_id);
        assert_eq!(message.msg_type, role);
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
            seed: Some(12345),
            stop_sequences: Some(vec![Some("\n\n".to_string()), Some("##".to_string())]),
            history_management_strategy: "none".to_string(),
            history_management_limit: 4096,
            model_name: "gemini-2.5-flash".to_string(),
            gemini_thinking_budget: None,
            gemini_enable_code_execution: None,
            chronicle_id: None,
        }
    }

    #[test]
    fn test_debug_chat_settings_response() {
        let settings = create_sample_chat_settings_response();
        let debug_str = format!("{settings:?}");
        assert!(debug_str.contains("ChatSettingsResponse"));
        assert!(debug_str.contains("system_prompt: Some(\"[REDACTED]\")"));
        assert!(debug_str.contains("temperature: Some"));
        assert!(debug_str.contains("history_management_strategy: \"none\""));
    }

    #[test]
    fn test_clone_chat_settings_response() {
        let original = create_sample_chat_settings_response();
        let cloned = &original;

        // Test overall equality first
        assert_eq!(original, *cloned);
        // Test specific fields to ensure deep clone
        assert_eq!(original.system_prompt, cloned.system_prompt);
        assert_eq!(original.temperature, cloned.temperature);
        assert_eq!(original.max_output_tokens, cloned.max_output_tokens);
        assert_eq!(
            original.history_management_strategy,
            cloned.history_management_strategy
        );
        assert_eq!(
            original.history_management_limit,
            cloned.history_management_limit
        );
        assert_eq!(original.model_name, cloned.model_name);
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
            seed: Some(42),
            stop_sequences: Some(vec![Some("\n\n".to_string()), Some("##".to_string())]),
            history_management_strategy: Some("sliding_window_tokens".to_string()),
            history_management_limit: Some(2000),
            model_name: Some("gemini-2.5-pro".to_string()),
            gemini_thinking_budget: None,
            gemini_enable_code_execution: None,
            chronicle_id: None,
        }
    }

    #[test]
    fn test_debug_update_chat_settings_request() {
        let settings = create_sample_update_chat_settings_request();
        let debug_str = format!("{settings:?}");
        assert!(debug_str.contains("UpdateChatSettingsRequest"));
        assert!(debug_str.contains("system_prompt: Some(\"[REDACTED]\")"));
        assert!(debug_str.contains("temperature: Some"));
        assert!(debug_str.contains("history_management_strategy: Some(\"sliding_window_tokens\")"));
    }

    #[test]
    fn test_clone_update_chat_settings_request() {
        let original = create_sample_update_chat_settings_request();
        let cloned = &original;

        // Test overall equality first
        assert_eq!(original, *cloned);
        // Test specific fields to ensure deep clone
        assert_eq!(original.system_prompt, cloned.system_prompt);
        assert_eq!(original.temperature, cloned.temperature);
        assert_eq!(original.max_output_tokens, cloned.max_output_tokens);
        assert_eq!(
            original.history_management_strategy,
            cloned.history_management_strategy
        );
        assert_eq!(
            original.history_management_limit,
            cloned.history_management_limit
        );
        assert_eq!(original.model_name, cloned.model_name);
    }

    #[test]
    fn test_serde_chat_settings_response() {
        let settings = create_sample_chat_settings_response();
        let serialized = serde_json::to_string(&settings).expect("Serialization failed");
        let deserialized: ChatSettingsResponse =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(settings.system_prompt, deserialized.system_prompt);
        assert_eq!(settings.temperature, deserialized.temperature);
        assert_eq!(settings.max_output_tokens, deserialized.max_output_tokens);
        assert_eq!(
            settings.history_management_strategy,
            deserialized.history_management_strategy
        );
        assert_eq!(
            settings.history_management_limit,
            deserialized.history_management_limit
        );
        assert_eq!(settings.model_name, deserialized.model_name);
    }

    #[test]
    fn test_serde_update_chat_settings_request() {
        let settings = create_sample_update_chat_settings_request();
        let serialized = serde_json::to_string(&settings).expect("Serialization failed");
        let deserialized: UpdateChatSettingsRequest =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(settings.system_prompt, deserialized.system_prompt);
        assert_eq!(settings.temperature, deserialized.temperature);
        assert_eq!(settings.max_output_tokens, deserialized.max_output_tokens);
        assert_eq!(
            settings.history_management_strategy,
            deserialized.history_management_strategy
        );
        assert_eq!(
            settings.history_management_limit,
            deserialized.history_management_limit
        );
        assert_eq!(settings.model_name, deserialized.model_name);
    }

    #[test]
    fn test_new_chat_message_request_serde() {
        let original = NewChatMessageRequest {
            content: "Hello AI".to_string(),
            model: Some("gemini-2.5-flash".to_string()),
        };

        let serialized = serde_json::to_string(&original).expect("Serialization failed");
        let deserialized: NewChatMessageRequest =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(original.content, deserialized.content);
        assert_eq!(original.model, deserialized.model);
    }

    #[test]
    fn test_generate_response_payload_serde() {
        let original = GenerateResponsePayload {
            content: "Hello human".to_string(),
            model: Some("gemini-2.5-flash".to_string()),
        };

        let serialized = serde_json::to_string(&original).expect("Serialization failed");
        let deserialized: GenerateResponsePayload =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(original.content, deserialized.content);
        assert_eq!(original.model, deserialized.model);
    }

    #[test]
    fn test_partial_eq_chat_settings_response() {
        let settings1 = create_sample_chat_settings_response();
        let mut settings2 = create_sample_chat_settings_response();

        assert_eq!(settings1, settings2);

        // Test temperature inequality
        settings2.temperature = Some(bd("0.9"));
        assert_ne!(settings1, settings2);

        // Test history_management_limit inequality
        let original_settings = create_sample_chat_settings_response();
        let mut settings3 = create_sample_chat_settings_response();
        settings3.history_management_limit = 1000;
        assert_ne!(original_settings, settings3);

        // Test history_management_strategy inequality
        let original_settings2 = create_sample_chat_settings_response();
        let mut settings4 = create_sample_chat_settings_response();
        settings4.history_management_strategy = "sliding_window_messages".to_string();
        assert_ne!(original_settings2, settings4);
    }

    #[test]
    fn test_partial_eq_update_chat_settings_request() {
        let settings1 = create_sample_update_chat_settings_request();
        let mut settings2 = create_sample_update_chat_settings_request();

        assert_eq!(settings1, settings2);

        // Test temperature inequality
        settings2.temperature = Some(bd("0.8"));
        assert_ne!(settings1, settings2);

        // Test history_management_strategy inequality
        let original_settings = create_sample_update_chat_settings_request();
        let mut settings3 = create_sample_update_chat_settings_request();
        settings3.history_management_strategy = Some("none".to_string());
        assert_ne!(original_settings, settings3);

        // Test history_management_limit inequality
        let original_settings2 = create_sample_update_chat_settings_request();
        let mut settings4 = create_sample_update_chat_settings_request();
        settings4.history_management_limit = Some(100);
        assert_ne!(original_settings2, settings4);
    }

    #[test]
    fn test_update_chat_settings_request_validation() {
        // Valid
        let valid_settings = UpdateChatSettingsRequest {
            history_management_strategy: Some("sliding_window_tokens".to_string()),
            history_management_limit: Some(1000),
            ..Default::default()
        };
        assert!(valid_settings.validate().is_ok());

        let valid_settings_none = UpdateChatSettingsRequest {
            history_management_strategy: Some("none".to_string()),
            history_management_limit: Some(1),
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
        assert!(
            err.field_errors()
                .contains_key("history_management_strategy")
        );
        assert_eq!(
            err.field_errors()["history_management_strategy"][0].code,
            "unknown_strategy"
        );

        // Invalid limit (zero)
        let invalid_limit_zero = UpdateChatSettingsRequest {
            history_management_strategy: Some("none".to_string()),
            history_management_limit: Some(0),
            ..Default::default()
        };
        let err = invalid_limit_zero.validate().unwrap_err();
        assert!(err.field_errors().contains_key("history_management_limit"));
        assert_eq!(
            err.field_errors()["history_management_limit"][0].code,
            "range"
        );

        // Invalid limit (negative)
        let invalid_limit_neg = UpdateChatSettingsRequest {
            history_management_strategy: Some("none".to_string()),
            history_management_limit: Some(-100),
            ..Default::default()
        };
        let err = invalid_limit_neg.validate().unwrap_err();
        assert!(err.field_errors().contains_key("history_management_limit"));
        assert_eq!(
            err.field_errors()["history_management_limit"][0].code,
            "range"
        );

        // Test optional fields being None (should be valid)
        let none_settings = UpdateChatSettingsRequest {
            history_management_strategy: None,
            history_management_limit: None,
            ..Default::default()
        };
        assert!(none_settings.validate().is_ok());
    }
}

// ============================================================================
// Message Variants Models
// ============================================================================

/// Database model for message variants
#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Clone, Associations)]
#[diesel(belongs_to(ChatMessage, foreign_key = parent_message_id))]
#[diesel(table_name = message_variants)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct MessageVariant {
    pub id: Uuid,
    pub parent_message_id: Uuid,
    pub variant_index: i32,
    pub content: Vec<u8>, // Encrypted content
    pub content_nonce: Option<Vec<u8>>,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Insertable model for creating new message variants
#[derive(Insertable, Serialize, Deserialize, Clone)]
#[diesel(table_name = message_variants)]
pub struct NewMessageVariant {
    pub parent_message_id: Uuid,
    pub variant_index: i32,
    pub content: Vec<u8>, // Encrypted content
    pub content_nonce: Option<Vec<u8>>,
    pub user_id: Uuid,
}

impl MessageVariant {
    /// Decrypt the content field using the provided DEK
    pub fn decrypt_content(&self, dek: &SecretBox<Vec<u8>>) -> Result<String, AppError> {
        if self.content.is_empty() {
            return Ok(String::new());
        }

        let nonce = self.content_nonce.as_ref().ok_or_else(|| {
            tracing::error!(
                "MessageVariant ID {} content is present but nonce is missing. Cannot decrypt.",
                self.id
            );
            AppError::DecryptionError("Missing nonce for content decryption".to_string())
        })?;

        if nonce.is_empty() {
            tracing::error!(
                "MessageVariant ID {} content is present but nonce is empty. Cannot decrypt.",
                self.id
            );
            return Err(AppError::DecryptionError(
                "Nonce is empty for content decryption".to_string(),
            ));
        }

        let plaintext_secret = decrypt_gcm(&self.content, nonce, dek).map_err(|e| {
            error!(
                "Failed to decrypt message variant content for ID {}: {}",
                self.id, e
            );
            AppError::DecryptionError(format!("Decryption failed for variant content: {e}"))
        })?;

        String::from_utf8(plaintext_secret.expose_secret().clone()).map_err(|e| {
            tracing::error!(
                "Failed to convert decrypted variant content to UTF-8: {}",
                e
            );
            AppError::DecryptionError("Failed to convert variant content to UTF-8".to_string())
        })
    }
}

impl NewMessageVariant {
    /// Create a new message variant with encrypted content
    pub fn new(
        parent_message_id: Uuid,
        variant_index: i32,
        content: &str,
        user_id: Uuid,
        dek: &SecretBox<Vec<u8>>,
    ) -> Result<Self, AppError> {
        let (encrypted_content, nonce) = encrypt_gcm(content.as_bytes(), dek)
            .map_err(|e| AppError::CryptoError(e.to_string()))?;

        Ok(Self {
            parent_message_id,
            variant_index,
            content: encrypted_content,
            content_nonce: Some(nonce),
            user_id,
        })
    }
}

/// DTO for API responses containing decrypted variant data
#[derive(Serialize, Deserialize, Clone)]
pub struct MessageVariantDto {
    pub id: Uuid,
    pub parent_message_id: Uuid,
    pub variant_index: i32,
    pub content: String, // Decrypted content
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl MessageVariantDto {
    /// Convert from database model with decrypted content
    pub fn from_model(variant: MessageVariant, dek: &SecretBox<Vec<u8>>) -> Result<Self, AppError> {
        let content = variant.decrypt_content(dek)?;

        Ok(Self {
            id: variant.id,
            parent_message_id: variant.parent_message_id,
            variant_index: variant.variant_index,
            content,
            user_id: variant.user_id,
            created_at: variant.created_at,
            updated_at: variant.updated_at,
        })
    }
}
