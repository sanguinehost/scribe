use crate::db::{DbBigInt, DbTimestamp};
use crate::schema::{chat_messages, chat_sessions, message_variants};
use bigdecimal::{BigDecimal, ToPrimitive};
use diesel::{Associations, Identifiable, Insertable, Queryable, Selectable};
use diesel::{BoolExpressionMethods, ExpressionMethods, QueryDsl, RunQueryDsl};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use validator::{Validate, ValidationError};

// Import necessary Diesel traits for manual enum mapping
use diesel::deserialize::{self, FromSql, FromSqlRow};
use diesel::expression::AsExpression;
use diesel::pg::{Pg, PgValue};
use diesel::serialize::{self, IsNull, Output, ToSql};
use std::io::Write;

use crate::crypto::{decrypt_gcm, encrypt_gcm};
use crate::errors::AppError;
use secrecy::ExposeSecret;
use secrecy::SecretBox;

/// Custom serializers for BigDecimal types
mod bigdecimal_serde {

    use serde::Serializer;
    use std::str::FromStr;

    /// Serialize BigDecimal as f64 for JSON compatibility
    pub fn serialize_as_f64<S>(
        value: &crate::db::DbDecimal,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert BigDecimal to string, then parse as f64
        let s = value.to_string();
        match f64::from_str(&s) {
            Ok(f) => serializer.serialize_f64(f),
            Err(e) => {
                tracing::error!(
                    "Failed to serialize crate::db::DbDecimal '{}' to f64: {}. Falling back to 0.0",
                    s,
                    e
                );
                serializer.serialize_f64(0.0)
            }
        }
    }
}

/// Represents the cost breakdown for an LLM generation request
///
/// This struct separates the raw API cost (in dollars) from the user-facing
/// credits charged, making the billing calculation clear and explicit.
#[derive(Debug, Clone, Copy)]
pub struct GenerationCost {
    /// Raw cost from the LLM provider in dollars (before any markup)
    pub api_cost_dollars: f64,
    /// Integer credits deducted from the user's balance (after markup)
    pub credits_charged: i32,
}

/// Represents the status of a chat message
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, diesel::query_builder::QueryId,
)]
pub enum MessageStatus {
    /// Message is being generated
    Streaming,
    /// Message was successfully completed
    Completed,
    /// Message generation failed with an error
    Failed,
    /// Message was partially generated before an error
    Partial,
    /// Message is pending (queued for generation)
    Pending,
}

impl std::fmt::Display for MessageStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Streaming => "streaming",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Partial => "partial",
            Self::Pending => "pending",
        };
        write!(f, "{}", s)
    }
}

impl std::str::FromStr for MessageStatus {
    type Err = AppError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "streaming" => Ok(Self::Streaming),
            "completed" => Ok(Self::Completed),
            "failed" => Ok(Self::Failed),
            "partial" => Ok(Self::Partial),
            "pending" => Ok(Self::Pending),
            _ => Err(AppError::BadRequest(format!(
                "Invalid message status: {}",
                s
            ))),
        }
    }
}

// Main Chat model (similar to the frontend Chat type)
// Type alias for the tuple returned when selecting/returning chat settings
pub type SettingsTuple = (
    Option<Vec<u8>>,                            // system_prompt_ciphertext
    Option<Vec<u8>>,                            // system_prompt_nonce
    Option<crate::db::DbDecimal>,               // temperature
    Option<i32>,                                // max_output_tokens
    Option<crate::db::DbDecimal>,               // frequency_penalty
    Option<crate::db::DbDecimal>,               // presence_penalty
    Option<i32>,                                // top_k
    Option<crate::db::DbDecimal>,               // top_p
    Option<i32>,                                // seed
    Option<crate::models::OptionalStringArray>, // stop_sequences
    String,                                     // history_management_strategy
    i32,                                        // history_management_limit
    String,                                     // model_name
    // -- Gemini Specific Options --
    Option<i32>,  // gemini_thinking_budget
    Option<bool>, // gemini_enable_code_execution
    // -- Chronicle Support --
    Option<crate::db::DbId>, // player_chronicle_id
    // -- Agent Mode --
    Option<String>, // agent_mode
    // -- Active Persona --
    Option<crate::db::DbId>, // active_custom_persona_id
    // -- Prompt Template --
    String, // prompt_template_id
); // Close the tuple definition
#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Clone)]
#[diesel(table_name = chat_sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Chat {
    pub id: crate::db::DbId,
    pub user_id: crate::db::DbId,
    pub character_id: Option<crate::db::DbId>,
    pub temperature: Option<crate::db::DbDecimal>,
    pub max_output_tokens: Option<i32>,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub frequency_penalty: Option<crate::db::DbDecimal>,
    pub presence_penalty: Option<crate::db::DbDecimal>,
    pub top_k: Option<i32>,
    pub top_p: Option<crate::db::DbDecimal>,
    pub repetition_penalty: Option<crate::db::DbDecimal>,
    pub min_p: Option<crate::db::DbDecimal>,
    pub top_a: Option<crate::db::DbDecimal>,
    pub seed: Option<i32>,
    pub logit_bias: Option<crate::db::DbJson>,
    pub history_management_strategy: String,
    pub history_management_limit: i32,
    pub model_name: String,
    pub thinking_budget: Option<i32>,
    pub enable_code_execution: Option<bool>,
    pub visibility: Option<String>,
    pub active_custom_persona_id: Option<crate::db::DbId>,
    pub active_impersonated_character_id: Option<crate::db::DbId>,
    pub system_prompt_ciphertext: Option<Vec<u8>>,
    pub system_prompt_nonce: Option<Vec<u8>>,
    pub title_ciphertext: Option<Vec<u8>>,
    pub title_nonce: Option<Vec<u8>>,
    pub stop_sequences: Option<crate::models::OptionalStringArray>,
    pub chat_mode: ChatMode,
    pub player_chronicle_id: Option<crate::db::DbId>,
    pub agent_mode: Option<String>,
    pub model_provider: Option<String>,
    pub total_prompt_tokens: DbBigInt,
    pub total_completion_tokens: DbBigInt,
    pub estimated_cost_cents: i32,
    pub tokens_counted_at: DbTimestamp,
    pub prompt_template_id: String,
    pub total_credits_used: crate::db::DbDecimal,
    // New cost tracking fields
    #[serde(serialize_with = "bigdecimal_serde::serialize_as_f64")]
    pub total_actual_cost: crate::db::DbDecimal,
    #[serde(serialize_with = "bigdecimal_serde::serialize_as_f64")]
    pub total_modified_cost: crate::db::DbDecimal,
    pub total_credit_cost: i32,
    #[serde(serialize_with = "bigdecimal_serde::serialize_as_f64")]
    pub total_actual_charge: crate::db::DbDecimal,
    pub narrative_style_override_ciphertext: Option<Vec<u8>>,
    pub narrative_style_override_nonce: Option<Vec<u8>>,
    // Game Master Agent fields
    pub game_state: Option<crate::db::DbJson>, // JSON-encoded GameState
    pub game_master_mode_enabled: bool,        // Feature flag
    pub thinking_level: Option<String>,
    pub rag_chronicles_limit: Option<i32>,
    pub rag_lorebooks_limit: Option<i32>,
    pub rag_older_chat_limit: Option<i32>,
    pub rag_cognitive_context_limit: Option<i32>,
}

/// Lightweight DTO for listing chats (avoids Diesel's 32-field tuple limit)
#[derive(Queryable, Selectable, Clone, Serialize, Deserialize)]
#[diesel(table_name = chat_sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ChatListQuery {
    pub id: crate::db::DbId,
    pub user_id: crate::db::DbId,
    pub character_id: Option<crate::db::DbId>,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub title_ciphertext: Option<Vec<u8>>,
    pub title_nonce: Option<Vec<u8>>,
    pub system_prompt_ciphertext: Option<Vec<u8>>,
    pub system_prompt_nonce: Option<Vec<u8>>,
    pub model_name: String,
    pub chat_mode: ChatMode,
    pub history_management_strategy: String,
    pub history_management_limit: i32,
    pub stop_sequences: Option<crate::models::OptionalStringArray>,
    pub total_prompt_tokens: DbBigInt,
    pub total_completion_tokens: DbBigInt,
    pub estimated_cost_cents: i32,
    pub tokens_counted_at: DbTimestamp,
    pub prompt_template_id: String,
    pub total_credits_used: crate::db::DbDecimal,
    pub total_actual_cost: crate::db::DbDecimal,
    pub total_modified_cost: crate::db::DbDecimal,
    pub total_credit_cost: i32,
    pub total_actual_charge: crate::db::DbDecimal,
    pub narrative_style_override_ciphertext: Option<Vec<u8>>,
    pub narrative_style_override_nonce: Option<Vec<u8>>,
    pub visibility: Option<String>,
    pub player_chronicle_id: Option<crate::db::DbId>,
    pub game_master_mode_enabled: bool,
    pub game_state: Option<crate::db::DbJson>,
}

impl ChatListQuery {
    /// Convert to ChatForClient with decrypted title and system_prompt
    pub fn into_decrypted_for_client(
        self,
        dek_opt: Option<&SecretBox<Vec<u8>>>,
    ) -> Result<ChatForClient, AppError> {
        let encryption_service = crate::services::encryption_service::EncryptionService::new();

        let decrypted_title = match (self.title_ciphertext, self.title_nonce) {
            (Some(ciphertext), Some(nonce)) => {
                if let Some(dek) = dek_opt {
                    if ciphertext.is_empty() && nonce.is_empty() {
                        Ok(Some(String::new()))
                    } else if ciphertext.is_empty() || nonce.is_empty() {
                        Err(AppError::DecryptionError(
                            "Mismatched ciphertext/nonce for chat title".to_string(),
                        ))
                    } else {
                        let decrypted_bytes = encryption_service.decrypt(
                            &ciphertext,
                            &nonce,
                            dek.expose_secret().as_slice(),
                        )?;
                        String::from_utf8(decrypted_bytes).map(Some).map_err(|e| {
                            AppError::DecryptionError(format!("Invalid UTF-8 for chat title: {e}"))
                        })
                    }
                } else {
                    Ok(Some("[Encrypted]".to_string()))
                }
            }
            (None, None) => Ok(None),
            _ => Err(AppError::DecryptionError(
                "Mismatched title ciphertext/nonce".to_string(),
            )),
        }?;

        let decrypted_system_prompt =
            match (self.system_prompt_ciphertext, self.system_prompt_nonce) {
                (Some(ciphertext), Some(nonce)) => {
                    if let Some(dek) = dek_opt {
                        if ciphertext.is_empty() && nonce.is_empty() {
                            Ok(Some(String::new()))
                        } else if ciphertext.is_empty() || nonce.is_empty() {
                            Err(AppError::DecryptionError(
                                "Mismatched ciphertext/nonce for system prompt".to_string(),
                            ))
                        } else {
                            let decrypted_bytes = encryption_service.decrypt(
                                &ciphertext,
                                &nonce,
                                dek.expose_secret().as_slice(),
                            )?;
                            String::from_utf8(decrypted_bytes).map(Some).map_err(|e| {
                                AppError::DecryptionError(format!(
                                    "Invalid UTF-8 for system prompt: {e}"
                                ))
                            })
                        }
                    } else {
                        Ok(Some("[Encrypted]".to_string()))
                    }
                }
                (None, None) => Ok(None),
                _ => Err(AppError::DecryptionError(
                    "Mismatched system prompt ciphertext/nonce".to_string(),
                )),
            }?;

        Ok(ChatForClient {
            id: self.id,
            user_id: self.user_id,
            character_id: self.character_id,
            title: decrypted_title,
            system_prompt: decrypted_system_prompt,
            temperature: None,
            max_output_tokens: None,
            created_at: self.created_at,
            updated_at: self.updated_at,
            frequency_penalty: None,
            presence_penalty: None,
            top_k: None,
            top_p: None,
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: None,
            logit_bias: None,
            stop_sequences: self.stop_sequences.clone(),
            history_management_strategy: self.history_management_strategy,
            history_management_limit: self.history_management_limit,
            model_name: Some(self.model_name),
            thinking_budget: None,
            enable_code_execution: None,
            visibility: self.visibility,
            active_custom_persona_id: None,
            active_impersonated_character_id: None,
            chat_mode: self.chat_mode,
            chronicle_id: self.player_chronicle_id,
            total_prompt_tokens: self.total_prompt_tokens,
            total_completion_tokens: self.total_completion_tokens,
            total_credits_used: self.total_credits_used,
            total_actual_cost: crate::db::DbDecimal::from(0), // ChatListItem doesn't have actual cost data
            game_master_mode_enabled: self.game_master_mode_enabled,
            game_state: self.game_state,
            thinking_level: None,
            rag_chronicles_limit: None,
            rag_lorebooks_limit: None,
            rag_older_chat_limit: None,
            rag_cognitive_context_limit: None,
        })
    }
}

/// DTO for active chat session queries (includes generation params, avoids 32-field limit)
#[derive(Queryable, Selectable, Clone, Serialize, Deserialize)]
#[diesel(table_name = chat_sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ChatSessionQuery {
    pub id: crate::db::DbId,
    pub user_id: crate::db::DbId,
    pub character_id: Option<crate::db::DbId>,
    pub temperature: Option<crate::db::DbDecimal>,
    pub max_output_tokens: Option<i32>,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub frequency_penalty: Option<crate::db::DbDecimal>,
    pub presence_penalty: Option<crate::db::DbDecimal>,
    pub top_k: Option<i32>,
    pub top_p: Option<crate::db::DbDecimal>,
    pub repetition_penalty: Option<crate::db::DbDecimal>,
    pub min_p: Option<crate::db::DbDecimal>,
    pub top_a: Option<crate::db::DbDecimal>,
    pub seed: Option<i32>,
    pub logit_bias: Option<crate::db::DbJson>,
    pub history_management_strategy: String,
    pub history_management_limit: i32,
    pub model_name: String,
    pub thinking_budget: Option<i32>,
    pub enable_code_execution: Option<bool>,
    pub visibility: Option<String>,
    pub active_custom_persona_id: Option<crate::db::DbId>,
    pub active_impersonated_character_id: Option<crate::db::DbId>,
    pub system_prompt_ciphertext: Option<Vec<u8>>,
    pub system_prompt_nonce: Option<Vec<u8>>,
    pub title_ciphertext: Option<Vec<u8>>,
    pub title_nonce: Option<Vec<u8>>,
    pub stop_sequences: Option<crate::models::OptionalStringArray>,
    pub chat_mode: ChatMode,
    pub player_chronicle_id: Option<crate::db::DbId>,
    pub agent_mode: Option<String>,
    pub model_provider: Option<String>,
    pub total_prompt_tokens: DbBigInt,
    pub total_completion_tokens: DbBigInt,
    pub estimated_cost_cents: i32,
    pub tokens_counted_at: DbTimestamp,
    pub prompt_template_id: String,
    pub total_credits_used: crate::db::DbDecimal,
    pub narrative_style_override_ciphertext: Option<Vec<u8>>,
    pub narrative_style_override_nonce: Option<Vec<u8>>,
    pub total_actual_cost: crate::db::DbDecimal,
    pub total_modified_cost: crate::db::DbDecimal,
    pub total_credit_cost: i32,
    pub total_actual_charge: crate::db::DbDecimal,
    pub game_master_mode_enabled: bool,
    pub game_state: Option<crate::db::DbJson>,
    pub thinking_level: Option<String>,
    pub rag_chronicles_limit: Option<i32>,
    pub rag_lorebooks_limit: Option<i32>,
    pub rag_older_chat_limit: Option<i32>,
    pub rag_cognitive_context_limit: Option<i32>,
}

impl ChatSessionQuery {
    /// Convert to ChatForClient with decrypted title and system_prompt
    pub fn into_decrypted_for_client(
        self,
        dek_opt: Option<&SecretBox<Vec<u8>>>,
    ) -> Result<ChatForClient, AppError> {
        let encryption_service = crate::services::encryption_service::EncryptionService::new();

        let decrypted_title = match (self.title_ciphertext, self.title_nonce) {
            (Some(ciphertext), Some(nonce)) => {
                if let Some(dek) = dek_opt {
                    if ciphertext.is_empty() && nonce.is_empty() {
                        Ok(Some(String::new()))
                    } else if ciphertext.is_empty() || nonce.is_empty() {
                        Err(AppError::DecryptionError(
                            "Mismatched ciphertext/nonce for chat title".to_string(),
                        ))
                    } else {
                        let decrypted_bytes = encryption_service.decrypt(
                            &ciphertext,
                            &nonce,
                            dek.expose_secret().as_slice(),
                        )?;
                        String::from_utf8(decrypted_bytes).map(Some).map_err(|e| {
                            AppError::DecryptionError(format!("Invalid UTF-8 for chat title: {e}"))
                        })
                    }
                } else {
                    Ok(Some("[Encrypted]".to_string()))
                }
            }
            (None, None) => Ok(None),
            _ => Err(AppError::DecryptionError(
                "Mismatched title ciphertext/nonce".to_string(),
            )),
        }?;

        let decrypted_system_prompt =
            match (self.system_prompt_ciphertext, self.system_prompt_nonce) {
                (Some(ciphertext), Some(nonce)) => {
                    if let Some(dek) = dek_opt {
                        if ciphertext.is_empty() && nonce.is_empty() {
                            Ok(Some(String::new()))
                        } else if ciphertext.is_empty() || nonce.is_empty() {
                            Err(AppError::DecryptionError(
                                "Mismatched ciphertext/nonce for system prompt".to_string(),
                            ))
                        } else {
                            let decrypted_bytes = encryption_service.decrypt(
                                &ciphertext,
                                &nonce,
                                dek.expose_secret().as_slice(),
                            )?;
                            String::from_utf8(decrypted_bytes).map(Some).map_err(|e| {
                                AppError::DecryptionError(format!(
                                    "Invalid UTF-8 for system prompt: {e}"
                                ))
                            })
                        }
                    } else {
                        Ok(Some("[Encrypted]".to_string()))
                    }
                }
                (None, None) => Ok(None),
                _ => Err(AppError::DecryptionError(
                    "Mismatched system prompt ciphertext/nonce".to_string(),
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
            repetition_penalty: self.repetition_penalty,
            min_p: self.min_p,
            top_a: self.top_a,
            seed: self.seed,
            logit_bias: self.logit_bias,
            stop_sequences: self.stop_sequences.clone(),
            history_management_strategy: self.history_management_strategy,
            history_management_limit: self.history_management_limit,
            model_name: Some(self.model_name),
            thinking_budget: self.thinking_budget,
            enable_code_execution: self.enable_code_execution,
            visibility: self.visibility,
            active_custom_persona_id: self.active_custom_persona_id,
            active_impersonated_character_id: self.active_impersonated_character_id,
            chat_mode: self.chat_mode,
            chronicle_id: self.player_chronicle_id,
            total_prompt_tokens: self.total_prompt_tokens,
            total_completion_tokens: self.total_completion_tokens,
            total_credits_used: self.total_credits_used,
            total_actual_cost: self.total_actual_cost,
            game_master_mode_enabled: self.game_master_mode_enabled,
            game_state: self.game_state,
            thinking_level: self.thinking_level,
            rag_chronicles_limit: self.rag_chronicles_limit,
            rag_lorebooks_limit: self.rag_lorebooks_limit,
            rag_older_chat_limit: self.rag_older_chat_limit,
            rag_cognitive_context_limit: self.rag_cognitive_context_limit,
        })
    }

    /// Decrypts and returns the session-level narrative style override.
    ///
    /// # Errors
    ///
    /// Returns `AppError::DecryptionError` if the encrypted data is malformed or cannot be decrypted.
    pub fn get_narrative_style_override(
        &self,
        dek: &secrecy::SecretBox<Vec<u8>>,
    ) -> Result<
        Option<crate::models::template_preferences::UpdateTemplatePreferenceRequest>,
        crate::errors::AppError,
    > {
        use crate::models::template_preferences::UpdateTemplatePreferenceRequest;

        match (
            &self.narrative_style_override_ciphertext,
            &self.narrative_style_override_nonce,
        ) {
            (Some(ciphertext), Some(nonce)) => {
                if ciphertext.is_empty() && nonce.is_empty() {
                    // Convention for empty encrypted field
                    return Ok(None);
                }

                if ciphertext.is_empty() || nonce.is_empty() {
                    return Err(crate::errors::AppError::DecryptionError(
                        "Mismatched ciphertext/nonce for narrative style override".to_string(),
                    ));
                }

                let encryption_service =
                    crate::services::encryption_service::EncryptionService::new();
                let decrypted_bytes = encryption_service.decrypt(
                    ciphertext,
                    nonce,
                    dek.expose_secret().as_slice(),
                )?;

                let json_str = String::from_utf8(decrypted_bytes).map_err(|e| {
                    crate::errors::AppError::DecryptionError(format!(
                        "Invalid UTF-8 for decrypted narrative style override: {e}"
                    ))
                })?;

                let override_data: UpdateTemplatePreferenceRequest =
                    serde_json::from_str(&json_str).map_err(|e| {
                        crate::errors::AppError::DecryptionError(format!(
                            "Failed to deserialize narrative style override: {e}"
                        ))
                    })?;

                Ok(Some(override_data))
            }
            (None, None) => Ok(None), // No override set
            (Some(_), None) => Err(crate::errors::AppError::DecryptionError(
                "Narrative style override ciphertext present but nonce missing".to_string(),
            )),
            (None, Some(_)) => Err(crate::errors::AppError::DecryptionError(
                "Narrative style override nonce present but ciphertext missing".to_string(),
            )),
        }
    }

    /// Encrypts and sets the session-level narrative style override.
    ///
    /// Pass `None` to clear the override.
    ///
    /// # Errors
    ///
    /// Returns `AppError::EncryptionError` if encryption or JSON serialization fails.
    pub fn set_narrative_style_override(
        &mut self,
        override_data: Option<crate::models::template_preferences::UpdateTemplatePreferenceRequest>,
        dek: &secrecy::SecretBox<Vec<u8>>,
    ) -> Result<(), crate::errors::AppError> {
        match override_data {
            Some(data) => {
                let json_str = serde_json::to_string(&data).map_err(|e| {
                    crate::errors::AppError::EncryptionError(format!(
                        "Failed to serialize narrative style override: {e}"
                    ))
                })?;

                let encryption_service =
                    crate::services::encryption_service::EncryptionService::new();
                let (ciphertext, nonce) =
                    encryption_service.encrypt(&json_str, dek.expose_secret().as_slice())?;

                self.narrative_style_override_ciphertext = Some(ciphertext);
                self.narrative_style_override_nonce = Some(nonce);
            }
            None => {
                // Clear the override
                self.narrative_style_override_ciphertext = None;
                self.narrative_style_override_nonce = None;
            }
        }

        Ok(())
    }
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
            .field("thinking_budget", &self.thinking_budget)
            .field("enable_code_execution", &self.enable_code_execution)
            .field("visibility", &self.visibility)
            // Add new fields to Debug output
            .field("active_custom_persona_id", &self.active_custom_persona_id)
            .field(
                "active_impersonated_character_id",
                &self.active_impersonated_character_id,
            )
            // Token tracking fields
            .field("total_prompt_tokens", &self.total_prompt_tokens)
            .field("total_completion_tokens", &self.total_completion_tokens)
            .field("estimated_cost_cents", &self.estimated_cost_cents)
            .field("tokens_counted_at", &self.tokens_counted_at)
            .field(
                "narrative_style_override_ciphertext",
                &self
                    .narrative_style_override_ciphertext
                    .as_ref()
                    .map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "narrative_style_override_nonce",
                &self
                    .narrative_style_override_nonce
                    .as_ref()
                    .map(|_| "[REDACTED_BYTES]"),
            )
            .finish()
    }
}

// New Chat for insertion
#[derive(Insertable, Clone, Default)]
#[diesel(table_name = chat_sessions)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewChat {
    pub id: crate::db::DbId,
    pub user_id: crate::db::DbId,
    pub character_id: crate::db::DbId,
    pub title_ciphertext: Option<Vec<u8>>,
    pub title_nonce: Option<Vec<u8>>,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub history_management_strategy: String,
    pub history_management_limit: i32,
    pub model_name: Option<String>,
    pub visibility: Option<String>,
    // Added to match schema and Chat struct
    pub active_custom_persona_id: Option<crate::db::DbId>,
    pub active_impersonated_character_id: Option<crate::db::DbId>,
    // Additional optional fields that can be set during insertion
    pub temperature: Option<crate::db::DbDecimal>,
    pub max_output_tokens: Option<i32>,
    pub frequency_penalty: Option<crate::db::DbDecimal>,
    pub presence_penalty: Option<crate::db::DbDecimal>,
    pub top_k: Option<i32>,
    pub top_p: Option<crate::db::DbDecimal>,
    pub seed: Option<i32>,
    pub stop_sequences: Option<crate::models::OptionalStringArray>,
    pub chat_mode: ChatMode,
    pub thinking_budget: Option<i32>,
    pub enable_code_execution: Option<bool>,
    pub system_prompt_ciphertext: Option<Vec<u8>>,
    pub system_prompt_nonce: Option<Vec<u8>>,
    pub player_chronicle_id: Option<crate::db::DbId>,
    // Token tracking fields with default values
    pub total_prompt_tokens: DbBigInt,
    pub total_completion_tokens: DbBigInt,
    pub estimated_cost_cents: i32,
    pub tokens_counted_at: DbTimestamp,
    pub prompt_template_id: String,
    pub total_credits_used: crate::db::DbDecimal,
    pub total_actual_cost: crate::db::DbDecimal,
    pub total_modified_cost: crate::db::DbDecimal,
    pub total_credit_cost: i32,
    pub total_actual_charge: crate::db::DbDecimal,
    pub narrative_style_override_ciphertext: Option<Vec<u8>>,
    pub narrative_style_override_nonce: Option<Vec<u8>>,
    pub game_state: Option<crate::db::DbJson>,
    pub game_master_mode_enabled: bool,
    pub thinking_level: Option<String>,
    pub rag_chronicles_limit: Option<i32>,
    pub rag_lorebooks_limit: Option<i32>,
    pub rag_older_chat_limit: Option<i32>,
    pub rag_cognitive_context_limit: Option<i32>,
}

impl NewChat {
    pub fn builder() -> NewChatBuilder {
        NewChatBuilder::default()
    }
}

#[derive(Default)]
pub struct NewChatBuilder {
    inner: NewChat,
}

impl NewChatBuilder {
    pub fn user_id(mut self, id: crate::db::DbId) -> Self {
        self.inner.user_id = id;
        self
    }
    pub fn character_id(mut self, id: crate::db::DbId) -> Self {
        self.inner.character_id = id;
        self
    }
    pub fn model_name(mut self, name: Option<String>) -> Self {
        self.inner.model_name = name;
        self
    }
    pub fn chat_mode(mut self, mode: ChatMode) -> Self {
        self.inner.chat_mode = mode;
        self
    }
    pub fn build(self) -> NewChat {
        self.inner
    }
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
            .field("thinking_budget", &self.thinking_budget)
            .field("enable_code_execution", &self.enable_code_execution)
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
            .field("player_chronicle_id", &self.player_chronicle_id)
            // Token tracking fields
            .field("total_prompt_tokens", &self.total_prompt_tokens)
            .field("total_completion_tokens", &self.total_completion_tokens)
            .field("estimated_cost_cents", &self.estimated_cost_cents)
            .field("tokens_counted_at", &self.tokens_counted_at)
            .field(
                "narrative_style_override_ciphertext",
                &self
                    .narrative_style_override_ciphertext
                    .as_ref()
                    .map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "narrative_style_override_nonce",
                &self
                    .narrative_style_override_nonce
                    .as_ref()
                    .map(|_| "[REDACTED_BYTES]"),
            )
            .finish()
    }
}

// MessageRole enum for database storage
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    AsExpression,
    FromSqlRow,
    diesel::query_builder::QueryId,
)]
#[diesel(sql_type = crate::schema::sql_types::MessageType)]
#[diesel(postgres_type(name = "message_type"))]
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

// SQLite implementations for MessageRole (stored as TEXT)

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
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    AsExpression,
    FromSqlRow,
    diesel::query_builder::QueryId,
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

// SQLite implementations for ChatMode (stored as TEXT)

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

// Query-optimized struct for loading chat messages (11 fields to respect Diesel's CompatibleType limit)
#[derive(Queryable, Clone)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ChatMessageQuery {
    pub id: crate::db::DbId,
    pub session_id: crate::db::DbId,
    pub message_type: MessageRole,
    pub content: Vec<u8>,
    pub content_nonce: Option<Vec<u8>>,
    pub created_at: DbTimestamp,
    pub user_id: crate::db::DbId,
    pub prompt_tokens: Option<DbBigInt>,
    pub completion_tokens: Option<DbBigInt>,
    pub model_name: String,
    pub status: String,
    pub reasoning_content: Option<Vec<u8>>,
    pub reasoning_content_nonce: Option<Vec<u8>>,
}

impl ChatMessageQuery {
    /// Convert to full ChatMessage with default values for cost tracking fields
    pub fn to_full_message(self) -> ChatMessage {
        ChatMessage {
            id: self.id,
            session_id: self.session_id,
            message_type: self.message_type,
            content: self.content,
            content_nonce: self.content_nonce,
            rag_embedding_id: None,
            created_at: self.created_at,
            updated_at: self.created_at,
            user_id: self.user_id,
            role: None,
            parts: None,
            attachments: None,
            prompt_tokens: self.prompt_tokens,
            completion_tokens: self.completion_tokens,
            model_name: self.model_name,
            status: self.status,
            game_time: None, // Not loaded from query
            // Fields not loaded from query - use defaults
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            error_message: None,
            superseded_at: None,
            variant_count: 0,
            current_variant_index: 0,
            credits_charged: 0,
            credits_cost: crate::db::DbDecimal::from(0),
            actual_cost: crate::db::DbDecimal::from(0),
            modified_cost: crate::db::DbDecimal::from(0),
            credit_cost: 0,
            actual_charge: crate::db::DbDecimal::from(0),
            reasoning_content: self.reasoning_content,
            reasoning_content_nonce: self.reasoning_content_nonce,
        }
    }
}

// Represents a chat message in the database
#[derive(Queryable, Selectable, Identifiable, Associations, Clone, Serialize, Deserialize)]
#[diesel(belongs_to(Chat, foreign_key = session_id))]
#[diesel(table_name = chat_messages)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ChatMessage {
    pub id: crate::db::DbId,
    pub session_id: crate::db::DbId,
    pub message_type: MessageRole,
    pub content: Vec<u8>,
    pub rag_embedding_id: Option<crate::db::DbId>,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub user_id: crate::db::DbId,
    pub content_nonce: Option<Vec<u8>>,
    pub role: Option<String>,
    pub parts: Option<crate::db::DbJson>,
    pub attachments: Option<crate::db::DbJson>,
    pub prompt_tokens: Option<DbBigInt>,
    pub completion_tokens: Option<DbBigInt>,
    pub raw_prompt_ciphertext: Option<Vec<u8>>,
    pub raw_prompt_nonce: Option<Vec<u8>>,
    pub model_name: String,
    pub status: String,
    pub error_message: Option<String>,
    pub superseded_at: Option<DbTimestamp>,
    pub variant_count: i32,
    pub current_variant_index: i32,
    pub credits_charged: i32,
    pub credits_cost: crate::db::DbDecimal,
    // New cost tracking fields
    #[serde(serialize_with = "bigdecimal_serde::serialize_as_f64")]
    pub actual_cost: crate::db::DbDecimal,
    #[serde(serialize_with = "bigdecimal_serde::serialize_as_f64")]
    pub modified_cost: crate::db::DbDecimal,
    pub credit_cost: i32,
    #[serde(serialize_with = "bigdecimal_serde::serialize_as_f64")]
    pub actual_charge: crate::db::DbDecimal,
    pub game_time: Option<crate::DbJson>,
    pub reasoning_content: Option<Vec<u8>>,
    pub reasoning_content_nonce: Option<Vec<u8>>,
}

impl Default for ChatMessage {
    fn default() -> Self {
        Self {
            id: crate::db::DbId::nil(),
            session_id: crate::db::DbId::nil(),
            message_type: MessageRole::User,
            content: Vec::new(),
            content_nonce: None,
            rag_embedding_id: None,
            created_at: DbTimestamp::now(),
            updated_at: DbTimestamp::now(),
            user_id: crate::db::DbId::nil(),
            role: None,
            parts: None,
            attachments: None,
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: String::new(),
            status: "completed".to_string(),
            error_message: None,
            superseded_at: None,
            variant_count: 0,
            current_variant_index: 0,
            credits_charged: 0,
            credits_cost: crate::db::DbDecimal::from(0),
            actual_cost: crate::db::DbDecimal::from(0),
            modified_cost: crate::db::DbDecimal::from(0),
            credit_cost: 0,
            actual_charge: crate::db::DbDecimal::from(0),
            game_time: None,
            reasoning_content: None,
            reasoning_content_nonce: None,
        }
    }
}

impl ChatMessage {
    pub fn builder() -> ChatMessageBuilder {
        ChatMessageBuilder::default()
    }
}

#[derive(Default)]
pub struct ChatMessageBuilder {
    inner: ChatMessage,
}

impl ChatMessageBuilder {
    pub fn id(mut self, id: crate::db::DbId) -> Self {
        self.inner.id = id;
        self
    }
    pub fn session_id(mut self, id: crate::db::DbId) -> Self {
        self.inner.session_id = id;
        self
    }
    pub fn message_type(mut self, role: MessageRole) -> Self {
        self.inner.message_type = role;
        self
    }
    pub fn content(mut self, content: Vec<u8>) -> Self {
        self.inner.content = content;
        self
    }
    pub fn content_nonce(mut self, nonce: Option<Vec<u8>>) -> Self {
        self.inner.content_nonce = nonce;
        self
    }
    pub fn user_id(mut self, id: crate::db::DbId) -> Self {
        self.inner.user_id = id;
        self
    }
    pub fn model_name(mut self, name: String) -> Self {
        self.inner.model_name = name;
        self
    }
    pub fn status(mut self, status: String) -> Self {
        self.inner.status = status;
        self
    }
    pub fn created_at(mut self, ts: DbTimestamp) -> Self {
        self.inner.created_at = ts;
        self
    }
    pub fn updated_at(mut self, ts: DbTimestamp) -> Self {
        self.inner.updated_at = ts;
        self
    }
    pub fn reasoning_content(mut self, content: Option<Vec<u8>>) -> Self {
        self.inner.reasoning_content = content;
        self
    }
    pub fn reasoning_content_nonce(mut self, nonce: Option<Vec<u8>>) -> Self {
        self.inner.reasoning_content_nonce = nonce;
        self
    }
    pub fn build(self) -> ChatMessage {
        self.inner
    }
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
            .field("status", &self.status)
            .field("error_message", &self.error_message)
            .field("superseded_at", &self.superseded_at)
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
            .field("game_time", &self.game_time)
            .field(
                "reasoning_content",
                &self.reasoning_content.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "reasoning_content_nonce",
                &self
                    .reasoning_content_nonce
                    .as_ref()
                    .map(|_| "[REDACTED_NONCE]"),
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

    /// Encrypts the reasoning_content field if plaintext is provided and a DEK is available.
    /// Updates `self.reasoning_content` and `self.reasoning_content_nonce`.
    ///
    /// # Errors
    /// Returns `AppError` if encryption fails
    pub fn encrypt_reasoning_field(
        &mut self,
        dek: &SecretBox<Vec<u8>>,
        plaintext_reasoning: &str,
    ) -> Result<(), AppError> {
        if plaintext_reasoning.is_empty() {
            self.reasoning_content = None;
            self.reasoning_content_nonce = None;
        } else {
            let (ciphertext, nonce) = encrypt_gcm(plaintext_reasoning.as_bytes(), dek)
                .map_err(|e| AppError::CryptoError(e.to_string()))?;
            self.reasoning_content = Some(ciphertext);
            self.reasoning_content_nonce = Some(nonce);
        }
        Ok(())
    }

    /// Decrypts the reasoning_content field if a DEK is available and content is encrypted.
    /// Returns the decrypted string.
    ///
    /// # Errors
    /// Returns `AppError::DecryptionError` if the nonce is empty, missing, or decryption fails
    pub fn decrypt_reasoning_field(
        &self,
        dek: &SecretBox<Vec<u8>>,
    ) -> Result<Option<String>, AppError> {
        match (&self.reasoning_content, &self.reasoning_content_nonce) {
            (None, None) => Ok(None),
            (Some(ciphertext), Some(nonce)) => {
                if ciphertext.is_empty() {
                    return Ok(Some(String::new()));
                }

                if nonce.is_empty() {
                    tracing::error!(
                        "ChatMessage ID {} reasoning_content is present but nonce is empty. Cannot decrypt.",
                        self.id
                    );
                    return Err(AppError::DecryptionError(
                        "Nonce is empty for reasoning decryption".to_string(),
                    ));
                }

                let plaintext_secret = decrypt_gcm(ciphertext, nonce, dek).map_err(|e| {
                    error!(
                        "Failed to decrypt chat message reasoning for ID {}: {}",
                        self.id, e
                    );
                    AppError::DecryptionError(format!(
                        "Decryption failed for message reasoning: {e}"
                    ))
                })?;

                let decrypted_text = String::from_utf8(plaintext_secret.expose_secret().clone())
                    .map_err(|e| {
                        tracing::error!(
                            "Failed to convert decrypted message reasoning to UTF-8: {}",
                            e
                        );
                        AppError::DecryptionError(
                            "Failed to convert message reasoning to UTF-8".to_string(),
                        )
                    })?;

                Ok(Some(decrypted_text))
            }
            _ => Err(AppError::DecryptionError(
                "Mismatched reasoning ciphertext/nonce pair".to_string(),
            )),
        }
    }

    /// Update the status and error message of this message in the database
    pub fn update_status(
        conn: &mut crate::DbConnection,
        message_id: crate::db::DbId,
        new_status: MessageStatus,
        error_msg: Option<String>,
    ) -> Result<(), AppError> {
        use crate::schema::chat_messages::dsl::*;

        let timestamp: crate::DbTimestamp = chrono::Utc::now().into();
        diesel::update(chat_messages.find(message_id))
            .set((
                status.eq(new_status.to_string()),
                error_message.eq(error_msg),
                updated_at.eq(timestamp),
            ))
            .execute(conn)
            .map_err(|e| {
                AppError::DatabaseQueryError(format!("Failed to update message status: {e}"))
            })?;

        Ok(())
    }

    /// Mark messages as superseded when retrying
    pub fn supersede_failed_messages(
        conn: &mut crate::DbConnection,
        session_id_val: crate::db::DbId,
        after_timestamp: DbTimestamp,
    ) -> Result<usize, AppError> {
        use crate::schema::chat_messages::dsl::*;

        let timestamp: Option<crate::DbTimestamp> = Some(chrono::Utc::now().into());
        let count = diesel::update(
            chat_messages.filter(
                session_id
                    .eq(session_id_val)
                    .and(created_at.ge(after_timestamp))
                    .and(superseded_at.is_null())
                    .and(
                        status
                            .eq("failed")
                            .or(status.eq("partial"))
                            .or(status.eq("streaming")),
                    ),
            ),
        )
        .set(superseded_at.eq(timestamp))
        .execute(conn)
        .map_err(|e| AppError::DatabaseQueryError(format!("Failed to supersede messages: {e}")))?;

        Ok(count)
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

        // Decrypt reasoning content if available
        let reasoning_content = if let Some(dek) = user_dek_secret_box {
            match self.decrypt_reasoning_field(dek) {
                Ok(decrypted_reasoning) => decrypted_reasoning,
                Err(e) => {
                    error!("Failed to decrypt reasoning for message {}: {}", self.id, e);
                    None
                }
            }
        } else if self.reasoning_content.is_some() {
            Some("[Reasoning encrypted, DEK not available]".to_string())
        } else {
            None
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
            model_name: Some(self.model_name),
            status: self.status,
            error_message: self.error_message,
            // Convert BigDecimal cost values to f64 for JSON serialization
            actual_cost: self.actual_cost.to_f64(),
            modified_cost: self.modified_cost.to_f64(),
            credit_cost: Some(self.credit_cost),
            actual_charge: self.actual_charge.to_f64(),
            game_time: self.game_time.clone().map(|j| j.0),
            reasoning_content,
        })
    }
}

// Chat Message model
#[derive(Queryable, Selectable, Identifiable, Serialize, Deserialize, Clone)]
#[diesel(table_name = chat_messages)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Message {
    pub id: crate::db::DbId,
    pub session_id: crate::db::DbId,
    pub message_type: MessageRole,
    pub content: Vec<u8>,
    pub rag_embedding_id: Option<crate::db::DbId>,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub user_id: crate::db::DbId,
    pub content_nonce: Option<Vec<u8>>,
    pub role: Option<String>,
    pub parts: Option<crate::DbJson>,
    pub attachments: Option<crate::DbJson>,
    pub prompt_tokens: Option<DbBigInt>,
    pub completion_tokens: Option<DbBigInt>,
    pub raw_prompt_ciphertext: Option<Vec<u8>>,
    pub raw_prompt_nonce: Option<Vec<u8>>,
    pub model_name: String,
    pub status: String,
    pub error_message: Option<String>,
    pub superseded_at: Option<DbTimestamp>,
    pub variant_count: i32,
    pub current_variant_index: i32,
    pub credits_charged: i32,
    pub credits_cost: crate::db::DbDecimal,
    // Cost tracking fields (same as ChatMessage)
    pub actual_cost: crate::db::DbDecimal,
    pub modified_cost: crate::db::DbDecimal,
    pub credit_cost: i32,
    pub actual_charge: crate::db::DbDecimal,
    pub game_time: Option<crate::DbJson>,
    pub reasoning_content: Option<Vec<u8>>,
    pub reasoning_content_nonce: Option<Vec<u8>>,
}

impl From<Message> for ChatMessage {
    fn from(m: Message) -> Self {
        Self {
            id: m.id,
            session_id: m.session_id,
            message_type: m.message_type,
            content: m.content,
            content_nonce: m.content_nonce,
            rag_embedding_id: m.rag_embedding_id,
            created_at: m.created_at,
            updated_at: m.updated_at,
            user_id: m.user_id,
            role: m.role,
            parts: m.parts,
            attachments: m.attachments,
            prompt_tokens: m.prompt_tokens,
            completion_tokens: m.completion_tokens,
            raw_prompt_ciphertext: m.raw_prompt_ciphertext,
            raw_prompt_nonce: m.raw_prompt_nonce,
            model_name: m.model_name,
            status: m.status,
            error_message: m.error_message,
            superseded_at: m.superseded_at,
            variant_count: m.variant_count,
            current_variant_index: m.current_variant_index,
            credits_charged: m.credits_charged,
            credits_cost: m.credits_cost,
            actual_cost: m.actual_cost,
            modified_cost: m.modified_cost,
            credit_cost: m.credit_cost,
            actual_charge: m.actual_charge,
            game_time: m.game_time,
            reasoning_content: m.reasoning_content,
            reasoning_content_nonce: m.reasoning_content_nonce,
        }
    }
}

impl Default for Message {
    fn default() -> Self {
        Self {
            id: crate::db::DbId::default(),
            session_id: crate::db::DbId::default(),
            message_type: MessageRole::User,
            content: Vec::new(),
            rag_embedding_id: None,
            created_at: DbTimestamp::default(),
            updated_at: DbTimestamp::default(),
            user_id: crate::db::DbId::default(),
            content_nonce: None,
            role: None,
            parts: None,
            attachments: None,
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: String::new(),
            status: "pending".to_string(),
            error_message: None,
            superseded_at: None,
            variant_count: 1,
            current_variant_index: 0,
            credits_charged: 0,
            credits_cost: crate::db::DbDecimal::from(0),
            actual_cost: crate::db::DbDecimal::from(0),
            modified_cost: crate::db::DbDecimal::from(0),
            credit_cost: 0,
            actual_charge: crate::db::DbDecimal::from(0),
            game_time: None,
            reasoning_content: None,
            reasoning_content_nonce: None,
        }
    }
}

pub struct MessageBuilder {
    inner: Message,
}

impl Default for MessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageBuilder {
    pub fn new() -> Self {
        Self {
            inner: Message::default(),
        }
    }

    pub fn id(mut self, id: crate::db::DbId) -> Self {
        self.inner.id = id;
        self
    }

    pub fn session_id(mut self, session_id: crate::db::DbId) -> Self {
        self.inner.session_id = session_id;
        self
    }

    pub fn message_type(mut self, message_type: MessageRole) -> Self {
        self.inner.message_type = message_type;
        self
    }

    pub fn content(mut self, content: Vec<u8>) -> Self {
        self.inner.content = content;
        self
    }

    pub fn rag_embedding_id(mut self, rag_embedding_id: Option<crate::db::DbId>) -> Self {
        self.inner.rag_embedding_id = rag_embedding_id;
        self
    }

    pub fn created_at(mut self, created_at: DbTimestamp) -> Self {
        self.inner.created_at = created_at;
        self
    }

    pub fn updated_at(mut self, updated_at: DbTimestamp) -> Self {
        self.inner.updated_at = updated_at;
        self
    }

    pub fn user_id(mut self, user_id: crate::db::DbId) -> Self {
        self.inner.user_id = user_id;
        self
    }

    pub fn content_nonce(mut self, content_nonce: Option<Vec<u8>>) -> Self {
        self.inner.content_nonce = content_nonce;
        self
    }

    pub fn role(mut self, role: Option<String>) -> Self {
        self.inner.role = role;
        self
    }

    pub fn parts(mut self, parts: Option<crate::DbJson>) -> Self {
        self.inner.parts = parts;
        self
    }

    pub fn attachments(mut self, attachments: Option<crate::DbJson>) -> Self {
        self.inner.attachments = attachments;
        self
    }

    pub fn prompt_tokens(mut self, prompt_tokens: Option<DbBigInt>) -> Self {
        self.inner.prompt_tokens = prompt_tokens;
        self
    }

    pub fn completion_tokens(mut self, completion_tokens: Option<DbBigInt>) -> Self {
        self.inner.completion_tokens = completion_tokens;
        self
    }

    pub fn raw_prompt_ciphertext(mut self, raw_prompt_ciphertext: Option<Vec<u8>>) -> Self {
        self.inner.raw_prompt_ciphertext = raw_prompt_ciphertext;
        self
    }

    pub fn raw_prompt_nonce(mut self, raw_prompt_nonce: Option<Vec<u8>>) -> Self {
        self.inner.raw_prompt_nonce = raw_prompt_nonce;
        self
    }

    pub fn model_name(mut self, model_name: String) -> Self {
        self.inner.model_name = model_name;
        self
    }

    pub fn status(mut self, status: String) -> Self {
        self.inner.status = status;
        self
    }

    pub fn error_message(mut self, error_message: Option<String>) -> Self {
        self.inner.error_message = error_message;
        self
    }

    pub fn superseded_at(mut self, superseded_at: Option<DbTimestamp>) -> Self {
        self.inner.superseded_at = superseded_at;
        self
    }

    pub fn variant_count(mut self, variant_count: i32) -> Self {
        self.inner.variant_count = variant_count;
        self
    }

    pub fn current_variant_index(mut self, current_variant_index: i32) -> Self {
        self.inner.current_variant_index = current_variant_index;
        self
    }

    pub fn credits_charged(mut self, credits_charged: i32) -> Self {
        self.inner.credits_charged = credits_charged;
        self
    }

    pub fn credits_cost(mut self, credits_cost: crate::db::DbDecimal) -> Self {
        self.inner.credits_cost = credits_cost;
        self
    }

    pub fn actual_cost(mut self, actual_cost: crate::db::DbDecimal) -> Self {
        self.inner.actual_cost = actual_cost;
        self
    }

    pub fn modified_cost(mut self, modified_cost: crate::db::DbDecimal) -> Self {
        self.inner.modified_cost = modified_cost;
        self
    }

    pub fn credit_cost(mut self, credit_cost: i32) -> Self {
        self.inner.credit_cost = credit_cost;
        self
    }

    pub fn actual_charge(mut self, actual_charge: crate::db::DbDecimal) -> Self {
        self.inner.actual_charge = actual_charge;
        self
    }

    pub fn game_time(mut self, game_time: Option<crate::DbJson>) -> Self {
        self.inner.game_time = game_time;
        self
    }

    pub fn reasoning_content(mut self, content: Option<Vec<u8>>) -> Self {
        self.inner.reasoning_content = content;
        self
    }

    pub fn reasoning_content_nonce(mut self, nonce: Option<Vec<u8>>) -> Self {
        self.inner.reasoning_content_nonce = nonce;
        self
    }

    pub fn build(self) -> Message {
        self.inner
    }
}

impl Message {
    pub fn builder() -> MessageBuilder {
        MessageBuilder::new()
    }
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
            .field("status", &self.status)
            .field("error_message", &self.error_message)
            .field("superseded_at", &self.superseded_at)
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
            .field("game_time", &self.game_time)
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

    /// Encrypts the reasoning_content field if plaintext is provided and a DEK is available.
    /// Updates `self.reasoning_content` and `self.reasoning_content_nonce`.
    ///
    /// # Errors
    /// Returns `AppError` if encryption fails
    pub fn encrypt_reasoning_field(
        &mut self,
        dek: &SecretBox<Vec<u8>>,
        plaintext_reasoning: &str,
    ) -> Result<(), AppError> {
        if plaintext_reasoning.is_empty() {
            self.reasoning_content = None;
            self.reasoning_content_nonce = None;
        } else {
            let (ciphertext, nonce) = encrypt_gcm(plaintext_reasoning.as_bytes(), dek)
                .map_err(|e| AppError::CryptoError(e.to_string()))?;
            self.reasoning_content = Some(ciphertext);
            self.reasoning_content_nonce = Some(nonce);
        }
        Ok(())
    }

    /// Decrypts the reasoning_content field if a DEK is available and content is encrypted.
    /// Returns the decrypted string.
    ///
    /// # Errors
    /// Returns `AppError::DecryptionError` if the nonce is empty, missing, or decryption fails
    pub fn decrypt_reasoning_field(
        &self,
        dek: &SecretBox<Vec<u8>>,
    ) -> Result<Option<String>, AppError> {
        match (&self.reasoning_content, &self.reasoning_content_nonce) {
            (None, None) => Ok(None),
            (Some(ciphertext), Some(nonce)) => {
                if ciphertext.is_empty() {
                    return Ok(Some(String::new()));
                }

                if nonce.is_empty() {
                    tracing::error!(
                        "Message ID {} reasoning_content is present but nonce is empty. Cannot decrypt.",
                        self.id
                    );
                    return Err(AppError::DecryptionError(
                        "Nonce is empty for reasoning decryption".to_string(),
                    ));
                }

                let plaintext_secret = decrypt_gcm(ciphertext, nonce, dek).map_err(|e| {
                    error!(
                        "Failed to decrypt message reasoning for ID {}: {}",
                        self.id, e
                    );
                    AppError::DecryptionError(format!(
                        "Decryption failed for message reasoning: {e}"
                    ))
                })?;

                let decrypted_text = String::from_utf8(plaintext_secret.expose_secret().clone())
                    .map_err(|e| {
                        tracing::error!(
                            "Failed to convert decrypted message reasoning to UTF-8: {}",
                            e
                        );
                        AppError::DecryptionError(
                            "Failed to convert message reasoning to UTF-8".to_string(),
                        )
                    })?;

                Ok(Some(decrypted_text))
            }
            _ => Err(AppError::DecryptionError(
                "Mismatched reasoning ciphertext/nonce pair".to_string(),
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

        // Decrypt reasoning if available before we start moving fields
        let reasoning_content = if let Some(dek) = user_dek_secret_box {
            self.decrypt_reasoning_field(dek).unwrap_or_else(|e| {
                error!("Failed to decrypt reasoning for message {}: {}", self.id, e);
                None
            })
        } else if self.reasoning_content.is_some() {
            Some("[Reasoning encrypted, DEK not available]".to_string())
        } else {
            None
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
            model_name: Some(self.model_name),
            status: self.status,
            error_message: self.error_message,
            // Convert BigDecimal cost values to f64 for JSON serialization
            actual_cost: self.actual_cost.to_f64(),
            modified_cost: self.modified_cost.to_f64(),
            credit_cost: Some(self.credit_cost),
            actual_charge: self.actual_charge.to_f64(),
            game_time: self.game_time.clone().map(|j| j.0),
            reasoning_content,
        })
    }
}

/// JSON-friendly structure for client responses
#[derive(Serialize, Deserialize, Clone)]
pub struct ClientChatMessage {
    pub id: crate::db::DbId,
    pub chat_id: crate::db::DbId,
    pub character_id: crate::db::DbId,
    pub content: String,
    pub role: Option<String>,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub reasoning_content: Option<String>,
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
            .field(
                "reasoning_content",
                &self.reasoning_content.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Structure for sending `ChatMessage` data to the client, with decrypted content.
#[derive(Serialize, Deserialize, Clone)]
pub struct ChatMessageForClient {
    pub id: crate::db::DbId,
    pub session_id: crate::db::DbId,
    pub message_type: MessageRole,
    pub content: String,
    pub created_at: DbTimestamp,
    pub user_id: crate::db::DbId,
    pub prompt_tokens: Option<DbBigInt>,
    pub completion_tokens: Option<DbBigInt>,
    pub raw_prompt: Option<String>,
    pub model_name: Option<String>,
    pub status: String,
    pub error_message: Option<String>,
    // Cost tracking fields (for frontend display)
    pub actual_cost: Option<f64>, // Raw Google API cost in dollars (always calculated)
    pub modified_cost: Option<f64>, // Cost with markup applied (when payment feature enabled)
    pub credit_cost: Option<i32>, // Credits consumed (when credits actually used)
    pub actual_charge: Option<f64>, // Actual dollar amount charged to user
    pub game_time: Option<serde_json::Value>,
    pub reasoning_content: Option<String>,
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
            .field("actual_cost", &self.actual_cost)
            .field("modified_cost", &self.modified_cost)
            .field("credit_cost", &self.credit_cost)
            .field("actual_charge", &self.actual_charge)
            .field("game_time", &self.game_time)
            .field(
                "reasoning_content",
                &self.reasoning_content.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

// For inserting a new chat message
#[derive(Insertable, Clone)]
#[diesel(table_name = chat_messages)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewChatMessage {
    pub id: crate::db::DbId,
    pub session_id: crate::db::DbId,
    pub message_type: MessageRole,
    pub content: Vec<u8>,
    pub content_nonce: Option<Vec<u8>>,
    pub rag_embedding_id: Option<crate::db::DbId>,
    pub user_id: crate::db::DbId,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub role: Option<String>,
    pub parts: Option<crate::DbJson>,
    pub attachments: Option<crate::DbJson>,
    pub prompt_tokens: Option<DbBigInt>,
    pub completion_tokens: Option<DbBigInt>,
    pub raw_prompt_ciphertext: Option<Vec<u8>>,
    pub raw_prompt_nonce: Option<Vec<u8>>,
    pub model_name: String, // Changed to String to match schema
    pub status: String,
    pub variant_count: i32,
    pub current_variant_index: i32,
    pub credits_charged: i32,
    pub credits_cost: crate::db::DbDecimal,
    pub actual_cost: crate::db::DbDecimal,
    pub modified_cost: crate::db::DbDecimal,
    pub credit_cost: i32,
    pub actual_charge: crate::db::DbDecimal,
    pub game_time: Option<crate::DbJson>,
    pub reasoning_content: Option<Vec<u8>>,
    pub reasoning_content_nonce: Option<Vec<u8>>,
}

impl Default for NewChatMessage {
    fn default() -> Self {
        Self {
            id: crate::db::DbId::default(),
            session_id: crate::db::DbId::default(),
            message_type: MessageRole::User,
            content: Vec::new(),
            content_nonce: None,
            rag_embedding_id: None,
            user_id: crate::db::DbId::default(),
            created_at: DbTimestamp::default(),
            updated_at: DbTimestamp::default(),
            role: None,
            parts: None,
            attachments: None,
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            model_name: String::new(),
            status: "pending".to_string(),
            variant_count: 1,
            current_variant_index: 0,
            credits_charged: 0,
            credits_cost: crate::db::DbDecimal::from(0),
            actual_cost: crate::db::DbDecimal::from(0),
            modified_cost: crate::db::DbDecimal::from(0),
            credit_cost: 0,
            actual_charge: crate::db::DbDecimal::from(0),
            game_time: None,
            reasoning_content: None,
            reasoning_content_nonce: None,
        }
    }
}

pub struct NewChatMessageBuilder {
    inner: NewChatMessage,
}

impl Default for NewChatMessageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NewChatMessageBuilder {
    pub fn new() -> Self {
        Self {
            inner: NewChatMessage::default(),
        }
    }

    pub fn id(mut self, id: crate::db::DbId) -> Self {
        self.inner.id = id;
        self
    }

    pub fn session_id(mut self, session_id: crate::db::DbId) -> Self {
        self.inner.session_id = session_id;
        self
    }

    pub fn message_type(mut self, message_type: MessageRole) -> Self {
        self.inner.message_type = message_type;
        self
    }

    pub fn content(mut self, content: Vec<u8>) -> Self {
        self.inner.content = content;
        self
    }

    pub fn content_nonce(mut self, content_nonce: Option<Vec<u8>>) -> Self {
        self.inner.content_nonce = content_nonce;
        self
    }

    pub fn rag_embedding_id(mut self, rag_embedding_id: Option<crate::db::DbId>) -> Self {
        self.inner.rag_embedding_id = rag_embedding_id;
        self
    }

    pub fn user_id(mut self, user_id: crate::db::DbId) -> Self {
        self.inner.user_id = user_id;
        self
    }

    pub fn created_at(mut self, created_at: DbTimestamp) -> Self {
        self.inner.created_at = created_at;
        self
    }

    pub fn updated_at(mut self, updated_at: DbTimestamp) -> Self {
        self.inner.updated_at = updated_at;
        self
    }

    pub fn role(mut self, role: Option<String>) -> Self {
        self.inner.role = role;
        self
    }

    pub fn parts(mut self, parts: Option<crate::DbJson>) -> Self {
        self.inner.parts = parts;
        self
    }

    pub fn attachments(mut self, attachments: Option<crate::DbJson>) -> Self {
        self.inner.attachments = attachments;
        self
    }

    pub fn prompt_tokens(mut self, prompt_tokens: Option<DbBigInt>) -> Self {
        self.inner.prompt_tokens = prompt_tokens;
        self
    }

    pub fn completion_tokens(mut self, completion_tokens: Option<DbBigInt>) -> Self {
        self.inner.completion_tokens = completion_tokens;
        self
    }

    pub fn raw_prompt_ciphertext(mut self, raw_prompt_ciphertext: Option<Vec<u8>>) -> Self {
        self.inner.raw_prompt_ciphertext = raw_prompt_ciphertext;
        self
    }

    pub fn raw_prompt_nonce(mut self, raw_prompt_nonce: Option<Vec<u8>>) -> Self {
        self.inner.raw_prompt_nonce = raw_prompt_nonce;
        self
    }

    pub fn model_name(mut self, model_name: String) -> Self {
        self.inner.model_name = model_name;
        self
    }

    pub fn status(mut self, status: String) -> Self {
        self.inner.status = status;
        self
    }

    pub fn variant_count(mut self, variant_count: i32) -> Self {
        self.inner.variant_count = variant_count;
        self
    }

    pub fn current_variant_index(mut self, current_variant_index: i32) -> Self {
        self.inner.current_variant_index = current_variant_index;
        self
    }

    pub fn credits_charged(mut self, credits_charged: i32) -> Self {
        self.inner.credits_charged = credits_charged;
        self
    }

    pub fn credits_cost(mut self, credits_cost: crate::db::DbDecimal) -> Self {
        self.inner.credits_cost = credits_cost;
        self
    }

    pub fn actual_cost(mut self, actual_cost: crate::db::DbDecimal) -> Self {
        self.inner.actual_cost = actual_cost;
        self
    }

    pub fn modified_cost(mut self, modified_cost: crate::db::DbDecimal) -> Self {
        self.inner.modified_cost = modified_cost;
        self
    }

    pub fn credit_cost(mut self, credit_cost: i32) -> Self {
        self.inner.credit_cost = credit_cost;
        self
    }

    pub fn actual_charge(mut self, actual_charge: crate::db::DbDecimal) -> Self {
        self.inner.actual_charge = actual_charge;
        self
    }

    pub fn game_time(mut self, game_time: Option<crate::DbJson>) -> Self {
        self.inner.game_time = game_time;
        self
    }

    pub fn reasoning_content(mut self, content: Option<Vec<u8>>) -> Self {
        self.inner.reasoning_content = content;
        self
    }

    pub fn reasoning_content_nonce(mut self, nonce: Option<Vec<u8>>) -> Self {
        self.inner.reasoning_content_nonce = nonce;
        self
    }

    pub fn build(self) -> NewChatMessage {
        self.inner
    }
}

impl NewChatMessage {
    pub fn builder() -> NewChatMessageBuilder {
        NewChatMessageBuilder::new()
    }
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
            .field("game_time", &self.game_time)
            .finish()
    }
}

// For inserting a new chat message with better naming clarity
#[derive(Insertable, Clone)]
#[diesel(table_name = chat_messages)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct DbInsertableChatMessage {
    pub id: crate::db::DbId,
    #[diesel(column_name = session_id)]
    pub chat_id: crate::db::DbId,
    #[diesel(column_name = message_type)]
    pub msg_type: MessageRole,
    pub content: Vec<u8>,
    pub content_nonce: Option<Vec<u8>>,
    pub rag_embedding_id: Option<crate::db::DbId>,
    pub user_id: crate::db::DbId,
    pub role: Option<String>,
    pub parts: Option<crate::DbJson>,
    pub attachments: Option<crate::DbJson>,
    pub prompt_tokens: Option<DbBigInt>,
    pub completion_tokens: Option<DbBigInt>,
    pub raw_prompt_ciphertext: Option<Vec<u8>>,
    pub raw_prompt_nonce: Option<Vec<u8>>,
    pub model_name: String,
    pub status: String,
    pub error_message: Option<String>,
    pub variant_count: i32,
    pub current_variant_index: i32,
    pub credits_charged: i32,
    pub credits_cost: crate::db::DbDecimal,
    // New cost tracking fields
    pub actual_cost: crate::db::DbDecimal,
    pub modified_cost: crate::db::DbDecimal,
    pub credit_cost: i32,
    pub actual_charge: crate::db::DbDecimal,
    pub game_time: Option<crate::DbJson>,
    pub reasoning_content: Option<Vec<u8>>,
    pub reasoning_content_nonce: Option<Vec<u8>>,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
}

impl std::fmt::Debug for DbInsertableChatMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbInsertableChatMessage")
            .field("id", &self.id)
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
            .field("game_time", &self.game_time)
            .field(
                "reasoning_content",
                &self.reasoning_content.as_ref().map(|_| "[REDACTED_BYTES]"),
            )
            .field(
                "reasoning_content_nonce",
                &self
                    .reasoning_content_nonce
                    .as_ref()
                    .map(|_| "[REDACTED_NONCE]"),
            )
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl DbInsertableChatMessage {
    /// Create a new chat message with required fields only
    #[must_use]
    pub fn new(
        chat_id: crate::db::DbId,
        user_id: crate::db::DbId,
        msg_type: MessageRole,
        content: Vec<u8>,
        content_nonce: Option<Vec<u8>>,
        model_name: String,
    ) -> Self {
        Self {
            id: crate::db::DbId::new(),
            chat_id,
            user_id,
            msg_type,
            content,
            content_nonce,
            rag_embedding_id: None,
            model_name,
            role: None,
            parts: None,
            attachments: None,
            prompt_tokens: None,
            completion_tokens: None,
            raw_prompt_ciphertext: None,
            raw_prompt_nonce: None,
            status: MessageStatus::Completed.to_string(),
            error_message: None,
            variant_count: 1, // Default to 1 (the original version is variant 0)
            current_variant_index: 0,
            credits_charged: 0,
            credits_cost: crate::db::DbDecimal::from(0),
            // Initialize new cost tracking fields
            actual_cost: crate::db::DbDecimal::from(0),
            modified_cost: crate::db::DbDecimal::from(0),
            credit_cost: 0,
            actual_charge: crate::db::DbDecimal::from(0),
            game_time: None,
            reasoning_content: None,
            reasoning_content_nonce: None,
            created_at: DbTimestamp::now(),
            updated_at: DbTimestamp::now(),
        }
    }

    #[must_use]
    pub fn with_id(mut self, id: crate::db::DbId) -> Self {
        self.id = id;
        self
    }

    #[must_use]
    pub fn with_created_at(mut self, created_at: DbTimestamp) -> Self {
        self.created_at = created_at;
        self
    }

    #[must_use]
    pub fn with_updated_at(mut self, updated_at: DbTimestamp) -> Self {
        self.updated_at = updated_at;
        self
    }

    /// Builder methods for optional fields
    #[must_use]
    pub fn with_role(mut self, role: String) -> Self {
        self.role = Some(role);
        self
    }

    #[must_use]
    pub fn with_parts(mut self, parts: crate::DbJson) -> Self {
        self.parts = Some(parts);
        self
    }

    #[must_use]
    pub fn with_attachments(mut self, attachments: crate::DbJson) -> Self {
        self.attachments = Some(attachments);
        self
    }

    #[must_use]
    pub const fn with_token_counts(
        mut self,
        prompt_tokens: Option<DbBigInt>,
        completion_tokens: Option<DbBigInt>,
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
    #[must_use]
    pub fn with_reasoning(
        mut self,
        reasoning_content: Option<Vec<u8>>,
        reasoning_content_nonce: Option<Vec<u8>>,
    ) -> Self {
        self.reasoning_content = reasoning_content;
        self.reasoning_content_nonce = reasoning_content_nonce;
        self
    }

    #[must_use]
    pub fn with_status(mut self, status: MessageStatus) -> Self {
        self.status = status.to_string();
        self
    }

    #[must_use]
    pub fn with_error_message(mut self, error_message: String) -> Self {
        self.error_message = Some(error_message);
        self
    }

    /// Set both credits_charged and credits_cost
    /// DEPRECATED: Use with_cost_tracking for new code
    #[must_use]
    pub fn with_credits(
        mut self,
        credits_charged: i32,
        credits_cost: crate::db::DbDecimal,
    ) -> Self {
        self.credits_charged = credits_charged;
        self.credits_cost = credits_cost;
        self
    }

    /// Set all cost tracking fields properly
    #[must_use]
    pub fn with_cost_tracking(
        mut self,
        actual_cost: crate::db::DbDecimal,
        modified_cost: crate::db::DbDecimal,
        credit_cost: i32,
        actual_charge: crate::db::DbDecimal,
        credits_charged: i32,
    ) -> Self {
        // Clone actual_cost for backwards compatibility before moving
        let actual_cost_clone = actual_cost.clone();
        self.actual_cost = actual_cost;
        self.modified_cost = modified_cost;
        self.credit_cost = credit_cost;
        self.actual_charge = actual_charge;
        self.credits_charged = credits_charged;
        // Keep credits_cost for backwards compatibility
        self.credits_cost = actual_cost_clone;
        self
    }

    #[must_use]
    pub fn with_variant_count(mut self, variant_count: i32) -> Self {
        self.variant_count = variant_count;
        self
    }

    #[must_use]
    pub fn with_current_variant_index(mut self, current_variant_index: i32) -> Self {
        self.current_variant_index = current_variant_index;
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
    pub character_id: Option<crate::db::DbId>,
    pub active_custom_persona_id: Option<crate::db::DbId>,
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
    pub reasoning: Option<String>,
}

impl std::fmt::Debug for CreateMessageVariantPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreateMessageVariantPayload")
            .field("content", &"[REDACTED]")
            .finish()
    }
}

#[derive(Deserialize, Serialize, Validate)]
pub struct SelectVariantRequest {
    #[validate(range(min = 0))]
    pub variant_index: i32,
}

impl std::fmt::Debug for SelectVariantRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectVariantRequest")
            .field("variant_index", &self.variant_index)
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
#[derive(Deserialize, Serialize, Clone, Validate, Default)]
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
#[derive(Deserialize, Serialize, Validate, Default)]
pub struct GenerateChatRequest {
    #[validate(length(min = 1))]
    #[validate(nested)]
    pub history: Vec<ApiChatMessage>,
    pub model: Option<String>,
    pub query_text_for_rag: Option<String>,
    pub analysis_mode: Option<String>, // "existing", "refresh", or "skip" for agent analysis control
    pub agent_mode: Option<String>,    // "disabled", "pre_processing", or "post_processing"
    pub guidance: Option<String>,      // Optional guidance text for regeneration steering
    pub variant_of: Option<crate::db::DbId>, // If provided, create a variant of this message instead of new message
    pub parent_message_id: Option<crate::db::DbId>, // Optional parent message ID for rewind/pruning
    pub game_master_mode_enabled: Option<bool>,
    pub thinking_level: Option<String>,
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
            .field("analysis_mode", &self.analysis_mode)
            .field("guidance", &self.guidance.as_ref().map(|_| "[REDACTED]"))
            .field("variant_of", &self.variant_of)
            .field("thinking_level", &self.thinking_level)
            .finish()
    }
}
// --- Chat Client Response Structures ---

/// Chat struct for client responses with decrypted fields
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatForClient {
    pub id: crate::db::DbId,
    pub user_id: crate::db::DbId,
    pub character_id: Option<crate::db::DbId>,
    pub title: Option<String>,
    pub system_prompt: Option<String>,
    pub temperature: Option<crate::db::DbDecimal>,
    pub max_output_tokens: Option<i32>,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub frequency_penalty: Option<crate::db::DbDecimal>,
    pub presence_penalty: Option<crate::db::DbDecimal>,
    pub top_k: Option<i32>,
    pub top_p: Option<crate::db::DbDecimal>,
    pub repetition_penalty: Option<crate::db::DbDecimal>,
    pub min_p: Option<crate::db::DbDecimal>,
    pub top_a: Option<crate::db::DbDecimal>,
    pub seed: Option<i32>,
    pub logit_bias: Option<crate::db::DbJson>,
    pub stop_sequences: Option<crate::models::OptionalStringArray>,
    pub history_management_strategy: String,
    pub history_management_limit: i32,
    pub model_name: Option<String>,
    pub thinking_budget: Option<i32>,
    pub enable_code_execution: Option<bool>,
    pub visibility: Option<String>,
    pub active_custom_persona_id: Option<crate::db::DbId>,
    pub active_impersonated_character_id: Option<crate::db::DbId>,
    pub chat_mode: ChatMode,
    pub chronicle_id: Option<crate::db::DbId>, // Chronicle association (maps to player_chronicle_id in database)
    pub total_prompt_tokens: DbBigInt,
    pub total_completion_tokens: DbBigInt,
    pub total_credits_used: crate::db::DbDecimal,
    pub total_actual_cost: crate::db::DbDecimal, // Raw API cost in dollars
    // Game Master Agent fields
    pub game_master_mode_enabled: bool,
    pub game_state: Option<crate::db::DbJson>,
    pub thinking_level: Option<String>,
    pub rag_chronicles_limit: Option<i32>,
    pub rag_lorebooks_limit: Option<i32>,
    pub rag_older_chat_limit: Option<i32>,
    pub rag_cognitive_context_limit: Option<i32>,
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
            repetition_penalty: self.repetition_penalty,
            min_p: self.min_p,
            top_a: self.top_a,
            seed: self.seed,
            logit_bias: self.logit_bias,
            stop_sequences: self.stop_sequences,
            history_management_strategy: self.history_management_strategy,
            history_management_limit: self.history_management_limit,
            model_name: Some(self.model_name),
            thinking_budget: self.thinking_budget,
            enable_code_execution: self.enable_code_execution,
            visibility: self.visibility,
            active_custom_persona_id: self.active_custom_persona_id,
            active_impersonated_character_id: self.active_impersonated_character_id,
            chat_mode: self.chat_mode,
            chronicle_id: self.player_chronicle_id, // Map database field to API field
            total_prompt_tokens: self.total_prompt_tokens,
            total_completion_tokens: self.total_completion_tokens,
            total_credits_used: self.total_credits_used,
            total_actual_cost: self.total_actual_cost,
            game_master_mode_enabled: self.game_master_mode_enabled,
            game_state: self.game_state,
            thinking_level: self.thinking_level,
            rag_chronicles_limit: self.rag_chronicles_limit,
            rag_lorebooks_limit: self.rag_lorebooks_limit,
            rag_older_chat_limit: self.rag_older_chat_limit,
            rag_cognitive_context_limit: self.rag_cognitive_context_limit,
        })
    }

    /// Decrypts and deserializes the session-level narrative style override.
    ///
    /// Returns `None` if no override is set, or `Some(override)` if one exists.
    ///
    /// # Errors
    ///
    /// Returns `AppError::DecryptionError` if decryption fails or JSON deserialization fails.
    pub fn get_narrative_style_override(
        &self,
        dek: &secrecy::SecretBox<Vec<u8>>,
    ) -> Result<
        Option<crate::models::template_preferences::UpdateTemplatePreferenceRequest>,
        crate::errors::AppError,
    > {
        use crate::models::template_preferences::UpdateTemplatePreferenceRequest;

        match (
            &self.narrative_style_override_ciphertext,
            &self.narrative_style_override_nonce,
        ) {
            (Some(ciphertext), Some(nonce)) => {
                if ciphertext.is_empty() && nonce.is_empty() {
                    // Convention for empty encrypted field
                    return Ok(None);
                }

                if ciphertext.is_empty() || nonce.is_empty() {
                    return Err(crate::errors::AppError::DecryptionError(
                        "Mismatched ciphertext/nonce for narrative style override".to_string(),
                    ));
                }

                let encryption_service =
                    crate::services::encryption_service::EncryptionService::new();
                let decrypted_bytes = encryption_service.decrypt(
                    ciphertext,
                    nonce,
                    dek.expose_secret().as_slice(),
                )?;

                let json_str = String::from_utf8(decrypted_bytes).map_err(|e| {
                    crate::errors::AppError::DecryptionError(format!(
                        "Invalid UTF-8 for decrypted narrative style override: {e}"
                    ))
                })?;

                let override_data: UpdateTemplatePreferenceRequest =
                    serde_json::from_str(&json_str).map_err(|e| {
                        crate::errors::AppError::DecryptionError(format!(
                            "Failed to deserialize narrative style override: {e}"
                        ))
                    })?;

                Ok(Some(override_data))
            }
            (None, None) => Ok(None), // No override set
            (Some(_), None) => Err(crate::errors::AppError::DecryptionError(
                "Narrative style override ciphertext present but nonce missing".to_string(),
            )),
            (None, Some(_)) => Err(crate::errors::AppError::DecryptionError(
                "Narrative style override nonce present but ciphertext missing".to_string(),
            )),
        }
    }

    /// Encrypts and sets the session-level narrative style override.
    ///
    /// Pass `None` to clear the override.
    ///
    /// # Errors
    ///
    /// Returns `AppError::EncryptionError` if encryption or JSON serialization fails.
    pub fn set_narrative_style_override(
        &mut self,
        override_data: Option<crate::models::template_preferences::UpdateTemplatePreferenceRequest>,
        dek: &secrecy::SecretBox<Vec<u8>>,
    ) -> Result<(), crate::errors::AppError> {
        match override_data {
            Some(data) => {
                let json_str = serde_json::to_string(&data).map_err(|e| {
                    crate::errors::AppError::EncryptionError(format!(
                        "Failed to serialize narrative style override: {e}"
                    ))
                })?;

                let encryption_service =
                    crate::services::encryption_service::EncryptionService::new();
                let (ciphertext, nonce) =
                    encryption_service.encrypt(&json_str, dek.expose_secret().as_slice())?;

                self.narrative_style_override_ciphertext = Some(ciphertext);
                self.narrative_style_override_nonce = Some(nonce);
            }
            None => {
                // Clear the override
                self.narrative_style_override_ciphertext = None;
                self.narrative_style_override_nonce = None;
            }
        }

        Ok(())
    }
}

// --- Chat Settings API Structures ---

/// Response body for GET /api/chat/{id}/settings
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct ChatSettingsResponse {
    pub system_prompt: Option<String>,
    pub temperature: Option<crate::db::DbDecimal>,
    pub max_output_tokens: Option<i32>,
    pub frequency_penalty: Option<crate::db::DbDecimal>,
    pub presence_penalty: Option<crate::db::DbDecimal>,
    pub top_k: Option<i32>,
    pub top_p: Option<crate::db::DbDecimal>,
    pub repetition_penalty: Option<crate::db::DbDecimal>,
    pub min_p: Option<crate::db::DbDecimal>,
    pub top_a: Option<crate::db::DbDecimal>,
    pub seed: Option<i32>,
    pub logit_bias: Option<crate::db::DbJson>,
    pub stop_sequences: Option<crate::models::OptionalStringArray>,
    // History Management Fields
    pub history_management_strategy: String,
    pub history_management_limit: i32,
    // Model Name
    pub model_name: Option<String>,
    // Gemini-specific options
    pub thinking_budget: Option<i32>,
    pub enable_code_execution: Option<bool>,
    // Chronicle association
    pub chronicle_id: Option<crate::db::DbId>,
    // Agent mode for context enrichment
    pub agent_mode: Option<String>,
    // Active custom persona for this chat session
    pub active_custom_persona_id: Option<crate::db::DbId>,
    // Prompt template to use for this chat session
    pub prompt_template_id: Option<String>,
    // Game Master mode flag
    pub game_master_mode_enabled: Option<bool>,
    pub thinking_level: Option<String>,
    pub rag_chronicles_limit: Option<i32>,
    pub rag_lorebooks_limit: Option<i32>,
    pub rag_older_chat_limit: Option<i32>,
    pub rag_cognitive_context_limit: Option<i32>,
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
            .field("thinking_budget", &self.thinking_budget)
            .field("enable_code_execution", &self.enable_code_execution)
            .field("chronicle_id", &self.chronicle_id)
            .field("agent_mode", &self.agent_mode)
            .field("active_custom_persona_id", &self.active_custom_persona_id)
            .field("prompt_template_id", &self.prompt_template_id)
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
            repetition_penalty: chat.repetition_penalty,
            min_p: chat.min_p,
            top_a: chat.top_a,
            seed: chat.seed,
            logit_bias: chat.logit_bias,
            stop_sequences: chat.stop_sequences,
            history_management_strategy: chat.history_management_strategy,
            history_management_limit: chat.history_management_limit,
            model_name: Some(chat.model_name),
            thinking_budget: chat.thinking_budget,
            enable_code_execution: chat.enable_code_execution,
            chronicle_id: chat.player_chronicle_id,
            agent_mode: chat.agent_mode,
            active_custom_persona_id: chat.active_custom_persona_id,
            prompt_template_id: Some(chat.prompt_template_id),
            game_master_mode_enabled: Some(chat.game_master_mode_enabled),
            thinking_level: chat.thinking_level,
            rag_chronicles_limit: chat.rag_chronicles_limit,
            rag_lorebooks_limit: chat.rag_lorebooks_limit,
            rag_older_chat_limit: chat.rag_older_chat_limit,
            rag_cognitive_context_limit: chat.rag_cognitive_context_limit,
        }
    }
}

/// Request body for PUT /api/chat/{id}/settings
/// All fields are optional to allow partial updates.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Validate, Default)]
pub struct UpdateChatSettingsRequest {
    pub system_prompt: Option<String>,
    #[validate(custom(function = "validate_optional_temperature"))]
    pub temperature: Option<crate::db::DbDecimal>,
    #[validate(range(min = 1))]
    pub max_output_tokens: Option<i32>,
    #[validate(custom(function = "validate_optional_frequency_penalty"))]
    pub frequency_penalty: Option<crate::db::DbDecimal>,
    #[validate(custom(function = "validate_optional_presence_penalty"))]
    pub presence_penalty: Option<crate::db::DbDecimal>,
    #[validate(range(min = 0))]
    pub top_k: Option<i32>,
    #[validate(custom(function = "validate_optional_top_p"))]
    pub top_p: Option<crate::db::DbDecimal>,
    pub repetition_penalty: Option<crate::db::DbDecimal>,
    pub min_p: Option<crate::db::DbDecimal>,
    pub top_a: Option<crate::db::DbDecimal>,
    pub seed: Option<i32>,
    pub logit_bias: Option<crate::db::DbJson>,
    #[serde(default)]
    pub stop_sequences: Option<crate::models::OptionalStringArray>,
    // History Management Fields
    #[validate(custom(function = "validate_optional_history_strategy"))]
    pub history_management_strategy: Option<String>,
    #[validate(range(min = 1))]
    pub history_management_limit: Option<i32>,
    // Model Name
    pub model_name: Option<String>,
    // Model Provider (local, gemini, etc.)
    pub model_provider: Option<String>,
    // Gemini-specific options
    pub thinking_budget: Option<i32>,
    pub thinking_level: Option<String>,
    pub enable_code_execution: Option<bool>,
    // Chronicle association
    pub chronicle_id: Option<crate::db::DbId>,
    // Agent mode for context enrichment
    #[validate(custom(function = "validate_optional_agent_mode"))]
    pub agent_mode: Option<String>,
    // Active custom persona for this chat session
    pub active_custom_persona_id: Option<crate::db::DbId>,
    // Prompt template to use for this chat session
    #[validate(custom(function = "validate_optional_template_id"))]
    pub prompt_template_id: Option<String>,
    // Game Master mode enable/disable
    pub game_master_mode_enabled: Option<bool>,
    // RAG Limits
    #[validate(range(min = 0, max = 1000000))]
    pub rag_chronicles_limit: Option<i32>,
    #[validate(range(min = 0, max = 1000000))]
    pub rag_lorebooks_limit: Option<i32>,
    #[validate(range(min = 0, max = 1000000))]
    pub rag_older_chat_limit: Option<i32>,
    #[validate(range(min = 0, max = 1000000))]
    pub rag_cognitive_context_limit: Option<i32>,
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
            .field("thinking_budget", &self.thinking_budget)
            .field("enable_code_execution", &self.enable_code_execution)
            .field("chronicle_id", &self.chronicle_id)
            .field("agent_mode", &self.agent_mode)
            .field("active_custom_persona_id", &self.active_custom_persona_id)
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
fn validate_optional_temperature(temp: &crate::db::DbDecimal) -> Result<(), ValidationError> {
    let zero = BigDecimal::from(0).into();
    let two = BigDecimal::from(2).into();
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
fn validate_optional_frequency_penalty(
    penalty: &crate::db::DbDecimal,
) -> Result<(), ValidationError> {
    let neg_two = BigDecimal::from(-2).into();
    let two = BigDecimal::from(2).into();
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
fn validate_optional_presence_penalty(
    penalty: &crate::db::DbDecimal,
) -> Result<(), ValidationError> {
    let neg_two = BigDecimal::from(-2).into();
    let two = BigDecimal::from(2).into();
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
fn validate_optional_top_p(value: &crate::db::DbDecimal) -> Result<(), ValidationError> {
    let zero = BigDecimal::from(0).into();
    let one = BigDecimal::from(1).into();
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

// MessageVariant struct for API responses
#[derive(Clone, Serialize, Deserialize)]
pub struct MessageVariantResponse {
    pub index: i32,
    pub content: String,
    pub created_at: DbTimestamp,
    pub prompt_tokens: Option<DbBigInt>,
    pub completion_tokens: Option<DbBigInt>,
    pub model_name: Option<String>,

    pub game_state: Option<serde_json::Value>,
    pub reasoning_content: Option<String>,
}

// MessageResponse struct for API responses
#[derive(Clone, Serialize, Deserialize)]
pub struct MessageResponse {
    pub id: crate::db::DbId,
    pub session_id: crate::db::DbId,
    pub message_type: MessageRole,
    pub role: String,
    pub content: String,
    pub parts: crate::DbJson,
    pub attachments: crate::DbJson,
    pub created_at: DbTimestamp,
    pub raw_prompt: Option<String>, // Debug field containing the full prompt sent to AI
    pub prompt_tokens: Option<DbBigInt>,
    pub completion_tokens: Option<DbBigInt>,
    pub model_name: Option<String>, // Optional for backward compatibility with existing messages
    pub status: String,
    pub error_message: Option<String>,

    // Variant metadata
    pub variant_count: i32,
    pub current_variant_index: i32,
    pub is_variant: bool,
    pub parent_message_id: Option<crate::db::DbId>,

    // Optional: Complete variant data for immediate access
    pub variants: Option<Vec<MessageVariantResponse>>,
    pub game_state: Option<serde_json::Value>,
    pub reasoning_content: Option<String>,
}

impl std::fmt::Debug for MessageResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageResponse")
            .field("id", &self.id)
            .field("session_id", &self.session_id)
            .field("message_type", &self.message_type)
            .field("role", &self.role)
            .field("content", &"[REDACTED]")
            .field("parts", &"[REDACTED_JSON]")
            .field("attachments", &"[REDACTED_JSON]")
            .field("created_at", &self.created_at)
            .field(
                "raw_prompt",
                &self.raw_prompt.as_ref().map(|_| "[REDACTED_RAW_PROMPT]"),
            )
            .field("status", &self.status)
            .field("variant_count", &self.variant_count)
            .field("current_variant_index", &self.current_variant_index)
            .field("is_variant", &self.is_variant)
            .field("parent_message_id", &self.parent_message_id)
            .field(
                "variants",
                &self
                    .variants
                    .as_ref()
                    .map(|v| format!("[{} variants]", v.len())),
            )
            .finish()
    }
}

// Vote struct for message voting
#[derive(Clone, Serialize, Deserialize)]
pub struct Vote {
    pub chat_id: crate::db::DbId,
    pub message_id: crate::db::DbId,
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
    pub message_id: crate::db::DbId,
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
    pub character_id: crate::db::DbId,
    pub title: Option<String>,
    pub active_custom_persona_id: Option<crate::db::DbId>,
    pub lorebook_ids: Option<Vec<crate::db::DbId>>,
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
    pub parts: Option<crate::DbJson>,
    pub attachments: Option<crate::DbJson>,
    pub parent_message_id: Option<crate::db::DbId>,
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
    pub parent_message_id: Option<crate::db::DbId>,
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
    pub parent_message_id: Option<crate::db::DbId>,
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

fn validate_optional_template_id(template_id: &String) -> Result<(), ValidationError> {
    use regex::Regex;
    use std::sync::LazyLock;

    static TEMPLATE_ID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[a-zA-Z0-9_]+$").expect("Failed to compile template ID regex")
    });

    // Check template ID format
    if template_id.is_empty() {
        let mut err = ValidationError::new("template_id_empty");
        err.message = Some("Template ID cannot be empty".into());
        return Err(err);
    }

    if template_id.len() > 50 {
        let mut err = ValidationError::new("template_id_too_long");
        err.message = Some("Template ID too long (max 50 characters)".into());
        return Err(err);
    }

    if !TEMPLATE_ID_REGEX.is_match(template_id) {
        let mut err = ValidationError::new("template_id_invalid_format");
        err.message =
            Some("Template ID must contain only alphanumeric characters and underscores".into());
        return Err(err);
    }

    // Check if template exists using the global template manager
    use crate::prompt_templates::TEMPLATE_MANAGER;
    if !TEMPLATE_MANAGER.read().unwrap().has_template(template_id) {
        let mut err = ValidationError::new("template_not_found");
        err.message = Some(format!("Template '{}' not found", template_id).into());
        return Err(err);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DbId;
    use bigdecimal::BigDecimal;
    use chrono::Utc;
    use ring::rand::{SecureRandom, SystemRandom};
    use secrecy::SecretBox;
    use std::str::FromStr;
    use validator::Validate;

    // Helper function to generate a dummy DEK for testing
    fn generate_dummy_dek() -> SecretBox<Vec<u8>> {
        let mut key_bytes = vec![0u8; 32];
        let rng = SystemRandom::new();
        rng.fill(&mut key_bytes).unwrap();
        SecretBox::new(Box::new(key_bytes))
    }

    // Helper function to create BigDecimal from a string for tests
    fn bd(s: &str) -> crate::db::DbDecimal {
        crate::db::DbDecimal::from_bigdecimal(
            BigDecimal::from_str(s).expect("Invalid decimal string"),
        )
    }

    // Helper function to create a sample chat session
    fn create_sample_chat_session() -> Chat {
        Chat {
            id: DbId::new(),
            user_id: DbId::new(),
            character_id: Some(DbId::new()),
            chat_mode: ChatMode::Character,
            title_ciphertext: None,
            title_nonce: None,
            system_prompt_ciphertext: None,
            system_prompt_nonce: None,
            temperature: Some(bd("0.7")),
            max_output_tokens: Some(1024),
            created_at: crate::db::DbTimestamp::now(),
            updated_at: crate::db::DbTimestamp::now(),
            frequency_penalty: Some(bd("0.0")),
            presence_penalty: Some(bd("0.0")),
            top_k: Some(50),
            top_p: Some(bd("0.9")),
            repetition_penalty: None,
            min_p: None,
            top_a: None,
            seed: Some(12345),
            logit_bias: None,
            stop_sequences: Some(crate::db::unified_types::DbStringArray(vec![
                Some("\n\n".to_string()),
                Some("##".to_string()),
            ])),
            history_management_strategy: "none".to_string(),
            history_management_limit: 4096,
            model_name: "gemini-2.5-flash".to_string(),
            thinking_budget: None,
            enable_code_execution: None,
            estimated_cost_cents: 0,
            prompt_template_id: "default".to_string(),
            tokens_counted_at: crate::db::DbTimestamp::now(),
            total_prompt_tokens: crate::db::DbBigInt::from(0),
            total_completion_tokens: crate::db::DbBigInt::from(0),
            total_credits_used: crate::db::DbDecimal::from(0i64),
            visibility: Some("private".to_string()),
            active_custom_persona_id: None,
            active_impersonated_character_id: None,
            player_chronicle_id: None,
            agent_mode: Some("disabled".to_string()),
            model_provider: None,
            total_actual_cost: crate::db::DbDecimal::from(0),
            total_modified_cost: crate::db::DbDecimal::from(0),
            total_credit_cost: 0,
            total_actual_charge: crate::db::DbDecimal::from(0),
            narrative_style_override_ciphertext: None,
            narrative_style_override_nonce: None,
            game_master_mode_enabled: false,
            game_state: None,
            thinking_level: None,
            rag_chronicles_limit: None,
            rag_cognitive_context_limit: None,
            rag_lorebooks_limit: None,
            rag_older_chat_limit: None,
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
        ChatMessage::builder()
            .id(DbId::new())
            .session_id(DbId::new())
            .message_type(MessageRole::User)
            .content(b"Hello, how are you?".to_vec())
            .created_at(crate::db::DbTimestamp::now())
            .updated_at(crate::db::DbTimestamp::now())
            .user_id(DbId::new())
            .model_name("test-model".to_string())
            .status("completed".to_string())
            .build()
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
        NewChatMessage::builder()
            .id(DbId::new())
            .session_id(DbId::new())
            .message_type(MessageRole::User)
            .content(b"Hello!".to_vec())
            .user_id(DbId::new())
            .created_at(Utc::now().into())
            .updated_at(Utc::now().into())
            .role(Some("user".to_string()))
            .model_name("test-model".to_string())
            .status("completed".to_string())
            .build()
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
        let chat_id = DbId::new();
        let user_id = DbId::new();
        let role = MessageRole::User;
        let content_str = "Test message";
        let content_vec = content_str.as_bytes().to_vec();

        let message = DbInsertableChatMessage::new(
            chat_id,
            user_id,
            role,
            content_vec.clone(),
            None,
            "test-model".to_string(),
        );
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
            repetition_penalty: Some(bd("1.0")),
            min_p: Some(bd("0.05")),
            top_a: Some(bd("0.0")),
            seed: Some(12345),
            logit_bias: None,
            stop_sequences: Some(crate::db::unified_types::DbStringArray::from_vec(vec![
                Some("\n\n".to_string()),
                Some("##".to_string()),
            ])),
            history_management_strategy: "none".to_string(),
            history_management_limit: 4096,
            model_name: Some("gemini-2.5-flash".to_string()),
            game_master_mode_enabled: Some(false),
            thinking_budget: None,
            enable_code_execution: None,
            chronicle_id: None,
            agent_mode: Some("disabled".to_string()),
            active_custom_persona_id: None,
            prompt_template_id: None,
            thinking_level: None,
            rag_chronicles_limit: None,
            rag_lorebooks_limit: None,
            rag_older_chat_limit: None,
            rag_cognitive_context_limit: None,
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
            repetition_penalty: Some(bd("1.0")),
            min_p: Some(bd("0.05")),
            top_a: Some(bd("0.0")),
            seed: Some(42),
            logit_bias: None,
            stop_sequences: Some(crate::db::unified_types::DbStringArray::from_vec(vec![
                Some("\n\n".to_string()),
                Some("##".to_string()),
            ])),
            history_management_strategy: Some("sliding_window_tokens".to_string()),
            history_management_limit: Some(2000),
            model_name: Some("gemini-2.5-pro".to_string()),
            model_provider: Some("gemini".to_string()),
            game_master_mode_enabled: Some(true),
            thinking_level: None,
            thinking_budget: None,
            enable_code_execution: None,
            chronicle_id: None,
            agent_mode: Some("disabled".to_string()),
            active_custom_persona_id: None,
            prompt_template_id: Some("neutral_roleplay".to_string()),
            rag_chronicles_limit: None,
            rag_cognitive_context_limit: None,
            rag_lorebooks_limit: None,
            rag_older_chat_limit: None,
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
        assert!(err
            .field_errors()
            .contains_key("history_management_strategy"));
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
    pub id: crate::db::DbId,
    pub parent_message_id: crate::db::DbId,
    pub variant_index: i32,
    pub content: Vec<u8>, // Encrypted content
    pub content_nonce: Option<Vec<u8>>,
    pub user_id: crate::db::DbId,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub raw_prompt_ciphertext: Option<Vec<u8>>,
    pub raw_prompt_nonce: Option<Vec<u8>>,
    pub game_state: Option<crate::db::DbJson>,
    pub prompt_tokens: Option<DbBigInt>,
    pub completion_tokens: Option<DbBigInt>,
    pub model_name: Option<String>,
    pub reasoning_content: Option<Vec<u8>>,
    pub reasoning_content_nonce: Option<Vec<u8>>,
}

/// Insertable model for creating new message variants
#[derive(Insertable, Serialize, Deserialize, Clone)]
#[diesel(table_name = message_variants)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewMessageVariant {
    pub parent_message_id: crate::db::DbId,
    pub variant_index: i32,
    pub content: Vec<u8>, // Encrypted content
    pub content_nonce: Option<Vec<u8>>,
    pub user_id: crate::db::DbId,
    pub raw_prompt_ciphertext: Option<Vec<u8>>,
    pub raw_prompt_nonce: Option<Vec<u8>>,
    pub game_state: Option<crate::db::DbJson>,
    pub prompt_tokens: Option<DbBigInt>,
    pub completion_tokens: Option<DbBigInt>,
    pub model_name: Option<String>,
    pub reasoning_content: Option<Vec<u8>>,
    pub reasoning_content_nonce: Option<Vec<u8>>,
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

    /// Decrypt the raw_prompt field using the provided DEK
    pub fn decrypt_raw_prompt(&self, dek: &SecretBox<Vec<u8>>) -> Result<Option<String>, AppError> {
        match (&self.raw_prompt_ciphertext, &self.raw_prompt_nonce) {
            (Some(ciphertext), Some(nonce)) if !ciphertext.is_empty() && !nonce.is_empty() => {
                let plaintext_secret = decrypt_gcm(ciphertext, nonce, dek).map_err(|e| {
                    error!(
                        "Failed to decrypt raw prompt for variant ID {}: {}",
                        self.id, e
                    );
                    AppError::DecryptionError(format!("Decryption failed for raw prompt: {e}"))
                })?;

                let raw_prompt_str = String::from_utf8(plaintext_secret.expose_secret().clone())
                    .map_err(|e| {
                        tracing::error!("Failed to convert decrypted raw prompt to UTF-8: {}", e);
                        AppError::DecryptionError(
                            "Failed to convert raw prompt to UTF-8".to_string(),
                        )
                    })?;

                Ok(Some(raw_prompt_str))
            }
            _ => Ok(None),
        }
    }

    /// Decrypt the reasoning_content field using the provided DEK
    pub fn decrypt_reasoning(&self, dek: &SecretBox<Vec<u8>>) -> Result<Option<String>, AppError> {
        match (&self.reasoning_content, &self.reasoning_content_nonce) {
            (Some(ciphertext), Some(nonce)) if !ciphertext.is_empty() && !nonce.is_empty() => {
                let plaintext_secret = decrypt_gcm(ciphertext, nonce, dek).map_err(|e| {
                    error!(
                        "Failed to decrypt reasoning for variant ID {}: {}",
                        self.id, e
                    );
                    AppError::DecryptionError(format!("Decryption failed for reasoning: {e}"))
                })?;

                let reasoning_str = String::from_utf8(plaintext_secret.expose_secret().clone())
                    .map_err(|e| {
                        tracing::error!("Failed to convert decrypted reasoning to UTF-8: {}", e);
                        AppError::DecryptionError(
                            "Failed to convert reasoning to UTF-8".to_string(),
                        )
                    })?;

                Ok(Some(reasoning_str))
            }
            _ => Ok(None),
        }
    }
}

impl NewMessageVariant {
    /// Create a new message variant with encrypted content
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent_message_id: crate::db::DbId,
        variant_index: i32,
        content: &str,
        user_id: crate::db::DbId,
        dek: &SecretBox<Vec<u8>>,
        raw_prompt_debug: Option<&str>,
        game_state: Option<serde_json::Value>,
        reasoning: Option<&str>,
    ) -> Result<Self, AppError> {
        let (encrypted_content, nonce) = encrypt_gcm(content.as_bytes(), dek)
            .map_err(|e| AppError::CryptoError(e.to_string()))?;

        // Encrypt raw_prompt if provided
        let (raw_prompt_ciphertext, raw_prompt_nonce) = if let Some(raw_prompt) = raw_prompt_debug {
            if !raw_prompt.is_empty() {
                let (ciphertext, nonce) = encrypt_gcm(raw_prompt.as_bytes(), dek)
                    .map_err(|e| AppError::CryptoError(e.to_string()))?;
                (Some(ciphertext), Some(nonce))
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let mut variant = Self {
            parent_message_id,
            variant_index,
            content: encrypted_content,
            content_nonce: Some(nonce),
            user_id,
            raw_prompt_ciphertext,
            raw_prompt_nonce,
            game_state: game_state.map(crate::db::DbJson::new),
            prompt_tokens: None,
            completion_tokens: None,
            model_name: None,
            reasoning_content: None,
            reasoning_content_nonce: None,
        };

        if let Some(reasoning_text) = reasoning {
            if !reasoning_text.is_empty() {
                let (ciphertext, r_nonce) = encrypt_gcm(reasoning_text.as_bytes(), dek)
                    .map_err(|e| AppError::CryptoError(e.to_string()))?;
                variant.reasoning_content = Some(ciphertext);
                variant.reasoning_content_nonce = Some(r_nonce);
            }
        }

        Ok(variant)
    }
    #[must_use]
    pub fn with_token_counts(
        mut self,
        prompt_tokens: Option<DbBigInt>,
        completion_tokens: Option<DbBigInt>,
    ) -> Self {
        self.prompt_tokens = prompt_tokens;
        self.completion_tokens = completion_tokens;
        self
    }

    #[must_use]
    pub fn with_model_name(mut self, model_name: String) -> Self {
        self.model_name = Some(model_name);
        self
    }
}

/// DTO for API responses containing decrypted variant data
#[derive(Serialize, Deserialize, Clone)]
pub struct MessageVariantDto {
    pub id: crate::db::DbId,
    pub parent_message_id: crate::db::DbId,
    pub variant_index: i32,
    pub content: String, // Decrypted content
    pub user_id: crate::db::DbId,
    pub created_at: DbTimestamp,
    pub updated_at: DbTimestamp,
    pub prompt_tokens: Option<DbBigInt>,
    pub completion_tokens: Option<DbBigInt>,
    pub model_name: Option<String>,
    pub raw_prompt: Option<String>,
    pub game_state: Option<serde_json::Value>,
    pub reasoning_content: Option<String>,
}

impl MessageVariantDto {
    /// Convert from database model with decrypted content
    pub fn from_model(variant: MessageVariant, dek: &SecretBox<Vec<u8>>) -> Result<Self, AppError> {
        let content = variant.decrypt_content(dek)?;
        let raw_prompt = variant.decrypt_raw_prompt(dek)?;

        Ok(Self {
            id: variant.id,
            parent_message_id: variant.parent_message_id,
            variant_index: variant.variant_index,
            content,
            user_id: variant.user_id,
            created_at: variant.created_at,
            updated_at: variant.updated_at,
            prompt_tokens: None,     // Not stored in message_variants table
            completion_tokens: None, // Not stored in message_variants table
            model_name: None,        // Not stored in message_variants table
            raw_prompt,
            game_state: variant.game_state.clone().map(|j| j.into_inner()),
            reasoning_content: variant.decrypt_reasoning(dek)?,
        })
    }
}

impl From<MessageVariantDto> for MessageVariantResponse {
    fn from(dto: MessageVariantDto) -> Self {
        Self {
            index: dto.variant_index,
            content: dto.content,
            created_at: dto.created_at,
            prompt_tokens: dto.prompt_tokens,
            completion_tokens: dto.completion_tokens,
            model_name: dto.model_name,
            game_state: dto.game_state,
            reasoning_content: dto.reasoning_content,
        }
    }
}
