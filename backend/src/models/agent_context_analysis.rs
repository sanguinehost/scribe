use crate::schema::agent_context_analysis;
use chrono::{DateTime, Utc};
use diesel::{Identifiable, Insertable, Queryable, Selectable, AsChangeset};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use uuid::Uuid;
use secrecy::{ExposeSecret, SecretBox};
use crate::crypto;
use crate::errors::AppError;

/// Mode of operation for the context enrichment agent
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalysisType {
    #[serde(rename = "pre_processing")]
    PreProcessing,
    #[serde(rename = "post_processing")]
    PostProcessing,
}

/// Status of the agent analysis
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalysisStatus {
    #[serde(rename = "pending")]
    Pending,
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "partial")]
    Partial,
}

impl std::fmt::Display for AnalysisType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalysisType::PreProcessing => write!(f, "pre_processing"),
            AnalysisType::PostProcessing => write!(f, "post_processing"),
        }
    }
}

impl std::str::FromStr for AnalysisType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pre_processing" => Ok(AnalysisType::PreProcessing),
            "post_processing" => Ok(AnalysisType::PostProcessing),
            _ => Err(format!("Unknown analysis type: {}", s)),
        }
    }
}

impl std::fmt::Display for AnalysisStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalysisStatus::Pending => write!(f, "pending"),
            AnalysisStatus::Success => write!(f, "success"),
            AnalysisStatus::Failed => write!(f, "failed"),
            AnalysisStatus::Partial => write!(f, "partial"),
        }
    }
}

impl std::str::FromStr for AnalysisStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(AnalysisStatus::Pending),
            "success" => Ok(AnalysisStatus::Success),
            "failed" => Ok(AnalysisStatus::Failed),
            "partial" => Ok(AnalysisStatus::Partial),
            _ => Err(format!("Unknown analysis status: {}", s)),
        }
    }
}

/// AgentContextAnalysis represents stored agent analysis for a chat session
#[derive(Debug, Clone, Queryable, Selectable, Identifiable, Serialize, Deserialize)]
#[diesel(table_name = agent_context_analysis)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct AgentContextAnalysis {
    pub id: Uuid,
    pub chat_session_id: Uuid,
    pub user_id: Uuid,
    pub analysis_type: String, // Will be converted to/from AnalysisType
    pub agent_reasoning: Option<String>, // Plaintext fallback (legacy)
    pub agent_reasoning_nonce: Option<Vec<u8>>,
    pub planned_searches: Option<JsonValue>,
    pub execution_log: Option<JsonValue>,
    pub execution_log_nonce: Option<Vec<u8>>,
    pub retrieved_context: Option<String>,
    pub retrieved_context_nonce: Option<Vec<u8>>,
    pub analysis_summary: Option<String>,
    pub analysis_summary_nonce: Option<Vec<u8>>,
    pub total_tokens_used: Option<i32>,
    pub execution_time_ms: Option<i32>,
    pub model_used: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub message_id: Uuid, // Link to specific message this analysis is for (REQUIRED)
    pub assistant_message_id: Option<Uuid>, // Link to assistant message (set after assistant responds)
    pub status: String, // Will be converted to/from AnalysisStatus
    pub error_message: Option<String>,
    pub retry_count: i32,
    pub superseded_at: Option<DateTime<Utc>>,
}

impl AgentContextAnalysis {
    /// Fetch active (non-superseded) agent analysis for a session and type
    pub fn get_for_session(
        conn: &mut PgConnection,
        session_id: Uuid,
        analysis_type: AnalysisType,
    ) -> Result<Option<Self>, AppError> {
        use crate::schema::agent_context_analysis::dsl;
        
        let analysis_type_str = analysis_type.to_string();
        
        // Only get non-superseded analyses
        dsl::agent_context_analysis
            .filter(dsl::chat_session_id.eq(session_id))
            .filter(dsl::analysis_type.eq(analysis_type_str))
            .filter(dsl::superseded_at.is_null())
            .first::<Self>(conn)
            .optional()
            .map_err(|e| AppError::DatabaseQueryError(format!("Failed to fetch agent analysis: {}", e)))
    }
    
    /// Get the analysis type as an enum
    pub fn get_analysis_type(&self) -> Result<AnalysisType, String> {
        self.analysis_type.parse()
    }
    
    /// Get the analysis status as an enum
    pub fn get_analysis_status(&self) -> Result<AnalysisStatus, String> {
        self.status.parse()
    }
    
    /// Mark failed/partial analyses as superseded for a session
    pub fn supersede_failed_analyses(
        conn: &mut PgConnection,
        session_id: Uuid,
        analysis_type: AnalysisType,
    ) -> Result<usize, AppError> {
        use crate::schema::agent_context_analysis::dsl;
        use diesel::prelude::*;
        
        let analysis_type_str = analysis_type.to_string();
        
        diesel::update(
            dsl::agent_context_analysis
                .filter(dsl::chat_session_id.eq(session_id))
                .filter(dsl::analysis_type.eq(analysis_type_str))
                .filter(dsl::superseded_at.is_null())
                .filter(
                    dsl::status.eq("failed")
                        .or(dsl::status.eq("partial"))
                        .or(dsl::status.eq("pending"))
                )
        )
        .set(dsl::superseded_at.eq(diesel::dsl::now))
        .execute(conn)
        .map_err(|e| AppError::DatabaseQueryError(
            format!("Failed to supersede failed analyses: {}", e)
        ))
    }
    
    /// Update the status of an analysis
    pub fn update_status(
        conn: &mut PgConnection,
        analysis_id: Uuid,
        status: AnalysisStatus,
        error_message: Option<String>,
    ) -> Result<(), AppError> {
        use crate::schema::agent_context_analysis::dsl;
        use diesel::prelude::*;
        
        let status_str = status.to_string();
        
        diesel::update(dsl::agent_context_analysis.find(analysis_id))
            .set((
                dsl::status.eq(status_str),
                dsl::error_message.eq(error_message),
                dsl::updated_at.eq(diesel::dsl::now),
            ))
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(
                format!("Failed to update analysis status: {}", e)
            ))?;
        
        Ok(())
    }

    /// Update the assistant_message_id for this analysis
    pub fn update_assistant_message_id(
        conn: &mut PgConnection,
        analysis_id: Uuid,
        assistant_message_id: Uuid,
    ) -> Result<(), AppError> {
        use crate::schema::agent_context_analysis::dsl;
        use diesel::prelude::*;
        
        diesel::update(dsl::agent_context_analysis.find(analysis_id))
            .set(dsl::assistant_message_id.eq(Some(assistant_message_id)))
            .execute(conn)
            .map_err(|e| AppError::DatabaseQueryError(
                format!("Failed to update assistant_message_id: {}", e)
            ))?;
        
        Ok(())
    }

    /// Get the decrypted agent reasoning using the provided DEK
    pub fn get_decrypted_reasoning(&self, dek: &SecretBox<Vec<u8>>) -> Result<String, AppError> {
        match (&self.agent_reasoning, &self.agent_reasoning_nonce) {
            (Some(encrypted), Some(nonce)) if !encrypted.is_empty() && encrypted != "ENCRYPTED" => {
                // Try to decode as encrypted data
                if let Ok(encrypted_bytes) = hex::decode(encrypted) {
                    let decrypted = crypto::decrypt_gcm(&encrypted_bytes, nonce, dek)
                        .map_err(|e| AppError::CryptoError(e.to_string()))?;
                    let decrypted_str = String::from_utf8(decrypted.expose_secret().clone())
                        .map_err(|e| AppError::CryptoError(format!("UTF-8 conversion failed: {}", e)))?;
                    Ok(decrypted_str)
                } else {
                    // Fallback to plaintext if not hex
                    Ok(encrypted.clone())
                }
            }
            (Some(plaintext), _) => {
                // Fallback to plaintext
                Ok(plaintext.clone())
            }
            _ => Ok(String::new()),
        }
    }

    /// Get the decrypted execution log using the provided DEK
    pub fn get_decrypted_execution_log(&self, dek: &SecretBox<Vec<u8>>) -> Result<JsonValue, AppError> {
        match (&self.execution_log, &self.execution_log_nonce) {
            (Some(log), Some(nonce)) if !nonce.is_empty() => {
                // Execution log is stored as JSON, but we need to decrypt it first
                if let Some(log_str) = log.as_str() {
                    if let Ok(encrypted_bytes) = hex::decode(log_str) {
                        let decrypted = crypto::decrypt_gcm(&encrypted_bytes, nonce, dek)
                            .map_err(|e| AppError::CryptoError(e.to_string()))?;
                        let decrypted_str = String::from_utf8(decrypted.expose_secret().clone())
                            .map_err(|e| AppError::CryptoError(format!("UTF-8 conversion failed: {}", e)))?;
                        let json_value = serde_json::from_str(&decrypted_str)?;
                        Ok(json_value)
                    } else {
                        // Already plaintext JSON
                        Ok(log.clone())
                    }
                } else {
                    // Already a JSON value
                    Ok(log.clone())
                }
            }
            (Some(log), _) => {
                // Fallback to plaintext JSON
                Ok(log.clone())
            }
            _ => Ok(JsonValue::Null),
        }
    }

    /// Get the decrypted retrieved context using the provided DEK
    pub fn get_decrypted_context(&self, dek: &SecretBox<Vec<u8>>) -> Result<String, AppError> {
        match (&self.retrieved_context, &self.retrieved_context_nonce) {
            (Some(encrypted), Some(nonce)) if !encrypted.is_empty() && encrypted != "ENCRYPTED" => {
                // Try to decode as encrypted data
                if let Ok(encrypted_bytes) = hex::decode(encrypted) {
                    let decrypted = crypto::decrypt_gcm(&encrypted_bytes, nonce, dek)
                        .map_err(|e| AppError::CryptoError(e.to_string()))?;
                    let decrypted_str = String::from_utf8(decrypted.expose_secret().clone())
                        .map_err(|e| AppError::CryptoError(format!("UTF-8 conversion failed: {}", e)))?;
                    Ok(decrypted_str)
                } else {
                    // Fallback to plaintext if not hex
                    Ok(encrypted.clone())
                }
            }
            (Some(plaintext), _) => {
                // Fallback to plaintext
                Ok(plaintext.clone())
            }
            _ => Ok(String::new()),
        }
    }

    /// Get the decrypted analysis summary using the provided DEK
    pub fn get_decrypted_summary(&self, dek: &SecretBox<Vec<u8>>) -> Result<String, AppError> {
        match (&self.analysis_summary, &self.analysis_summary_nonce) {
            (Some(encrypted), Some(nonce)) if !encrypted.is_empty() && encrypted != "ENCRYPTED" => {
                // Try to decode as encrypted data
                if let Ok(encrypted_bytes) = hex::decode(encrypted) {
                    let decrypted = crypto::decrypt_gcm(&encrypted_bytes, nonce, dek)
                        .map_err(|e| AppError::CryptoError(e.to_string()))?;
                    let decrypted_str = String::from_utf8(decrypted.expose_secret().clone())
                        .map_err(|e| AppError::CryptoError(format!("UTF-8 conversion failed: {}", e)))?;
                    Ok(decrypted_str)
                } else {
                    // Fallback to plaintext if not hex
                    Ok(encrypted.clone())
                }
            }
            (Some(plaintext), _) => {
                // Fallback to plaintext
                Ok(plaintext.clone())
            }
            _ => Ok(String::new()),
        }
    }
}

/// Insertable struct for creating new agent context analysis records
#[derive(Debug, Clone, Insertable, Serialize, Deserialize)]
#[diesel(table_name = agent_context_analysis)]
pub struct NewAgentContextAnalysis {
    pub chat_session_id: Uuid,
    pub user_id: Uuid,
    pub analysis_type: String,
    pub agent_reasoning: Option<String>,
    pub agent_reasoning_nonce: Option<Vec<u8>>,
    pub planned_searches: Option<JsonValue>,
    pub execution_log: Option<JsonValue>,
    pub execution_log_nonce: Option<Vec<u8>>,
    pub retrieved_context: Option<String>,
    pub retrieved_context_nonce: Option<Vec<u8>>,
    pub analysis_summary: Option<String>,
    pub analysis_summary_nonce: Option<Vec<u8>>,
    pub total_tokens_used: Option<i32>,
    pub execution_time_ms: Option<i32>,
    pub model_used: Option<String>,
    pub message_id: Uuid, // Link to specific message this analysis is for (REQUIRED)
    pub assistant_message_id: Option<Uuid>, // Link to assistant message (set after assistant responds)
    pub status: String,
    pub error_message: Option<String>,
    pub retry_count: i32,
    pub superseded_at: Option<DateTime<Utc>>,
}

impl NewAgentContextAnalysis {
    /// Create a new agent context analysis with encrypted fields
    pub fn new_encrypted(
        chat_session_id: Uuid,
        user_id: Uuid,
        analysis_type: AnalysisType,
        agent_reasoning: &str,
        planned_searches: &JsonValue,
        execution_log: &JsonValue,
        retrieved_context: &str,
        analysis_summary: &str,
        total_tokens_used: u32,
        execution_time_ms: u64,
        model_used: &str,
        dek: &SecretBox<Vec<u8>>,
        message_id: Uuid, // Required message ID to link analysis to specific message
    ) -> Result<Self, AppError> {
        // Encrypt sensitive text fields
        let (encrypted_reasoning, reasoning_nonce) = if !agent_reasoning.is_empty() {
            let (encrypted, nonce) = crypto::encrypt_gcm(agent_reasoning.as_bytes(), dek)
                .map_err(|e| AppError::CryptoError(format!("Failed to encrypt reasoning: {}", e)))?;
            (Some(hex::encode(encrypted)), Some(nonce))
        } else {
            (Some(String::new()), None)
        };

        let (encrypted_log, log_nonce) = {
            let log_str = serde_json::to_string(execution_log)?;
            if !log_str.is_empty() && log_str != "null" {
                let (encrypted, nonce) = crypto::encrypt_gcm(log_str.as_bytes(), dek)
                    .map_err(|e| AppError::CryptoError(format!("Failed to encrypt execution log: {}", e)))?;
                // Store encrypted data as a JSON string
                (Some(JsonValue::String(hex::encode(encrypted))), Some(nonce))
            } else {
                (Some(execution_log.clone()), None)
            }
        };

        let (encrypted_context, context_nonce) = if !retrieved_context.is_empty() {
            let (encrypted, nonce) = crypto::encrypt_gcm(retrieved_context.as_bytes(), dek)
                .map_err(|e| AppError::CryptoError(format!("Failed to encrypt context: {}", e)))?;
            (Some(hex::encode(encrypted)), Some(nonce))
        } else {
            (Some(String::new()), None)
        };

        let (encrypted_summary, summary_nonce) = if !analysis_summary.is_empty() {
            let (encrypted, nonce) = crypto::encrypt_gcm(analysis_summary.as_bytes(), dek)
                .map_err(|e| AppError::CryptoError(format!("Failed to encrypt summary: {}", e)))?;
            (Some(hex::encode(encrypted)), Some(nonce))
        } else {
            (Some(String::new()), None)
        };

        Ok(Self {
            chat_session_id,
            user_id,
            analysis_type: analysis_type.to_string(),
            agent_reasoning: encrypted_reasoning,
            agent_reasoning_nonce: reasoning_nonce,
            planned_searches: Some(planned_searches.clone()),
            execution_log: encrypted_log,
            execution_log_nonce: log_nonce,
            retrieved_context: encrypted_context,
            retrieved_context_nonce: context_nonce,
            analysis_summary: encrypted_summary,
            analysis_summary_nonce: summary_nonce,
            total_tokens_used: Some(total_tokens_used as i32),
            execution_time_ms: Some(execution_time_ms as i32),
            model_used: Some(model_used.to_string()),
            message_id,
            assistant_message_id: None, // Will be set later when assistant message is created
            status: AnalysisStatus::Success.to_string(), // Default to success for backward compatibility
            error_message: None,
            retry_count: 0,
            superseded_at: None,
        })
    }
}

/// Updateable struct for modifying existing agent context analysis records
#[derive(Debug, Clone, AsChangeset, Serialize, Deserialize)]
#[diesel(table_name = agent_context_analysis)]
pub struct UpdateAgentContextAnalysis {
    pub agent_reasoning: Option<String>,
    pub agent_reasoning_nonce: Option<Vec<u8>>,
    pub planned_searches: Option<JsonValue>,
    pub execution_log: Option<JsonValue>,
    pub execution_log_nonce: Option<Vec<u8>>,
    pub retrieved_context: Option<String>,
    pub retrieved_context_nonce: Option<Vec<u8>>,
    pub analysis_summary: Option<String>,
    pub analysis_summary_nonce: Option<Vec<u8>>,
    pub total_tokens_used: Option<i32>,
    pub execution_time_ms: Option<i32>,
    pub model_used: Option<String>,
    pub updated_at: Option<DateTime<Utc>>,
    pub assistant_message_id: Option<Option<Uuid>>, // Option<Option> to allow setting NULL or a value
    pub status: Option<String>,
    pub error_message: Option<Option<String>>, // Option<Option> to allow setting NULL or a value
    pub retry_count: Option<i32>,
    pub superseded_at: Option<Option<DateTime<Utc>>>, // Option<Option> to allow setting NULL or a value
}