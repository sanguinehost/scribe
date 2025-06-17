use super::utils::{
    extract_bool_from_payload, extract_optional_string_from_payload, extract_string_from_payload,
    extract_string_list_from_payload, extract_uuid_from_payload,
};
use crate::errors::AppError;
use qdrant_client::qdrant::Value as QdrantValue;
use std::collections::HashMap;
use uuid::Uuid;

// Metadata for chat message chunks
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ChatMessageChunkMetadata {
    pub message_id: Uuid,
    pub session_id: Uuid,
    pub user_id: Uuid, // Added user_id
    pub speaker: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub text: String, // Full text of the chunk
    pub source_type: String,
}
impl TryFrom<HashMap<String, QdrantValue>> for ChatMessageChunkMetadata {
    type Error = AppError;

    fn try_from(payload: HashMap<String, QdrantValue>) -> Result<Self, Self::Error> {
        let message_id =
            extract_uuid_from_payload(&payload, "message_id", "ChatMessageChunkMetadata")?;
        let session_id =
            extract_uuid_from_payload(&payload, "session_id", "ChatMessageChunkMetadata")?;
        let user_id = extract_uuid_from_payload(&payload, "user_id", "ChatMessageChunkMetadata")?;

        let speaker = extract_string_from_payload(&payload, "speaker", "ChatMessageChunkMetadata")?;
        let timestamp_str =
            extract_string_from_payload(&payload, "timestamp", "ChatMessageChunkMetadata")?;
        let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
            .map_err(|e| {
                AppError::SerializationError(format!(
                    "Failed to parse 'timestamp' in ChatMessageChunkMetadata: {e}"
                ))
            })
            .map(|dt| dt.with_timezone(&chrono::Utc))?;

        let text = extract_string_from_payload(&payload, "text", "ChatMessageChunkMetadata")?;
        let source_type =
            extract_string_from_payload(&payload, "source_type", "ChatMessageChunkMetadata")?;

        Ok(Self {
            message_id,
            session_id,
            user_id, // Added user_id
            speaker,
            timestamp,
            text,
            source_type,
        })
    }
}
// Metadata for lorebook entry chunks
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct LorebookChunkMetadata {
    pub original_lorebook_entry_id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
    pub chunk_text: String, // Full text of the chunk
    pub entry_title: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub is_enabled: bool,
    pub is_constant: bool,
    pub source_type: String,
}
impl TryFrom<HashMap<String, QdrantValue>> for LorebookChunkMetadata {
    type Error = AppError;

    fn try_from(payload: HashMap<String, QdrantValue>) -> Result<Self, Self::Error> {
        let original_lorebook_entry_id = extract_uuid_from_payload(
            &payload,
            "original_lorebook_entry_id",
            "LorebookChunkMetadata",
        )?;
        let lorebook_id =
            extract_uuid_from_payload(&payload, "lorebook_id", "LorebookChunkMetadata")?;
        let user_id = extract_uuid_from_payload(&payload, "user_id", "LorebookChunkMetadata")?;

        let chunk_text =
            extract_string_from_payload(&payload, "chunk_text", "LorebookChunkMetadata")?;
        let entry_title = extract_optional_string_from_payload(&payload, "entry_title");
        let keywords =
            extract_string_list_from_payload(&payload, "keywords", "LorebookChunkMetadata")?;

        let is_enabled =
            extract_bool_from_payload(&payload, "is_enabled", "LorebookChunkMetadata")?;
        let is_constant =
            extract_bool_from_payload(&payload, "is_constant", "LorebookChunkMetadata")?;
        let source_type =
            extract_string_from_payload(&payload, "source_type", "LorebookChunkMetadata")?;

        Ok(Self {
            original_lorebook_entry_id,
            lorebook_id,
            user_id,
            chunk_text,
            entry_title,
            keywords,
            is_enabled,
            is_constant,
            source_type,
        })
    }
}
/// Parameters for processing a lorebook entry
#[derive(Debug, Clone)]
pub struct LorebookEntryParams {
    pub original_lorebook_entry_id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
    pub decrypted_content: String,
    pub decrypted_title: Option<String>,
    pub decrypted_keywords: Option<Vec<String>>,
    pub is_enabled: bool,
    pub is_constant: bool,
}
