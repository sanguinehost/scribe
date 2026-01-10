use super::utils::{
    extract_bool_from_payload, extract_optional_string_from_payload, extract_string_from_payload,
    extract_string_list_from_payload, extract_uuid_from_payload,
};
use crate::db::DbId;
use crate::errors::AppError;
use qdrant_client::qdrant::Value as QdrantValue;
use std::collections::HashMap;

// Metadata for chat message chunks
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct ChatMessageChunkMetadata {
    pub message_id: crate::db::DbId,
    pub session_id: crate::db::DbId,
    pub chronicle_id: Option<crate::db::DbId>, // Added for chronicle-scoped search
    pub user_id: crate::db::DbId,              // Added user_id
    pub speaker: String,
    pub timestamp: crate::DbTimestamp,
    #[deprecated(note = "Use encrypted_text instead for security")]
    pub text: String, // Full text of the chunk (DEPRECATED - use encrypted_text)
    pub source_type: String,
    // Encrypted fields for secure storage
    pub encrypted_text: Option<Vec<u8>>, // Encrypted text content
    pub text_nonce: Option<Vec<u8>>,     // Nonce for decrypting text
    pub game_time: Option<serde_json::Value>, // Game time metadata
}
impl TryFrom<HashMap<String, QdrantValue>> for ChatMessageChunkMetadata {
    type Error = AppError;

    #[allow(deprecated)]
    fn try_from(payload: HashMap<String, QdrantValue>) -> Result<Self, Self::Error> {
        let message_id =
            extract_uuid_from_payload(&payload, "message_id", "ChatMessageChunkMetadata")?;
        let session_id =
            extract_uuid_from_payload(&payload, "session_id", "ChatMessageChunkMetadata")?;
        let chronicle_id = payload
            .get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| DbId::parse_str(s).ok());
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

        // Try to get encrypted fields first, fall back to plaintext for backward compatibility
        let (text, encrypted_text, text_nonce) = if let Some(enc_text) =
            payload.get("encrypted_text")
        {
            // We have encrypted content
            let encrypted_bytes = enc_text.as_list().and_then(|list| {
                let bytes: Option<Vec<u8>> = list
                    .iter()
                    .map(|v| v.as_integer().map(|i| i as u8))
                    .collect();
                bytes
            });

            let nonce_bytes = payload
                .get("text_nonce")
                .and_then(|v| v.as_list())
                .and_then(|list| {
                    let bytes: Option<Vec<u8>> = list
                        .iter()
                        .map(|v| v.as_integer().map(|i| i as u8))
                        .collect();
                    bytes
                });

            // If we have encrypted content, we still need a text field for backward compat
            // Use placeholder text
            let text = extract_string_from_payload(&payload, "text", "ChatMessageChunkMetadata")
                .unwrap_or_else(|_| "[encrypted]".to_string());

            (text, encrypted_bytes, nonce_bytes)
        } else {
            // SECURITY: All chat messages must be encrypted - no plaintext mode allowed
            tracing::warn!("SECURITY VIOLATION: Chat message payload missing encrypted_text field");
            ("[MISSING ENCRYPTION]".to_string(), None, None)
        };

        let source_type =
            extract_string_from_payload(&payload, "source_type", "ChatMessageChunkMetadata")?;

        let game_time = extract_optional_string_from_payload(&payload, "game_time")
            .and_then(|s| serde_json::from_str(&s).ok());

        Ok(Self {
            message_id,
            session_id,
            chronicle_id: chronicle_id.map(|id| id.into()),
            user_id, // Added user_id
            speaker,
            timestamp: timestamp.into(),
            text,
            source_type,
            encrypted_text,
            text_nonce,
            game_time,
        })
    }
}
// Metadata for lorebook entry chunks
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct LorebookChunkMetadata {
    pub original_lorebook_entry_id: crate::db::DbId,
    pub lorebook_id: crate::db::DbId,
    pub user_id: crate::db::DbId,
    #[deprecated(note = "Use encrypted_chunk_text instead for security")]
    pub chunk_text: String, // Full text of the chunk (DEPRECATED - use encrypted_chunk_text)
    pub entry_title: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub is_enabled: bool,
    pub is_constant: bool,
    pub source_type: String,
    // Encrypted fields for secure storage
    pub encrypted_chunk_text: Option<Vec<u8>>, // Encrypted chunk content
    pub chunk_text_nonce: Option<Vec<u8>>,     // Nonce for decrypting chunk
    pub encrypted_title: Option<Vec<u8>>,      // Encrypted title
    pub title_nonce: Option<Vec<u8>>,          // Nonce for decrypting title
}
impl TryFrom<HashMap<String, QdrantValue>> for LorebookChunkMetadata {
    type Error = AppError;

    #[allow(deprecated)]
    fn try_from(payload: HashMap<String, QdrantValue>) -> Result<Self, Self::Error> {
        let original_lorebook_entry_id = extract_uuid_from_payload(
            &payload,
            "original_lorebook_entry_id",
            "LorebookChunkMetadata",
        )?;
        let lorebook_id =
            extract_uuid_from_payload(&payload, "lorebook_id", "LorebookChunkMetadata")?;
        let user_id = extract_uuid_from_payload(&payload, "user_id", "LorebookChunkMetadata")?;

        // Try to get encrypted fields first, fall back to plaintext for backward compatibility
        let (chunk_text, encrypted_chunk_text, chunk_text_nonce) =
            if let Some(enc_text) = payload.get("encrypted_chunk_text") {
                // We have encrypted content
                let encrypted_bytes = enc_text.as_list().and_then(|list| {
                    let bytes: Option<Vec<u8>> = list
                        .iter()
                        .map(|v| v.as_integer().map(|i| i as u8))
                        .collect();
                    bytes
                });

                let nonce_bytes = payload
                    .get("chunk_text_nonce")
                    .and_then(|v| v.as_list())
                    .and_then(|list| {
                        let bytes: Option<Vec<u8>> = list
                            .iter()
                            .map(|v| v.as_integer().map(|i| i as u8))
                            .collect();
                        bytes
                    });

                // If we have encrypted content, still need chunk_text for backward compat
                // Encrypted content available - use placeholder for deprecated field
                let chunk_text = "[encrypted]".to_string();
                (chunk_text, encrypted_bytes, nonce_bytes)
            } else {
                // SECURITY: All lorebook content must be encrypted - no plaintext mode allowed
                tracing::warn!(
                    "SECURITY VIOLATION: Lorebook chunk payload missing encrypted_chunk_text field"
                );
                ("[MISSING ENCRYPTION]".to_string(), None, None)
            };

        // Handle encrypted title
        let (entry_title, encrypted_title, title_nonce) =
            if let Some(enc_title) = payload.get("encrypted_title") {
                let encrypted_bytes = enc_title.as_list().and_then(|list| {
                    let bytes: Option<Vec<u8>> = list
                        .iter()
                        .map(|v| v.as_integer().map(|i| i as u8))
                        .collect();
                    bytes
                });

                let nonce_bytes = payload
                    .get("title_nonce")
                    .and_then(|v| v.as_list())
                    .and_then(|list| {
                        let bytes: Option<Vec<u8>> = list
                            .iter()
                            .map(|v| v.as_integer().map(|i| i as u8))
                            .collect();
                        bytes
                    });

                let entry_title = extract_optional_string_from_payload(&payload, "entry_title");
                (entry_title, encrypted_bytes, nonce_bytes)
            } else {
                // SECURITY: Titles should also be encrypted - warn if missing
                tracing::warn!("Lorebook entry title not encrypted (may be legacy data)");
                let entry_title = extract_optional_string_from_payload(&payload, "entry_title");
                (entry_title, None, None)
            };

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
            encrypted_chunk_text,
            chunk_text_nonce,
            encrypted_title,
            title_nonce,
        })
    }
}
/// Parameters for processing a lorebook entry
#[derive(Debug)]
pub struct LorebookEntryParams {
    pub original_lorebook_entry_id: crate::db::DbId,
    pub lorebook_id: crate::db::DbId,
    pub user_id: crate::db::DbId,
    pub decrypted_content: String,
    pub decrypted_title: Option<String>,
    pub decrypted_keywords: Option<Vec<String>>,
    pub is_enabled: bool,
    pub is_constant: bool,
    /// SessionDek for encrypting content before storing in Qdrant
    pub session_dek: Option<secrecy::SecretBox<Vec<u8>>>,
}

impl Clone for LorebookEntryParams {
    fn clone(&self) -> Self {
        Self {
            original_lorebook_entry_id: self.original_lorebook_entry_id,
            lorebook_id: self.lorebook_id,
            user_id: self.user_id,
            decrypted_content: self.decrypted_content.clone(),
            decrypted_title: self.decrypted_title.clone(),
            decrypted_keywords: self.decrypted_keywords.clone(),
            is_enabled: self.is_enabled,
            is_constant: self.is_constant,
            session_dek: self.session_dek.as_ref().map(|dek| {
                let dek_bytes = secrecy::ExposeSecret::expose_secret(dek).clone();
                secrecy::SecretBox::new(Box::new(dek_bytes))
            }),
        }
    }
}
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct EntityMetadata {
    pub user_id: crate::db::DbId,
    pub entity_name_hash: String,
    pub source_type: String,
}

impl TryFrom<HashMap<String, QdrantValue>> for EntityMetadata {
    type Error = AppError;

    fn try_from(payload: HashMap<String, QdrantValue>) -> Result<Self, Self::Error> {
        let user_id = extract_uuid_from_payload(&payload, "user_id", "EntityMetadata")?;
        let entity_name_hash =
            extract_string_from_payload(&payload, "entity_name_hash", "EntityMetadata")?;
        let source_type = extract_string_from_payload(&payload, "source_type", "EntityMetadata")?;

        Ok(Self {
            user_id,
            entity_name_hash,
            source_type,
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct OpinionMetadata {
    pub user_id: crate::db::DbId,
    pub opinion_id: crate::db::DbId,
    pub source_type: String,
}

impl TryFrom<HashMap<String, QdrantValue>> for OpinionMetadata {
    type Error = AppError;

    fn try_from(payload: HashMap<String, QdrantValue>) -> Result<Self, Self::Error> {
        let user_id = extract_uuid_from_payload(&payload, "user_id", "OpinionMetadata")?;
        let opinion_id = extract_uuid_from_payload(&payload, "opinion_id", "OpinionMetadata")?;
        let source_type = extract_string_from_payload(&payload, "source_type", "OpinionMetadata")?;

        Ok(Self {
            user_id,
            opinion_id,
            source_type,
        })
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct CognitiveFactMetadata {
    pub user_id: crate::db::DbId,
    pub fact_id: crate::db::DbId,
    pub chronicle_id: crate::db::DbId,
    pub source_type: String,
}

impl TryFrom<HashMap<String, QdrantValue>> for CognitiveFactMetadata {
    type Error = AppError;

    fn try_from(payload: HashMap<String, QdrantValue>) -> Result<Self, Self::Error> {
        let user_id = extract_uuid_from_payload(&payload, "user_id", "CognitiveFactMetadata")?;
        let fact_id = extract_uuid_from_payload(&payload, "fact_id", "CognitiveFactMetadata")?;
        let chronicle_id =
            extract_uuid_from_payload(&payload, "chronicle_id", "CognitiveFactMetadata")?;
        let source_type =
            extract_string_from_payload(&payload, "source_type", "CognitiveFactMetadata")?;

        Ok(Self {
            user_id,
            fact_id,
            chronicle_id,
            source_type,
        })
    }
}
