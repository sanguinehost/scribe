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
    pub chronicle_id: Option<Uuid>, // Added for chronicle-scoped search
    pub user_id: Uuid, // Added user_id
    pub speaker: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    #[deprecated(note = "Use encrypted_text instead for security")]
    pub text: String, // Full text of the chunk (DEPRECATED - use encrypted_text)
    pub source_type: String,
    // Encrypted fields for secure storage
    pub encrypted_text: Option<Vec<u8>>, // Encrypted text content
    pub text_nonce: Option<Vec<u8>>, // Nonce for decrypting text
}
impl TryFrom<HashMap<String, QdrantValue>> for ChatMessageChunkMetadata {
    type Error = AppError;

    fn try_from(payload: HashMap<String, QdrantValue>) -> Result<Self, Self::Error> {
        let message_id =
            extract_uuid_from_payload(&payload, "message_id", "ChatMessageChunkMetadata")?;
        let session_id =
            extract_uuid_from_payload(&payload, "session_id", "ChatMessageChunkMetadata")?;
        let chronicle_id = payload.get("chronicle_id")
            .and_then(|v| v.as_str())
            .and_then(|s| Uuid::parse_str(s).ok());
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
        let (text, encrypted_text, text_nonce) = if let Some(enc_text) = payload.get("encrypted_text") {
            // We have encrypted content
            let encrypted_bytes = enc_text.as_list()
                .and_then(|list| {
                    let bytes: Option<Vec<u8>> = list.iter()
                        .map(|v| v.as_integer().map(|i| i as u8))
                        .collect();
                    bytes
                });
            
            let nonce_bytes = payload.get("text_nonce")
                .and_then(|v| v.as_list())
                .and_then(|list| {
                    let bytes: Option<Vec<u8>> = list.iter()
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
            // Legacy plaintext mode
            let text = extract_string_from_payload(&payload, "text", "ChatMessageChunkMetadata")?;
            (text, None, None)
        };
        
        let source_type =
            extract_string_from_payload(&payload, "source_type", "ChatMessageChunkMetadata")?;

        Ok(Self {
            message_id,
            session_id,
            chronicle_id,
            user_id, // Added user_id
            speaker,
            timestamp,
            text,
            source_type,
            encrypted_text,
            text_nonce,
        })
    }
}
// Metadata for lorebook entry chunks
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct LorebookChunkMetadata {
    pub original_lorebook_entry_id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
    #[deprecated(note = "Use encrypted_chunk_text instead for security")]
    pub chunk_text: String, // Full text of the chunk (DEPRECATED - use encrypted_chunk_text)
    pub entry_title: Option<String>,
    pub keywords: Option<Vec<String>>,
    pub is_enabled: bool,
    pub is_constant: bool,
    pub source_type: String,
    // Encrypted fields for secure storage
    pub encrypted_chunk_text: Option<Vec<u8>>, // Encrypted chunk content
    pub chunk_text_nonce: Option<Vec<u8>>, // Nonce for decrypting chunk
    pub encrypted_title: Option<Vec<u8>>, // Encrypted title
    pub title_nonce: Option<Vec<u8>>, // Nonce for decrypting title
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

        // Try to get encrypted fields first, fall back to plaintext for backward compatibility
        let (chunk_text, encrypted_chunk_text, chunk_text_nonce) = 
            if let Some(enc_text) = payload.get("encrypted_chunk_text") {
                // We have encrypted content
                let encrypted_bytes = enc_text.as_list()
                    .and_then(|list| {
                        let bytes: Option<Vec<u8>> = list.iter()
                            .map(|v| v.as_integer().map(|i| i as u8))
                            .collect();
                        bytes
                    });
                
                let nonce_bytes = payload.get("chunk_text_nonce")
                    .and_then(|v| v.as_list())
                    .and_then(|list| {
                        let bytes: Option<Vec<u8>> = list.iter()
                            .map(|v| v.as_integer().map(|i| i as u8))
                            .collect();
                        bytes
                    });
                
                // If we have encrypted content, still need chunk_text for backward compat
                let chunk_text = extract_string_from_payload(&payload, "chunk_text", "LorebookChunkMetadata")
                    .unwrap_or_else(|_| "[encrypted]".to_string());
                
                (chunk_text, encrypted_bytes, nonce_bytes)
            } else {
                // Legacy plaintext mode
                let chunk_text =
                    extract_string_from_payload(&payload, "chunk_text", "LorebookChunkMetadata")?;
                (chunk_text, None, None)
            };
        
        // Handle encrypted title
        let (entry_title, encrypted_title, title_nonce) = 
            if let Some(enc_title) = payload.get("encrypted_title") {
                let encrypted_bytes = enc_title.as_list()
                    .and_then(|list| {
                        let bytes: Option<Vec<u8>> = list.iter()
                            .map(|v| v.as_integer().map(|i| i as u8))
                            .collect();
                        bytes
                    });
                
                let nonce_bytes = payload.get("title_nonce")
                    .and_then(|v| v.as_list())
                    .and_then(|list| {
                        let bytes: Option<Vec<u8>> = list.iter()
                            .map(|v| v.as_integer().map(|i| i as u8))
                            .collect();
                        bytes
                    });
                
                let entry_title = extract_optional_string_from_payload(&payload, "entry_title");
                (entry_title, encrypted_bytes, nonce_bytes)
            } else {
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
    pub original_lorebook_entry_id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
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
