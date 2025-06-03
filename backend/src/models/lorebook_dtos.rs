use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use validator::Validate;

// --- Lorebook DTOs ---

#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct CreateLorebookPayload {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    #[validate(length(max = 10000))]
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct UpdateLorebookPayload {
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    #[validate(length(max = 10000))]
    pub description: Option<String>,
    // Add other updatable fields like is_public if needed in the future
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LorebookResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub source_format: String, // e.g., "sillytavern_v1", "scribe_v1"
    pub is_public: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// --- Lorebook Entry DTOs ---

#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct CreateLorebookEntryPayload {
    #[validate(length(min = 1, max = 255))]
    pub entry_title: String,
    #[validate(length(max = 10000))]
    pub keys_text: Option<String>, // Concatenated keywords
    #[validate(length(min = 1, max = 65535))] // Max TEXT size in some DBs, adjust if needed
    pub content: String,
    #[validate(length(max = 10000))]
    pub comment: Option<String>,
    pub is_enabled: Option<bool>,     // Defaults to true in service
    pub is_constant: Option<bool>,    // Defaults to false in service
    pub insertion_order: Option<i32>, // Defaults to 100 in service
    #[validate(length(max = 50))]
    pub placement_hint: Option<String>, // e.g., "before_prompt", "after_prompt"
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone, Default, PartialEq, Eq)]
pub struct UpdateLorebookEntryPayload {
    #[validate(length(min = 1, max = 255))]
    pub entry_title: Option<String>,
    #[validate(length(max = 10000))]
    pub keys_text: Option<String>,
    #[validate(length(min = 1, max = 65535))]
    pub content: Option<String>,
    #[validate(length(max = 10000))]
    pub comment: Option<String>,
    pub is_enabled: Option<bool>,
    pub is_constant: Option<bool>,
    pub insertion_order: Option<i32>,
    #[validate(length(max = 50))]
    pub placement_hint: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LorebookEntryResponse {
    pub id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
    pub entry_title: String,
    pub keys_text: Option<String>,
    pub content: String, // Decrypted content
    pub comment: Option<String>,
    pub is_enabled: bool,
    pub is_constant: bool,
    pub insertion_order: i32,
    pub placement_hint: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// --- Chat Session Lorebook Association DTOs ---

#[derive(Debug, Serialize, Deserialize, Clone)] // Removed Validate from derive
pub struct AssociateLorebookToChatPayload {
    // #[validate] // Removed validation from Uuid field
    pub lorebook_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatSessionLorebookAssociationResponse {
    pub chat_session_id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
    pub lorebook_name: String, // For better UX, requires join or extra query
    pub created_at: DateTime<Utc>, // Assuming this comes from the association table
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatSessionBasicInfo {
    pub chat_session_id: Uuid,
    pub title: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LorebookEntrySummaryResponse {
    pub id: Uuid,
    pub lorebook_id: Uuid,
    pub entry_title: String, // Decrypted title
    pub is_enabled: bool,
    pub is_constant: bool,
    pub insertion_order: i32,
    pub updated_at: DateTime<Utc>,
}

// --- Import/Export DTOs ---

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UploadedLorebookEntry {
    pub key: Vec<String>,         // Keywords/triggers
    pub content: String,          // Entry content
    pub comment: Option<String>,  // Optional comment
    pub disable: Option<bool>,    // true means disabled (will invert to is_enabled)
    pub constant: Option<bool>,   // Maps to is_constant
    pub order: Option<i32>,       // Maps to insertion_order
    pub position: Option<i32>,    // 0=before prompt, 1=after prompt
    pub uid: Option<i32>,         // Original SillyTavern UID
}

#[derive(Debug, Serialize, Deserialize, Validate, Clone)]
pub struct LorebookUploadPayload {
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    #[validate(length(max = 10000))]
    pub description: Option<String>,
    pub is_public: bool,
    pub entries: HashMap<String, UploadedLorebookEntry>, // Keyed by original uid
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LorebookWithEntriesResponse {
    pub lorebook: LorebookResponse,
    pub entries: Vec<LorebookEntryResponse>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportedLorebookEntry {
    pub key: Vec<String>,
    pub content: String,
    pub comment: String,
    pub disable: bool,
    pub constant: bool,
    pub order: i32,
    pub position: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportedLorebook {
    pub entries: HashMap<String, ExportedLorebookEntry>,
}
