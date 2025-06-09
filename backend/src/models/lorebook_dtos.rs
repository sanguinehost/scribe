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

// Enhanced version with source information
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum LorebookAssociationSource {
    Chat,      // Directly associated with this chat session
    Character, // Associated via the character used in this chat
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EnhancedChatSessionLorebookAssociationResponse {
    pub chat_session_id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
    pub lorebook_name: String,
    pub source: LorebookAssociationSource,
    pub is_overridden: bool, // Whether this character lorebook has been disabled/enabled via override
    pub override_action: Option<String>, // "disable" or "enable" if overridden
    pub created_at: DateTime<Utc>, // Association creation time (chat or character association)
}

// Union type for responses
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ChatLorebookAssociationsResponse {
    Basic(Vec<ChatSessionLorebookAssociationResponse>),
    Enhanced(Vec<EnhancedChatSessionLorebookAssociationResponse>),
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
    #[serde(alias = "keys")]
    pub key: Option<Vec<String>>, // Keywords/triggers, can be null in some ST exports
    pub content: String,         // Entry content
    pub comment: Option<String>, // Optional comment
    pub disable: Option<bool>,   // true means disabled (will invert to is_enabled)
    pub enabled: Option<bool>,   // true means enabled (alternative to disable field)
    pub constant: Option<bool>,  // Maps to is_constant
    #[serde(alias = "insertion_order")]
    pub order: Option<i32>, // Maps to insertion_order
    #[serde(deserialize_with = "deserialize_position")]
    pub position: Option<i32>, // 0=before prompt, 1=after prompt
    pub uid: Option<i32>,        // Original SillyTavern UID
    #[serde(default, alias = "id")]
    pub id: Option<i32>, // Alternative to uid for some exports
    #[serde(default, alias = "displayName")] // Added alias for compatibility
    pub display_name: Option<String>, // Field for SillyTavern entry title

    // Additional SillyTavern fields that we'll ignore but need for deserialization
    #[serde(default)]
    pub keysecondary: Option<Vec<String>>,
    #[serde(default)]
    pub selective: Option<bool>,
    #[serde(default, rename = "displayIndex")]
    pub display_index: Option<i32>,
    #[serde(default, rename = "addMemo")]
    pub add_memo: Option<bool>,
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default, rename = "groupOverride")]
    pub group_override: Option<bool>,
    #[serde(default, rename = "groupWeight")]
    pub group_weight: Option<i32>,
    #[serde(default)]
    pub sticky: Option<i32>,
    #[serde(default)]
    pub cooldown: Option<i32>,
    #[serde(default)]
    pub delay: Option<i32>,
    #[serde(default)]
    pub probability: Option<i32>,
    #[serde(default)]
    pub depth: Option<i32>,
    #[serde(default, rename = "useProbability")]
    pub use_probability: Option<bool>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub vectorized: Option<bool>,
    #[serde(default, rename = "excludeRecursion")]
    pub exclude_recursion: Option<bool>,
    #[serde(default, rename = "preventRecursion")]
    pub prevent_recursion: Option<bool>,
    #[serde(default, rename = "delayUntilRecursion")]
    pub delay_until_recursion: Option<bool>,
    #[serde(default, rename = "scanDepth")]
    pub scan_depth: Option<i32>,
    #[serde(default, rename = "caseSensitive")]
    pub case_sensitive: Option<bool>,
    #[serde(default, rename = "matchWholeWords")]
    pub match_whole_words: Option<bool>,
    #[serde(default, rename = "useGroupScoring")]
    pub use_group_scoring: Option<bool>,
    #[serde(default, rename = "automationId")]
    pub automation_id: Option<String>,
    #[serde(default, rename = "matchPersonaDescription")]
    pub match_persona_description: Option<bool>,
    #[serde(default, rename = "matchCharacterDescription")]
    pub match_character_description: Option<bool>,
    #[serde(default, rename = "matchCharacterPersonality")]
    pub match_character_personality: Option<bool>,
    #[serde(default, rename = "matchCharacterDepthPrompt")]
    pub match_character_depth_prompt: Option<bool>,
    #[serde(default, rename = "matchScenario")]
    pub match_scenario: Option<bool>,
    #[serde(default, rename = "matchCreatorNotes")]
    pub match_creator_notes: Option<bool>,
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

// New DTO for SillyTavern import, which often lacks top-level metadata
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SillyTavernImportPayload {
    pub entries: HashMap<String, UploadedLorebookEntry>,
    // Optional metadata that might be present in some full exports, but not always
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub is_public: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LorebookWithEntriesResponse {
    pub lorebook: LorebookResponse,
    pub entries: Vec<LorebookEntryResponse>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportedLorebookEntry {
    pub uid: i32,
    pub key: Vec<String>,
    #[serde(default)]
    pub keysecondary: Vec<String>, // Not used by Scribe but included for compatibility
    pub comment: String,
    pub content: String,
    pub disable: bool,
    pub constant: bool,
    pub order: i32,
    pub position: i32,
    #[serde(default)]
    pub selective: bool, // Not used by Scribe but included for compatibility
    #[serde(default, rename = "displayIndex")]
    pub display_index: i32,
    #[serde(default, rename = "addMemo")]
    pub add_memo: bool,
    #[serde(default)]
    pub group: String,
    #[serde(default, rename = "groupOverride")]
    pub group_override: bool,
    #[serde(default, rename = "groupWeight")]
    pub group_weight: i32,
    #[serde(default)]
    pub sticky: i32,
    #[serde(default)]
    pub cooldown: i32,
    #[serde(default)]
    pub delay: i32,
    #[serde(default)]
    pub probability: i32,
    #[serde(default)]
    pub depth: i32,
    #[serde(default, rename = "useProbability")]
    pub use_probability: bool,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub vectorized: bool,
    #[serde(default, rename = "excludeRecursion")]
    pub exclude_recursion: bool,
    #[serde(default, rename = "preventRecursion")]
    pub prevent_recursion: bool,
    #[serde(default, rename = "delayUntilRecursion")]
    pub delay_until_recursion: bool,
    #[serde(default, rename = "scanDepth")]
    pub scan_depth: Option<i32>,
    #[serde(default, rename = "caseSensitive")]
    pub case_sensitive: Option<bool>,
    #[serde(default, rename = "matchWholeWords")]
    pub match_whole_words: Option<bool>,
    #[serde(default, rename = "useGroupScoring")]
    pub use_group_scoring: Option<bool>,
    #[serde(default, rename = "automationId")]
    pub automation_id: String,
    #[serde(default, rename = "matchPersonaDescription")]
    pub match_persona_description: bool,
    #[serde(default, rename = "matchCharacterDescription")]
    pub match_character_description: bool,
    #[serde(default, rename = "matchCharacterPersonality")]
    pub match_character_personality: bool,
    #[serde(default, rename = "matchCharacterDepthPrompt")]
    pub match_character_depth_prompt: bool,
    #[serde(default, rename = "matchScenario")]
    pub match_scenario: bool,
    #[serde(default, rename = "matchCreatorNotes")]
    pub match_creator_notes: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ExportedLorebook {
    pub entries: HashMap<String, ExportedLorebookEntry>,
    // Optional metadata that can be added for full SillyTavern compatibility
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// Minimal Scribe format for RAG-based systems
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScribeMinimalLorebookEntry {
    pub title: String,
    pub keywords: Vec<String>,
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScribeMinimalLorebook {
    pub name: String,
    pub description: Option<String>,
    pub entries: Vec<ScribeMinimalLorebookEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExportFormat {
    ScribeMinimal,
    SillyTavernFull,
}

// Custom deserializer for position field that handles both string and integer formats
fn deserialize_position<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error, Unexpected};
    use serde_json::Value;

    let value = Value::deserialize(deserializer)?;

    match value {
        Value::Null => Ok(None),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Some(i as i32))
            } else {
                Err(Error::invalid_type(
                    Unexpected::Float(n.as_f64().unwrap_or(0.0)),
                    &"integer",
                ))
            }
        }
        Value::String(s) => {
            match s.as_str() {
                "before_char" | "before_prompt" => Ok(Some(0)),
                "after_char" | "after_prompt" => Ok(Some(1)),
                _ => {
                    // Try to parse as integer
                    s.parse::<i32>().map(Some).map_err(|_| {
                        Error::invalid_value(Unexpected::Str(&s), &"integer, 'before_char', 'after_char', 'before_prompt', or 'after_prompt'")
                    })
                }
            }
        }
        _ => Err(Error::invalid_type(
            Unexpected::Other(&value.to_string()),
            &"integer or string",
        )),
    }
}

// --- Lorebook Override DTOs ---

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SetCharacterLorebookOverridePayload {
    pub action: String, // "disable" or "enable"
}

// Manual validation for SetCharacterLorebookOverridePayload
impl SetCharacterLorebookOverridePayload {
    pub fn validate(&self) -> Result<(), validator::ValidationErrors> {
        let mut errors = validator::ValidationErrors::new();

        if !matches!(self.action.as_str(), "disable" | "enable") {
            let mut error = validator::ValidationError::new("invalid_action");
            error.message = Some("Action must be 'disable' or 'enable'".into());
            errors.add("action", error);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CharacterLorebookOverrideResponse {
    pub id: Uuid,
    pub chat_session_id: Uuid,
    pub lorebook_id: Uuid,
    pub user_id: Uuid,
    pub action: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
