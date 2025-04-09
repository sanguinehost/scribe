use serde::{Deserialize, Serialize};
use serde_json::Value; // Using Value for flexibility in extensions and mixed types like id
use std::collections::HashMap;

// Main Character Card Structure (V3)
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CharacterCardV3 {
    #[serde(default)] // Use default for spec fields if missing in JSON
    pub spec: String,
    #[serde(default)]
    pub spec_version: String,
    #[serde(default)] // Uses Default impl of CharacterCardDataV3
    pub data: CharacterCardDataV3,
}

// Character Card Data Payload (V3)
#[derive(Serialize, Deserialize, Debug, Clone, Default)] // Add Default back
#[serde(rename_all = "snake_case")]
pub struct CharacterCardDataV3 {
    // --- Fields from V2 (or with V2 counterparts) ---
    // Sticking to the TS interface provided in the spec initially
    pub name: Option<String>, // Made optional for robustness with V2/missing fields
    #[serde(default)] // Use default empty string if missing
    pub description: String,
    #[serde(default)]
    pub personality: String,
    #[serde(default)]
    pub scenario: String,
    #[serde(default)]
    pub first_mes: String,
    #[serde(default)]
    pub mes_example: String,

    // V2 fields often included but technically extensions/optional
    #[serde(default)]
    pub creator_notes: String,
    #[serde(default)]
    pub system_prompt: String,
    #[serde(default)]
    pub post_history_instructions: String,
    #[serde(default)]
    pub alternate_greetings: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub creator: String,
    #[serde(default)]
    pub character_version: String,
    #[serde(default)]
    pub extensions: HashMap<String, Value>,

    // --- V2 fields changed/clarified in V3 ---
    // `creator_notes`: Already included above, V3 clarifies multilingual handling.
    pub character_book: Option<Lorebook>, // V3 makes this optional

    // --- New Fields in V3 ---
    pub assets: Option<Vec<Asset>>,
    pub nickname: Option<String>,
    pub creator_notes_multilingual: Option<HashMap<String, String>>,
    pub source: Option<Vec<String>>,
    #[serde(default)]
    pub group_only_greetings: Vec<String>,
    pub creation_date: Option<i64>, // Unix timestamp (seconds)
    pub modification_date: Option<i64>, // Unix timestamp (seconds)
}

// Asset Definition (within assets array)
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct Asset {
    pub r#type: String, // Using r# prefix as 'type' is a Rust keyword
    pub uri: String,
    pub name: String,
    pub ext: String,
}

// Lorebook Definition
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "snake_case")]
pub struct Lorebook {
    pub name: Option<String>,
    pub description: Option<String>,
    pub scan_depth: Option<i64>,
    pub token_budget: Option<i64>,
    pub recursive_scanning: Option<bool>,
    #[serde(default)]
    pub extensions: HashMap<String, Value>,
    #[serde(default)]
    pub entries: Vec<LorebookEntry>,
}

// Lorebook Entry Definition
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub struct LorebookEntry {
    #[serde(default)]
    pub keys: Vec<String>,
    pub content: String,
    #[serde(default)]
    pub extensions: HashMap<String, Value>,
    pub enabled: bool,
    #[serde(default)] // Assume 0 if missing.
    pub insertion_order: i64,
    pub case_sensitive: Option<bool>,

    // V3 additions / Required V2 optionals
    #[serde(default)] // Default is false
    pub use_regex: bool,
    pub constant: Option<bool>,

    // Optional fields (compatibility)
    pub name: Option<String>,
    pub priority: Option<i64>,
    pub id: Option<Value>, // Can be string or number according to spec
    pub comment: Option<String>,

    // Selective Activation fields
    pub selective: Option<bool>,
    #[serde(default)]
    // Sticking with TS Array<string> definition from spec for now
    pub secondary_keys: Vec<String>,


    // Position (only before/after_char mentioned in struct definition)
    // Making this optional as it's not always present
    pub position: Option<LorebookEntryPosition>,
}

// Enum for Lorebook Entry Position Field
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LorebookEntryPosition {
    BeforeChar,
    AfterChar,
    // V3 spec mentions more positions under decorators (after_desc, before_desc, personality, scenario)
    // These seem handled by decorators, not this specific field based on the struct definition.
    // Keeping this enum minimal based on the direct `position` field description.
}

// Standalone Lorebook Structure (for export/import)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StandaloneLorebook {
    pub spec: String, // Should be "lorebook_v3"
    pub data: Lorebook,
}

// Declare the test module (it lives in a separate file)
#[cfg(test)]
#[path = "character_card_tests.rs"]
mod tests;

// Test module removed from here 