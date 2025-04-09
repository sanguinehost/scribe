use serde::{Deserialize, Serialize};
use serde_json::Value; // Using Value for flexibility in extensions and mixed types like id
use std::collections::HashMap;
use uuid::Uuid; // <-- Add Uuid import

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

// --- Diesel Database Models ---

use diesel::prelude::*;
use crate::schema::{characters, character_assets, lorebooks, lorebook_entries};
use crate::models::users::User; // Assuming User model exists here
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue; // Alias to avoid conflict with serde_json::Value

#[derive(Queryable, Selectable, Identifiable, Associations, Debug, Serialize)]
#[diesel(table_name = characters)]
#[diesel(belongs_to(User))] // Foreign key user_id -> users(id)
pub struct Character {
    #[diesel(deserialize_as = Uuid)] // Specify type if needed, though Diesel might infer
    pub id: Uuid, // Changed from i32
    #[diesel(deserialize_as = Uuid)]
    pub user_id: Uuid, // Changed from i32
    pub spec: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<String>,
    pub personality: Option<String>,
    pub scenario: Option<String>,
    pub first_mes: Option<String>,
    pub mes_example: Option<String>,
    pub creator_notes: Option<String>,
    pub system_prompt: Option<String>,
    pub post_history_instructions: Option<String>,
    pub tags: Option<Vec<Option<String>>>, // Assuming TEXT[] maps to Vec<Option<String>>
    pub creator: Option<String>,
    pub character_version: Option<String>,
    pub alternate_greetings: Option<Vec<Option<String>>>,
    pub nickname: Option<String>,
    pub creator_notes_multilingual: Option<JsonValue>, // JSONB
    pub source: Option<Vec<Option<String>>>,
    pub group_only_greetings: Option<Vec<Option<String>>>,
    pub creation_date: Option<DateTime<Utc>>, // TIMESTAMP WITH TIME ZONE
    pub modification_date: Option<DateTime<Utc>>, // TIMESTAMP WITH TIME ZONE
    pub created_at: DateTime<Utc>, // Changed from Option<DateTime<Utc>>
    pub updated_at: DateTime<Utc>, // Changed from Option<DateTime<Utc>>
}

// Note: For Insertable, we might need a separate struct `NewCharacter`
// if some fields (like id, created_at, updated_at) are not set manually during insertion.
#[derive(Insertable, Debug)]
#[diesel(table_name = characters)]
pub struct NewCharacter {
    #[diesel(serialize_as = Uuid)] // Specify type if needed
    pub user_id: Uuid, // Changed from i32
    pub spec: String,
    pub spec_version: String,
    pub name: String,
    pub description: Option<String>,
    pub personality: Option<String>,
    pub scenario: Option<String>,
    pub first_mes: Option<String>,
    pub mes_example: Option<String>,
    pub creator_notes: Option<String>,
    pub system_prompt: Option<String>,
    pub post_history_instructions: Option<String>,
    pub tags: Option<Vec<Option<String>>>,
    pub creator: Option<String>,
    pub character_version: Option<String>,
    pub alternate_greetings: Option<Vec<Option<String>>>,
    pub nickname: Option<String>,
    pub creator_notes_multilingual: Option<JsonValue>,
    pub source: Option<Vec<Option<String>>>,
    pub group_only_greetings: Option<Vec<Option<String>>>,
    pub creation_date: Option<DateTime<Utc>>,
    pub modification_date: Option<DateTime<Utc>>,
    // created_at and updated_at are usually handled by the database default
}


#[derive(Queryable, Selectable, Identifiable, Associations, Debug, Serialize)]
#[diesel(table_name = character_assets)]
#[diesel(belongs_to(Character))] // Foreign key character_id -> characters(id)
pub struct CharacterAsset {
    pub id: i32,
    #[diesel(deserialize_as = Uuid)]
    pub character_id: Uuid, // Changed from i32
    #[serde(rename = "type")] // Match JSON spec, handle Rust keyword
    pub asset_type: String, // Renamed from `type_` to match DB column
    pub uri: String,
    pub name: String,
    pub ext: String,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = character_assets)]
pub struct NewCharacterAsset {
    #[diesel(serialize_as = Uuid)]
    pub character_id: Uuid, // Changed from i32
    pub asset_type: String, // Renamed from `type_`
    pub uri: String,
    pub name: String,
    pub ext: String,
}


#[derive(Queryable, Selectable, Identifiable, Associations, Debug, Serialize)]
#[diesel(table_name = lorebooks)]
#[diesel(belongs_to(Character))] // Foreign key character_id -> characters(id)
pub struct DbLorebook {
    pub id: i32,
    #[diesel(deserialize_as = Uuid)]
    pub character_id: Uuid, // Changed from i32
    pub name: Option<String>,
    pub description: Option<String>,
    pub scan_depth: Option<i32>,
    pub token_budget: Option<i32>,
    pub recursive_scanning: Option<bool>,
    pub extensions: Option<JsonValue>, // JSONB
}

#[derive(Insertable, Debug)]
#[diesel(table_name = lorebooks)]
pub struct NewDbLorebook {
    #[diesel(serialize_as = Uuid)]
    pub character_id: Uuid, // Changed from i32
    pub name: Option<String>,
    pub description: Option<String>,
    pub scan_depth: Option<i32>,
    pub token_budget: Option<i32>,
    pub recursive_scanning: Option<bool>,
    pub extensions: Option<JsonValue>,
}


#[derive(Queryable, Selectable, Identifiable, Associations, Debug, Serialize)]
#[diesel(table_name = lorebook_entries)]
#[diesel(belongs_to(DbLorebook, foreign_key = lorebook_id))] // Explicitly set foreign key
pub struct DbLorebookEntry {
    pub id: i32,
    pub lorebook_id: i32,
    pub keys: Vec<Option<String>>, // TEXT[]
    pub content: String,
    pub extensions: Option<JsonValue>, // JSONB
    pub enabled: bool,
    pub insertion_order: i32,
    pub case_sensitive: Option<bool>,
    pub use_regex: bool,
    pub constant: Option<bool>,
    pub name: Option<String>,
    pub priority: Option<i32>,
    pub entry_id: Option<String>,
    pub comment: Option<String>,
    pub selective: Option<bool>,
    pub secondary_keys: Option<Vec<Option<String>>>, // TEXT[]
    pub position: Option<String>,
}

#[derive(Insertable, Debug)]
#[diesel(table_name = lorebook_entries)]
pub struct NewDbLorebookEntry {
    pub lorebook_id: i32,
    pub keys: Vec<Option<String>>,
    pub content: String,
    pub extensions: Option<JsonValue>,
    pub enabled: bool,
    pub insertion_order: i32,
    pub case_sensitive: Option<bool>,
    pub use_regex: bool,
    pub constant: Option<bool>,
    pub name: Option<String>,
    pub priority: Option<i32>,
    pub entry_id: Option<String>,
    pub comment: Option<String>,
    pub selective: Option<bool>,
    pub secondary_keys: Option<Vec<Option<String>>>,
    pub position: Option<String>,
} 