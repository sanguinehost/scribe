use serde::{Deserialize, Deserializer, Serialize}; // Added Deserializer
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
    pub creation_date: Option<i64>,     // Unix timestamp (seconds)
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

// --- Lorebook Decorator Definitions ---

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DecoratorRole {
    Assistant,
    System,
    User,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DecoratorPosition {
    AfterDesc,
    BeforeDesc,
    Personality,
    Scenario,
    // Application specific positions could be added here if needed
    #[serde(other)] // Catch-all for unknown positions
    Unknown,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DecoratorUiPromptType {
    PostHistoryInstructions,
    SystemPrompt,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decorator {
    pub name: String,
    pub value: Option<String>,     // Store raw value string for flexibility
    pub fallbacks: Vec<Decorator>, // For @@@ fallback mechanism
}

// --- End Lorebook Decorator Definitions ---

// Helper function to parse decorators from content string
// Making this private again as tests are now colocated
fn parse_decorators_from_content(raw_content: &str) -> (Vec<Decorator>, String) {
    let mut decorators = Vec::new();
    let mut content_lines = Vec::new();
    let mut lines = raw_content.lines().peekable();

    while let Some(line) = lines.next() {
        let trimmed_line = line.trim(); // Trim leading/trailing whitespace

        if trimmed_line.starts_with("@@") && !trimmed_line.starts_with("@@@") {
            // Found a potential main decorator line
            // Trim leading whitespace *after* the prefix before splitting
            let content_after_prefix = trimmed_line[2..].trim();

            // If there's no content after @@, treat it as content
            if content_after_prefix.is_empty() {
                content_lines.push(line);
                continue;
            }

            let parts: Vec<&str> = content_after_prefix
                .splitn(2, |c: char| c.is_whitespace())
                .collect();
            // Trim potential trailing whitespace from name
            let name = parts.get(0).unwrap_or(&"").trim_end().to_string();

            if name.is_empty() {
                // Invalid decorator line, treat as content
                content_lines.push(line);
                continue;
            }

            let value = parts.get(1).map(|v| v.trim().to_string());

            let mut fallbacks = Vec::new();
            // Check subsequent lines for fallbacks (@@@)
            while let Some(next_line) = lines.peek() {
                let trimmed_next = next_line.trim(); // Trim first to check prefix
                if trimmed_next.starts_with("@@@") {
                    // Original line needed for whitespace check later: let fallback_line = lines.next().unwrap();
                    // Consume the fallback line
                    let fallback_line = lines.next().unwrap();

                    // Skip if the line is just "@@@" or "@@@" followed by whitespace
                    if trimmed_next == "@@@" || trimmed_next[3..].trim().is_empty() {
                        content_lines.push(fallback_line);
                        continue;
                    }

                    // Trim leading whitespace *after* the prefix before splitting
                    let fallback_content_after_prefix = trimmed_next[3..].trim();

                    // If there's no content after @@@, treat it as content
                    if fallback_content_after_prefix.is_empty() {
                        content_lines.push(fallback_line);
                        continue;
                    }

                    let fallback_parts: Vec<&str> = fallback_content_after_prefix
                        .splitn(2, |c: char| c.is_whitespace())
                        .collect();
                    // Trim potential trailing whitespace from name
                    let fallback_name = fallback_parts.get(0).unwrap_or(&"").trim_end().to_string();

                    if fallback_name.is_empty() {
                        // Invalid fallback line, treat as content
                        content_lines.push(fallback_line);
                        continue;
                    }

                    let fallback_value = fallback_parts.get(1).map(|v| v.trim().to_string());

                    // Check: If original line had leading whitespace AND value is missing, treat as content
                    // We use the original `fallback_line` (consumed earlier) vs `trimmed_next`
                    if fallback_line != trimmed_next && fallback_value.is_none() {
                        content_lines.push(fallback_line); // Use the original consumed line
                        continue; // Skip adding this as a fallback
                    }

                    // Fallbacks don't have their own fallbacks according to spec example
                    fallbacks.push(Decorator {
                        name: fallback_name,
                        value: fallback_value,
                        fallbacks: Vec::new(), // Fallbacks don't have fallbacks
                    });
                } else {
                    // Next line is not a fallback, stop checking
                    break;
                }
            }

            decorators.push(Decorator {
                name,
                value,
                fallbacks,
            });
        } else {
            // Not a valid decorator line, add to content
            content_lines.push(line);
        }
    }

    // Reconstruct content, trimming leading/trailing empty lines that might result from decorator removal
    let processed_content = content_lines
        .join("\n")
        .trim_matches('\n') // Remove leading/trailing newlines potentially left by decorators
        .to_string();

    (decorators, processed_content)
}

// Lorebook Entry Definition
#[derive(Serialize, Debug, Clone)] // Removed Deserialize temporarily, will add custom later
#[serde(rename_all = "snake_case")]
pub struct LorebookEntry {
    #[serde(default)]
    pub keys: Vec<String>,
    // Raw content as read from JSON
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
    pub secondary_keys: Vec<String>,

    // Position (only before/after_char mentioned in struct definition)
    pub position: Option<LorebookEntryPosition>,

    // --- Fields derived from parsing decorators ---
    #[serde(skip)] // Don't serialize/deserialize this directly
    pub parsed_decorators: Vec<Decorator>,
    #[serde(skip)] // Don't serialize/deserialize this directly
    pub processed_content: String, // Content after decorators are stripped
}

// We need a temporary struct for deserialization before processing decorators
#[derive(Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
struct RawLorebookEntry {
    #[serde(default)]
    keys: Vec<String>,
    content: String,
    #[serde(default)]
    extensions: HashMap<String, Value>,
    enabled: bool,
    #[serde(default)]
    insertion_order: i64,
    case_sensitive: Option<bool>,
    #[serde(default)]
    use_regex: bool,
    constant: Option<bool>,
    name: Option<String>,
    priority: Option<i64>,
    id: Option<Value>,
    comment: Option<String>,
    selective: Option<bool>,
    #[serde(default)]
    secondary_keys: Vec<String>,
    position: Option<LorebookEntryPosition>,
}

// Custom Deserialize implementation for LorebookEntry to handle decorator parsing
impl<'de> Deserialize<'de> for LorebookEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw: RawLorebookEntry = RawLorebookEntry::deserialize(deserializer)?;

        // Parse decorators from the raw content
        let (parsed_decorators, processed_content) = parse_decorators_from_content(&raw.content);

        Ok(LorebookEntry {
            keys: raw.keys,
            content: raw.content, // Keep original raw content
            extensions: raw.extensions,
            enabled: raw.enabled,
            insertion_order: raw.insertion_order,
            case_sensitive: raw.case_sensitive,
            use_regex: raw.use_regex,
            constant: raw.constant,
            name: raw.name,
            priority: raw.priority,
            id: raw.id,
            comment: raw.comment,
            selective: raw.selective,
            secondary_keys: raw.secondary_keys,
            position: raw.position,
            // --- Populate derived fields ---
            parsed_decorators,
            processed_content,
        })
    }
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

// Test module declaration removed as tests are now in the /tests directory
/*
// Declare the test module (it lives in a separate file)
#[cfg(test)]
#[path = "character_card_tests.rs"]
mod tests;
*/

// Test module removed from here

// --- Diesel Database Models ---

use crate::schema::{character_assets, lorebook_entries, lorebooks};
use diesel::prelude::*; // Removed unused: characters
// use crate::models::users::User; // Unused import
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue; // Alias to avoid conflict with serde_json::Value

#[derive(Debug, Queryable, Selectable, Serialize, Deserialize, Clone)]
#[diesel(table_name = crate::schema::characters)]
#[diesel(check_for_backend(diesel::pg::Pg))]
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
    pub created_at: DateTime<Utc>,            // Changed from Option<DateTime<Utc>>
    pub updated_at: DateTime<Utc>,            // Changed from Option<DateTime<Utc>>
}

// Note: For Insertable, we might need a separate struct `NewCharacter`
// if some fields (like id, created_at, updated_at) are not set manually during insertion.
#[derive(Default)] // Added Default derive
#[derive(Debug, Insertable, Clone)]
#[diesel(table_name = crate::schema::characters)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct NewCharacter {
    pub user_id: Uuid,
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
}

// --- Conversion from Parsed Card to NewCharacter ---
use crate::services::character_parser::ParsedCharacterCard;

impl NewCharacter {
    // Add user_id parameter
    pub fn from_parsed_card(parsed: &ParsedCharacterCard, user_id: Uuid) -> Self {
        match parsed {
            ParsedCharacterCard::V3(card_v3) => {
                // --- Handling V3 Card ---
                let data = &card_v3.data; // Borrow data to avoid repeated card_v3.data

                // Ensure spec and spec_version are handled correctly
                let spec = card_v3.spec.clone();
                let spec_version = card_v3.spec_version.clone();

                // Convert tags if necessary (Vec<String> -> Option<Vec<Option<String>>>)
                let tags = if data.tags.is_empty() {
                    None
                } else {
                    Some(data.tags.clone().into_iter().map(Some).collect())
                };
                let alternate_greetings = if data.alternate_greetings.is_empty() {
                    None
                } else {
                    Some(
                        data.alternate_greetings
                            .clone()
                            .into_iter()
                            .map(Some)
                            .collect(),
                    )
                };
                let group_only_greetings = if data.group_only_greetings.is_empty() {
                    None
                } else {
                    Some(
                        data.group_only_greetings
                            .clone()
                            .into_iter()
                            .map(Some)
                            .collect(),
                    )
                };
                let source = data.source.as_ref().and_then(|s| {
                    if s.is_empty() {
                        None
                    } else {
                        Some(s.clone().into_iter().map(Some).collect())
                    }
                });

                // Convert optional timestamps (Option<i64> -> Option<DateTime<Utc>>)
                let creation_date_ts = data
                    .creation_date
                    .and_then(|ts| DateTime::from_timestamp(ts, 0));
                let modification_date_ts = data
                    .modification_date
                    .and_then(|ts| DateTime::from_timestamp(ts, 0));

                let creator_notes_multilingual_json = data
                    .creator_notes_multilingual
                    .as_ref()
                    .and_then(|m| serde_json::to_value(m).ok()) // Convert HashMap to JsonValue
                    .filter(|v| !v.is_null()); // Ensure it's not null before storing

                NewCharacter {
                    user_id,                                     // Use passed user_id
                    name: data.name.clone().unwrap_or_default(), // V3 name is Option<String>, DB needs String
                    // Wrap non-optional V3 strings in Some() for DB Option<String>, filter empty
                    description: Some(data.description.clone()).filter(|s| !s.is_empty()),
                    personality: Some(data.personality.clone()).filter(|s| !s.is_empty()),
                    scenario: Some(data.scenario.clone()).filter(|s| !s.is_empty()),
                    first_mes: Some(data.first_mes.clone()).filter(|s| !s.is_empty()),
                    mes_example: Some(data.mes_example.clone()).filter(|s| !s.is_empty()),
                    creator_notes: Some(data.creator_notes.clone()).filter(|s| !s.is_empty()),
                    system_prompt: Some(data.system_prompt.clone()).filter(|s| !s.is_empty()),
                    post_history_instructions: Some(data.post_history_instructions.clone())
                        .filter(|s| !s.is_empty()),
                    creator: Some(data.creator.clone()).filter(|s| !s.is_empty()),
                    character_version: Some(data.character_version.clone())
                        .filter(|s| !s.is_empty()),
                    // Use converted vecs
                    alternate_greetings,
                    tags,
                    spec,         // Use extracted spec
                    spec_version, // Use extracted spec_version
                    // character_book: data.character_book.clone(), // DB has separate table, handle later if needed
                    nickname: data.nickname.clone(), // Already Option<String>
                    creator_notes_multilingual: creator_notes_multilingual_json, // Already Option<JsonValue>
                    source,                          // Already Option<Vec<Option<String>>>
                    group_only_greetings,            // Already Option<Vec<Option<String>>>
                    creation_date: creation_date_ts, // Already Option<DateTime<Utc>>
                    modification_date: modification_date_ts, // Already Option<DateTime<Utc>>
                }
            }
            ParsedCharacterCard::V2Fallback(data_v2) => {
                // --- Handling V2 Fallback Card ---
                // Map relevant V2 fields, set spec/version for fallback

                // V2 tags/greetings are Vec<String>, DB wants Option<Vec<Option<String>>>
                let tags = if data_v2.tags.is_empty() {
                    None
                } else {
                    Some(data_v2.tags.clone().into_iter().map(Some).collect())
                };
                let alternate_greetings = if data_v2.alternate_greetings.is_empty() {
                    None
                } else {
                    Some(
                        data_v2
                            .alternate_greetings
                            .clone()
                            .into_iter()
                            .map(Some)
                            .collect(),
                    )
                };

                // Most V2 fields are String, DB wants Option<String>. Wrap in Some() and filter empty.
                NewCharacter {
                    user_id,                                        // Use passed user_id
                    name: data_v2.name.clone().unwrap_or_default(), // V2 name is Option<String>, DB needs String
                    description: Some(data_v2.description.clone()).filter(|s| !s.is_empty()),
                    personality: Some(data_v2.personality.clone()).filter(|s| !s.is_empty()),
                    scenario: Some(data_v2.scenario.clone()).filter(|s| !s.is_empty()),
                    first_mes: Some(data_v2.first_mes.clone()).filter(|s| !s.is_empty()),
                    mes_example: Some(data_v2.mes_example.clone()).filter(|s| !s.is_empty()),
                    creator_notes: Some(data_v2.creator_notes.clone()).filter(|s| !s.is_empty()),
                    system_prompt: Some(data_v2.system_prompt.clone()).filter(|s| !s.is_empty()),
                    post_history_instructions: Some(data_v2.post_history_instructions.clone())
                        .filter(|s| !s.is_empty()),
                    tags, // Use converted tags
                    creator: Some(data_v2.creator.clone()).filter(|s| !s.is_empty()),
                    character_version: Some(data_v2.character_version.clone())
                        .filter(|s| !s.is_empty()),
                    alternate_greetings, // Use converted greetings
                    spec: "chara_card_v2_fallback".to_string(), // Indicate fallback
                    spec_version: "2.0".to_string(), // Indicate V2 origin
                    // V3 specific fields are left None or default
                    nickname: None,
                    creator_notes_multilingual: None,
                    source: None,
                    group_only_greetings: None,
                    creation_date: None,
                    modification_date: None,
                }
            }
        }
    }
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

// --- Unit tests ---
#[cfg(test)]
mod tests {
    use super::*; // Import items from the parent module

    // --- Tests for parse_decorators_from_content (moved from tests/character_card_tests.rs) ---

    #[test]
    fn test_parse_decorators_no_decorators() {
        let content = "This is normal content.\nWith multiple lines.";
        let (decorators, processed_content) = parse_decorators_from_content(content);
        assert!(decorators.is_empty());
        assert_eq!(processed_content, content);
    }

    #[test]
    fn test_parse_decorators_simple() {
        let content = "@@role system\n@@position after_desc\nActual content here.";
        let (decorators, processed_content) = parse_decorators_from_content(content);
        assert_eq!(decorators.len(), 2);
        assert_eq!(decorators[0].name, "role");
        assert_eq!(decorators[0].value, Some("system".to_string()));
        assert!(decorators[0].fallbacks.is_empty());
        assert_eq!(decorators[1].name, "position");
        assert_eq!(decorators[1].value, Some("after_desc".to_string()));
        assert!(decorators[1].fallbacks.is_empty());
        assert_eq!(processed_content, "Actual content here.");
    }

    #[test]
    fn test_parse_decorators_no_value() {
        let content = "@@enabled\nContent line.";
        let (decorators, processed_content) = parse_decorators_from_content(content);
        assert_eq!(decorators.len(), 1);
        assert_eq!(decorators[0].name, "enabled");
        assert_eq!(decorators[0].value, None);
        assert!(decorators[0].fallbacks.is_empty());
        assert_eq!(processed_content, "Content line.");
    }

    #[test]
    fn test_parse_decorators_with_fallbacks() {
        let content = "@@name Character Name\n@@@nombre Nombre del Personaje\n@@@nom Nom du Personnage\nDescription starts here.";
        let (decorators, processed_content) = parse_decorators_from_content(content);
        assert_eq!(decorators.len(), 1);
        let main_decorator = &decorators[0];
        assert_eq!(main_decorator.name, "name");
        assert_eq!(main_decorator.value, Some("Character Name".to_string()));
        assert_eq!(main_decorator.fallbacks.len(), 2);
        assert_eq!(main_decorator.fallbacks[0].name, "nombre");
        assert_eq!(
            main_decorator.fallbacks[0].value,
            Some("Nombre del Personaje".to_string())
        );
        assert!(main_decorator.fallbacks[0].fallbacks.is_empty());
        assert_eq!(main_decorator.fallbacks[1].name, "nom");
        assert_eq!(
            main_decorator.fallbacks[1].value,
            Some("Nom du Personnage".to_string())
        );
        assert!(main_decorator.fallbacks[1].fallbacks.is_empty());
        assert_eq!(processed_content, "Description starts here.");
    }

    #[test]
    fn test_parse_decorators_mixed_content() {
        let content = "Line 1\n@@decorator1 value1\nLine 2\n@@decorator2\n@@@fallback2 val_fb\nLine 3";
        let (decorators, processed_content) = parse_decorators_from_content(content);
        assert_eq!(decorators.len(), 2);
        assert_eq!(decorators[0].name, "decorator1");
        assert_eq!(decorators[0].value, Some("value1".to_string()));
        assert!(decorators[0].fallbacks.is_empty());
        assert_eq!(decorators[1].name, "decorator2");
        assert_eq!(decorators[1].value, None);
        assert_eq!(decorators[1].fallbacks.len(), 1);
        assert_eq!(decorators[1].fallbacks[0].name, "fallback2");
        assert_eq!(decorators[1].fallbacks[0].value, Some("val_fb".to_string()));
        assert_eq!(processed_content, "Line 1\nLine 2\nLine 3");
    }

    #[test]
    fn test_parse_decorators_invalid_lines() {
        let content =
            "Line 1\n@@\n@@@ \n@@ name value\n@@@fallback val\n  @@@ invalid_fallback\nLine 2";
        let (decorators, processed_content) = parse_decorators_from_content(content);
        assert_eq!(decorators.len(), 1); // Only the valid "@@ name value" should be parsed
        assert_eq!(decorators[0].name, "name");
        assert_eq!(decorators[0].value, Some("value".to_string()));
        assert_eq!(decorators[0].fallbacks.len(), 1); // Only the valid "@@@fallback val"
        assert_eq!(decorators[0].fallbacks[0].name, "fallback");
        assert_eq!(decorators[0].fallbacks[0].value, Some("val".to_string()));
        // Invalid lines should be treated as content
        assert_eq!(
            processed_content,
            "Line 1\n@@\n@@@ \n  @@@ invalid_fallback\nLine 2"
        );
    }

    #[test]
    fn test_parse_decorators_whitespace_handling() {
        let content =
            "  @@ spaced_name   spaced value  \n\t@@@ spaced_fallback \t spaced_fb_value \t\nContent";
        let (decorators, processed_content) = parse_decorators_from_content(content);
        assert_eq!(decorators.len(), 1);
        assert_eq!(decorators[0].name, "spaced_name");
        assert_eq!(decorators[0].value, Some("spaced value".to_string()));
        assert_eq!(decorators[0].fallbacks.len(), 1);
        assert_eq!(decorators[0].fallbacks[0].name, "spaced_fallback");
        assert_eq!(
            decorators[0].fallbacks[0].value,
            Some("spaced_fb_value".to_string())
        );
        assert_eq!(processed_content, "Content");
    }

    #[test]
    fn test_parse_decorators_empty_content() {
        let content = "";
        let (decorators, processed_content) = parse_decorators_from_content(content);
        assert!(decorators.is_empty());
        assert_eq!(processed_content, "");
    }

    #[test]
    fn test_parse_decorators_only_decorators() {
        let content = "@@d1 v1\n@@@f1 vf1\n@@d2";
        let (decorators, processed_content) = parse_decorators_from_content(content);
        assert_eq!(decorators.len(), 2);
        assert_eq!(decorators[0].name, "d1");
        assert_eq!(decorators[0].value, Some("v1".to_string()));
        assert_eq!(decorators[0].fallbacks.len(), 1);
        assert_eq!(decorators[1].name, "d2");
        assert_eq!(decorators[1].value, None);
        assert!(decorators[1].fallbacks.is_empty());
        assert_eq!(processed_content, ""); // Content should be empty
    }

    #[test]
    fn test_parse_decorators_fallback_without_main() {
        let content = "Line 1\n@@@fallback value\nLine 2";
        let (decorators, processed_content) = parse_decorators_from_content(content);
        assert!(decorators.is_empty()); // Fallback without main is treated as content
        assert_eq!(processed_content, content);
    }

    #[test]
    fn test_parse_decorators_edge_cases() {
        // Test @@ followed by nothing or whitespace
        let content1 = "@@\nContent";
        let (decorators1, processed_content1) = parse_decorators_from_content(content1);
        assert!(decorators1.is_empty());
        assert_eq!(processed_content1, "@@\nContent"); // Should be treated as content

        let content2 = "@@ \nContent";
        let (decorators2, processed_content2) = parse_decorators_from_content(content2);
        assert!(decorators2.is_empty());
        assert_eq!(processed_content2, "@@ \nContent"); // Should be treated as content

        // Test @@@ followed by nothing or whitespace
        let content3 = "@@main val\n@@@\nContent";
        let (decorators3, processed_content3) = parse_decorators_from_content(content3);
        assert_eq!(decorators3.len(), 1);
        assert!(decorators3[0].fallbacks.is_empty());
        assert_eq!(processed_content3, "@@@\nContent"); // @@@ treated as content

        let content4 = "@@main val\n@@@ \nContent";
        let (decorators4, processed_content4) = parse_decorators_from_content(content4);
        assert_eq!(decorators4.len(), 1);
        assert!(decorators4[0].fallbacks.is_empty());
        assert_eq!(processed_content4, "@@@ \nContent"); // @@@ treated as content

        // Test @@@ fallback_name (no value) with leading whitespace
        let content5 = "@@main val\n  @@@fallback_no_val\nContent";
        let (decorators5, processed_content5) = parse_decorators_from_content(content5);
        assert_eq!(decorators5.len(), 1);
        assert!(decorators5[0].fallbacks.is_empty()); // Fallback treated as content due to whitespace + no value
        assert_eq!(processed_content5, "  @@@fallback_no_val\nContent");

        // Test @@@ with empty name
        let content6 = "@@main val\n@@@ \nContent"; // Already tested by content4, but re-verify logic
        let (decorators6, processed_content6) = parse_decorators_from_content(content6);
        assert_eq!(decorators6.len(), 1);
        assert!(decorators6[0].fallbacks.is_empty());
        assert_eq!(processed_content6, "@@@ \nContent");

        // Test @@ with empty name
        let content7 = "@@ \nContent"; // Already tested by content2, but re-verify logic
        let (decorators7, processed_content7) = parse_decorators_from_content(content7);
        assert!(decorators7.is_empty());
        assert_eq!(processed_content7, "@@ \nContent");
    }

    // TODO: Add other tests for character_card.rs structs/impls here if needed
}
